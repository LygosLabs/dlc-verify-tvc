//! Deterministic request handlers and TVC App Proof construction.

use crate::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use verifier_schema::{
    AppProof, Network, VerificationPolicy, VerificationRequest, VerificationResult,
    VerifiedResponse,
};

const APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofPayload<'a> {
    proof_type: &'static str,
    schema_version: &'static str,
    verifier_version: &'static str,
    request_digest: String,
    challenge: &'a str,
    result: &'a VerificationResult,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Transitional input accepted by the TypeScript-compatible routes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LegacyVerificationRequest {
    #[serde(alias = "offerHex")]
    offer: String,
    #[serde(alias = "acceptHex")]
    accept: String,
    #[serde(default)]
    sign_hex: Option<String>,
    #[serde(default)]
    expected_oracle_pubkey: Option<String>,
    #[serde(default)]
    network: Option<Network>,
    #[serde(default)]
    policy: Option<VerificationPolicy>,
    #[serde(default)]
    challenge: Option<String>,
}

impl LegacyVerificationRequest {
    fn into_request(self) -> VerificationRequest {
        let mut policy = self.policy.unwrap_or_default();
        if policy.expected_oracle_pubkey.is_none() {
            policy.expected_oracle_pubkey = self.expected_oracle_pubkey;
        }
        if policy.network.is_none() {
            policy.network = self.network;
        }
        let has_policy = policy.network.is_some()
            || policy.expected_oracle_pubkey.is_some()
            || policy.expected_total_collateral_sats.is_some()
            || policy.oracle_event.is_some();
        VerificationRequest {
            offer: self.offer,
            accept: self.accept,
            sign: self.sign_hex,
            policy: has_policy.then_some(policy),
            challenge: self.challenge,
        }
    }
}

pub(crate) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy"}))
}

pub(crate) async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "dlc-verify-tvc",
        "version": env!("CARGO_PKG_VERSION"),
        "schemaVersion": "lygos.dlc-verification.v1",
        "egressRequired": false
    }))
}

pub(crate) async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerificationRequest>,
) -> Result<Json<VerifiedResponse>, Response> {
    verify_and_prove(state, request).await.map(Json)
}

pub(crate) async fn verify_legacy(
    Json(request): Json<LegacyVerificationRequest>,
) -> Result<Json<VerificationResult>, Response> {
    let request = request.into_request();
    let result = tokio::task::spawn_blocking(move || verifier_core::verify(&request))
        .await
        .map_err(|error| internal_error(format!("verifier task failed: {error}")))?
        .map_err(bad_request)?;
    Ok(Json(result))
}

pub(crate) async fn verify_policy_legacy(
    State(state): State<AppState>,
    Json(request): Json<LegacyVerificationRequest>,
) -> Result<Json<VerifiedResponse>, Response> {
    verify_and_prove(state, request.into_request())
        .await
        .map(Json)
}

async fn verify_and_prove(
    state: AppState,
    request: VerificationRequest,
) -> Result<VerifiedResponse, Response> {
    let challenge = request
        .challenge
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| bad_request_message("challenge is required for proof-bearing endpoints"))?
        .to_owned();
    let request_bytes = qos_json::to_vec(&request).map_err(internal_serialization_error)?;
    let request_digest = format!("{:x}", Sha256::digest(&request_bytes));
    let result = tokio::task::spawn_blocking(move || verifier_core::verify(&request))
        .await
        .map_err(|error| internal_error(format!("verifier task failed: {error}")))?
        .map_err(bad_request)?;

    let proof_payload = ProofPayload {
        proof_type: "APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION",
        schema_version: "1",
        verifier_version: env!("CARGO_PKG_VERSION"),
        request_digest,
        challenge: &challenge,
        result: &result,
    };
    let proof_payload_bytes =
        qos_json::to_vec(&proof_payload).map_err(internal_serialization_error)?;
    let signature = state
        .ephemeral_key
        .sign(&proof_payload_bytes)
        .map_err(|error| internal_error(format!("failed to sign App Proof: {error:?}")))?;
    let proof_payload = String::from_utf8(proof_payload_bytes)
        .map_err(|error| internal_error(format!("proof payload is not UTF-8: {error}")))?;

    Ok(VerifiedResponse {
        result,
        proof: AppProof {
            scheme: APP_PROOF_SCHEME.to_owned(),
            public_key: qos_hex::encode(&state.ephemeral_key.public_key().to_bytes()),
            proof_payload,
            signature: qos_hex::encode(&signature),
        },
    })
}

fn bad_request(error: verifier_core::VerifyError) -> Response {
    bad_request_message(error.to_string())
}

fn bad_request_message(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn internal_serialization_error(error: serde_json::Error) -> Response {
    internal_error(format!(
        "failed to serialize canonical proof payload: {error}"
    ))
}

fn internal_error(message: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody { error: message }),
    )
        .into_response()
}
