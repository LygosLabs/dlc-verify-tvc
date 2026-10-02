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
    AppProof, DlcPolicyVerificationResult, DlcVerificationPolicy, DlcVerifyResult, PolicyNetwork,
    TvcVerificationRequest, VerifiedResponse,
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
    result: &'a DlcPolicyVerificationResult,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Exact request accepted by DLC Verify's `/api/verify` endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyVerificationRequest {
    #[serde(alias = "offerHex")]
    offer: Option<String>,
    #[serde(alias = "acceptHex")]
    accept: Option<String>,
    #[serde(default)]
    sign_hex: Option<String>,
    #[serde(default)]
    expected_oracle_pubkey: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

/// Exact request accepted by DLC Verify PR #9's `/api/verify-policy` endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPolicyVerificationRequest {
    #[serde(alias = "offerHex")]
    offer: Option<String>,
    #[serde(alias = "acceptHex")]
    accept: Option<String>,
    #[serde(default)]
    sign_hex: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    policy: Option<DlcVerificationPolicy>,
}

pub(crate) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy"}))
}

pub(crate) async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "dlc-verify-tvc",
        "version": env!("CARGO_PKG_VERSION"),
        "schemaVersion": "lygos.dlc-verification.v1",
        "compatibilityTarget": "LygosLabs/dlc-verify#9@e46703e7adf21ce407e150d4f46ff455ba46fd57",
        "ddkVersion": "2.0.0-rc.8",
        "egressRequired": false
    }))
}

pub(crate) async fn verify(
    State(state): State<AppState>,
    Json(request): Json<TvcVerificationRequest>,
) -> Result<Json<VerifiedResponse>, Response> {
    verify_and_prove(state, request).await.map(Json)
}

pub(crate) async fn verify_legacy(
    State(state): State<AppState>,
    Json(request): Json<LegacyVerificationRequest>,
) -> Result<Json<DlcVerifyResult>, Response> {
    let offer = required_legacy_field(request.offer, "Missing offer or accept hex")
        .map_err(bad_request_message)?;
    let accept = required_legacy_field(request.accept, "Missing offer or accept hex")
        .map_err(bad_request_message)?;
    Ok(Json(
        run_verifier(
            &state,
            offer,
            accept,
            request.sign_hex,
            request.expected_oracle_pubkey,
            request.network,
        )
        .await,
    ))
}

pub(crate) async fn verify_policy_legacy(
    State(state): State<AppState>,
    Json(request): Json<LegacyPolicyVerificationRequest>,
) -> Result<Json<DlcPolicyVerificationResult>, Response> {
    let offer = required_legacy_field(request.offer, "Missing required fields: offer, accept")
        .map_err(bad_request_message)?;
    let accept = required_legacy_field(request.accept, "Missing required fields: offer, accept")
        .map_err(bad_request_message)?;
    let network = request.network.or_else(|| {
        request
            .policy
            .as_ref()
            .and_then(|policy| policy.network)
            .map(policy_network_name)
            .map(str::to_owned)
    });
    run_policy_verifier(
        &state,
        offer,
        accept,
        request.sign_hex,
        request
            .policy
            .as_ref()
            .and_then(|policy| policy.expected_oracle_pubkey.clone()),
        network,
        request.policy,
    )
    .await
    .map(Json)
}

async fn verify_and_prove(
    state: AppState,
    request: TvcVerificationRequest,
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
    let network = request
        .network
        .map(policy_network_name)
        .map(str::to_owned)
        .or_else(|| {
            request
                .policy
                .as_ref()
                .and_then(|policy| policy.network)
                .map(policy_network_name)
                .map(str::to_owned)
        });
    let expected_oracle_pubkey = request
        .policy
        .as_ref()
        .and_then(|policy| policy.expected_oracle_pubkey.clone());
    let result = run_policy_verifier(
        &state,
        request.offer,
        request.accept,
        request.sign_hex,
        expected_oracle_pubkey,
        network,
        request.policy,
    )
    .await?;

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

async fn run_verifier(
    state: &AppState,
    offer: String,
    accept: String,
    sign_hex: Option<String>,
    expected_oracle_pubkey: Option<String>,
    network: Option<String>,
) -> DlcVerifyResult {
    let permit = match state.verifier_permits.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(error) => return task_failure(format!("verifier capacity is unavailable: {error}")),
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verifier_core::verify_dlc_compatibility(
            &offer,
            &accept,
            sign_hex.as_deref(),
            expected_oracle_pubkey.as_deref(),
            network.as_deref(),
        )
    })
    .await
    .unwrap_or_else(|error| task_failure(format!("verifier task failed: {error}")))
}

async fn run_policy_verifier(
    state: &AppState,
    offer: String,
    accept: String,
    sign_hex: Option<String>,
    expected_oracle_pubkey: Option<String>,
    network: Option<String>,
    policy: Option<DlcVerificationPolicy>,
) -> Result<DlcPolicyVerificationResult, Response> {
    let permit = state
        .verifier_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| internal_error(format!("verifier capacity is unavailable: {error}")))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let verification = verifier_core::verify_dlc_compatibility(
            &offer,
            &accept,
            sign_hex.as_deref(),
            expected_oracle_pubkey.as_deref(),
            network.as_deref(),
        );
        verifier_policy::evaluate_dlc_policy(&verification, policy.as_ref())
    })
    .await
    .map_err(|error| internal_error(format!("verifier task failed: {error}")))?
    .map_err(|error| internal_error(format!("policy evaluation failed: {error}")))
}

fn task_failure(error: String) -> DlcVerifyResult {
    let mut result = DlcVerifyResult {
        verification_status: verifier_schema::VerificationStatus::Fail,
        ..DlcVerifyResult::default()
    };
    result
        .verification_failures
        .push("verifier-task-failed".to_owned());
    result.error = Some(error);
    result
}

fn policy_network_name(network: PolicyNetwork) -> &'static str {
    match network {
        PolicyNetwork::Mainnet => "mainnet",
        PolicyNetwork::Testnet => "testnet",
        PolicyNetwork::Regtest => "regtest",
    }
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

fn required_legacy_field(
    value: Option<String>,
    message: &'static str,
) -> Result<String, &'static str> {
    value.filter(|field| !field.is_empty()).ok_or(message)
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
