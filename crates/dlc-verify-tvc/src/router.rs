//! HTTP router containing only verifier, health, version, and metrics surfaces.

use crate::{AppState, handler};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post},
};
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Build the TVC application router.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handler::health))
        .route("/version", get(handler::version))
        .route("/api/verify", post(handler::verify_legacy))
        .route("/api/verify-policy", post(handler::verify_policy_legacy))
        .route("/v1/verify", post(handler::verify))
        .layer(DefaultBodyLimit::max(7 * 1024 * 1024))
        .layer(ConcurrencyLimitLayer::new(8))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(
            // Trace metadata only: DLC request bodies and loan terms are never logged.
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use qos_p256::P256Pair;
    use tower::ServiceExt as _;
    use turnkey_client::generated::external::data::v1::AppProof as TurnkeyAppProof;

    fn fixture_request() -> serde_json::Value {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../verifier-core/tests/fixtures/sample.json"
        ))
        .expect("fixture must be JSON");
        serde_json::json!({
            "offer": fixture["offer"],
            "accept": fixture["accept"],
            "challenge": "proof-roundtrip"
        })
    }

    #[tokio::test]
    async fn app_proof_verifies_with_official_turnkey_library() {
        let app = router_with_state(AppState::new(
            P256Pair::generate().expect("ephemeral key generation must succeed"),
        ));
        let response = app
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(fixture_request().to_string()))
                    .expect("request must build"),
            )
            .await
            .expect("request must complete");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body must collect")
            .to_bytes();
        let response: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response must be JSON");
        let proof: TurnkeyAppProof = serde_json::from_value(response["proof"].clone())
            .expect("proof must match Turnkey's standard schema");

        turnkey_proofs::verify_app_proof_signature(&proof)
            .expect("official Turnkey verifier must accept the App Proof");
        assert_eq!(qos_hex::decode(&proof.public_key).unwrap().len(), 130);
        assert_eq!(qos_hex::decode(&proof.signature).unwrap().len(), 64);
        let payload: serde_json::Value =
            serde_json::from_str(&proof.proof_payload).expect("proof payload must be JSON");
        assert_eq!(payload["challenge"], "proof-roundtrip");
        assert_eq!(
            payload["result"]["schemaVersion"],
            "lygos.dlc-verification.v1"
        );
    }

    #[tokio::test]
    async fn legacy_route_accepts_typescript_field_names() {
        let fixture = fixture_request();
        let request = serde_json::json!({
            "offer": fixture["offer"],
            "accept": fixture["accept"]
        });
        let app = router_with_state(AppState::new(P256Pair::generate().unwrap()));
        let response = app
            .oneshot(
                Request::post("/api/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn proof_route_requires_a_challenge() {
        let mut request = fixture_request();
        request.as_object_mut().unwrap().remove("challenge");
        let app = router_with_state(AppState::new(P256Pair::generate().unwrap()));
        let response = app
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
