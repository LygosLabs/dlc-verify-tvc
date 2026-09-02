//! Conformance smoke tests over the public Lygos DLC Verify fixtures.
#![allow(clippy::expect_used)]

use serde::Deserialize;
use verifier_core::verify;
use verifier_schema::{VerificationRequest, VerificationStatus};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    offer: String,
    accept: String,
    #[serde(default)]
    sign: Option<String>,
}

fn fixture(contents: &str) -> Fixture {
    serde_json::from_str(contents).expect("public fixture must be valid JSON")
}

fn verify_fixture(contents: &str) {
    let fixture = fixture(contents);
    let result = verify(&VerificationRequest {
        offer: fixture.offer,
        accept: fixture.accept,
        sign: fixture.sign,
        policy: None,
        challenge: Some("fixture-conformance".to_owned()),
    })
    .expect("DDK must parse the public Lygos fixture");

    assert_ne!(result.verification_status, VerificationStatus::Fail);
    assert!(result.verification_failures.is_empty());
    assert!(!result.outcomes.is_empty());
    assert!(result.oracle_sig_valid);
}

#[test]
fn parses_sample() {
    let contents = include_str!("fixtures/sample.json");
    verify_fixture(contents);
    let fixture = fixture(contents);
    let result = verify(&VerificationRequest {
        offer: fixture.offer,
        accept: fixture.accept,
        sign: None,
        policy: None,
        challenge: None,
    })
    .expect("sample must verify");
    assert_eq!(
        result.transcript_hash,
        "fa8fe1a048c54304e90c9efd618cb4b7c47a82f5d19da5c5bc5fafd6faf4b1ca"
    );
}

#[test]
fn parses_matured_loan() {
    verify_fixture(include_str!("fixtures/loan-matured-7932e4c2.json"));
}

#[test]
fn parses_signed_testnet_loan() {
    let contents = include_str!("fixtures/testnet-loan-118c9fc9.json");
    verify_fixture(contents);
    let fixture = fixture(contents);
    let result = verify(&VerificationRequest {
        offer: fixture.offer,
        accept: fixture.accept,
        sign: fixture.sign,
        policy: None,
        challenge: None,
    })
    .expect("signed fixture must verify");
    assert_eq!(
        result.transcript_hash,
        "c3032618cb79eb23f5de100d50849017b7311e03290076ee3fcc14d3e2afde25"
    );
}

#[test]
fn rejects_trailing_message_bytes() {
    let fixture = fixture(include_str!("fixtures/sample.json"));
    let error = verify(&VerificationRequest {
        offer: format!("{}00", fixture.offer),
        accept: fixture.accept,
        sign: None,
        policy: None,
        challenge: None,
    })
    .expect_err("strict parser must reject trailing bytes");
    assert!(error.to_string().contains("trailing bytes"));
}
