//! Conformance smoke tests over the public Lygos DLC Verify fixtures.
#![allow(clippy::expect_used)]

use serde::Deserialize;
use verifier_core::{verify, verify_dlc_compatibility};
use verifier_schema::{DlcVerificationPolicy, VerificationRequest, VerificationStatus};

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
    assert!(error.to_string().contains("offer"), "{error}");
}

fn assert_pr9_golden(fixture_contents: &str, golden_contents: &str, expected_key: bool) {
    let fixture = fixture(fixture_contents);
    let expected: serde_json::Value =
        serde_json::from_str(golden_contents).expect("PR #9 golden must be valid JSON");
    let actual = verify_dlc_compatibility(
        &fixture.offer,
        &fixture.accept,
        fixture.sign.as_deref(),
        expected_key
            .then(|| {
                serde_json::from_str::<serde_json::Value>(fixture_contents)
                    .expect("fixture must be JSON")["oraclePubkey"]
                    .as_str()
                    .expect("signed fixture must carry oraclePubkey")
                    .to_owned()
            })
            .as_deref(),
        Some("regtest"),
    );
    let actual = serde_json::to_value(actual).expect("Rust result must serialize");
    assert_eq!(actual, expected);
}

#[test]
fn exact_pr9_sample_result_parity() {
    assert_pr9_golden(
        include_str!("fixtures/sample.json"),
        include_str!("golden/pr9-sample.json"),
        false,
    );
}

#[test]
fn exact_pr9_matured_result_parity() {
    assert_pr9_golden(
        include_str!("fixtures/loan-matured-7932e4c2.json"),
        include_str!("golden/pr9-matured.json"),
        false,
    );
}

#[test]
fn exact_pr9_signed_result_parity() {
    assert_pr9_golden(
        include_str!("fixtures/testnet-loan-118c9fc9.json"),
        include_str!("golden/pr9-signed.json"),
        true,
    );
}

#[test]
fn exact_pr9_signed_policy_parity() {
    let fixture_contents = include_str!("fixtures/testnet-loan-118c9fc9.json");
    let fixture = fixture(fixture_contents);
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../verifier-policy/tests/golden/pr9-signed-policy.json"
    ))
    .expect("PR #9 policy golden must be JSON");
    let policy: DlcVerificationPolicy = serde_json::from_value(golden["policy"].clone())
        .expect("PR #9 policy must match the Rust wire schema");
    let verification = verify_dlc_compatibility(
        &fixture.offer,
        &fixture.accept,
        fixture.sign.as_deref(),
        policy.expected_oracle_pubkey.as_deref(),
        Some("regtest"),
    );
    let actual = verifier_policy::evaluate_dlc_policy(&verification, Some(&policy))
        .expect("policy evaluation must serialize");
    assert_eq!(
        serde_json::to_value(actual).expect("policy result must serialize"),
        golden["result"]
    );
}

#[test]
fn compatibility_output_is_deterministic() {
    let fixture = fixture(include_str!("fixtures/testnet-loan-118c9fc9.json"));
    let first = verify_dlc_compatibility(
        &fixture.offer,
        &fixture.accept,
        fixture.sign.as_deref(),
        None,
        Some("regtest"),
    );
    let second = verify_dlc_compatibility(
        &fixture.offer,
        &fixture.accept,
        fixture.sign.as_deref(),
        None,
        Some("regtest"),
    );
    assert_eq!(
        serde_json::to_value(first).expect("first result must serialize"),
        serde_json::to_value(second).expect("second result must serialize")
    );
}

#[test]
fn bounded_arbitrary_transcripts_never_panic() {
    let mut state = 0x4c79_676f_7344_4c43_u64;
    for length in 0..256_usize {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            bytes.push((state >> 32) as u8);
        }
        let arbitrary = hex::encode(bytes);
        let result = std::panic::catch_unwind(|| {
            verify_dlc_compatibility(
                &arbitrary,
                &arbitrary,
                Some(&arbitrary),
                Some(&"ab".repeat(32)),
                Some("regtest"),
            )
        });
        assert!(result.is_ok(), "bounded input of {length} bytes panicked");
    }
}
