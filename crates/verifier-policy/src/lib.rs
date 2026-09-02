//! Pure, deterministic evaluation of PR #9 DLC verification policies.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use verifier_schema::{
    AttestedCet, DlcPartyRole, DlcPolicyVerificationResult, DlcVerificationPolicy, DlcVerifyResult,
    OracleEventPreimage, PolicyCheck, PolicyCheckStatus, PolicyCoverage, PolicyNetwork,
    PolicyOracleEventExpectation, PolicyVerificationStatus, VerificationAttestationPayload,
    VerificationStatus,
};

/// Fixed schema committed by every policy verification digest.
pub const ATTESTATION_SCHEMA_VERSION: &str = "lygos.dlc-verification.v1";

/// Maximum caller-supplied outcome expectations evaluated in one request.
pub const MAX_EXPECTED_LENDER_OUTCOMES: usize = 4_096;

/// Error produced while serializing a value for canonical hashing.
#[derive(Debug)]
pub struct CanonicalHashError(serde_json::Error);

impl fmt::Display for CanonicalHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "canonical JSON serialization failed: {}", self.0)
    }
}

impl Error for CanonicalHashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

impl From<serde_json::Error> for CanonicalHashError {
    fn from(error: serde_json::Error) -> Self {
        Self(error)
    }
}

/// Derive the current Lygos loan oracle event ID from its canonical preimage.
///
/// This intentionally matches PR #9: trim each field, join them with `//`, hash the UTF-8
/// bytes with SHA-256, and prefix the digest with the trimmed event type and a hyphen.
#[must_use]
pub fn derive_lygos_oracle_event_id(input: &OracleEventPreimage) -> String {
    let event_type = input.event_type.trim();
    let payload = [
        event_type,
        input.loan_id.trim(),
        input.repayment_address.trim(),
        input.repayment_amount.trim(),
    ]
    .join("//");
    let digest = Sha256::digest(payload.as_bytes());
    format!("{event_type}-{}", hex::encode(digest))
}

/// Hash a value using the recursively key-sorted compact JSON algorithm used by PR #9.
///
/// Array order is significant. Object keys are sorted at every depth. Missing policy fields are
/// omitted by the schema's serde attributes, matching JavaScript's treatment of `undefined`.
pub fn sha256_canonical<T: Serialize>(value: &T) -> Result<String, CanonicalHashError> {
    let value = serde_json::to_value(value)?;
    let canonical = canonical_json(&value)?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Classify a policy as absent, partial, or complete using PR #9's ten required fields.
#[must_use]
pub fn policy_coverage(policy: Option<&DlcVerificationPolicy>) -> PolicyCoverage {
    let Some(policy) = policy else {
        return PolicyCoverage::NotProvided;
    };

    if !policy_has_any_value(policy) {
        return PolicyCoverage::NotProvided;
    }

    if policy.lender_role.is_some()
        && policy.network.is_some()
        && has_non_empty_string(policy.expected_oracle_pubkey.as_deref())
        && has_non_empty_string(policy.expected_lender_funding_pubkey.as_deref())
        && has_non_empty_string(policy.expected_lender_payout_address.as_deref())
        && has_non_empty_string(policy.expected_total_collateral_sats.as_deref())
        && policy.oracle_event.is_some()
        && policy.expected_cet_locktime.is_some()
        && policy.expected_refund_locktime.is_some()
        && policy
            .expected_lender_outcomes
            .as_ref()
            .is_some_and(|outcomes| !outcomes.is_empty())
    {
        PolicyCoverage::Complete
    } else {
        PolicyCoverage::Partial
    }
}

/// Evaluate a caller policy against a complete DLC Verify compatibility result.
///
/// The evaluator performs no I/O and does not trust the caller-selected rendering network: the
/// network check is always compared with `chainHashNetwork` extracted from the offer.
pub fn evaluate_dlc_policy(
    verification: &DlcVerifyResult,
    policy: Option<&DlcVerificationPolicy>,
) -> Result<DlcPolicyVerificationResult, CanonicalHashError> {
    let mut checks = Vec::new();
    let lender_funding_pubkey = lender_value(
        policy.and_then(|value| value.lender_role),
        verification.offerer_funding_pubkey.as_ref(),
        verification.accepter_funding_pubkey.as_ref(),
    );
    let lender_payout_address = lender_value(
        policy.and_then(|value| value.lender_role),
        verification.offerer_payout_address.as_ref(),
        verification.accepter_payout_address.as_ref(),
    );

    if let Some(expected) = policy.and_then(|value| value.network) {
        add_check(
            &mut checks,
            "network",
            Value::String(policy_network_name(expected).to_owned()),
            option_string_value(verification.chain_hash_network.as_ref()),
        );
    }
    if let Some(expected) = policy.and_then(|value| value.expected_oracle_pubkey.as_ref()) {
        add_check(
            &mut checks,
            "oracle-pubkey",
            Value::String(normalize_hex(expected)),
            verification
                .extracted_oracle_pubkey
                .as_ref()
                .map(|actual| Value::String(normalize_hex(actual)))
                .unwrap_or(Value::Null),
        );
    }
    if let Some(expected) = policy.and_then(|value| value.expected_lender_funding_pubkey.as_ref()) {
        add_check(
            &mut checks,
            "lender-funding-pubkey",
            Value::String(normalize_hex(expected)),
            lender_funding_pubkey
                .as_ref()
                .map(|actual| Value::String(normalize_hex(actual)))
                .unwrap_or(Value::Null),
        );
    }
    if let Some(expected) = policy.and_then(|value| value.expected_lender_payout_address.as_ref()) {
        add_check(
            &mut checks,
            "lender-payout-address",
            Value::String(expected.clone()),
            option_string_value(lender_payout_address.as_ref()),
        );
        add_check(
            &mut checks,
            "refund-pays-lender-address",
            Value::Bool(true),
            Value::Bool(
                verification
                    .refund_outputs
                    .iter()
                    .any(|output| output.address.as_ref() == Some(expected)),
            ),
        );
    }
    if let Some(expected) = policy.and_then(|value| value.expected_total_collateral_sats.as_ref()) {
        add_check(
            &mut checks,
            "total-collateral-sats",
            Value::String(expected.clone()),
            option_string_value(verification.total_collateral.as_ref()),
        );
    }
    if let Some(expectation) = policy.and_then(|value| value.oracle_event.as_ref()) {
        match expected_event_id(expectation) {
            Some(expected) => add_check(
                &mut checks,
                "oracle-event-id",
                Value::String(expected),
                option_string_value(verification.oracle_event_id.as_ref()),
            ),
            None => checks.push(PolicyCheck {
                id: "oracle-event-id".to_owned(),
                status: PolicyCheckStatus::Fail,
                expected: Value::String(
                    "a non-empty expectedEventId or complete eventIdPreimage".to_owned(),
                ),
                actual: serde_json::to_value(expectation)?,
            }),
        }
    }
    if let Some(expected) = policy.and_then(|value| value.expected_cet_locktime) {
        add_check(
            &mut checks,
            "cet-locktime",
            Value::from(expected),
            verification
                .cet_locktime
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
    }
    if let Some(expected) = policy.and_then(|value| value.expected_refund_locktime) {
        add_check(
            &mut checks,
            "refund-locktime",
            Value::from(expected),
            verification
                .refund_locktime
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
    }

    if let Some(expected_outcomes) =
        policy.and_then(|value| value.expected_lender_outcomes.as_ref())
    {
        if expected_outcomes.len() > MAX_EXPECTED_LENDER_OUTCOMES {
            checks.push(PolicyCheck {
                id: "lender-outcomes-count-limit".to_owned(),
                status: PolicyCheckStatus::Fail,
                expected: Value::String(format!("at most {MAX_EXPECTED_LENDER_OUTCOMES}")),
                actual: Value::from(expected_outcomes.len()),
            });
        } else {
            evaluate_lender_outcomes(&mut checks, verification, policy, expected_outcomes);
        }
    }

    let coverage = policy_coverage(policy);
    let policy_verification = if checks.is_empty() {
        PolicyVerificationStatus::NotProvided
    } else if checks
        .iter()
        .all(|check| check.status == PolicyCheckStatus::Pass)
    {
        PolicyVerificationStatus::Pass
    } else {
        PolicyVerificationStatus::Fail
    };
    let cryptographic_verification = verification.verification_status;
    let verdict = if cryptographic_verification == VerificationStatus::Fail
        || policy_verification == PolicyVerificationStatus::Fail
    {
        VerificationStatus::Fail
    } else if cryptographic_verification == VerificationStatus::Pass
        && coverage == PolicyCoverage::Complete
        && policy_verification == PolicyVerificationStatus::Pass
    {
        VerificationStatus::Pass
    } else {
        VerificationStatus::Incomplete
    };
    let policy_hash = if coverage == PolicyCoverage::NotProvided {
        None
    } else {
        policy.map(sha256_canonical).transpose()?
    };
    let attestation_payload = VerificationAttestationPayload {
        schema_version: ATTESTATION_SCHEMA_VERSION.to_owned(),
        verdict,
        cryptographic_verification,
        policy_verification,
        policy_coverage: coverage,
        transcript_hash: verification.transcript_hash.clone(),
        policy_hash,
        contract_id: verification.contract_id.clone(),
        funding_tx_id: verification.fund_tx_id.clone(),
        fund_output_index: verification.fund_output_index,
        funding_value_sats: verification.funding_value_sats.clone(),
        total_collateral_sats: verification.total_collateral.clone(),
        oracle_pubkey: verification.extracted_oracle_pubkey.clone(),
        oracle_event_id: verification.oracle_event_id.clone(),
        lender_funding_pubkey,
        lender_payout_address,
        refund_tx_id: verification.refund_tx_id.clone(),
        cet_txids: verification
            .cets
            .iter()
            .map(|cet| AttestedCet {
                outcome: cet.outcome.clone(),
                txid: cet.txid.clone(),
            })
            .collect(),
    };
    let verification_digest = sha256_canonical(&attestation_payload)?;

    Ok(DlcPolicyVerificationResult {
        verdict,
        cryptographic_verification,
        policy_verification,
        policy_coverage: coverage,
        checks,
        verification_digest,
        attestation_payload,
        verification: verification.clone(),
    })
}

fn evaluate_lender_outcomes(
    checks: &mut Vec<PolicyCheck>,
    verification: &DlcVerifyResult,
    policy: Option<&DlcVerificationPolicy>,
    expected_outcomes: &[verifier_schema::ExpectedLenderOutcome],
) {
    let mut expected_names: Vec<String> = expected_outcomes
        .iter()
        .map(|outcome| outcome.outcome.clone())
        .collect();
    let mut actual_names: Vec<String> = verification
        .outcomes
        .iter()
        .map(|outcome| outcome.label.clone())
        .collect();
    let expected_unique = all_unique(&expected_names);
    let actual_unique = all_unique(&actual_names);
    add_check(
        checks,
        "lender-outcomes-unique",
        Value::Bool(true),
        Value::Bool(expected_unique && actual_unique),
    );
    expected_names.sort();
    actual_names.sort();
    add_check(
        checks,
        "lender-outcome-set",
        string_array_value(expected_names),
        string_array_value(actual_names),
    );
    let actual_by_label: BTreeMap<&str, &verifier_schema::OutcomeInfo> = verification
        .outcomes
        .iter()
        .map(|outcome| (outcome.label.as_str(), outcome))
        .collect();
    for expectation in expected_outcomes {
        let actual = actual_by_label
            .get(expectation.outcome.as_str())
            .and_then(|outcome| match policy.and_then(|value| value.lender_role) {
                Some(DlcPartyRole::Offerer) => Some(outcome.offerer_sats.clone()),
                Some(DlcPartyRole::Accepter) => Some(outcome.accepter_sats.clone()),
                None => None,
            });
        add_check(
            checks,
            format!("lender-outcome:{}", expectation.outcome),
            Value::String(expectation.lender_payout_sats.clone()),
            actual.map(Value::String).unwrap_or(Value::Null),
        );
    }
}

fn canonical_json(value: &Value) -> Result<String, serde_json::Error> {
    match value {
        Value::Array(values) => {
            let mut output = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(value)?);
            }
            output.push(']');
            Ok(output)
        }
        Value::Object(values) => {
            let mut entries: Vec<(&String, &Value)> = values.iter().collect();
            // JavaScript's `localeCompare` (used by PR #9) collates these ASCII schema keys
            // case-insensitively. This notably places `fundingTxId` before `fundOutputIndex`.
            entries.sort_by(|(left, _), (right, _)| {
                left.to_ascii_lowercase()
                    .cmp(&right.to_ascii_lowercase())
                    .then_with(|| left.cmp(right))
            });
            let mut output = String::from("{");
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                output.push_str(&canonical_json(value)?);
            }
            output.push('}');
            Ok(output)
        }
        scalar => serde_json::to_string(scalar),
    }
}

fn policy_has_any_value(policy: &DlcVerificationPolicy) -> bool {
    policy.lender_role.is_some()
        || policy.network.is_some()
        || has_non_empty_string(policy.expected_oracle_pubkey.as_deref())
        || has_non_empty_string(policy.expected_lender_funding_pubkey.as_deref())
        || has_non_empty_string(policy.expected_lender_payout_address.as_deref())
        || has_non_empty_string(policy.expected_total_collateral_sats.as_deref())
        || policy.oracle_event.is_some()
        || policy.expected_cet_locktime.is_some()
        || policy.expected_refund_locktime.is_some()
        || policy
            .expected_lender_outcomes
            .as_ref()
            .is_some_and(|outcomes| !outcomes.is_empty())
}

fn has_non_empty_string(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn normalize_hex(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    normalized
        .strip_prefix("0x")
        .unwrap_or(&normalized)
        .to_owned()
}

fn expected_event_id(expectation: &PolicyOracleEventExpectation) -> Option<String> {
    if let Some(expected) = expectation.expected_event_id.as_deref()
        && !expected.trim().is_empty()
    {
        return Some(expected.trim().to_owned());
    }

    let preimage = expectation.event_id_preimage.as_ref()?;
    let complete = [
        preimage.event_type.as_str(),
        preimage.loan_id.as_str(),
        preimage.repayment_address.as_str(),
        preimage.repayment_amount.as_str(),
    ]
    .iter()
    .all(|value| !value.trim().is_empty());
    complete.then(|| derive_lygos_oracle_event_id(preimage))
}

fn policy_network_name(network: PolicyNetwork) -> &'static str {
    match network {
        PolicyNetwork::Mainnet => "mainnet",
        PolicyNetwork::Testnet => "testnet",
        PolicyNetwork::Regtest => "regtest",
    }
}

fn lender_value(
    role: Option<DlcPartyRole>,
    offerer: Option<&String>,
    accepter: Option<&String>,
) -> Option<String> {
    match role {
        Some(DlcPartyRole::Offerer) => offerer.cloned(),
        Some(DlcPartyRole::Accepter) => accepter.cloned(),
        None => None,
    }
}

fn option_string_value(value: Option<&String>) -> Value {
    value.cloned().map(Value::String).unwrap_or(Value::Null)
}

fn string_array_value(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn add_check(checks: &mut Vec<PolicyCheck>, id: impl Into<String>, expected: Value, actual: Value) {
    let status = if actual == expected {
        PolicyCheckStatus::Pass
    } else {
        PolicyCheckStatus::Fail
    };
    checks.push(PolicyCheck {
        id: id.into(),
        status,
        expected,
        actual,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use verifier_schema::{
        CetTransactionInfo, ExpectedLenderOutcome, OutcomeInfo, TransactionOutputInfo,
    };

    fn verification_fixture() -> DlcVerifyResult {
        DlcVerifyResult {
            network: "regtest".to_owned(),
            chain_hash_network: Some("regtest".to_owned()),
            total_collateral: Some("100".to_owned()),
            outcomes: vec![
                OutcomeInfo {
                    label: "WIN".to_owned(),
                    offerer_sats: "60".to_owned(),
                    accepter_sats: "40".to_owned(),
                },
                OutcomeInfo {
                    label: "LOSE".to_owned(),
                    offerer_sats: "0".to_owned(),
                    accepter_sats: "100".to_owned(),
                },
            ],
            extracted_oracle_pubkey: Some("aabb".to_owned()),
            oracle_event_id: Some("event-1".to_owned()),
            cet_locktime: Some(10),
            refund_locktime: Some(20),
            offerer_funding_pubkey: Some("02ab".to_owned()),
            accepter_funding_pubkey: Some("03cd".to_owned()),
            offerer_payout_address: Some("bcrt1qlender".to_owned()),
            accepter_payout_address: Some("bcrt1qborrower".to_owned()),
            contract_id: Some("cid".to_owned()),
            transcript_hash: "transcript".to_owned(),
            fund_output_index: Some(1),
            funding_value_sats: Some("100".to_owned()),
            refund_tx_id: Some("refundtx".to_owned()),
            refund_outputs: vec![TransactionOutputInfo {
                index: 0,
                sats: "100".to_owned(),
                script_pub_key: "0014aa".to_owned(),
                address: Some("bcrt1qlender".to_owned()),
            }],
            cets: vec![
                CetTransactionInfo {
                    outcome: "WIN".to_owned(),
                    txid: "cet-win".to_owned(),
                    locktime: 10,
                    outputs: Vec::new(),
                },
                CetTransactionInfo {
                    outcome: "LOSE".to_owned(),
                    txid: "cet-lose".to_owned(),
                    locktime: 10,
                    outputs: Vec::new(),
                },
            ],
            fund_tx_id: Some("fundtx".to_owned()),
            verification_status: VerificationStatus::Pass,
            ..DlcVerifyResult::default()
        }
    }

    fn complete_policy() -> DlcVerificationPolicy {
        DlcVerificationPolicy {
            lender_role: Some(DlcPartyRole::Offerer),
            network: Some(PolicyNetwork::Regtest),
            expected_oracle_pubkey: Some("0xAABB".to_owned()),
            expected_lender_funding_pubkey: Some("0x02AB".to_owned()),
            expected_lender_payout_address: Some("bcrt1qlender".to_owned()),
            expected_total_collateral_sats: Some("100".to_owned()),
            oracle_event: Some(PolicyOracleEventExpectation {
                expected_event_id: Some("event-1".to_owned()),
                event_id_preimage: None,
            }),
            expected_cet_locktime: Some(10),
            expected_refund_locktime: Some(20),
            expected_lender_outcomes: Some(vec![
                ExpectedLenderOutcome {
                    outcome: "WIN".to_owned(),
                    lender_payout_sats: "60".to_owned(),
                },
                ExpectedLenderOutcome {
                    outcome: "LOSE".to_owned(),
                    lender_payout_sats: "0".to_owned(),
                },
            ]),
        }
    }

    #[test]
    fn event_id_matches_pr9_vector_and_binds_address() {
        let input = OracleEventPreimage {
            event_type: " loan-matured ".to_owned(),
            loan_id: " loan-123 ".to_owned(),
            repayment_address: " bc1qrepayment ".to_owned(),
            repayment_amount: " 100000 ".to_owned(),
        };
        assert_eq!(
            derive_lygos_oracle_event_id(&input),
            "loan-matured-3a0c8f7e56452482f216ca063904ee5f58c7cfe2e245982599955fcae2668071"
        );

        let changed = OracleEventPreimage {
            repayment_address: "bc1qdifferent".to_owned(),
            ..input
        };
        assert_ne!(
            derive_lygos_oracle_event_id(&changed),
            "loan-matured-3a0c8f7e56452482f216ca063904ee5f58c7cfe2e245982599955fcae2668071"
        );
    }

    #[test]
    fn policy_coverage_requires_all_ten_non_empty_fields() {
        assert_eq!(policy_coverage(None), PolicyCoverage::NotProvided);
        assert_eq!(
            policy_coverage(Some(&DlcVerificationPolicy::default())),
            PolicyCoverage::NotProvided
        );

        let mut policy = complete_policy();
        policy.expected_cet_locktime = None;
        assert_eq!(policy_coverage(Some(&policy)), PolicyCoverage::Partial);
        assert_eq!(
            policy_coverage(Some(&complete_policy())),
            PolicyCoverage::Complete
        );
    }

    #[test]
    fn complete_policy_checks_and_hashes_match_pr9_vectors() -> Result<(), CanonicalHashError> {
        let result = evaluate_dlc_policy(&verification_fixture(), Some(&complete_policy()))?;

        assert_eq!(result.verdict, VerificationStatus::Pass);
        assert_eq!(result.policy_verification, PolicyVerificationStatus::Pass);
        assert_eq!(result.policy_coverage, PolicyCoverage::Complete);
        assert!(
            result
                .checks
                .iter()
                .all(|check| check.status == PolicyCheckStatus::Pass)
        );
        assert_eq!(
            result.attestation_payload.policy_hash.as_deref(),
            Some("2905a214fdb4cef06f732e94567a3efa7eb51bfc72891c054b1d99db75ebf2a6")
        );
        assert_eq!(
            result.verification_digest,
            "a44e47103883a6d049b5ca6b22a5d2a17018796441a76ef50c6f6b53a3550048"
        );
        Ok(())
    }

    #[test]
    fn checks_chain_hash_network_instead_of_rendering_network() -> Result<(), CanonicalHashError> {
        let verification = verification_fixture();
        let policy = DlcVerificationPolicy {
            network: Some(PolicyNetwork::Mainnet),
            ..DlcVerificationPolicy::default()
        };
        let result = evaluate_dlc_policy(&verification, Some(&policy))?;

        assert_eq!(result.verdict, VerificationStatus::Fail);
        assert_eq!(result.checks.len(), 1);
        assert_eq!(result.checks[0].id, "network");
        assert_eq!(result.checks[0].status, PolicyCheckStatus::Fail);
        assert_eq!(result.checks[0].actual, Value::String("regtest".to_owned()));
        Ok(())
    }

    #[test]
    fn outcome_policy_requires_an_exact_duplicate_free_set() -> Result<(), CanonicalHashError> {
        let mut policy = DlcVerificationPolicy {
            lender_role: Some(DlcPartyRole::Offerer),
            expected_lender_outcomes: Some(vec![ExpectedLenderOutcome {
                outcome: "WIN".to_owned(),
                lender_payout_sats: "60".to_owned(),
            }]),
            ..DlcVerificationPolicy::default()
        };
        let subset = evaluate_dlc_policy(&verification_fixture(), Some(&policy))?;
        assert!(subset.checks.iter().any(|check| {
            check.id == "lender-outcome-set" && check.status == PolicyCheckStatus::Fail
        }));

        policy.expected_lender_outcomes = Some(vec![
            ExpectedLenderOutcome {
                outcome: "WIN".to_owned(),
                lender_payout_sats: "60".to_owned(),
            },
            ExpectedLenderOutcome {
                outcome: "WIN".to_owned(),
                lender_payout_sats: "60".to_owned(),
            },
        ]);
        let duplicate = evaluate_dlc_policy(&verification_fixture(), Some(&policy))?;
        assert!(duplicate.checks.iter().any(|check| {
            check.id == "lender-outcomes-unique" && check.status == PolicyCheckStatus::Fail
        }));
        Ok(())
    }

    #[test]
    fn oversized_outcome_policy_fails_without_expanding_checks() -> Result<(), CanonicalHashError> {
        let policy = DlcVerificationPolicy {
            lender_role: Some(DlcPartyRole::Offerer),
            expected_lender_outcomes: Some(
                (0..=MAX_EXPECTED_LENDER_OUTCOMES)
                    .map(|index| ExpectedLenderOutcome {
                        outcome: format!("OUTCOME-{index}"),
                        lender_payout_sats: "0".to_owned(),
                    })
                    .collect(),
            ),
            ..DlcVerificationPolicy::default()
        };

        let result = evaluate_dlc_policy(&verification_fixture(), Some(&policy))?;
        assert_eq!(result.verdict, VerificationStatus::Fail);
        assert_eq!(result.checks.len(), 1);
        assert_eq!(result.checks[0].id, "lender-outcomes-count-limit");
        assert_eq!(result.checks[0].status, PolicyCheckStatus::Fail);
        Ok(())
    }

    #[test]
    fn detects_oracle_lender_locktime_refund_and_payout_mismatches()
    -> Result<(), CanonicalHashError> {
        let mut policy = complete_policy();
        policy.expected_oracle_pubkey = Some("deadbeef".to_owned());
        policy.expected_lender_funding_pubkey = Some("03cd".to_owned());
        policy.expected_lender_payout_address = Some("bcrt1qwrong".to_owned());
        policy.expected_total_collateral_sats = Some("101".to_owned());
        policy.expected_cet_locktime = Some(11);
        policy.expected_refund_locktime = Some(21);
        if let Some(outcomes) = policy.expected_lender_outcomes.as_mut()
            && let Some(first) = outcomes.first_mut()
        {
            first.lender_payout_sats = "59".to_owned();
        }

        let result = evaluate_dlc_policy(&verification_fixture(), Some(&policy))?;
        for id in [
            "oracle-pubkey",
            "lender-funding-pubkey",
            "lender-payout-address",
            "refund-pays-lender-address",
            "total-collateral-sats",
            "cet-locktime",
            "refund-locktime",
            "lender-outcome:WIN",
        ] {
            assert!(
                result
                    .checks
                    .iter()
                    .any(|check| { check.id == id && check.status == PolicyCheckStatus::Fail })
            );
        }
        assert_eq!(result.verdict, VerificationStatus::Fail);
        Ok(())
    }

    #[test]
    fn no_policy_is_incomplete_and_has_no_policy_hash() -> Result<(), CanonicalHashError> {
        let result = evaluate_dlc_policy(&verification_fixture(), None)?;
        assert_eq!(result.verdict, VerificationStatus::Incomplete);
        assert_eq!(result.policy_coverage, PolicyCoverage::NotProvided);
        assert_eq!(
            result.policy_verification,
            PolicyVerificationStatus::NotProvided
        );
        assert!(result.checks.is_empty());
        assert!(result.attestation_payload.policy_hash.is_none());
        Ok(())
    }

    #[test]
    fn malformed_oracle_event_becomes_a_policy_failure() -> Result<(), CanonicalHashError> {
        let policy = DlcVerificationPolicy {
            oracle_event: Some(PolicyOracleEventExpectation::default()),
            ..DlcVerificationPolicy::default()
        };
        let result = evaluate_dlc_policy(&verification_fixture(), Some(&policy))?;

        assert_eq!(result.verdict, VerificationStatus::Fail);
        assert_eq!(result.policy_verification, PolicyVerificationStatus::Fail);
        assert_eq!(result.checks.len(), 1);
        assert_eq!(result.checks[0].id, "oracle-event-id");
        assert_eq!(result.checks[0].status, PolicyCheckStatus::Fail);
        assert_eq!(result.checks[0].actual, Value::Object(Default::default()));
        Ok(())
    }
}
