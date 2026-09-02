//! Stable wire types shared by the deterministic verifier and the TVC app.

use serde::{Deserialize, Serialize};

/// Maximum accepted byte length of any decoded DLC message.
pub const MAX_DLC_MESSAGE_BYTES: usize = 1024 * 1024;

/// A request to verify a DLC negotiation transcript.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationRequest {
    /// Hex-encoded `DlcOffer` wire message.
    #[serde(alias = "offerHex")]
    pub offer: String,
    /// Hex-encoded `DlcAccept` wire message.
    #[serde(alias = "acceptHex")]
    pub accept: String,
    /// Optional hex-encoded `DlcSign` wire message.
    #[serde(default, alias = "signHex", skip_serializing_if = "Option::is_none")]
    pub sign: Option<String>,
    /// Optional expectations supplied by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<VerificationPolicy>,
    /// Optional caller challenge bound into the signed App Proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

/// Versioned TVC request whose complete policy result is bound into an App Proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TvcVerificationRequest {
    /// Hex-encoded `DlcOffer` wire message.
    #[serde(alias = "offerHex")]
    pub offer: String,
    /// Hex-encoded `DlcAccept` wire message.
    #[serde(alias = "acceptHex")]
    pub accept: String,
    /// Optional hex-encoded `DlcSign` wire message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
    /// Caller-selected network used only to render Bitcoin addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<PolicyNetwork>,
    /// Authorization expectations evaluated against the verified transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<DlcVerificationPolicy>,
    /// One-time caller challenge bound into the signed App Proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

/// Caller-supplied expectations. These are distinct from facts parsed from the DLC.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationPolicy {
    /// Expected network declared by the offer chain hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    /// Expected oracle x-only public key in lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_oracle_pubkey: Option<String>,
    /// Expected total collateral in satoshis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_total_collateral_sats: Option<String>,
    /// Expected oracle event, either directly or from its canonical Lygos preimage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_event: Option<OracleEventExpectation>,
}

/// Supported settlement networks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// Bitcoin testnet3.
    Testnet,
    /// Bitcoin testnet4.
    Testnet4,
    /// Bitcoin regtest.
    Regtest,
    /// Bitcoin signet.
    Signet,
}

/// Expected oracle event ID input.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    untagged,
    deny_unknown_fields
)]
pub enum OracleEventExpectation {
    /// Direct expected event ID.
    Expected {
        /// Canonical event ID.
        expected_event_id: String,
    },
    /// Inputs to the current Lygos event-ID derivation.
    Preimage {
        /// Canonical Lygos event preimage.
        event_id_preimage: OracleEventPreimage,
    },
}

/// Current canonical Lygos loan-event preimage.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OracleEventPreimage {
    /// Event type prefix.
    pub event_type: String,
    /// Loan identifier.
    pub loan_id: String,
    /// Repayment address.
    pub repayment_address: String,
    /// Repayment amount, preserving the caller's canonical decimal representation.
    pub repayment_amount: String,
}

/// Overall verification disposition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    /// Every implemented required check passed.
    Pass,
    /// At least one required check failed.
    Fail,
    /// No required check failed, but authorization-grade verification is not complete.
    Incomplete,
}

/// An enumerated DLC outcome and both parties' payouts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeInfo {
    /// Oracle outcome label.
    pub label: String,
    /// Offerer payout in satoshis.
    pub offerer_sats: String,
    /// Accepter payout in satoshis.
    pub accepter_sats: String,
}

/// A named check suitable for machines and audit displays.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationCheck {
    /// Stable check identifier.
    pub id: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Human-readable detail without secret input material.
    pub detail: String,
}

/// Deterministic result returned by the Rust verifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    /// Result schema identifier.
    pub schema_version: String,
    /// Overall status.
    pub verification_status: VerificationStatus,
    /// Required check failures.
    pub verification_failures: Vec<String>,
    /// Authorization-grade checks that are not implemented yet.
    pub verification_incomplete: Vec<String>,
    /// Individual structural and policy checks.
    pub checks: Vec<VerificationCheck>,
    /// Network derived only from the offer chain hash.
    pub chain_hash_network: Option<Network>,
    /// Offer chain hash in wire byte order.
    pub chain_hash: String,
    /// DLC contract shape.
    pub contract_type: String,
    /// Offer temporary contract ID.
    pub temporary_contract_id: String,
    /// Total collateral in satoshis.
    pub total_collateral: String,
    /// Offer collateral in satoshis.
    pub offer_collateral: String,
    /// Accept collateral in satoshis.
    pub accept_collateral: String,
    /// Enumerated outcomes, empty for an unsupported descriptor.
    pub outcomes: Vec<OutcomeInfo>,
    /// Oracle x-only public key.
    pub oracle_pubkey: Option<String>,
    /// Oracle event ID.
    pub oracle_event_id: Option<String>,
    /// Oracle announcement signature validity.
    pub oracle_sig_valid: bool,
    /// CET locktime.
    pub cet_locktime: u32,
    /// Refund locktime.
    pub refund_locktime: u32,
    /// Offerer funding public key.
    pub offerer_funding_pubkey: String,
    /// Accepter funding public key.
    pub accepter_funding_pubkey: String,
    /// Number of accepter CET adaptor signatures present.
    pub accepter_adaptor_signature_count: usize,
    /// Whether a sign message was supplied.
    pub sign_available: bool,
    /// Contract ID carried by the sign message.
    pub sign_contract_id: Option<String>,
    /// Number of offerer CET adaptor signatures present.
    pub offerer_adaptor_signature_count: usize,
    /// Number of offerer funding signatures present.
    pub offerer_funding_signature_count: usize,
    /// SHA-256 commitment to the decoded offer/accept/sign bytes.
    pub transcript_hash: String,
}

/// App Proof envelope produced by the TVC ephemeral key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProof {
    /// Turnkey proof scheme discriminator.
    pub scheme: String,
    /// Enclave ephemeral public key, hex encoded.
    pub public_key: String,
    /// Exact canonical payload signed by the ephemeral key.
    pub proof_payload: String,
    /// P-256 signature over `payload`, hex encoded.
    pub signature: String,
}

/// The response returned by the TVC application.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedResponse {
    /// The deterministic cryptographic and policy verification result.
    pub result: DlcPolicyVerificationResult,
    /// TVC App Proof binding the result and request challenge.
    pub proof: AppProof,
}

/// Which party is the lender for policy evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DlcPartyRole {
    /// The party that created the offer.
    Offerer,
    /// The party that accepted the offer.
    Accepter,
}

/// The source used for the oracle public key exposed by DLC Verify.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OraclePubkeySource {
    /// The caller supplied the public key.
    Provided,
    /// The public key was extracted from the oracle announcement.
    Derived,
}

/// A funding input exposed by the DLC Verify compatibility response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FundingInputInfo {
    /// Transaction ID and output index in `txid:vout` form.
    pub outpoint: String,
    /// Previous output value in satoshis, when available.
    pub sats: Option<String>,
}

/// A transaction output exposed by the DLC Verify compatibility response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOutputInfo {
    /// Zero-based transaction output index.
    pub index: usize,
    /// Output value in satoshis.
    pub sats: String,
    /// Script public key as lowercase hexadecimal.
    pub script_pub_key: String,
    /// Network-rendered address, when the script has a standard address form.
    pub address: Option<String>,
}

/// A deterministically reconstructed CET exposed by DLC Verify.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CetTransactionInfo {
    /// Oracle outcome associated with this CET.
    pub outcome: String,
    /// CET transaction ID.
    pub txid: String,
    /// CET locktime.
    pub locktime: u32,
    /// Ordered CET outputs.
    pub outputs: Vec<TransactionOutputInfo>,
}

/// Full wire-compatible response returned by the TypeScript DLC Verify API.
///
/// This type intentionally remains separate from [`VerificationResult`]. The latter is the
/// proof-aware TVC foundation result; this DTO preserves every field and nullable boundary of
/// PR #9 so compatibility adapters can be introduced without breaking existing callers.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DlcVerifyResult {
    /// Network selected by the caller for address rendering.
    pub network: String,
    /// Network claimed by the offer chain hash, or `null` for an unknown hash.
    pub chain_hash_network: Option<String>,
    /// DLC contract descriptor kind.
    pub contract_type: Option<String>,
    /// Total collateral in satoshis.
    pub total_collateral: Option<String>,
    /// Offerer collateral in satoshis.
    pub offer_collateral: Option<String>,
    /// Accepter collateral in satoshis.
    pub accept_collateral: Option<String>,
    /// Enumerated outcomes.
    pub outcomes: Vec<OutcomeInfo>,
    /// Oracle public key used by verification.
    pub oracle_pubkey: Option<String>,
    /// Oracle public key extracted from the announcement.
    pub extracted_oracle_pubkey: Option<String>,
    /// Caller-supplied expected oracle public key.
    pub expected_oracle_pubkey: Option<String>,
    /// Source of `oraclePubkey`.
    pub oracle_pubkey_source: OraclePubkeySource,
    /// Whether the extracted and expected oracle keys match.
    pub oracle_pubkey_matches_expected: Option<bool>,
    /// Oracle event identifier.
    pub oracle_event_id: Option<String>,
    /// Whether the oracle announcement signature is valid.
    pub oracle_sig_valid: bool,
    /// Oracle signature verification error, if any.
    pub oracle_sig_error: Option<String>,
    /// CET locktime.
    pub cet_locktime: Option<u32>,
    /// Refund locktime.
    pub refund_locktime: Option<u32>,
    /// Fee rate in satoshis per virtual byte.
    pub fee_rate_per_vb: Option<String>,
    /// Offerer funding public key.
    pub offerer_funding_pubkey: Option<String>,
    /// Accepter funding public key.
    pub accepter_funding_pubkey: Option<String>,
    /// P2WSH funding address.
    pub funding_address: Option<String>,
    /// Funding witness script.
    pub witness_script: Option<String>,
    /// Offerer payout address.
    pub offerer_payout_address: Option<String>,
    /// Offerer change address.
    pub offerer_change_address: Option<String>,
    /// Accepter payout address.
    pub accepter_payout_address: Option<String>,
    /// Accepter change address.
    pub accepter_change_address: Option<String>,
    /// Offerer funding inputs.
    pub offer_inputs: Vec<FundingInputInfo>,
    /// Accepter funding inputs.
    pub accept_inputs: Vec<FundingInputInfo>,
    /// Final contract ID.
    pub contract_id: Option<String>,
    /// Domain-separated transcript hash.
    pub transcript_hash: String,
    /// Funding output index.
    pub fund_output_index: Option<usize>,
    /// Funding output value in satoshis.
    pub funding_value_sats: Option<String>,
    /// Refund transaction ID.
    pub refund_tx_id: Option<String>,
    /// Ordered refund transaction outputs.
    pub refund_outputs: Vec<TransactionOutputInfo>,
    /// Ordered reconstructed CETs.
    pub cets: Vec<CetTransactionInfo>,
    /// Whether adaptor verification support was available.
    pub adaptor_sig_verification_available: bool,
    /// Human-readable note about adaptor verification availability.
    pub adaptor_sig_verification_note: Option<String>,
    /// Funding transaction ID.
    pub fund_tx_id: Option<String>,
    /// Number of reconstructed CETs.
    pub cet_count: Option<usize>,
    /// Whether all accepter adaptor signatures are valid.
    pub adaptor_valid: Option<bool>,
    /// Number of valid accepter adaptor signatures.
    pub adaptor_valid_count: usize,
    /// Number of accepter adaptor signatures checked.
    pub adaptor_total_count: usize,
    /// Accepter adaptor signature verification error.
    pub adaptor_error: Option<String>,
    /// Whether the accepter refund signature is valid.
    pub refund_sig_valid: Option<bool>,
    /// Accepter refund signature verification error.
    pub refund_sig_error: Option<String>,
    /// Whether a DLC Sign message was supplied.
    pub sign_available: bool,
    /// Contract ID carried by the Sign message.
    pub sign_contract_id: Option<String>,
    /// Whether the Sign contract ID matches the computed contract ID.
    pub sign_contract_id_matches: Option<bool>,
    /// Whether all offerer adaptor signatures are valid.
    pub sign_adaptor_valid: Option<bool>,
    /// Number of valid offerer adaptor signatures.
    pub sign_adaptor_valid_count: usize,
    /// Number of offerer adaptor signatures checked.
    pub sign_adaptor_total_count: usize,
    /// Offerer adaptor signature verification error.
    pub sign_adaptor_error: Option<String>,
    /// Whether the offerer refund signature is valid.
    pub sign_refund_sig_valid: Option<bool>,
    /// Offerer refund signature verification error.
    pub sign_refund_sig_error: Option<String>,
    /// Fail-closed cryptographic verification status.
    pub verification_status: VerificationStatus,
    /// Stable identifiers for failed required checks.
    pub verification_failures: Vec<String>,
    /// Stable identifiers for unavailable authorization-grade checks.
    pub verification_incomplete: Vec<String>,
    /// Top-level reconstruction error.
    pub error: Option<String>,
}

impl Default for DlcVerifyResult {
    fn default() -> Self {
        Self {
            network: "mainnet".to_owned(),
            chain_hash_network: None,
            contract_type: None,
            total_collateral: None,
            offer_collateral: None,
            accept_collateral: None,
            outcomes: Vec::new(),
            oracle_pubkey: None,
            extracted_oracle_pubkey: None,
            expected_oracle_pubkey: None,
            oracle_pubkey_source: OraclePubkeySource::Derived,
            oracle_pubkey_matches_expected: None,
            oracle_event_id: None,
            oracle_sig_valid: false,
            oracle_sig_error: None,
            cet_locktime: None,
            refund_locktime: None,
            fee_rate_per_vb: None,
            offerer_funding_pubkey: None,
            accepter_funding_pubkey: None,
            funding_address: None,
            witness_script: None,
            offerer_payout_address: None,
            offerer_change_address: None,
            accepter_payout_address: None,
            accepter_change_address: None,
            offer_inputs: Vec::new(),
            accept_inputs: Vec::new(),
            contract_id: None,
            transcript_hash: String::new(),
            fund_output_index: None,
            funding_value_sats: None,
            refund_tx_id: None,
            refund_outputs: Vec::new(),
            cets: Vec::new(),
            adaptor_sig_verification_available: false,
            adaptor_sig_verification_note: None,
            fund_tx_id: None,
            cet_count: None,
            adaptor_valid: None,
            adaptor_valid_count: 0,
            adaptor_total_count: 0,
            adaptor_error: None,
            refund_sig_valid: None,
            refund_sig_error: None,
            sign_available: false,
            sign_contract_id: None,
            sign_contract_id_matches: None,
            sign_adaptor_valid: None,
            sign_adaptor_valid_count: 0,
            sign_adaptor_total_count: 0,
            sign_adaptor_error: None,
            sign_refund_sig_valid: None,
            sign_refund_sig_error: None,
            verification_status: VerificationStatus::Incomplete,
            verification_failures: Vec::new(),
            verification_incomplete: Vec::new(),
            error: None,
        }
    }
}

/// A lender payout required for one enumerated DLC outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedLenderOutcome {
    /// Expected outcome label.
    pub outcome: String,
    /// Expected lender payout in satoshis.
    pub lender_payout_sats: String,
}

/// Oracle-event expectation accepted by the PR #9 policy endpoint.
///
/// Both fields are optional so a malformed `{}` request reaches the pure evaluator and produces
/// the same `oracle-event-id` policy failure as the TypeScript implementation.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyOracleEventExpectation {
    /// Direct expected event ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_event_id: Option<String>,
    /// Inputs to the current Lygos event-ID derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id_preimage: Option<OracleEventPreimage>,
}

/// PR #9-compatible policy for binding cryptographic verification to loan terms.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DlcVerificationPolicy {
    /// Party treated as the lender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lender_role: Option<DlcPartyRole>,
    /// Expected chain-hash network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<PolicyNetwork>,
    /// Expected oracle x-only public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_oracle_pubkey: Option<String>,
    /// Expected lender funding public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lender_funding_pubkey: Option<String>,
    /// Expected lender payout address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lender_payout_address: Option<String>,
    /// Expected total collateral in satoshis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_total_collateral_sats: Option<String>,
    /// Expected oracle event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_event: Option<PolicyOracleEventExpectation>,
    /// Expected CET locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_cet_locktime: Option<u32>,
    /// Expected refund locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_refund_locktime: Option<u32>,
    /// Complete expected outcome set and lender payouts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lender_outcomes: Option<Vec<ExpectedLenderOutcome>>,
}

/// Networks accepted by the PR #9 policy wire format.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyNetwork {
    /// Bitcoin mainnet.
    Mainnet,
    /// Bitcoin testnet.
    Testnet,
    /// Local Bitcoin regtest.
    Regtest,
}

/// Whether a policy was supplied and contains every authorization field.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCoverage {
    /// No non-empty policy value was supplied.
    NotProvided,
    /// At least one policy value was supplied but required fields are missing.
    Partial,
    /// Every authorization policy field is present and non-empty.
    Complete,
}

/// Aggregate policy evaluation status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerificationStatus {
    /// No policy check was requested.
    NotProvided,
    /// Every requested policy check passed.
    Pass,
    /// At least one requested policy check failed.
    Fail,
}

/// Status of an individual policy check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyCheckStatus {
    /// Expected and actual values match.
    Pass,
    /// Expected and actual values do not match.
    Fail,
}

/// Overall authorization verdict returned by policy verification.
pub type VerificationVerdict = VerificationStatus;

/// Result of one policy comparison.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCheck {
    /// Stable check identifier.
    pub id: String,
    /// Pass or fail status.
    pub status: PolicyCheckStatus,
    /// Expected JSON value.
    pub expected: serde_json::Value,
    /// Actual JSON value.
    pub actual: serde_json::Value,
}

/// CET identity included in the signed verification attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestedCet {
    /// Oracle outcome label.
    pub outcome: String,
    /// CET transaction ID.
    pub txid: String,
}

/// Minimal authorization facts committed by the verification digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationAttestationPayload {
    /// Fixed schema identifier.
    pub schema_version: String,
    /// Overall authorization verdict.
    pub verdict: VerificationVerdict,
    /// Underlying cryptographic verification status.
    pub cryptographic_verification: VerificationStatus,
    /// Policy evaluation status.
    pub policy_verification: PolicyVerificationStatus,
    /// Policy coverage classification.
    pub policy_coverage: PolicyCoverage,
    /// Transcript commitment.
    pub transcript_hash: String,
    /// Canonical policy hash, or `null` when no policy was supplied.
    pub policy_hash: Option<String>,
    /// Final contract ID.
    pub contract_id: Option<String>,
    /// Funding transaction ID.
    pub funding_tx_id: Option<String>,
    /// Funding output index.
    pub fund_output_index: Option<usize>,
    /// Funding output value in satoshis.
    pub funding_value_sats: Option<String>,
    /// Total collateral in satoshis.
    pub total_collateral_sats: Option<String>,
    /// Extracted oracle public key.
    pub oracle_pubkey: Option<String>,
    /// Oracle event identifier.
    pub oracle_event_id: Option<String>,
    /// Funding public key selected by `lenderRole`.
    pub lender_funding_pubkey: Option<String>,
    /// Payout address selected by `lenderRole`.
    pub lender_payout_address: Option<String>,
    /// Refund transaction ID.
    pub refund_tx_id: Option<String>,
    /// Ordered CET identities.
    pub cet_txids: Vec<AttestedCet>,
}

/// PR #9-compatible response from `/api/verify-policy`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DlcPolicyVerificationResult {
    /// Overall authorization verdict.
    pub verdict: VerificationVerdict,
    /// Underlying cryptographic verification status.
    pub cryptographic_verification: VerificationStatus,
    /// Aggregate policy status.
    pub policy_verification: PolicyVerificationStatus,
    /// Policy coverage classification.
    pub policy_coverage: PolicyCoverage,
    /// Ordered individual policy checks.
    pub checks: Vec<PolicyCheck>,
    /// Canonical digest of `attestationPayload`.
    pub verification_digest: String,
    /// Facts committed by `verificationDigest`.
    pub attestation_payload: VerificationAttestationPayload,
    /// Full underlying DLC verification result.
    pub verification: DlcVerifyResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_wire_names_match_pr9_and_missing_fields_are_omitted() -> Result<(), serde_json::Error>
    {
        let policy = DlcVerificationPolicy {
            network: Some(PolicyNetwork::Regtest),
            oracle_event: Some(PolicyOracleEventExpectation {
                expected_event_id: Some("event-1".to_owned()),
                event_id_preimage: None,
            }),
            ..DlcVerificationPolicy::default()
        };
        let value = serde_json::to_value(policy)?;

        assert_eq!(value["network"], "regtest");
        assert_eq!(value["oracleEvent"]["expectedEventId"], "event-1");
        assert!(value.get("lenderRole").is_none());
        assert!(value.get("expectedLenderOutcomes").is_none());

        let malformed: DlcVerificationPolicy = serde_json::from_str(r#"{"oracleEvent":{}}"#)?;
        assert!(malformed.oracle_event.is_some());
        Ok(())
    }

    #[test]
    fn verification_result_preserves_pr9_nullability_and_status_names()
    -> Result<(), serde_json::Error> {
        let value = serde_json::to_value(DlcVerifyResult::default())?;

        assert_eq!(value["verificationStatus"], "incomplete");
        assert_eq!(value["oraclePubkeySource"], "derived");
        assert!(value["chainHashNetwork"].is_null());
        assert!(value["contractId"].is_null());
        assert!(value["refundOutputs"].is_array());
        assert!(value.get("chain_hash_network").is_none());
        Ok(())
    }
}
