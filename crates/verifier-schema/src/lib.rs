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
#[serde(rename_all = "camelCase", untagged, deny_unknown_fields)]
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
    /// The deterministic verification result.
    pub result: VerificationResult,
    /// TVC App Proof binding the result and request challenge.
    pub proof: AppProof,
}
