//! Deterministic, side-effect-free DLC transcript verification.

use bitcoin::{
    Amount, Network as BitcoinNetwork, blockdata::constants::genesis_block, hashes::Hash as _,
};
use ddk_messages::{
    AcceptDlc, OfferDlc, SignDlc,
    contract_msgs::{ContractDescriptor, ContractInfo},
    oracle_msgs::OracleInfo,
};
use lightning::{io::Cursor, util::ser::Readable};
use secp256k1_zkp::Secp256k1;
use sha2::{Digest, Sha256};
use verifier_schema::{
    MAX_DLC_MESSAGE_BYTES, Network, OracleEventExpectation, OracleEventPreimage, OutcomeInfo,
    VerificationCheck, VerificationPolicy, VerificationRequest, VerificationResult,
    VerificationStatus,
};

/// Errors which prevent the verifier from producing a parsed result.
#[derive(Debug)]
pub enum VerifyError {
    /// A hex field is invalid or outside the service limit.
    InvalidEncoding {
        /// Request field name.
        field: &'static str,
        /// Safe parse detail.
        detail: String,
    },
    /// A DLC wire message cannot be decoded completely.
    InvalidMessage {
        /// Request field name.
        field: &'static str,
        /// Safe decode detail.
        detail: String,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding { field, detail } => {
                write!(formatter, "invalid {field} encoding: {detail}")
            }
            Self::InvalidMessage { field, detail } => {
                write!(formatter, "invalid {field} message: {detail}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, VerifyError> {
    let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if normalized.len() / 2 > MAX_DLC_MESSAGE_BYTES {
        return Err(VerifyError::InvalidEncoding {
            field,
            detail: format!("exceeds {MAX_DLC_MESSAGE_BYTES} decoded bytes"),
        });
    }
    if !normalized.len().is_multiple_of(2) {
        return Err(VerifyError::InvalidEncoding {
            field,
            detail: "hex must contain an even number of characters".to_owned(),
        });
    }
    hex::decode(normalized).map_err(|error| VerifyError::InvalidEncoding {
        field,
        detail: error.to_string(),
    })
}

fn strict_read<T: Readable>(field: &'static str, bytes: &[u8]) -> Result<T, VerifyError> {
    let mut cursor = Cursor::new(bytes);
    let value = T::read(&mut cursor).map_err(|error| VerifyError::InvalidMessage {
        field,
        detail: format!("{error:?}"),
    })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(VerifyError::InvalidMessage {
            field,
            detail: format!(
                "trailing bytes: decoded {} of {}",
                cursor.position(),
                bytes.len()
            ),
        });
    }
    Ok(value)
}

fn push_check(
    checks: &mut Vec<VerificationCheck>,
    failures: &mut Vec<String>,
    id: &str,
    passed: bool,
    detail: impl Into<String>,
) {
    checks.push(VerificationCheck {
        id: id.to_owned(),
        passed,
        detail: detail.into(),
    });
    if !passed {
        failures.push(id.to_owned());
    }
}

fn network_from_chain_hash(chain_hash: &[u8; 32]) -> Option<Network> {
    [
        (BitcoinNetwork::Bitcoin, Network::Mainnet),
        (BitcoinNetwork::Testnet, Network::Testnet),
        (BitcoinNetwork::Testnet4, Network::Testnet4),
        (BitcoinNetwork::Regtest, Network::Regtest),
        (BitcoinNetwork::Signet, Network::Signet),
    ]
    .into_iter()
    .find_map(|(bitcoin_network, network)| {
        let block_hash = genesis_block(bitcoin_network).block_hash();
        let display_order = block_hash.to_string();
        let display_bytes = hex::decode(display_order).ok()?;
        let direct = block_hash.to_byte_array();
        if chain_hash.as_slice() == direct || chain_hash.as_slice() == display_bytes.as_slice() {
            Some(network)
        } else {
            None
        }
    })
}

/// Derive the current canonical Lygos oracle event ID.
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
    format!("{event_type}-{:x}", Sha256::digest(payload.as_bytes()))
}

fn expected_event_id(expectation: &OracleEventExpectation) -> String {
    match expectation {
        OracleEventExpectation::Expected { expected_event_id } => {
            expected_event_id.trim().to_owned()
        }
        OracleEventExpectation::Preimage { event_id_preimage } => {
            derive_lygos_oracle_event_id(event_id_preimage)
        }
    }
}

fn amount_string(amount: Amount) -> String {
    amount.to_sat().to_string()
}

fn normalize_expected_oracle_pubkey(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let normalized = normalized.strip_prefix("0x").unwrap_or(&normalized);
    (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| normalized.to_owned())
}

/// Verify and summarize a DLC negotiation transcript without network or filesystem access.
pub fn verify(request: &VerificationRequest) -> Result<VerificationResult, VerifyError> {
    let offer_bytes = decode_hex("offer", &request.offer)?;
    let accept_bytes = decode_hex("accept", &request.accept)?;
    let sign_bytes = request
        .sign
        .as_deref()
        .map(|value| decode_hex("sign", value))
        .transpose()?;
    let offer: OfferDlc = strict_read("offer", &offer_bytes)?;
    let accept: AcceptDlc = strict_read("accept", &accept_bytes)?;
    let sign: Option<SignDlc> = sign_bytes
        .as_deref()
        .map(|bytes| strict_read("sign", bytes))
        .transpose()?;

    let mut checks = Vec::new();
    let mut failures = Vec::new();
    let mut incomplete = vec![
        "funding-transaction-reconstruction".to_owned(),
        "cet-transaction-reconstruction".to_owned(),
        "refund-transaction-reconstruction".to_owned(),
        "accepter-adaptor-signature-verification".to_owned(),
        "accepter-refund-signature-verification".to_owned(),
    ];
    if sign.is_some() {
        incomplete.extend([
            "offerer-adaptor-signature-verification".to_owned(),
            "offerer-refund-signature-verification".to_owned(),
            "offerer-funding-signature-verification".to_owned(),
            "computed-contract-id-comparison".to_owned(),
        ]);
    }

    push_check(
        &mut checks,
        &mut failures,
        "temporary-contract-id",
        offer.temporary_contract_id == accept.temporary_contract_id,
        "DlcOffer and DlcAccept temporary contract IDs must match",
    );
    let total_collateral = offer.get_total_collateral();
    let collateral_sum = offer.offer_collateral.checked_add(accept.accept_collateral);
    push_check(
        &mut checks,
        &mut failures,
        "collateral-sum",
        collateral_sum == Some(total_collateral),
        "offer and accept collateral must equal contract total collateral",
    );

    let derived_network = network_from_chain_hash(&offer.chain_hash);
    push_check(
        &mut checks,
        &mut failures,
        "known-chain-hash",
        derived_network.is_some(),
        "offer chain hash must identify a supported Bitcoin network",
    );

    let (contract_type, outcomes, oracle_pubkey, oracle_event_id, oracle_sig_valid) = match &offer
        .contract_info
    {
        ContractInfo::SingleContractInfo(single) => {
            let (outcomes, descriptor_supported, descriptor_kind) =
                match &single.contract_info.contract_descriptor {
                    ContractDescriptor::EnumeratedContractDescriptor(descriptor) => {
                        let mut values = Vec::with_capacity(descriptor.payouts.len());
                        for payout in &descriptor.payouts {
                            let accepter_payout = total_collateral.checked_sub(payout.offer_payout);
                            if accepter_payout.is_none() {
                                push_check(
                                    &mut checks,
                                    &mut failures,
                                    "outcome-payout-bounds",
                                    false,
                                    "offerer payout cannot exceed total collateral",
                                );
                            }
                            values.push(OutcomeInfo {
                                label: payout.outcome.clone(),
                                offerer_sats: amount_string(payout.offer_payout),
                                accepter_sats: accepter_payout
                                    .map_or_else(|| "0".to_owned(), amount_string),
                            });
                        }
                        (values, true, "single-enumerated")
                    }
                    ContractDescriptor::NumericOutcomeContractDescriptor(_) => {
                        (Vec::new(), false, "single-numeric")
                    }
                };
            push_check(
                &mut checks,
                &mut failures,
                "supported-contract-descriptor",
                descriptor_supported,
                "version 1 supports enumerated contracts only",
            );
            match &single.contract_info.oracle_info {
                OracleInfo::Single(single_oracle) => {
                    let announcement = &single_oracle.oracle_announcement;
                    let secp = Secp256k1::verification_only();
                    let signature_valid = announcement.validate(&secp).is_ok();
                    push_check(
                        &mut checks,
                        &mut failures,
                        "oracle-announcement-signature",
                        signature_valid,
                        "oracle announcement signature and nonce count must be valid",
                    );
                    (
                        descriptor_kind.to_owned(),
                        outcomes,
                        Some(announcement.oracle_public_key.to_string()),
                        Some(announcement.oracle_event.event_id.clone()),
                        signature_valid,
                    )
                }
                OracleInfo::Multi(_) => {
                    push_check(
                        &mut checks,
                        &mut failures,
                        "supported-oracle-shape",
                        false,
                        "version 1 supports one oracle only",
                    );
                    (
                        format!("{descriptor_kind}-multi-oracle"),
                        outcomes,
                        None,
                        None,
                        false,
                    )
                }
            }
        }
        ContractInfo::DisjointContractInfo(_) => {
            push_check(
                &mut checks,
                &mut failures,
                "supported-contract-shape",
                false,
                "version 1 does not support disjoint contracts",
            );
            ("disjoint".to_owned(), Vec::new(), None, None, false)
        }
    };

    if let Some(policy) = &request.policy {
        evaluate_policy(
            policy,
            derived_network,
            total_collateral,
            oracle_pubkey.as_deref(),
            oracle_event_id.as_deref(),
            &mut checks,
            &mut failures,
        );
    }

    let transcript_hash = transcript_hash(&offer_bytes, &accept_bytes, sign_bytes.as_deref());

    let verification_status = if failures.is_empty() {
        if incomplete.is_empty() {
            VerificationStatus::Pass
        } else {
            VerificationStatus::Incomplete
        }
    } else {
        VerificationStatus::Fail
    };

    Ok(VerificationResult {
        schema_version: "lygos.dlc-verification.v1".to_owned(),
        verification_status,
        verification_failures: failures,
        verification_incomplete: incomplete,
        checks,
        chain_hash_network: derived_network,
        chain_hash: hex::encode(offer.chain_hash),
        contract_type,
        temporary_contract_id: hex::encode(offer.temporary_contract_id),
        total_collateral: amount_string(total_collateral),
        offer_collateral: amount_string(offer.offer_collateral),
        accept_collateral: amount_string(accept.accept_collateral),
        outcomes,
        oracle_pubkey,
        oracle_event_id,
        oracle_sig_valid,
        cet_locktime: offer.cet_locktime,
        refund_locktime: offer.refund_locktime,
        offerer_funding_pubkey: offer.funding_pubkey.to_string(),
        accepter_funding_pubkey: accept.funding_pubkey.to_string(),
        accepter_adaptor_signature_count: accept
            .cet_adaptor_signatures
            .ecdsa_adaptor_signatures
            .len(),
        sign_available: sign.is_some(),
        sign_contract_id: sign.as_ref().map(|value| hex::encode(value.contract_id)),
        offerer_adaptor_signature_count: sign.as_ref().map_or(0, |value| {
            value.cet_adaptor_signatures.ecdsa_adaptor_signatures.len()
        }),
        offerer_funding_signature_count: sign
            .as_ref()
            .map_or(0, |value| value.funding_signatures.funding_signatures.len()),
        transcript_hash,
    })
}

fn transcript_hash(offer: &[u8], accept: &[u8], sign: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Lygos/DLCVerify/transcript/v1\0");
    for (label, bytes) in [
        (b"offer".as_slice(), offer),
        (b"accept".as_slice(), accept),
        (b"sign".as_slice(), sign.unwrap_or_default()),
    ] {
        hasher.update(label);
        hasher.update([0]);
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy(
    policy: &VerificationPolicy,
    network: Option<Network>,
    total_collateral: Amount,
    oracle_pubkey: Option<&str>,
    oracle_event_id: Option<&str>,
    checks: &mut Vec<VerificationCheck>,
    failures: &mut Vec<String>,
) {
    if let Some(expected) = policy.network {
        push_check(
            checks,
            failures,
            "policy-network",
            network == Some(expected),
            "expected network is compared to the offer chain hash",
        );
    }
    if let Some(expected) = &policy.expected_total_collateral_sats {
        push_check(
            checks,
            failures,
            "policy-total-collateral",
            expected.trim() == total_collateral.to_sat().to_string(),
            "expected total collateral must match exactly",
        );
    }
    if let Some(expected) = &policy.expected_oracle_pubkey {
        let normalized = normalize_expected_oracle_pubkey(expected);
        push_check(
            checks,
            failures,
            "policy-oracle-pubkey",
            normalized.as_deref().is_some_and(|expected| {
                oracle_pubkey.is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
            }),
            "expected oracle key must match the signed announcement",
        );
    }
    if let Some(expectation) = &policy.oracle_event {
        let expected = expected_event_id(expectation);
        push_check(
            checks,
            failures,
            "policy-oracle-event-id",
            oracle_event_id.is_some_and(|actual| actual == expected),
            "expected oracle event ID must match exactly",
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn event_id_matches_typescript_formula() {
        let input = OracleEventPreimage {
            event_type: "repaid".to_owned(),
            loan_id: "loan-123".to_owned(),
            repayment_address: "0xabc".to_owned(),
            repayment_amount: "1000000".to_owned(),
        };
        assert_eq!(
            derive_lygos_oracle_event_id(&input),
            "repaid-9b36abbe91f84a0c59c4df15aabc1a034f3297d67dcad93bae4b67f4c583b092"
        );
    }

    #[test]
    fn rejects_odd_hex_before_parsing() {
        let error = decode_hex("offer", "abc").expect_err("odd hex must fail");
        assert!(error.to_string().contains("even number"));
    }

    #[test]
    fn normalizes_expected_oracle_key_like_typescript() {
        let key = "AA".repeat(32);
        assert_eq!(
            normalize_expected_oracle_pubkey(&format!("  0x{key}  ")),
            Some("aa".repeat(32))
        );
        assert_eq!(normalize_expected_oracle_pubkey("abcd"), None);
        assert_eq!(normalize_expected_oracle_pubkey(&"zz".repeat(32)), None);
    }
}
