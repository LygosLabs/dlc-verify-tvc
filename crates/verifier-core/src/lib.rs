//! Deterministic, side-effect-free DLC transcript verification.

mod reconstruction;

use std::collections::HashSet;

use bitcoin::{
    Amount, Network as BitcoinNetwork, blockdata::constants::genesis_block, hashes::Hash as _,
};
use ddk_dlc::FeeRule;
use ddk_messages::{
    AcceptDlc, OfferDlc, SignDlc,
    contract_msgs::{ContractDescriptor, ContractInfo},
    oracle_msgs::{EventDescriptor, OracleInfo},
};
use lightning::{
    io::Cursor,
    util::ser::{Readable, Writeable},
};
use secp256k1_zkp::Secp256k1;
use sha2::{Digest, Sha256};
use verifier_schema::{
    CetTransactionInfo, DlcVerifyResult, FundingInputInfo, MAX_DLC_MESSAGE_BYTES, Network,
    OracleEventExpectation, OracleEventPreimage, OraclePubkeySource, OutcomeInfo,
    TransactionOutputInfo, VerificationCheck, VerificationPolicy, VerificationRequest,
    VerificationResult, VerificationStatus,
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

fn normalize_expected_oracle_pubkey(value: &str) -> Result<Option<String>, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let normalized = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let normalized = normalized
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if normalized.is_empty() {
        return Ok(None);
    }
    if !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Oracle pubkey must be hex".to_owned());
    }
    if normalized.len() != 64 {
        return Err("Oracle pubkey must be a 32-byte x-only pubkey (64 hex chars)".to_owned());
    }
    Ok(Some(normalized))
}

fn rendering_network(value: Option<&str>) -> (&'static str, BitcoinNetwork) {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("testnet") => ("testnet", BitcoinNetwork::Testnet),
        Some("regtest") => ("regtest", BitcoinNetwork::Regtest),
        _ => ("mainnet", BitcoinNetwork::Bitcoin),
    }
}

fn chain_hash_network_name(chain_hash: &[u8; 32]) -> Option<String> {
    [
        (BitcoinNetwork::Bitcoin, "mainnet"),
        (BitcoinNetwork::Testnet, "testnet"),
        (BitcoinNetwork::Regtest, "regtest"),
    ]
    .into_iter()
    .find_map(|(network, name)| {
        (chain_hash == &genesis_block(network).block_hash().to_byte_array())
            .then(|| name.to_owned())
    })
}

fn validate_enumerated_oracle_event(
    descriptor: &ddk_messages::contract_msgs::EnumeratedContractDescriptor,
    oracle_event_descriptor: &EventDescriptor,
) -> Result<(), String> {
    let EventDescriptor::EnumEvent(oracle_descriptor) = oracle_event_descriptor else {
        return Err(
            "enumerated contracts require an enumerated oracle event descriptor".to_owned(),
        );
    };
    if descriptor.payouts.len() != oracle_descriptor.outcomes.len() {
        return Err(format!(
            "contract and oracle outcome counts differ: contract={} oracle={}",
            descriptor.payouts.len(),
            oracle_descriptor.outcomes.len()
        ));
    }
    let contract_outcomes = descriptor
        .payouts
        .iter()
        .map(|payout| payout.outcome.as_str())
        .collect::<HashSet<_>>();
    let oracle_outcomes = oracle_descriptor
        .outcomes
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if contract_outcomes.len() != descriptor.payouts.len()
        || oracle_outcomes.len() != oracle_descriptor.outcomes.len()
    {
        return Err("contract and oracle outcomes must each be unique".to_owned());
    }
    if contract_outcomes != oracle_outcomes {
        return Err("contract outcomes do not match the signed oracle outcome set".to_owned());
    }
    Ok(())
}

fn validate_contract_maturity(offer: &OfferDlc, event_maturity_epoch: u32) -> Result<(), String> {
    if offer.cet_locktime > event_maturity_epoch {
        return Err(format!(
            "CET locktime {} is after oracle event maturity {event_maturity_epoch}",
            offer.cet_locktime
        ));
    }
    if offer.refund_locktime <= event_maturity_epoch {
        return Err(format!(
            "refund locktime {} must be after oracle event maturity {event_maturity_epoch}",
            offer.refund_locktime
        ));
    }
    Ok(())
}

fn address_for_script(script: &bitcoin::ScriptBuf, network: BitcoinNetwork) -> Option<String> {
    bitcoin::Address::from_script(script, network)
        .ok()
        .map(|address| address.to_string())
}

fn finalize_compatibility_status(result: &mut DlcVerifyResult, sign_requested: bool) {
    let mut failures = std::mem::take(&mut result.verification_failures);
    let mut incomplete = std::mem::take(&mut result.verification_incomplete);

    if result.error.is_some() {
        failures.push("message-parsing-or-reconstruction-failed".to_owned());
    }
    if result.expected_oracle_pubkey.is_some()
        && result.oracle_pubkey_matches_expected != Some(true)
    {
        failures.push("oracle-pubkey-mismatch-or-unavailable".to_owned());
    }
    if !result.oracle_sig_valid {
        failures.push("oracle-announcement-signature-invalid".to_owned());
    }
    if !result.adaptor_sig_verification_available {
        failures.push("accepter-adaptor-verification-unavailable".to_owned());
    } else if result.adaptor_valid != Some(true) {
        failures.push("accepter-adaptor-signatures-invalid".to_owned());
    }
    if result.refund_sig_valid != Some(true) {
        failures.push("accepter-refund-signature-invalid-or-unavailable".to_owned());
    }

    if !sign_requested {
        incomplete.push("dlc-sign-not-provided".to_owned());
    } else if !result.sign_available {
        failures.push("dlc-sign-invalid-or-unparseable".to_owned());
    } else {
        if result.sign_contract_id_matches != Some(true) {
            failures.push("sign-contract-id-mismatch-or-unavailable".to_owned());
        }
        if result.sign_adaptor_valid != Some(true) {
            failures.push("offerer-adaptor-signatures-invalid-or-unavailable".to_owned());
        }
        if result.sign_refund_sig_valid != Some(true) {
            failures.push("offerer-refund-signature-invalid-or-unavailable".to_owned());
        }
    }

    failures.dedup();
    incomplete.dedup();
    result.verification_status = if failures.is_empty() {
        if incomplete.is_empty() {
            VerificationStatus::Pass
        } else {
            VerificationStatus::Incomplete
        }
    } else {
        VerificationStatus::Fail
    };
    result.verification_failures = failures;
    result.verification_incomplete = incomplete;
}

fn compatibility_parse_failure(
    mut result: DlcVerifyResult,
    sign_requested: bool,
    error: impl Into<String>,
) -> DlcVerifyResult {
    result.error = Some(error.into());
    finalize_compatibility_status(&mut result, sign_requested);
    result
}

/// The single enumerated oracle announcement an offer's CETs are signed against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferAnnouncement {
    /// Chain hash the offer names.
    pub chain_hash: [u8; 32],
    /// The announcement as the offer serializes it.
    pub bytes: Vec<u8>,
    /// Oracle event id.
    pub event_id: String,
    /// Outcomes in the oracle's order.
    pub outcomes: Vec<String>,
}

/// Extract the oracle announcement from an offer.
///
/// # Errors
///
/// Fails when the offer does not parse or is not a single-oracle enumerated contract.
pub fn offer_announcement(offer_hex: &str) -> Result<OfferAnnouncement, VerifyError> {
    let unsupported = |detail: &str| VerifyError::InvalidMessage {
        field: "offer",
        detail: detail.to_owned(),
    };
    let offer: OfferDlc = strict_read("offer", &decode_hex("offer", offer_hex)?)?;
    let ContractInfo::SingleContractInfo(single) = &offer.contract_info else {
        return Err(unsupported("disjoint contracts are not supported"));
    };
    let OracleInfo::Single(oracle) = &single.contract_info.oracle_info else {
        return Err(unsupported("exactly one oracle is required"));
    };
    let announcement = &oracle.oracle_announcement;
    let EventDescriptor::EnumEvent(descriptor) = &announcement.oracle_event.event_descriptor else {
        return Err(unsupported("an enumerated oracle event is required"));
    };
    Ok(OfferAnnouncement {
        chain_hash: offer.chain_hash,
        bytes: announcement.encode(),
        event_id: announcement.oracle_event.event_id.clone(),
        outcomes: descriptor.outcomes.clone(),
    })
}

/// Reproduce the PR #9 DLC Verify result with DDK-native Rust verification.
///
/// Malformed or unsupported bounded inputs produce a structured fail-closed result rather than
/// an unsigned application error. The function is deterministic and performs no I/O.
#[must_use]
pub fn verify_dlc_compatibility(
    offer_hex: &str,
    accept_hex: &str,
    sign_hex: Option<&str>,
    expected_oracle_pubkey: Option<&str>,
    network: Option<&str>,
) -> DlcVerifyResult {
    let sign_requested = sign_hex.is_some();
    let (network_name, bitcoin_network) = rendering_network(network);
    let offer_bytes = decode_hex("offer", offer_hex).unwrap_or_default();
    let accept_bytes = decode_hex("accept", accept_hex).unwrap_or_default();
    let sign_bytes = sign_hex.and_then(|value| decode_hex("sign", value).ok());
    let mut result = DlcVerifyResult {
        network: network_name.to_owned(),
        transcript_hash: transcript_hash(&offer_bytes, &accept_bytes, sign_bytes.as_deref()),
        ..DlcVerifyResult::default()
    };
    let normalized_expected = match expected_oracle_pubkey
        .map(normalize_expected_oracle_pubkey)
        .transpose()
    {
        Ok(value) => value.flatten(),
        Err(error) => return compatibility_parse_failure(result, sign_requested, error),
    };
    result.expected_oracle_pubkey = normalized_expected.clone();
    result.oracle_pubkey_source = if normalized_expected.is_some() {
        OraclePubkeySource::Provided
    } else {
        OraclePubkeySource::Derived
    };

    let offer: OfferDlc =
        match decode_hex("offer", offer_hex).and_then(|bytes| strict_read("offer", &bytes)) {
            Ok(offer) => offer,
            Err(error) => {
                return compatibility_parse_failure(result, sign_requested, error.to_string());
            }
        };
    let accept: AcceptDlc =
        match decode_hex("accept", accept_hex).and_then(|bytes| strict_read("accept", &bytes)) {
            Ok(accept) => accept,
            Err(error) => {
                return compatibility_parse_failure(result, sign_requested, error.to_string());
            }
        };
    if offer.temporary_contract_id != accept.temporary_contract_id {
        return compatibility_parse_failure(
            result,
            sign_requested,
            "Offer and Accept temporary contract IDs do not match",
        );
    }

    let sign = match sign_hex {
        Some(value) => {
            match decode_hex("sign", value).and_then(|bytes| strict_read("sign", &bytes)) {
                Ok(sign) => {
                    result.sign_available = true;
                    Some(sign)
                }
                Err(error) => {
                    let message = format!("Failed to parse sign message: {error}");
                    result.sign_adaptor_error = Some(message.clone());
                    result.sign_refund_sig_error = Some(message);
                    None
                }
            }
        }
        None => None,
    };
    result.sign_contract_id = sign
        .as_ref()
        .map(|sign: &SignDlc| hex::encode(sign.contract_id));

    let (descriptor, announcement) = match &offer.contract_info {
        ContractInfo::SingleContractInfo(single) => {
            let descriptor = match &single.contract_info.contract_descriptor {
                ContractDescriptor::EnumeratedContractDescriptor(descriptor) => descriptor,
                ContractDescriptor::NumericOutcomeContractDescriptor(_) => {
                    return compatibility_parse_failure(
                        result,
                        sign_requested,
                        "Adaptor signature verification currently supports EnumeratedDescriptor contracts only",
                    );
                }
            };
            let announcement = match &single.contract_info.oracle_info {
                OracleInfo::Single(oracle) => &oracle.oracle_announcement,
                OracleInfo::Multi(_) => {
                    return compatibility_parse_failure(
                        result,
                        sign_requested,
                        "Adaptor signature verification currently supports one oracle only",
                    );
                }
            };
            (descriptor, announcement)
        }
        ContractInfo::DisjointContractInfo(_) => {
            return compatibility_parse_failure(
                result,
                sign_requested,
                "Adaptor signature verification does not support disjoint contracts",
            );
        }
    };
    if let Err(error) =
        validate_enumerated_oracle_event(descriptor, &announcement.oracle_event.event_descriptor)
    {
        return compatibility_parse_failure(result, sign_requested, error);
    }
    if let Err(error) =
        validate_contract_maturity(&offer, announcement.oracle_event.event_maturity_epoch)
    {
        return compatibility_parse_failure(result, sign_requested, error);
    }

    let total_collateral = offer.get_total_collateral();
    result.chain_hash_network = chain_hash_network_name(&offer.chain_hash);
    result.contract_type = Some("Enumerated".to_owned());
    result.total_collateral = Some(amount_string(total_collateral));
    result.offer_collateral = Some(amount_string(offer.offer_collateral));
    result.accept_collateral = Some(amount_string(accept.accept_collateral));
    result.outcomes = descriptor
        .payouts
        .iter()
        .map(|payout| OutcomeInfo {
            label: payout.outcome.clone(),
            offerer_sats: amount_string(payout.offer_payout),
            accepter_sats: total_collateral
                .checked_sub(payout.offer_payout)
                .map_or_else(|| "0".to_owned(), amount_string),
        })
        .collect();
    result.cet_locktime = Some(offer.cet_locktime);
    result.refund_locktime = Some(offer.refund_locktime);
    result.fee_rate_per_vb = Some(offer.fee_rate_per_vb.to_string());
    result.offerer_funding_pubkey = Some(offer.funding_pubkey.to_string());
    result.accepter_funding_pubkey = Some(accept.funding_pubkey.to_string());
    result.offerer_payout_address = address_for_script(&offer.payout_spk, bitcoin_network);
    result.offerer_change_address = address_for_script(&offer.change_spk, bitcoin_network);
    result.accepter_payout_address = address_for_script(&accept.payout_spk, bitcoin_network);
    result.accepter_change_address = address_for_script(&accept.change_spk, bitcoin_network);

    let extracted_oracle_pubkey = announcement.oracle_public_key.to_string();
    result.extracted_oracle_pubkey = Some(extracted_oracle_pubkey.clone());
    result.oracle_pubkey = normalized_expected
        .clone()
        .or_else(|| Some(extracted_oracle_pubkey.clone()));
    result.oracle_pubkey_matches_expected = normalized_expected
        .as_ref()
        .map(|expected| expected == &extracted_oracle_pubkey);
    result.oracle_event_id = Some(announcement.oracle_event.event_id.clone());
    let secp = Secp256k1::verification_only();
    match announcement.validate(&secp) {
        Ok(()) => result.oracle_sig_valid = true,
        Err(error) => result.oracle_sig_error = Some(error.to_string()),
    }

    let (reconstruction, signatures) = match reconstruction::reconstruct_and_verify(
        &offer,
        &accept,
        sign.as_ref(),
        descriptor,
        announcement,
        bitcoin_network,
    ) {
        Ok(verified) => verified,
        Err(error) => return compatibility_parse_failure(result, sign_requested, error),
    };
    let funding_script = &reconstruction.transactions.funding_witness_script;
    result.witness_script = Some(hex::encode(funding_script.as_bytes()));
    result.funding_address = address_for_script(&funding_script.to_p2wsh(), bitcoin_network);
    result.offer_inputs = reconstruction
        .offer_inputs
        .iter()
        .map(|input| FundingInputInfo {
            outpoint: input.outpoint.clone(),
            sats: Some(input.sats.clone()),
        })
        .collect();
    result.accept_inputs = reconstruction
        .accept_inputs
        .iter()
        .map(|input| FundingInputInfo {
            outpoint: input.outpoint.clone(),
            sats: Some(input.sats.clone()),
        })
        .collect();
    result.contract_id = Some(hex::encode(reconstruction.contract_id));
    result.fund_output_index = Some(reconstruction.fund_output_index);
    result.funding_value_sats = Some(reconstruction.funding_value.to_sat().to_string());
    result.fund_tx_id = Some(reconstruction.transactions.fund.compute_txid().to_string());
    result.cet_count = Some(reconstruction.transactions.cets.len());
    result.refund_tx_id = Some(
        reconstruction
            .transactions
            .refund
            .compute_txid()
            .to_string(),
    );
    result.refund_outputs = reconstruction
        .refund_outputs
        .iter()
        .map(|output| TransactionOutputInfo {
            index: output.index,
            sats: output.sats.clone(),
            script_pub_key: output.script_pubkey.clone(),
            address: output.address.clone(),
        })
        .collect();
    result.cets = reconstruction
        .cets
        .iter()
        .map(|cet| CetTransactionInfo {
            outcome: cet.outcome.clone(),
            txid: cet.txid.clone(),
            locktime: cet.locktime,
            outputs: cet
                .outputs
                .iter()
                .map(|output| TransactionOutputInfo {
                    index: output.index,
                    sats: output.sats.clone(),
                    script_pub_key: output.script_pubkey.clone(),
                    address: output.address.clone(),
                })
                .collect(),
        })
        .collect();

    result.adaptor_sig_verification_available = true;
    result.adaptor_valid = Some(signatures.accept_adaptor_valid);
    result.adaptor_valid_count = signatures.accept_adaptor_valid_count;
    result.adaptor_total_count = signatures.accept_adaptor_total_count;
    result.adaptor_error = (!signatures.accept_adaptor_valid)
        .then(|| "DDK verifyCetAdaptorSigsFromOracleInfo returned false".to_owned());
    result.refund_sig_valid = Some(signatures.accept_refund_valid);
    result.refund_sig_error = (!signatures.accept_refund_valid)
        .then(|| "Accepter refund signature verification failed".to_owned());
    result.sign_contract_id_matches = signatures.sign_contract_id_matches;
    result.sign_adaptor_valid = signatures.sign_adaptor_valid;
    result.sign_adaptor_valid_count = signatures.sign_adaptor_valid_count;
    result.sign_adaptor_total_count = signatures.sign_adaptor_total_count;
    result.sign_adaptor_error = signatures
        .sign_adaptor_valid
        .is_some_and(|valid| !valid)
        .then(|| "DDK verification of offerer CET adaptor signatures returned false".to_owned());
    result.sign_refund_sig_valid = signatures.sign_refund_valid;
    result.sign_refund_sig_error = signatures
        .sign_refund_valid
        .is_some_and(|valid| !valid)
        .then(|| "Offerer refund signature verification failed".to_owned());
    // The TypeScript goldens pin the 1.x wording; only the DDK 2.0 fee rule is called out.
    let fee_rule = match signatures.fee_rule {
        FeeRule::OwnPayoutOnly => "",
        FeeRule::CounterpartyPayout => ", DDK 2.0 counterparty-payout fee rule",
    };
    result.adaptor_sig_verification_note = Some(if signatures.accept_adaptor_valid {
        format!(
            "All {} CET adaptor signatures cryptographically valid (DDK{fee_rule})",
            signatures.accept_adaptor_total_count
        )
    } else {
        "Adaptor signature verification failed".to_owned()
    });
    if signatures.sign_protocol_valid == Some(false) {
        result
            .verification_failures
            .push("unsupported-sign-protocol-version".to_owned());
    }
    if signatures.sign_funding_witnesses.valid == Some(false) {
        result
            .verification_failures
            .push("offerer-funding-signatures-invalid".to_owned());
    }
    if signatures.sign_funding_witnesses.valid.is_none()
        && !signatures.sign_funding_witnesses.incomplete.is_empty()
    {
        result
            .verification_incomplete
            .push("offerer-funding-signature-verification-unsupported".to_owned());
    }
    // Counts and the safe diagnostic are retained for audit logging by higher-level callers even
    // though the frozen PR #9 wire schema has no funding-witness fields.
    let _funding_witness_audit = (
        signatures.sign_funding_witnesses.valid_count,
        signatures.sign_funding_witnesses.total_count,
        signatures.sign_funding_witnesses.error.as_deref(),
    );

    finalize_compatibility_status(&mut result, sign_requested);
    result
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
        let normalized = normalize_expected_oracle_pubkey(expected).ok().flatten();
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
            Ok(Some("aa".repeat(32)))
        );
        assert_eq!(
            normalize_expected_oracle_pubkey(&format!("0x{} {}", "AA".repeat(16), "BB".repeat(16))),
            Ok(Some(format!("{}{}", "aa".repeat(16), "bb".repeat(16))))
        );
        assert_eq!(normalize_expected_oracle_pubkey("   "), Ok(None));
        assert_eq!(
            normalize_expected_oracle_pubkey("abcd"),
            Err("Oracle pubkey must be a 32-byte x-only pubkey (64 hex chars)".to_owned())
        );
        assert_eq!(
            normalize_expected_oracle_pubkey(&"zz".repeat(32)),
            Err("Oracle pubkey must be hex".to_owned())
        );
    }

    #[test]
    fn compatibility_chain_hashes_match_pr9_exactly() {
        for (network, expected) in [
            (BitcoinNetwork::Bitcoin, "mainnet"),
            (BitcoinNetwork::Testnet, "testnet"),
            (BitcoinNetwork::Regtest, "regtest"),
        ] {
            assert_eq!(
                chain_hash_network_name(&genesis_block(network).block_hash().to_byte_array()),
                Some(expected.to_owned())
            );
        }

        assert_eq!(
            chain_hash_network_name(
                &genesis_block(BitcoinNetwork::Testnet4)
                    .block_hash()
                    .to_byte_array()
            ),
            None
        );
        let reversed_testnet: [u8; 32] = hex::decode(
            genesis_block(BitcoinNetwork::Testnet)
                .block_hash()
                .to_string(),
        )
        .expect("display hash must be hex")
        .try_into()
        .expect("block hash must be 32 bytes");
        assert_eq!(chain_hash_network_name(&reversed_testnet), None);
    }

    #[test]
    fn enumerated_contract_requires_the_exact_unique_oracle_outcome_set() {
        use bitcoin::Amount;
        use ddk_messages::{
            contract_msgs::{ContractOutcome, EnumeratedContractDescriptor},
            oracle_msgs::{
                DigitDecompositionEventDescriptor, EnumEventDescriptor, EventDescriptor,
            },
        };

        let descriptor = EnumeratedContractDescriptor {
            payouts: vec![
                ContractOutcome {
                    outcome: "repaid".to_owned(),
                    offer_payout: Amount::from_sat(1),
                },
                ContractOutcome {
                    outcome: "defaulted".to_owned(),
                    offer_payout: Amount::ZERO,
                },
            ],
        };
        let exact_reordered = EventDescriptor::EnumEvent(EnumEventDescriptor {
            outcomes: vec!["defaulted".to_owned(), "repaid".to_owned()],
        });
        assert!(validate_enumerated_oracle_event(&descriptor, &exact_reordered).is_ok());

        let mismatched = EventDescriptor::EnumEvent(EnumEventDescriptor {
            outcomes: vec!["repaid".to_owned(), "liquidated".to_owned()],
        });
        assert!(validate_enumerated_oracle_event(&descriptor, &mismatched).is_err());

        let duplicate = EventDescriptor::EnumEvent(EnumEventDescriptor {
            outcomes: vec!["repaid".to_owned(), "repaid".to_owned()],
        });
        assert!(validate_enumerated_oracle_event(&descriptor, &duplicate).is_err());

        let numeric = EventDescriptor::DigitDecompositionEvent(DigitDecompositionEventDescriptor {
            base: 2,
            is_signed: false,
            unit: "sats".to_owned(),
            precision: 0,
            nb_digits: 1,
        });
        assert!(validate_enumerated_oracle_event(&descriptor, &numeric).is_err());
    }

    #[test]
    fn contract_locktimes_must_bracket_oracle_maturity() {
        let mut offer = OfferDlc {
            protocol_version: 1,
            contract_flags: 0,
            chain_hash: [0; 32],
            temporary_contract_id: [0; 32],
            contract_info: ContractInfo::DisjointContractInfo(
                ddk_messages::contract_msgs::DisjointContractInfo {
                    total_collateral: Amount::ZERO,
                    contract_infos: Vec::new(),
                },
            ),
            funding_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .expect("generator public key"),
            payout_spk: bitcoin::ScriptBuf::new(),
            payout_serial_id: 0,
            offer_collateral: Amount::ZERO,
            funding_inputs: Vec::new(),
            change_spk: bitcoin::ScriptBuf::new(),
            change_serial_id: 1,
            fund_output_serial_id: 2,
            fee_rate_per_vb: 1,
            cet_locktime: 10,
            refund_locktime: 30,
            tlvs: Default::default(),
        };
        assert!(validate_contract_maturity(&offer, 20).is_ok());

        offer.cet_locktime = 21;
        assert!(validate_contract_maturity(&offer, 20).is_err());

        offer.cet_locktime = 10;
        offer.refund_locktime = 20;
        assert!(validate_contract_maturity(&offer, 20).is_err());
    }

    #[test]
    fn malformed_supplied_oracle_key_fails_closed() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/testnet-loan-118c9fc9.json"))
                .expect("fixture must be JSON");
        let result = verify_dlc_compatibility(
            fixture["offer"].as_str().expect("fixture offer"),
            fixture["accept"].as_str().expect("fixture accept"),
            fixture["sign"].as_str(),
            Some("not-a-public-key"),
            Some("regtest"),
        );

        assert_eq!(result.verification_status, VerificationStatus::Fail);
        assert_eq!(result.expected_oracle_pubkey, None);
        assert_eq!(result.oracle_pubkey_source, OraclePubkeySource::Derived);
        assert_eq!(result.error.as_deref(), Some("Oracle pubkey must be hex"));
        assert!(
            result
                .verification_failures
                .iter()
                .any(|failure| failure == "message-parsing-or-reconstruction-failed")
        );
    }
}
