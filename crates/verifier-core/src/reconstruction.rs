//! DDK-native transaction reconstruction and cryptographic verification.

use std::{
    collections::HashSet,
    panic::{AssertUnwindSafe, catch_unwind},
};

use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, Script, ScriptBuf, Transaction,
    consensus::deserialize, hashes::Hash as _, sighash::SighashCache,
};
use ddk_dlc::{
    DlcTransactions, FeeRule, OracleInfo as DlcOracleInfo, PartyParams, Payout, TxInputInfo,
    create_dlc_transactions_with_fee_rule, create_spliced_dlc_transactions_with_fee_rule,
    verify_cet_adaptor_sig_from_oracle_info, verify_tx_input_sig,
};
use ddk_messages::{
    AcceptDlc, CetAdaptorSignature, FundingInput, FundingSignature, OfferDlc, SignDlc,
    contract_msgs::EnumeratedContractDescriptor,
    oracle_msgs::{OracleAnnouncement, tagged_attestation_msg},
};
use secp256k1_zkp::{Message, Secp256k1, ecdsa::Signature};

/// Upper bound for collections which drive transaction or signature work.
pub(crate) const MAX_CONTRACT_ITEMS: usize = 4_096;
const MAX_WITNESS_ELEMENTS: usize = 128;
const MAX_WITNESS_ELEMENT_BYTES: usize = 16_384;
const REGULAR_SPLICE_WITNESS_LEN: u16 = 108;
const DLC_SPLICE_WITNESS_LEN: u16 = 220;
const SUPPORTED_PROTOCOL_VERSION: u32 = 1;
const SUPPORTED_CONTRACT_FLAGS: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FundingInputFact {
    pub(crate) outpoint: String,
    pub(crate) sats: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputFact {
    pub(crate) index: usize,
    pub(crate) sats: String,
    pub(crate) script_pubkey: String,
    pub(crate) address: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CetFact {
    pub(crate) outcome: String,
    pub(crate) txid: String,
    pub(crate) locktime: u32,
    pub(crate) outputs: Vec<OutputFact>,
}

#[derive(Clone)]
pub(crate) struct Reconstruction {
    pub(crate) transactions: DlcTransactions,
    pub(crate) fund_output_index: usize,
    pub(crate) funding_value: Amount,
    pub(crate) contract_id: [u8; 32],
    pub(crate) offer_inputs: Vec<FundingInputFact>,
    pub(crate) accept_inputs: Vec<FundingInputFact>,
    pub(crate) refund_outputs: Vec<OutputFact>,
    pub(crate) cets: Vec<CetFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FundingWitnessChecks {
    /// `None` means no Sign message or at least one unsupported input form.
    pub(crate) valid: Option<bool>,
    pub(crate) valid_count: usize,
    pub(crate) total_count: usize,
    pub(crate) error: Option<String>,
    pub(crate) incomplete: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SignatureChecks {
    pub(crate) accept_adaptor_valid: bool,
    pub(crate) accept_adaptor_valid_count: usize,
    pub(crate) accept_adaptor_total_count: usize,
    pub(crate) accept_refund_valid: bool,
    pub(crate) sign_protocol_valid: Option<bool>,
    pub(crate) sign_adaptor_valid: Option<bool>,
    pub(crate) sign_adaptor_valid_count: usize,
    pub(crate) sign_adaptor_total_count: usize,
    pub(crate) sign_refund_valid: Option<bool>,
    pub(crate) sign_contract_id_matches: Option<bool>,
    pub(crate) sign_funding_witnesses: FundingWitnessChecks,
}

#[derive(Clone)]
struct DecodedFundingInput {
    transaction: Transaction,
    previous_output: bitcoin::TxOut,
    outpoint: OutPoint,
}

fn decoded_funding_input(input: &FundingInput) -> Result<DecodedFundingInput, String> {
    let transaction: Transaction =
        deserialize(&input.prev_tx).map_err(|error| format!("invalid funding prev_tx: {error}"))?;
    let previous_output = transaction
        .output
        .get(input.prev_tx_vout as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "funding prev_tx_vout {} is out of bounds",
                input.prev_tx_vout
            )
        })?;
    let outpoint = OutPoint::new(transaction.compute_txid(), input.prev_tx_vout);
    Ok(DecodedFundingInput {
        transaction,
        previous_output,
        outpoint,
    })
}

fn decode_funding_input(
    input: &FundingInput,
) -> Result<
    (
        TxInputInfo,
        Option<ddk_dlc::dlc_input::DlcInputInfo>,
        Amount,
        FundingInputFact,
    ),
    String,
> {
    let decoded = decoded_funding_input(input)?;
    let tx_input = TxInputInfo {
        outpoint: decoded.outpoint,
        max_witness_len: usize::from(input.max_witness_len),
        redeem_script: input.redeem_script.clone(),
        serial_id: input.input_serial_id,
    };
    let dlc_input = if let Some(dlc_input) = &input.dlc_input {
        if dlc_input.local_fund_pubkey == dlc_input.remote_fund_pubkey {
            return Err("DLC input funding public keys must be distinct".to_owned());
        }
        if !input.redeem_script.is_empty() {
            return Err("DLC input redeem script must be empty".to_owned());
        }
        let expected_script = ddk_dlc::make_funding_redeemscript(
            &dlc_input.local_fund_pubkey,
            &dlc_input.remote_fund_pubkey,
        )
        .to_p2wsh();
        if decoded.previous_output.script_pubkey != expected_script {
            return Err(format!(
                "DLC input {} does not spend the declared 2-of-2 funding script",
                decoded.outpoint
            ));
        }
        Some(ddk_dlc::dlc_input::DlcInputInfo {
            fund_tx: decoded.transaction.clone(),
            fund_vout: input.prev_tx_vout,
            local_fund_pubkey: dlc_input.local_fund_pubkey,
            remote_fund_pubkey: dlc_input.remote_fund_pubkey,
            fund_amount: decoded.previous_output.value,
            max_witness_len: usize::from(input.max_witness_len),
            input_serial_id: input.input_serial_id,
            contract_id: dlc_input.contract_id,
        })
    } else {
        None
    };
    let fact = FundingInputFact {
        outpoint: decoded.outpoint.to_string(),
        sats: decoded.previous_output.value.to_sat().to_string(),
    };
    Ok((tx_input, dlc_input, decoded.previous_output.value, fact))
}

fn party_params(
    fund_pubkey: secp256k1_zkp::PublicKey,
    change_script_pubkey: &ScriptBuf,
    change_serial_id: u64,
    payout_script_pubkey: &ScriptBuf,
    payout_serial_id: u64,
    funding_inputs: &[FundingInput],
    collateral: Amount,
) -> Result<(PartyParams, Vec<FundingInputFact>), String> {
    if funding_inputs.len() > MAX_CONTRACT_ITEMS {
        return Err(format!("too many funding inputs: {}", funding_inputs.len()));
    }
    let mut inputs = Vec::with_capacity(funding_inputs.len());
    let mut dlc_inputs = Vec::new();
    let mut input_amount = Amount::ZERO;
    let mut facts = Vec::with_capacity(funding_inputs.len());
    for input in funding_inputs {
        let (tx_input, dlc_input, amount, fact) = decode_funding_input(input)?;
        input_amount = input_amount
            .checked_add(amount)
            .ok_or_else(|| "funding input amount overflow".to_owned())?;
        inputs.push(tx_input);
        if let Some(dlc_input) = dlc_input {
            dlc_inputs.push(dlc_input);
        }
        facts.push(fact);
    }
    Ok((
        PartyParams {
            fund_pubkey,
            change_script_pubkey: change_script_pubkey.clone(),
            change_serial_id,
            payout_script_pubkey: payout_script_pubkey.clone(),
            payout_serial_id,
            inputs,
            dlc_inputs,
            input_amount,
            collateral,
        },
        facts,
    ))
}

fn validate_reconstruction_inputs(
    offer: &OfferDlc,
    accept: &AcceptDlc,
    descriptor: &EnumeratedContractDescriptor,
) -> Result<(), String> {
    if offer.protocol_version != SUPPORTED_PROTOCOL_VERSION
        || accept.protocol_version != SUPPORTED_PROTOCOL_VERSION
    {
        return Err(format!(
            "unsupported protocol versions: offer={} accept={}",
            offer.protocol_version, accept.protocol_version
        ));
    }
    if offer.contract_flags != SUPPORTED_CONTRACT_FLAGS {
        return Err(format!(
            "unsupported contract flags: {}",
            offer.contract_flags
        ));
    }
    if offer.temporary_contract_id != accept.temporary_contract_id {
        return Err("Offer and Accept temporary contract IDs do not match".to_owned());
    }
    let total_input_count = offer
        .funding_inputs
        .len()
        .checked_add(accept.funding_inputs.len())
        .ok_or_else(|| "funding input count overflow".to_owned())?;
    if total_input_count > MAX_CONTRACT_ITEMS {
        return Err(format!(
            "too many combined funding inputs: {total_input_count}"
        ));
    }
    if descriptor.payouts.is_empty() || descriptor.payouts.len() > MAX_CONTRACT_ITEMS {
        return Err(format!(
            "invalid outcome count: {}",
            descriptor.payouts.len()
        ));
    }
    let collateral_sum = offer
        .offer_collateral
        .checked_add(accept.accept_collateral)
        .ok_or_else(|| "collateral amount overflow".to_owned())?;
    if collateral_sum != offer.get_total_collateral() {
        return Err("offer and accept collateral do not equal total collateral".to_owned());
    }
    ddk_dlc::util::validate_fee_rate(offer.fee_rate_per_vb)
        .map_err(|error| format!("invalid fee rate: {error}"))?;

    let mut outcome_labels = HashSet::with_capacity(descriptor.payouts.len());
    for payout in &descriptor.payouts {
        if payout.outcome.is_empty() || !outcome_labels.insert(payout.outcome.as_str()) {
            return Err(format!(
                "outcome labels must be non-empty and unique: {:?}",
                payout.outcome
            ));
        }
    }

    let mut output_serial_ids = HashSet::with_capacity(3);
    for serial_id in [
        offer.fund_output_serial_id,
        offer.change_serial_id,
        accept.change_serial_id,
    ] {
        if !output_serial_ids.insert(serial_id) {
            return Err(format!("duplicate funding output serial ID: {serial_id}"));
        }
    }
    if offer.payout_serial_id == accept.payout_serial_id {
        return Err(format!(
            "duplicate payout serial ID: {}",
            offer.payout_serial_id
        ));
    }

    let total_inputs = offer
        .funding_inputs
        .iter()
        .chain(accept.funding_inputs.iter());
    let mut input_serial_ids = HashSet::with_capacity(total_input_count);
    let mut outpoints = HashSet::with_capacity(total_input_count);
    let spliced = offer
        .funding_inputs
        .iter()
        .chain(accept.funding_inputs.iter())
        .any(|input| input.dlc_input.is_some());
    for input in total_inputs {
        if !input_serial_ids.insert(input.input_serial_id) {
            return Err(format!(
                "duplicate funding input serial ID: {}",
                input.input_serial_id
            ));
        }
        let decoded = decoded_funding_input(input)?;
        if !outpoints.insert(decoded.outpoint) {
            return Err(format!("duplicate funding outpoint: {}", decoded.outpoint));
        }
        if spliced {
            let expected = if input.dlc_input.is_some() {
                DLC_SPLICE_WITNESS_LEN
            } else {
                REGULAR_SPLICE_WITNESS_LEN
            };
            if input.max_witness_len != expected {
                return Err(format!(
                    "unsupported splice witness length for {}: expected {expected}, got {}",
                    decoded.outpoint, input.max_witness_len
                ));
            }
        }
    }
    Ok(())
}

fn compute_contract_id(
    temporary_contract_id: &[u8; 32],
    fund_txid: bitcoin::Txid,
    output_index: usize,
) -> Result<[u8; 32], String> {
    let output_index = u16::try_from(output_index)
        .map_err(|_| format!("fund output index {output_index} exceeds u16"))?;
    let display_txid = hex::decode(fund_txid.to_string())
        .map_err(|error| format!("failed to encode funding txid: {error}"))?;
    let display_txid: [u8; 32] = display_txid
        .try_into()
        .map_err(|_| "funding txid must contain 32 display-order bytes".to_owned())?;
    let mut contract_id = [0_u8; 32];
    for (index, value) in contract_id.iter_mut().enumerate() {
        *value = display_txid[index] ^ temporary_contract_id[index];
    }
    contract_id[30] ^= ((output_index >> 8) & 0xff) as u8;
    contract_id[31] ^= (output_index & 0xff) as u8;
    Ok(contract_id)
}

fn output_facts(transaction: &Transaction, network: Network) -> Vec<OutputFact> {
    transaction
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| OutputFact {
            index,
            sats: output.value.to_sat().to_string(),
            script_pubkey: hex::encode(output.script_pubkey.as_bytes()),
            address: Address::from_script(&output.script_pubkey, network)
                .ok()
                .map(|address| address.to_string()),
        })
        .collect()
}

pub(crate) fn reconstruct(
    offer: &OfferDlc,
    accept: &AcceptDlc,
    descriptor: &EnumeratedContractDescriptor,
    rendering_network: Network,
    fee_rule: FeeRule,
) -> Result<Reconstruction, String> {
    validate_reconstruction_inputs(offer, accept, descriptor)?;
    let total_collateral = offer.get_total_collateral();
    let payouts = descriptor
        .payouts
        .iter()
        .map(|outcome| {
            let accept_payout = total_collateral
                .checked_sub(outcome.offer_payout)
                .ok_or_else(|| format!("outcome {} exceeds collateral", outcome.outcome))?;
            Ok(Payout {
                offer: outcome.offer_payout,
                accept: accept_payout,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let (offer_params, offer_inputs) = party_params(
        offer.funding_pubkey,
        &offer.change_spk,
        offer.change_serial_id,
        &offer.payout_spk,
        offer.payout_serial_id,
        &offer.funding_inputs,
        offer.offer_collateral,
    )?;
    let (accept_params, accept_inputs) = party_params(
        accept.funding_pubkey,
        &accept.change_spk,
        accept.change_serial_id,
        &accept.payout_spk,
        accept.payout_serial_id,
        &accept.funding_inputs,
        accept.accept_collateral,
    )?;
    let spliced = !offer_params.dlc_inputs.is_empty() || !accept_params.dlc_inputs.is_empty();
    let transaction_result = catch_unwind(AssertUnwindSafe(|| {
        if spliced {
            create_spliced_dlc_transactions_with_fee_rule(
                &offer_params,
                &accept_params,
                &payouts,
                offer.refund_locktime,
                offer.fee_rate_per_vb,
                0,
                offer.cet_locktime,
                offer.fund_output_serial_id,
                offer.contract_flags,
                fee_rule,
            )
        } else {
            create_dlc_transactions_with_fee_rule(
                &offer_params,
                &accept_params,
                &payouts,
                offer.refund_locktime,
                offer.fee_rate_per_vb,
                0,
                offer.cet_locktime,
                offer.fund_output_serial_id,
                offer.contract_flags,
                fee_rule,
            )
        }
    }))
    .map_err(|_| "DDK transaction reconstruction panicked".to_owned())?;
    let transactions = transaction_result
        .map_err(|error| format!("DDK transaction reconstruction failed: {error}"))?;
    if transactions.cets.len() != descriptor.payouts.len() {
        return Err(format!(
            "DDK returned {} CETs for {} outcomes",
            transactions.cets.len(),
            descriptor.payouts.len()
        ));
    }

    let funding_output_script = transactions.funding_witness_script.to_p2wsh();
    let matching_outputs = transactions
        .fund
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| output.script_pubkey == funding_output_script)
        .collect::<Vec<_>>();
    if matching_outputs.len() != 1 {
        return Err(format!(
            "expected exactly one reconstructed funding output, found {}",
            matching_outputs.len()
        ));
    }
    let (fund_output_index, fund_output) = matching_outputs[0];
    let funding_value = fund_output.value;
    let contract_id = compute_contract_id(
        &offer.temporary_contract_id,
        transactions.fund.compute_txid(),
        fund_output_index,
    )?;
    let cets = transactions
        .cets
        .iter()
        .zip(descriptor.payouts.iter())
        .map(|(transaction, outcome)| CetFact {
            outcome: outcome.outcome.clone(),
            txid: transaction.compute_txid().to_string(),
            locktime: transaction.lock_time.to_consensus_u32(),
            outputs: output_facts(transaction, rendering_network),
        })
        .collect();
    let refund_outputs = output_facts(&transactions.refund, rendering_network);

    Ok(Reconstruction {
        transactions,
        fund_output_index,
        funding_value,
        contract_id,
        offer_inputs,
        accept_inputs,
        refund_outputs,
        cets,
    })
}

fn verify_adaptors(
    signatures: &[CetAdaptorSignature],
    pubkey: &secp256k1_zkp::PublicKey,
    descriptor: &EnumeratedContractDescriptor,
    announcement: &OracleAnnouncement,
    reconstruction: &Reconstruction,
) -> (bool, usize, usize) {
    if signatures.len() > MAX_CONTRACT_ITEMS
        || signatures.len() != reconstruction.transactions.cets.len()
        || signatures.len() != descriptor.payouts.len()
    {
        return (false, 0, signatures.len());
    }
    let secp = Secp256k1::new();
    let oracle_infos = [DlcOracleInfo::from(announcement)];
    let mut valid_count = 0;
    for (index, signature) in signatures.iter().enumerate() {
        let outcome = &descriptor.payouts[index];
        let messages = [vec![tagged_attestation_msg(&outcome.outcome)]];
        let check = catch_unwind(AssertUnwindSafe(|| {
            verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &signature.signature,
                &reconstruction.transactions.cets[index],
                &oracle_infos,
                pubkey,
                &reconstruction.transactions.funding_witness_script,
                reconstruction.funding_value,
                &messages,
            )
        }));
        if matches!(check, Ok(Ok(()))) {
            valid_count += 1;
        }
    }
    (
        valid_count == signatures.len(),
        valid_count,
        signatures.len(),
    )
}

fn verify_refund_signature(
    signature: &Signature,
    pubkey: &secp256k1_zkp::PublicKey,
    reconstruction: &Reconstruction,
) -> bool {
    let secp = Secp256k1::new();
    let check = catch_unwind(AssertUnwindSafe(|| {
        verify_tx_input_sig(
            &secp,
            signature,
            &reconstruction.transactions.refund,
            0,
            &reconstruction.transactions.funding_witness_script,
            reconstruction.funding_value,
            pubkey,
        )
    }));
    matches!(check, Ok(Ok(())))
}

enum WitnessResult {
    Valid,
    Invalid(String),
    Unsupported(String),
}

fn validate_witness_bounds(signature: &FundingSignature) -> Result<(), String> {
    if signature.witness_elements.is_empty()
        || signature.witness_elements.len() > MAX_WITNESS_ELEMENTS
    {
        return Err(format!(
            "invalid funding witness element count: {}",
            signature.witness_elements.len()
        ));
    }
    if signature
        .witness_elements
        .iter()
        .any(|element| element.witness.len() > MAX_WITNESS_ELEMENT_BYTES)
    {
        return Err("funding witness element exceeds size limit".to_owned());
    }
    Ok(())
}

fn verify_dlc_input_witness(
    input: &FundingInput,
    signature: &FundingSignature,
    fund_transaction: &Transaction,
    input_index: usize,
) -> WitnessResult {
    if let Err(error) = validate_witness_bounds(signature) {
        return WitnessResult::Invalid(error);
    }
    let Some(message_dlc_input) = &input.dlc_input else {
        return WitnessResult::Invalid("missing DLC input metadata".to_owned());
    };
    if signature.witness_elements.len() > 2 {
        return WitnessResult::Invalid("unsupported DLC input witness shape".to_owned());
    }
    if let Some(pubkey_element) = signature.witness_elements.get(1)
        && pubkey_element.witness != message_dlc_input.local_fund_pubkey.serialize()
    {
        return WitnessResult::Invalid(
            "legacy DLC input witness public key does not match local funding key".to_owned(),
        );
    }
    let signature_bytes = &signature.witness_elements[0].witness;
    let syntactically_valid = if signature_bytes.len() == 64 {
        Signature::from_compact(signature_bytes).is_ok()
    } else {
        signature_bytes.last() == Some(&(EcdsaSighashType::All as u8))
            && Signature::from_der(&signature_bytes[..signature_bytes.len().saturating_sub(1)])
                .is_ok()
    };
    if !syntactically_valid {
        return WitnessResult::Invalid("invalid DLC input funding signature encoding".to_owned());
    }
    let dlc_input = match decode_funding_input(input) {
        Ok((_, Some(value), _, _)) => value,
        Ok((_, None, _, _)) => {
            return WitnessResult::Invalid("missing DLC input metadata".to_owned());
        }
        Err(error) => return WitnessResult::Invalid(error),
    };
    let secp = Secp256k1::verification_only();
    let check = catch_unwind(AssertUnwindSafe(|| {
        ddk_dlc::dlc_input::verify_dlc_funding_input_signature(
            &secp,
            fund_transaction,
            input_index,
            &dlc_input,
            signature_bytes.clone(),
            &message_dlc_input.local_fund_pubkey,
        )
    }));
    if matches!(check, Ok(Ok(()))) {
        WitnessResult::Valid
    } else {
        WitnessResult::Invalid("DLC input funding signature verification failed".to_owned())
    }
}

fn p2wpkh_program(
    input: &FundingInput,
    previous_output_script: &Script,
    witness_pubkey: &bitcoin::PublicKey,
) -> Result<Option<ScriptBuf>, String> {
    let expected_program = ScriptBuf::new_p2wpkh(
        &witness_pubkey
            .wpubkey_hash()
            .map_err(|error| format!("invalid compressed witness public key: {error}"))?,
    );
    if previous_output_script.is_p2wpkh() {
        if !input.redeem_script.is_empty() || previous_output_script != expected_program.as_script()
        {
            return Err("native P2WPKH witness does not match previous output".to_owned());
        }
        return Ok(Some(expected_program));
    }
    if previous_output_script.is_p2sh() {
        let redeem_program = if input.redeem_script.is_p2wpkh() {
            input.redeem_script.clone()
        } else if input.redeem_script.len() == 20 {
            let hash = bitcoin::WPubkeyHash::from_slice(input.redeem_script.as_bytes())
                .map_err(|error| format!("invalid P2SH-P2WPKH redeem program: {error}"))?;
            ScriptBuf::new_p2wpkh(&hash)
        } else {
            return Ok(None);
        };
        if redeem_program != expected_program
            || redeem_program.to_p2sh().as_script() != previous_output_script
        {
            return Err("P2SH-P2WPKH witness does not match previous output".to_owned());
        }
        return Ok(Some(redeem_program));
    }
    Ok(None)
}

fn verify_p2wpkh_witness(
    input: &FundingInput,
    signature: &FundingSignature,
    fund_transaction: &Transaction,
    input_index: usize,
) -> WitnessResult {
    if let Err(error) = validate_witness_bounds(signature) {
        return WitnessResult::Invalid(error);
    }
    if signature.witness_elements.len() != 2 {
        return WitnessResult::Invalid(
            "P2WPKH witness must contain signature and public key".to_owned(),
        );
    }
    let signature_bytes = &signature.witness_elements[0].witness;
    if signature_bytes.last() != Some(&(EcdsaSighashType::All as u8)) {
        return WitnessResult::Invalid("P2WPKH signature must use SIGHASH_ALL".to_owned());
    }
    let parsed_signature =
        match Signature::from_der(&signature_bytes[..signature_bytes.len().saturating_sub(1)]) {
            Ok(value) => value,
            Err(error) => {
                return WitnessResult::Invalid(format!("invalid P2WPKH DER signature: {error}"));
            }
        };
    let witness_pubkey_bytes = &signature.witness_elements[1].witness;
    let witness_bitcoin_pubkey = match bitcoin::PublicKey::from_slice(witness_pubkey_bytes) {
        Ok(value) => value,
        Err(error) => {
            return WitnessResult::Invalid(format!("invalid P2WPKH public key: {error}"));
        }
    };
    let witness_pubkey = match secp256k1_zkp::PublicKey::from_slice(witness_pubkey_bytes) {
        Ok(value) => value,
        Err(error) => {
            return WitnessResult::Invalid(format!("invalid P2WPKH public key: {error}"));
        }
    };
    let decoded = match decoded_funding_input(input) {
        Ok(value) => value,
        Err(error) => return WitnessResult::Invalid(error),
    };
    let witness_program = match p2wpkh_program(
        input,
        &decoded.previous_output.script_pubkey,
        &witness_bitcoin_pubkey,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return WitnessResult::Unsupported(format!(
                "unsupported offer funding script for {}",
                decoded.outpoint
            ));
        }
        Err(error) => return WitnessResult::Invalid(error),
    };
    let sighash = match SighashCache::new(fund_transaction).p2wpkh_signature_hash(
        input_index,
        &witness_program,
        decoded.previous_output.value,
        EcdsaSighashType::All,
    ) {
        Ok(value) => value,
        Err(error) => {
            return WitnessResult::Invalid(format!("P2WPKH sighash failed: {error}"));
        }
    };
    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    if secp
        .verify_ecdsa(&message, &parsed_signature, &witness_pubkey)
        .is_ok()
    {
        WitnessResult::Valid
    } else {
        WitnessResult::Invalid("P2WPKH funding signature verification failed".to_owned())
    }
}

fn verify_funding_witnesses(
    offer: &OfferDlc,
    sign: Option<&SignDlc>,
    reconstruction: &Reconstruction,
) -> FundingWitnessChecks {
    let Some(sign) = sign else {
        return FundingWitnessChecks {
            valid: None,
            valid_count: 0,
            total_count: 0,
            error: None,
            incomplete: Vec::new(),
        };
    };
    let signatures = &sign.funding_signatures.funding_signatures;
    if signatures.len() > MAX_CONTRACT_ITEMS || signatures.len() != offer.funding_inputs.len() {
        return FundingWitnessChecks {
            valid: Some(false),
            valid_count: 0,
            total_count: signatures.len(),
            error: Some(format!(
                "Sign funding signature count {} does not match offer input count {}",
                signatures.len(),
                offer.funding_inputs.len()
            )),
            incomplete: Vec::new(),
        };
    }

    let mut valid_count = 0;
    let mut invalid = Vec::new();
    let mut incomplete = Vec::new();
    for (position, (input, signature)) in offer
        .funding_inputs
        .iter()
        .zip(signatures.iter())
        .enumerate()
    {
        let decoded = match decoded_funding_input(input) {
            Ok(value) => value,
            Err(error) => {
                invalid.push(format!("offer funding input {position}: {error}"));
                continue;
            }
        };
        let Some(input_index) = reconstruction
            .transactions
            .fund
            .input
            .iter()
            .position(|tx_input| tx_input.previous_output == decoded.outpoint)
        else {
            invalid.push(format!(
                "offer funding input {position} is absent from reconstructed transaction"
            ));
            continue;
        };
        let result = if input.dlc_input.is_some() {
            verify_dlc_input_witness(
                input,
                signature,
                &reconstruction.transactions.fund,
                input_index,
            )
        } else {
            verify_p2wpkh_witness(
                input,
                signature,
                &reconstruction.transactions.fund,
                input_index,
            )
        };
        match result {
            WitnessResult::Valid => valid_count += 1,
            WitnessResult::Invalid(error) => {
                invalid.push(format!("offer funding input {position}: {error}"));
            }
            WitnessResult::Unsupported(error) => incomplete.push(error),
        }
    }
    FundingWitnessChecks {
        valid: if invalid.is_empty() {
            if incomplete.is_empty() {
                Some(true)
            } else {
                None
            }
        } else {
            Some(false)
        },
        valid_count,
        total_count: signatures.len(),
        error: (!invalid.is_empty()).then(|| invalid.join("; ")),
        incomplete,
    }
}

/// Rebuilds the DLC and checks its signatures under the DDK 2.0 fee rule,
/// falling back to the DDK 1.x rule when only that one matches the accepter's
/// adaptor signatures. Nothing on the wire says which rule a contract used.
pub(crate) fn reconstruct_and_verify(
    offer: &OfferDlc,
    accept: &AcceptDlc,
    sign: Option<&SignDlc>,
    descriptor: &EnumeratedContractDescriptor,
    announcement: &OracleAnnouncement,
    rendering_network: Network,
) -> Result<(Reconstruction, SignatureChecks), String> {
    let attempt = |fee_rule| {
        let reconstruction = reconstruct(offer, accept, descriptor, rendering_network, fee_rule)?;
        let checks = verify_signatures(
            offer,
            accept,
            sign,
            descriptor,
            announcement,
            &reconstruction,
        );
        Ok::<_, String>((reconstruction, checks))
    };
    let current = attempt(FeeRule::CounterpartyPayout);
    if matches!(&current, Ok((_, checks)) if checks.accept_adaptor_valid) {
        return current;
    }
    match attempt(FeeRule::OwnPayoutOnly) {
        Ok(legacy) if legacy.1.accept_adaptor_valid || current.is_err() => Ok(legacy),
        _ => current,
    }
}

fn verify_signatures(
    offer: &OfferDlc,
    accept: &AcceptDlc,
    sign: Option<&SignDlc>,
    descriptor: &EnumeratedContractDescriptor,
    announcement: &OracleAnnouncement,
    reconstruction: &Reconstruction,
) -> SignatureChecks {
    let accept_signatures = &accept.cet_adaptor_signatures.ecdsa_adaptor_signatures;
    let (accept_adaptor_valid, accept_adaptor_valid_count, accept_adaptor_total_count) =
        verify_adaptors(
            accept_signatures,
            &accept.funding_pubkey,
            descriptor,
            announcement,
            reconstruction,
        );
    let accept_refund_valid = verify_refund_signature(
        &accept.refund_signature,
        &accept.funding_pubkey,
        reconstruction,
    );

    let sign_protocol_valid =
        sign.map(|value| value.protocol_version == SUPPORTED_PROTOCOL_VERSION);
    let (sign_adaptor_valid, sign_adaptor_valid_count, sign_adaptor_total_count) =
        sign.map_or((None, 0, 0), |sign| {
            if sign.protocol_version != SUPPORTED_PROTOCOL_VERSION {
                return (
                    Some(false),
                    0,
                    sign.cet_adaptor_signatures.ecdsa_adaptor_signatures.len(),
                );
            }
            let (valid, count, total) = verify_adaptors(
                &sign.cet_adaptor_signatures.ecdsa_adaptor_signatures,
                &offer.funding_pubkey,
                descriptor,
                announcement,
                reconstruction,
            );
            (Some(valid), count, total)
        });
    let sign_refund_valid = sign.map(|value| {
        value.protocol_version == SUPPORTED_PROTOCOL_VERSION
            && verify_refund_signature(
                &value.refund_signature,
                &offer.funding_pubkey,
                reconstruction,
            )
    });
    let sign_contract_id_matches = sign.map(|value| {
        value.protocol_version == SUPPORTED_PROTOCOL_VERSION
            && value.contract_id == reconstruction.contract_id
    });
    let mut sign_funding_witnesses = verify_funding_witnesses(offer, sign, reconstruction);
    if sign_protocol_valid == Some(false) {
        sign_funding_witnesses.valid = Some(false);
        sign_funding_witnesses.error = Some("unsupported Sign protocol version".to_owned());
    }

    SignatureChecks {
        accept_adaptor_valid,
        accept_adaptor_valid_count,
        accept_adaptor_total_count,
        accept_refund_valid,
        sign_protocol_valid,
        sign_adaptor_valid,
        sign_adaptor_valid_count,
        sign_adaptor_total_count,
        sign_refund_valid,
        sign_contract_id_matches,
        sign_funding_witnesses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddk_messages::{
        contract_msgs::{ContractDescriptor, ContractInfo},
        oracle_msgs::OracleInfo,
    };
    use lightning::{io::Cursor, util::ser::Readable};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        offer: String,
        accept: String,
        #[serde(default)]
        sign: Option<String>,
    }

    fn read_message<T: Readable>(hex_value: &str) -> Result<T, String> {
        let bytes = hex::decode(hex_value).map_err(|error| error.to_string())?;
        let mut cursor = Cursor::new(&bytes);
        let value = T::read(&mut cursor).map_err(|error| format!("{error:?}"))?;
        if cursor.position() != bytes.len() as u64 {
            return Err("message has trailing bytes".to_owned());
        }
        Ok(value)
    }

    fn fixture(value: &str) -> Result<(OfferDlc, AcceptDlc, Option<SignDlc>), String> {
        let fixture: Fixture = serde_json::from_str(value).map_err(|error| error.to_string())?;
        Ok((
            read_message(&fixture.offer)?,
            read_message(&fixture.accept)?,
            fixture.sign.as_deref().map(read_message).transpose()?,
        ))
    }

    fn descriptor_and_announcement(
        offer: &OfferDlc,
    ) -> Result<(&EnumeratedContractDescriptor, &OracleAnnouncement), String> {
        let ContractInfo::SingleContractInfo(single) = &offer.contract_info else {
            return Err("fixture is not a single contract".to_owned());
        };
        let ContractDescriptor::EnumeratedContractDescriptor(descriptor) =
            &single.contract_info.contract_descriptor
        else {
            return Err("fixture is not enumerated".to_owned());
        };
        let OracleInfo::Single(oracle) = &single.contract_info.oracle_info else {
            return Err("fixture does not use one oracle".to_owned());
        };
        Ok((descriptor, &oracle.oracle_announcement))
    }

    #[test]
    fn sample_reconstruction_matches_expected_transactions() -> Result<(), String> {
        let (offer, accept, sign) = fixture(include_str!("../tests/fixtures/sample.json"))?;
        let (descriptor, announcement) = descriptor_and_announcement(&offer)?;
        let reconstructed = reconstruct(
            &offer,
            &accept,
            descriptor,
            Network::Bitcoin,
            FeeRule::OwnPayoutOnly,
        )?;
        let checks = verify_signatures(
            &offer,
            &accept,
            sign.as_ref(),
            descriptor,
            announcement,
            &reconstructed,
        );
        assert_eq!(
            reconstructed.transactions.fund.compute_txid().to_string(),
            "fdc7dfe8e53f8fb66c40c74bc717ea1d4ed9b8c546bbdbdf2e844ecb894620dc"
        );
        assert_eq!(
            reconstructed.transactions.refund.compute_txid().to_string(),
            "5ccfca200a6e1f79a96aa525e9adc84544406281d438823e373b914b388a5963"
        );
        assert_eq!(
            hex::encode(reconstructed.contract_id),
            "882f2ffd2fb8cdfa3395daef064c42f9d3df9e03089c227a73880c62cbc301b7"
        );
        assert_eq!(
            reconstructed
                .transactions
                .cets
                .iter()
                .map(|transaction| transaction.compute_txid().to_string())
                .collect::<Vec<_>>(),
            [
                "153e588e053eb7636aad5e3dfffbc8cecbeb5ed515da67f30a837d13aac5ff21",
                "153e588e053eb7636aad5e3dfffbc8cecbeb5ed515da67f30a837d13aac5ff21",
                "e5f2c35345b5a59ac6c29145ba4bca64071b3db2efc4a81235e71e09497e7b79",
                "e5f2c35345b5a59ac6c29145ba4bca64071b3db2efc4a81235e71e09497e7b79",
            ]
        );
        assert!(checks.accept_adaptor_valid);
        assert!(checks.accept_refund_valid);
        Ok(())
    }

    #[test]
    fn signed_splice_reconstruction_and_signatures_are_valid() -> Result<(), String> {
        let (offer, accept, sign) =
            fixture(include_str!("../tests/fixtures/testnet-loan-118c9fc9.json"))?;
        let (descriptor, announcement) = descriptor_and_announcement(&offer)?;
        let reconstructed = reconstruct(
            &offer,
            &accept,
            descriptor,
            Network::Testnet,
            FeeRule::OwnPayoutOnly,
        )?;
        let checks = verify_signatures(
            &offer,
            &accept,
            sign.as_ref(),
            descriptor,
            announcement,
            &reconstructed,
        );
        assert_eq!(
            reconstructed.transactions.fund.compute_txid().to_string(),
            "6d25bbc76f22fbe298a7348c9794266bc8def89895a3de0c32ce6eb67e8f5536"
        );
        assert_eq!(
            reconstructed.transactions.refund.compute_txid().to_string(),
            "24cec8b66af24de7e49ed50d099a414210ac2b35943ef55b0c3756ab32ded113"
        );
        assert_eq!(
            hex::encode(reconstructed.contract_id),
            "3ef02af266fcbc17f6bc7eddeb33166f0bc093cbc5b83b09b12969471db3314f"
        );
        assert_eq!(
            reconstructed
                .transactions
                .cets
                .iter()
                .map(|transaction| transaction.compute_txid().to_string())
                .collect::<Vec<_>>(),
            [
                "d939804579d246366677a9f420a9992a10aa4265c200541d3b57987fce09c944",
                "d939804579d246366677a9f420a9992a10aa4265c200541d3b57987fce09c944",
                "b7574910f8f091be828a3d6b9e9f0d02a4a7a64bded9fe90adc1e1c2116ae14c",
                "b7574910f8f091be828a3d6b9e9f0d02a4a7a64bded9fe90adc1e1c2116ae14c",
                "b7574910f8f091be828a3d6b9e9f0d02a4a7a64bded9fe90adc1e1c2116ae14c",
            ]
        );
        assert!(checks.accept_adaptor_valid);
        assert!(checks.accept_refund_valid);
        assert_eq!(checks.sign_protocol_valid, Some(true));
        assert_eq!(checks.sign_adaptor_valid, Some(true));
        assert_eq!(checks.sign_refund_valid, Some(true));
        assert_eq!(checks.sign_contract_id_matches, Some(true));
        assert_eq!(checks.sign_funding_witnesses.valid, Some(true));
        assert_eq!(checks.sign_funding_witnesses.valid_count, 2);
        Ok(())
    }

    #[test]
    fn malformed_serials_and_funding_witnesses_fail_closed() -> Result<(), String> {
        let (offer, mut accept, _sign) =
            fixture(include_str!("../tests/fixtures/testnet-loan-118c9fc9.json"))?;
        let (descriptor, _) = descriptor_and_announcement(&offer)?;
        accept.change_serial_id = offer.fund_output_serial_id;
        let serial_error = reconstruct(
            &offer,
            &accept,
            descriptor,
            Network::Testnet,
            FeeRule::OwnPayoutOnly,
        )
        .err()
        .ok_or_else(|| "duplicate serial ID was accepted".to_owned())?;
        assert!(serial_error.contains("duplicate funding output serial ID"));

        let (offer, accept, mut sign) =
            fixture(include_str!("../tests/fixtures/testnet-loan-118c9fc9.json"))?;
        let (descriptor, announcement) = descriptor_and_announcement(&offer)?;
        let reconstructed = reconstruct(
            &offer,
            &accept,
            descriptor,
            Network::Testnet,
            FeeRule::OwnPayoutOnly,
        )?;
        let sign = sign
            .as_mut()
            .ok_or_else(|| "signed fixture has no Sign message".to_owned())?;
        let signature = sign
            .funding_signatures
            .funding_signatures
            .get_mut(0)
            .and_then(|signature| signature.witness_elements.get_mut(0))
            .ok_or_else(|| "signed fixture has no first funding witness".to_owned())?;
        let first_byte = signature
            .witness
            .first_mut()
            .ok_or_else(|| "signed fixture has an empty funding signature".to_owned())?;
        *first_byte ^= 1;
        let checks = verify_signatures(
            &offer,
            &accept,
            Some(sign),
            descriptor,
            announcement,
            &reconstructed,
        );
        assert_eq!(checks.sign_funding_witnesses.valid, Some(false));
        assert_eq!(checks.sign_funding_witnesses.valid_count, 1);
        assert!(checks.sign_funding_witnesses.error.is_some());
        Ok(())
    }
}
