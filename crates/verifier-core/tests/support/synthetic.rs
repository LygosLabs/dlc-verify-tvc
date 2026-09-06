//! TEST ONLY. Every secret key is deliberately public. Never fund these keys.
//! Re-signs the existing PUBLIC message template with independent synthetic keys,
//! synthetic previous transactions, and a known event preimage.
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, absolute::LockTime, hashes::Hash as _,
    sighash::SighashCache, transaction::Version,
};
use ddk_dlc::{PartyParams, Payout, TxInputInfo};
use ddk_messages::{
    AcceptDlc, CetAdaptorSignature, CetAdaptorSignatures, FundingInput, FundingSignature,
    FundingSignatures, OfferDlc, SignDlc, WitnessElement,
    contract_msgs::{ContractDescriptor, ContractInfo},
    oracle_msgs::{OracleInfo, tagged_announcement_msg, tagged_attestation_msg},
};
use lightning::{
    io::Cursor,
    util::ser::{Readable, Writeable},
};
use secp256k1_zkp::{EcdsaAdaptorSignature, Keypair, Message, PublicKey, Secp256k1, SecretKey};
use verifier_schema::OracleEventPreimage;
pub struct DlcTermsWitnessV1 {
    pub offer_hex: String,
    pub accept_hex: String,
    pub sign_hex: String,
    pub policy: DlcVerificationPolicy,
}

use verifier_schema::{
    DlcPartyRole, DlcVerificationPolicy, ExpectedLenderOutcome, PolicyNetwork,
    PolicyOracleEventExpectation,
};
type E = Box<dyn std::error::Error>;
fn decode<T: Readable>(s: &str) -> Result<T, E> {
    let bytes = hex::decode(s)?;
    let mut c = Cursor::new(bytes.as_slice());
    let value = T::read(&mut c).map_err(|e| format!("public fixture parse failed: {e:?}"))?;
    if c.position() != bytes.len() as u64 {
        return Err("trailing fixture bytes".into());
    }
    Ok(value)
}
fn encoded<T: Writeable>(v: &T) -> Result<String, E> {
    let mut bytes = Vec::new();
    v.write(&mut bytes)?;
    Ok(hex::encode(bytes))
}
fn input(spk: &ScriptBuf, id: u64) -> FundingInput {
    let prev = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(id as u32),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![1, 1]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: spk.clone(),
        }],
    };
    FundingInput {
        input_serial_id: id,
        prev_tx: bitcoin::consensus::serialize(&prev),
        prev_tx_vout: 0,
        sequence: u32::MAX,
        max_witness_len: 108,
        redeem_script: ScriptBuf::new(),
        dlc_input: None,
    }
}
fn params(
    key: PublicKey,
    spk: &ScriptBuf,
    change_id: u64,
    payout_id: u64,
    inputs: &[FundingInput],
    collateral: Amount,
) -> PartyParams {
    PartyParams {
        fund_pubkey: key,
        change_script_pubkey: spk.clone(),
        change_serial_id: change_id,
        payout_script_pubkey: spk.clone(),
        payout_serial_id: payout_id,
        inputs: inputs.iter().map(TxInputInfo::from).collect(),
        dlc_inputs: vec![],
        input_amount: Amount::from_sat(200_000),
        collateral,
    }
}
/// A synthetic five-outcome loan with fresh complete signatures and known preimage.
pub fn synthetic(flags: u8) -> Result<DlcTermsWitnessV1, E> {
    if flags > 1 {
        return Err("fixture supports only flags 0 and 1".into());
    }
    let template: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/testnet-loan-118c9fc9.json"))?;
    let mut offer: OfferDlc = decode(template["offer"].as_str().ok_or("offer missing")?)?;
    let mut accept: AcceptDlc = decode(template["accept"].as_str().ok_or("accept missing")?)?;
    let mut sign: SignDlc = decode(template["sign"].as_str().ok_or("sign missing")?)?;
    let secp = Secp256k1::new();
    let offer_sk = SecretKey::from_slice(&[11; 32])?;
    let accept_sk = SecretKey::from_slice(&[12; 32])?;
    let oracle_sk = SecretKey::from_slice(&[13; 32])?;
    let nonce_sk = SecretKey::from_slice(&[14; 32])?;
    let offer_pk = PublicKey::from_secret_key(&secp, &offer_sk);
    let accept_pk = PublicKey::from_secret_key(&secp, &accept_sk);
    let oracle_kp = Keypair::from_secret_key(&secp, &oracle_sk);
    let oracle_pk = oracle_kp.x_only_public_key().0;
    let nonce_pk = PublicKey::from_secret_key(&secp, &nonce_sk)
        .x_only_public_key()
        .0;
    let offer_spk =
        Address::p2wpkh(&CompressedPublicKey(offer_pk), Network::Regtest).script_pubkey();
    let accept_spk =
        Address::p2wpkh(&CompressedPublicKey(accept_pk), Network::Regtest).script_pubkey();
    let preimage = OracleEventPreimage {
        event_type: "loan-matured".into(),
        loan_id: format!("synthetic-zk-loan-flags-{flags}"),
        repayment_address: "0x0000000000000000000000000000000000000001".into(),
        repayment_amount: "100.00".into(),
    };
    let event_id = verifier_policy::derive_lygos_oracle_event_id(&preimage);
    offer.protocol_version = 1;
    offer.contract_flags = flags;
    offer.chain_hash = bitcoin::blockdata::constants::genesis_block(Network::Regtest)
        .block_hash()
        .to_byte_array();
    offer.temporary_contract_id = [0x42; 32];
    offer.funding_pubkey = offer_pk;
    offer.payout_spk = offer_spk.clone();
    offer.change_spk = offer_spk.clone();
    offer.payout_serial_id = 20;
    offer.change_serial_id = 10;
    offer.fund_output_serial_id = 30;
    offer.offer_collateral = Amount::from_sat(50_000);
    offer.fee_rate_per_vb = 2;
    offer.funding_inputs = vec![input(&offer_spk, 1)];
    offer.cet_locktime = 1_769_702_735;
    offer.refund_locktime = 1_779_724_800;
    accept.protocol_version = 1;
    accept.temporary_contract_id = offer.temporary_contract_id;
    accept.funding_pubkey = accept_pk;
    accept.payout_spk = accept_spk.clone();
    accept.change_spk = accept_spk.clone();
    accept.payout_serial_id = 21;
    accept.change_serial_id = 11;
    accept.accept_collateral = Amount::from_sat(50_000);
    accept.funding_inputs = vec![input(&accept_spk, 2)];
    accept.negotiation_fields = None;
    let (descriptor, announcement) = {
        let ContractInfo::SingleContractInfo(single) = &mut offer.contract_info else {
            return Err("not single".into());
        };
        single.total_collateral = Amount::from_sat(100_000);
        let ContractDescriptor::EnumeratedContractDescriptor(d) =
            &mut single.contract_info.contract_descriptor
        else {
            return Err("not enumerated".into());
        };
        for (i, p) in d.payouts.iter_mut().enumerate() {
            p.offer_payout = Amount::from_sat(if i % 2 == 0 { 100_000 } else { 0 });
        }
        let OracleInfo::Single(oracle) = &mut single.contract_info.oracle_info else {
            return Err("not one oracle".into());
        };
        let a = &mut oracle.oracle_announcement;
        a.oracle_public_key = oracle_pk;
        a.oracle_event.oracle_nonces = vec![nonce_pk];
        a.oracle_event.event_id = event_id.clone();
        a.oracle_event.event_maturity_epoch = offer.cet_locktime;
        a.announcement_signature =
            secp.sign_schnorr_no_aux_rand(&tagged_announcement_msg(&a.oracle_event), &oracle_kp);
        (d.clone(), a.clone())
    };
    let payouts: Vec<Payout> = descriptor
        .payouts
        .iter()
        .map(|p| Payout {
            offer: p.offer_payout,
            accept: Amount::from_sat(100_000 - p.offer_payout.to_sat()),
        })
        .collect();
    let txs = ddk_dlc::create_dlc_transactions(
        &params(
            offer_pk,
            &offer_spk,
            10,
            20,
            &offer.funding_inputs,
            offer.offer_collateral,
        ),
        &params(
            accept_pk,
            &accept_spk,
            11,
            21,
            &accept.funding_inputs,
            accept.accept_collateral,
        ),
        &payouts,
        offer.refund_locktime,
        offer.fee_rate_per_vb,
        0,
        offer.cet_locktime,
        30,
        flags,
    )?;
    let (vout, output) = txs
        .fund
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == txs.funding_script_pubkey.to_p2wsh())
        .ok_or("funding output missing")?;
    let funding_value = output.value;
    let oracle_infos = [ddk_dlc::OracleInfo::from(&announcement)];
    let signatures = |sk: &SecretKey| -> Result<CetAdaptorSignatures, E> {
        let mut values = Vec::new();
        for (tx, outcome) in txs.cets.iter().zip(descriptor.payouts.iter()) {
            let messages = [vec![tagged_attestation_msg(&outcome.outcome)]];
            let point =
                ddk_dlc::get_adaptor_point_from_oracle_info(&secp, &oracle_infos, &messages)?;
            let msg =
                ddk_dlc::util::get_sig_hash_msg(tx, 0, &txs.funding_script_pubkey, funding_value)?;
            values.push(CetAdaptorSignature {
                signature: EcdsaAdaptorSignature::encrypt_no_aux_rand(&secp, &msg, sk, &point),
            });
        }
        Ok(CetAdaptorSignatures {
            ecdsa_adaptor_signatures: values,
        })
    };
    accept.cet_adaptor_signatures = signatures(&accept_sk)?;
    sign.cet_adaptor_signatures = signatures(&offer_sk)?;
    let refund_msg =
        ddk_dlc::util::get_sig_hash_msg(&txs.refund, 0, &txs.funding_script_pubkey, funding_value)?;
    accept.refund_signature = secp.sign_ecdsa(&refund_msg, &accept_sk);
    sign.refund_signature = secp.sign_ecdsa(&refund_msg, &offer_sk);
    sign.protocol_version = 1;
    let display_txid = hex::decode(txs.fund.compute_txid().to_string())?;
    let mut contract_id = offer.temporary_contract_id;
    for (a, b) in contract_id.iter_mut().zip(display_txid) {
        *a ^= b;
    }
    let index = u16::try_from(vout)?.to_be_bytes();
    contract_id[30] ^= index[0];
    contract_id[31] ^= index[1];
    sign.contract_id = contract_id;
    let hash = SighashCache::new(&txs.fund).p2wpkh_signature_hash(
        0,
        &offer_spk,
        Amount::from_sat(200_000),
        EcdsaSighashType::All,
    )?;
    let sig = secp.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &offer_sk);
    let mut der = sig.serialize_der().to_vec();
    der.push(1);
    sign.funding_signatures = FundingSignatures {
        funding_signatures: vec![FundingSignature {
            witness_elements: vec![
                WitnessElement { witness: der },
                WitnessElement {
                    witness: offer_pk.serialize().to_vec(),
                },
            ],
        }],
    };
    let policy = DlcVerificationPolicy {
        lender_role: Some(DlcPartyRole::Accepter),
        network: Some(PolicyNetwork::Regtest),
        expected_oracle_pubkey: Some(oracle_pk.to_string()),
        expected_lender_funding_pubkey: Some(accept_pk.to_string()),
        expected_lender_payout_address: Some(
            Address::p2wpkh(&CompressedPublicKey(accept_pk), Network::Regtest).to_string(),
        ),
        expected_total_collateral_sats: Some("100000".into()),
        oracle_event: Some(PolicyOracleEventExpectation {
            expected_event_id: Some(event_id),
            event_id_preimage: Some(preimage.clone()),
        }),
        expected_cet_locktime: Some(offer.cet_locktime),
        expected_refund_locktime: Some(offer.refund_locktime),
        expected_lender_outcomes: Some(
            descriptor
                .payouts
                .iter()
                .map(|p| ExpectedLenderOutcome {
                    outcome: p.outcome.clone(),
                    lender_payout_sats: (100_000 - p.offer_payout.to_sat()).to_string(),
                })
                .collect(),
        ),
    };
    Ok(DlcTermsWitnessV1 {
        offer_hex: encoded(&offer)?,
        accept_hex: encoded(&accept)?,
        sign_hex: encoded(&sign)?,
        policy,
    })
}
