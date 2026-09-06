//! Refund-mode compatibility using fresh signatures and public test keys only.
#[path = "support/synthetic.rs"]
mod synthetic;
use ddk_messages::{AcceptDlc, SignDlc};
use lightning::{
    io::Cursor,
    util::ser::{Readable, Writeable},
};
use verifier_schema::{DlcPartyRole, VerificationStatus};
type E = Box<dyn std::error::Error>;
fn verify(w: &synthetic::DlcTermsWitnessV1) -> verifier_schema::DlcVerifyResult {
    verifier_core::verify_dlc_compatibility(
        &w.offer_hex,
        &w.accept_hex,
        Some(&w.sign_hex),
        None,
        Some("regtest"),
    )
}
fn decode<T: Readable>(s: &str) -> Result<T, E> {
    let b = hex::decode(s)?;
    T::read(&mut Cursor::new(&b)).map_err(|e| format!("{e:?}").into())
}
fn encode<T: Writeable>(v: &T) -> Result<String, E> {
    let mut b = Vec::new();
    v.write(&mut b)?;
    Ok(hex::encode(b))
}
#[test]
fn both_signed_modes_pass_with_their_exact_refund_outputs() -> Result<(), E> {
    for flag in [0, 1] {
        let w = synthetic::synthetic(flag)?;
        let v = verify(&w);
        assert_eq!(v.verification_status, VerificationStatus::Pass);
        assert!(v.verification_failures.is_empty());
        assert!(v.verification_incomplete.is_empty());
        assert_eq!(v.refund_sig_valid, Some(true));
        assert_eq!(v.sign_refund_sig_valid, Some(true));
        assert_eq!(v.sign_adaptor_valid, Some(true));
        assert_eq!(v.adaptor_valid, Some(true));
        assert_eq!(v.sign_contract_id_matches, Some(true));
        assert_eq!(v.refund_outputs.len(), if flag == 1 { 1 } else { 2 });
        for o in &v.refund_outputs {
            assert_eq!(o.sats, if flag == 1 { "100000" } else { "50000" });
            if flag == 1 {
                assert_eq!(o.address, v.accepter_payout_address);
            }
        }
        assert_eq!(
            verifier_policy::evaluate_dlc_policy(&v, Some(&w.policy))?.verdict,
            VerificationStatus::Pass
        );
    }
    Ok(())
}
#[test]
fn every_unknown_flag_bit_is_rejected() -> Result<(), E> {
    let mut w = synthetic::synthetic(1)?;
    for flags in 2..=255 {
        let mut b = hex::decode(&w.offer_hex)?;
        b[6] = flags;
        w.offer_hex = hex::encode(b);
        let v = verify(&w);
        assert_eq!(v.verification_status, VerificationStatus::Fail);
        assert!(serde_json::to_string(&v)?.contains("unsupported contract flags"));
    }
    Ok(())
}
#[test]
fn switching_either_signed_mode_without_resigning_fails_both_refund_signatures() -> Result<(), E> {
    for flags in [0, 1] {
        let mut w = synthetic::synthetic(flags)?;
        let mut b = hex::decode(&w.offer_hex)?;
        b[6] ^= 1;
        w.offer_hex = hex::encode(b);
        let v = verify(&w);
        assert_eq!(v.verification_status, VerificationStatus::Fail);
        assert_eq!(v.refund_sig_valid, Some(false));
        assert_eq!(v.sign_refund_sig_valid, Some(false));
    }
    Ok(())
}
#[test]
fn each_refund_signature_is_required_in_flag_one() -> Result<(), E> {
    let mut w = synthetic::synthetic(1)?;
    let mut a: AcceptDlc = decode(&w.accept_hex)?;
    let mut s: SignDlc = decode(&w.sign_hex)?;
    let original = w.accept_hex.clone();
    a.refund_signature = s.refund_signature;
    w.accept_hex = encode(&a)?;
    assert_eq!(verify(&w).refund_sig_valid, Some(false));
    w.accept_hex = original;
    a = decode(&w.accept_hex)?;
    s.refund_signature = a.refund_signature;
    w.sign_hex = encode(&s)?;
    assert_eq!(verify(&w).sign_refund_sig_valid, Some(false));
    Ok(())
}
#[test]
fn refund_policy_still_rejects_an_offerer_lender() -> Result<(), E> {
    let mut w = synthetic::synthetic(1)?;
    let v = verify(&w);
    w.policy.lender_role = Some(DlcPartyRole::Offerer);
    w.policy.expected_lender_funding_pubkey = v.offerer_funding_pubkey.clone();
    w.policy.expected_lender_payout_address = v.offerer_payout_address.clone();
    if let Some(outcomes) = &mut w.policy.expected_lender_outcomes {
        for outcome in outcomes {
            outcome.lender_payout_sats =
                (100_000 - outcome.lender_payout_sats.parse::<u64>()?).to_string();
        }
    }
    let result = verifier_policy::evaluate_dlc_policy(&v, Some(&w.policy))?;
    assert_eq!(result.verdict, VerificationStatus::Fail);
    let refund = result
        .checks
        .iter()
        .find(|check| check.id == "refund-pays-lender-address")
        .ok_or("refund policy check missing")?;
    assert_eq!(refund.status, verifier_schema::PolicyCheckStatus::Fail);
    assert_eq!(
        result
            .checks
            .iter()
            .filter(|check| check.status == verifier_schema::PolicyCheckStatus::Fail)
            .count(),
        1
    );
    Ok(())
}
