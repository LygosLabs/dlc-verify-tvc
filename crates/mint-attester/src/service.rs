//! The attest endpoint: DLC transcript, Midnight policy, lock proof, signed receipt.

use crate::{
    midnight::{self, REFUND_GAP_SECS, Terms},
    receipt::{Domain, Receipt, sign_digest},
    spv::{Lock, LockProof, verify_lock},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bitcoin::absolute::LOCK_TIME_THRESHOLD;
use bitcoin::{
    Network, ScriptBuf, Txid,
    consensus::encode::deserialize_hex,
    hashes::Hash,
    secp256k1::{PublicKey, XOnlyPublicKey},
};
use p256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tower_http::timeout::TimeoutLayer;
use verifier_core::{OfferAnnouncement, offer_announcement, verify_dlc_compatibility};
use verifier_schema::{DlcVerifyResult, VerificationStatus};

/// What the enclave pins. All of it comes from launch arguments the QOS manifest measures, except
/// the key, which QOS provisions.
pub struct Config {
    /// Bitcoin network the locks are on.
    pub network: Network,
    /// The Midnight Lygos funding key.
    pub lygos_funding_pubkey: PublicKey,
    /// The Midnight oracle's key. Typed so an empty pin, which verifier-core reads as "no
    /// expected oracle", cannot be constructed.
    pub oracle_pubkey: XOnlyPublicKey,
    /// The quorum signing key the `Verifier` contract trusts.
    pub key: SigningKey,
    /// Sign receipts for a network whose proof of work is free to forge. Test deployments only.
    pub allow_insecure_network: bool,
    /// Fewest headers that must confirm the funding block before a receipt is signed. The SPV
    /// check proves work, not membership in the real chain, so this is the enclave's own floor on
    /// how much work a forged lock costs; the `Verifier` contract may require more.
    pub min_confirmations: u32,
}

/// Body of `POST /v1/attest`. Hex throughout; EVM values may carry a `0x` prefix.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestRequest {
    /// DLC offer message.
    pub offer: String,
    /// DLC accept message.
    pub accept: String,
    /// DLC sign message.
    pub sign: String,
    /// The confirmed funding transaction.
    pub tx: String,
    /// Position of `tx` in its block.
    pub tx_index: u32,
    /// Merkle siblings from leaf to root, as block explorers print them (reversed byte order).
    pub merkle_branch: Vec<String>,
    /// The 80-byte header of the funding block, then each confirming header, in chain order.
    pub headers: Vec<String>,
    /// `abi.encode(Market)` of the Midnight market.
    pub market: String,
    /// EVM chain id of the Originator.
    pub chain_id: u64,
    /// Originator address.
    pub originator: String,
    /// The borrower's EVM key.
    pub controller: String,
    /// Mint deadline from the announcement request; 0 on a successor.
    pub mint_deadline: u64,
    /// Timestamp of the block the oracle froze the liquidator set at.
    pub announced_at: u64,
    /// `Verifier` address the receipt is signed for.
    pub verifier: String,
}

/// The request's EVM-side terms, decoded.
#[derive(Clone, Debug)]
pub struct LoanTerms {
    /// `abi.encode(Market)`.
    pub market: Vec<u8>,
    /// EVM chain id of the Originator.
    pub chain_id: u64,
    /// Originator address.
    pub originator: [u8; 20],
    /// The borrower's EVM key.
    pub controller: [u8; 20],
    /// Mint deadline; 0 on a successor.
    pub mint_deadline: u64,
    /// Timestamp of the block the oracle froze the liquidator set at.
    pub announced_at: u64,
}

/// Check a request end to end and return the signed receipt as JSON.
///
/// # Errors
///
/// Returns why the request was refused.
pub fn attest(config: &Config, request: &AttestRequest) -> Result<Value, String> {
    let terms = LoanTerms {
        market: bytes("market", &request.market)?,
        chain_id: request.chain_id,
        originator: fixed("originator", &request.originator)?,
        controller: fixed("controller", &request.controller)?,
        mint_deadline: request.mint_deadline,
        announced_at: request.announced_at,
    };
    let verifier = fixed("verifier", &request.verifier)?;

    // The cheap parse first: reconstruction allocates per outcome, and a Midnight list is a
    // handful of entries, so an oversized one is refused before any signature work.
    let announcement = offer_announcement(&request.offer).map_err(|error| error.to_string())?;
    if announcement.outcomes.len() > MAX_OUTCOMES {
        return Err(format!("more than {MAX_OUTCOMES} outcomes"));
    }
    let dlc = verify_dlc_compatibility(
        &request.offer,
        &request.accept,
        Some(&request.sign),
        Some(&config.oracle_pubkey.to_string()),
        Some(network_name(config.network)),
    );

    let proof = LockProof {
        tx: deserialize_hex(&request.tx).map_err(|error| format!("invalid tx: {error}"))?,
        vout: dlc
            .fund_output_index
            .and_then(|index| u32::try_from(index).ok())
            .ok_or("the DLC has no funding output")?,
        tx_index: request.tx_index,
        merkle_branch: request
            .merkle_branch
            .iter()
            .map(|node| {
                let mut node: [u8; 32] = fixed("merkleBranch", node)?;
                node.reverse();
                Ok(node)
            })
            .collect::<Result<_, String>>()?,
        headers: request
            .headers
            .iter()
            .map(|header| {
                deserialize_hex(header).map_err(|error| format!("invalid header: {error}"))
            })
            .collect::<Result<_, _>>()?,
    };
    let lock = verify_lock(config.network, &proof)
        .map_err(|error| format!("lock proof refused: {error}"))?;

    let receipt = receipt_for(config, &dlc, &announcement, &lock, &terms)?;
    let digest = receipt.digest(&Domain {
        chain_id: receipt.chain_id,
        verifier,
    });
    let signature =
        sign_digest(&config.key, &digest).map_err(|error| format!("signing failed: {error}"))?;
    let hex0x = |value: &[u8]| format!("0x{}", hex::encode(value));
    Ok(json!({
        "claimId": hex0x(&receipt.claim_id),
        "termsHash": hex0x(&receipt.terms_hash),
        "eventId": hex0x(&receipt.event_id),
        "marketId": hex0x(&receipt.market_id),
        "controller": hex0x(&receipt.controller),
        "sats": receipt.sats,
        "confirmations": receipt.confirmations,
        "announcedAt": receipt.announced_at,
        "expiresAt": receipt.expires_at,
        "inputClaimIds": receipt.input_claim_ids.iter().map(|id| hex0x(id)).collect::<Vec<_>>(),
        "chainId": receipt.chain_id,
        "originator": hex0x(&receipt.originator),
        "verifier": hex0x(&verifier),
        "digest": hex0x(&digest),
        "signature": hex0x(&signature),
    }))
}

/// Apply the Midnight policy to a verified transcript and a proven lock.
///
/// # Errors
///
/// Returns the first policy check that fails.
pub fn receipt_for(
    config: &Config,
    dlc: &DlcVerifyResult,
    announcement: &OfferAnnouncement,
    lock: &Lock,
    terms: &LoanTerms,
) -> Result<Receipt, String> {
    if dlc.verification_status != VerificationStatus::Pass {
        return Err(format!(
            "the DLC transcript did not verify: {}",
            [
                dlc.verification_failures.join(", "),
                dlc.verification_incomplete.join(", ")
            ]
            .join(" ")
        ));
    }
    if config.network != Network::Bitcoin && !config.allow_insecure_network {
        return Err("this network's proof of work is free to forge; pass --allow-insecure-network for a test deployment".to_owned());
    }
    if &announcement.chain_hash != config.network.chain_hash().as_bytes() {
        return Err("the DLC is for another Bitcoin network".to_owned());
    }
    if lock.confirmations < config.min_confirmations {
        return Err(format!(
            "the funding transaction has {} confirmation(s); at least {} are required",
            lock.confirmations, config.min_confirmations
        ));
    }

    let lygos_key = config.lygos_funding_pubkey.to_string();
    let lygos = lygos_key.as_str();
    let offerer = dlc.offerer_funding_pubkey.as_deref().unwrap_or_default();
    let accepter = dlc.accepter_funding_pubkey.as_deref().unwrap_or_default();
    // The refund is the trusted last resort and must pay the Lygos side: the whole funding output
    // to the accepter, with Lygos as the accepter.
    if offerer == lygos || accepter != lygos {
        return Err(
            "the Midnight Lygos funding key must be the accepter's, and only the accepter's"
                .to_owned(),
        );
    }
    if announcement.contract_flags != REFUND_TO_ACCEPTER_FLAG {
        return Err("the DLC must refund to the accepter (contract flags 0x01)".to_owned());
    }
    let borrower = offerer;

    let market = midnight::market(&terms.market)?;
    if market.chain_id != terms.chain_id {
        return Err("the market is on another chain".to_owned());
    }
    let refund_locktime = u64::from(
        dlc.refund_locktime
            .ok_or("the DLC has no refund locktime")?,
    );
    if refund_locktime < market.maturity.saturating_add(REFUND_GAP_SECS) {
        return Err("the refund locktime is less than two weeks after maturity".to_owned());
    }

    let liquidators = midnight::liquidators(&announcement.outcomes, terms.mint_deadline != 0)?;
    let event_id = midnight::event_id(
        terms.chain_id,
        &terms.originator,
        &market.id,
        borrower,
        &liquidators,
        &terms.controller,
        terms.mint_deadline,
        terms.announced_at,
    );
    if announcement.event_id != midnight::event_name(market.maturity, &event_id) {
        return Err("the announcement's event id does not commit to these terms".to_owned());
    }

    if dlc.fund_tx_id.as_deref() != Some(lock.txid.to_string().as_str())
        || dlc.funding_value_sats.as_deref() != Some(lock.sats.to_string().as_str())
    {
        return Err("the proven transaction is not the DLC's funding transaction".to_owned());
    }
    let funding_script = dlc
        .witness_script
        .as_deref()
        .and_then(|script| hex::decode(script).ok())
        .map(|script| ScriptBuf::from_bytes(script).to_p2wsh());
    if funding_script.as_ref() != Some(&lock.script_pubkey) {
        return Err("the proven output is not the DLC's funding output".to_owned());
    }

    // ponytail: payout addresses stay off-chain, where each co-signer checks its own, so only the
    // split is checked here: Lygos stakes nothing, the borrower takes the whole collateral unless
    // the loan is liquidated, and the Lygos side takes it all when it is.
    if dlc.accept_collateral.as_deref() != Some("0") {
        return Err("Lygos must stake no collateral".to_owned());
    }
    let total = dlc.total_collateral.as_deref().unwrap_or_default();
    for outcome in &announcement.outcomes {
        let payout = dlc.outcomes.iter().find(|payout| &payout.label == outcome);
        let split = payout.map(|payout| {
            let (lygos, borrower) = (payout.accepter_sats.as_str(), payout.offerer_sats.as_str());
            if outcome.starts_with("liquidated-by-") {
                (lygos, borrower)
            } else {
                (borrower, lygos)
            }
        });
        if split != Some((total, "0")) {
            return Err(format!(
                "the {outcome} payout is not the whole collateral to one side"
            ));
        }
    }
    // A CET must be spendable as soon as the lock exists: no locktime, or a time the funding
    // block has already passed. A block-height locktime cannot be checked without the height.
    let cet_locktime = dlc.cet_locktime.ok_or("the DLC has no CET locktime")?;
    if cet_locktime != 0 && !(LOCK_TIME_THRESHOLD..=lock.block_time).contains(&cet_locktime) {
        return Err("the CET locktime is not a time before the funding block".to_owned());
    }

    let txid = |value: Option<&str>| -> Result<[u8; 32], String> {
        value
            .and_then(|value| value.parse::<Txid>().ok())
            .map(Txid::to_byte_array)
            .ok_or_else(|| "the DLC is missing a CET or its refund".to_owned())
    };
    let cet_txids = announcement
        .outcomes
        .iter()
        .map(|outcome| {
            txid(
                dlc.cets
                    .iter()
                    .find(|cet| &cet.outcome == outcome)
                    .map(|cet| cet.txid.as_str()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let terms_hash = Terms {
        claim_id: &lock.claim_id,
        event_id: &event_id,
        lygos_funding_pubkey: &bytes("funding key", lygos)?,
        borrower_funding_pubkey: &bytes("funding key", borrower)?,
        announcement: &announcement.bytes,
        cet_txids: &cet_txids,
        refund_txid: &txid(dlc.refund_tx_id.as_deref())?,
    }
    .hash();

    Ok(Receipt {
        claim_id: lock.claim_id,
        terms_hash,
        event_id,
        market_id: market.id,
        controller: terms.controller,
        // The CETs pay out the collateral; the funding output also holds their fees. Minting the
        // collateral keeps every unit deliverable.
        sats: dlc
            .total_collateral
            .as_deref()
            .and_then(|sats| sats.parse().ok())
            .ok_or("the DLC has no collateral")?,
        confirmations: lock.confirmations,
        announced_at: terms.announced_at,
        expires_at: terms.mint_deadline,
        input_claim_ids: lock.input_claim_ids.clone(),
        chain_id: terms.chain_id,
        originator: terms.originator,
    })
}

/// Parse the `--network` launch argument.
///
/// # Errors
///
/// Fails for an unknown network.
pub fn parse_network(name: &str) -> Result<Network, String> {
    match name {
        "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unsupported network {other:?}")),
    }
}

/// `verifier-core` uses the network only to render addresses, so every test network is "testnet".
fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Regtest => "regtest",
        _ => "testnet",
    }
}

fn bytes(field: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| format!("invalid {field}: {error}"))
}

fn fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    bytes(field, value)?
        .try_into()
        .map_err(|_| format!("invalid {field}: expected {N} bytes"))
}

/// Attestations in flight, timed-out ones included. `/health` is not subject to it.
static ATTEST_SLOTS: Semaphore = Semaphore::const_new(8);
/// DDK's refund-to-accepter contract flag.
const REFUND_TO_ACCEPTER_FLAG: u8 = 0x01;
/// A Midnight outcome list is `not-minted`, `released`, and one entry per liquidator.
const MAX_OUTCOMES: usize = 64;
/// How long a request may take to deliver its body once it holds a slot.
const BODY_READ_LIMIT: Duration = Duration::from_secs(5);

/// Build the attester's router.
pub fn router(config: Config) -> Router {
    Router::new()
        .route("/health", get(async || Json(json!({"status": "healthy"}))))
        .route("/v1/attest", post(handle))
        .layer(DefaultBodyLimit::max(7 * 1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .with_state(Arc::new(config))
}

async fn handle(State(config): State<Arc<Config>>, request: Request) -> Response {
    // ponytail: the permit rides inside the blocking task, so a request that times out keeps its
    // slot until the work actually ends; tower's ConcurrencyLimitLayer released it at the timeout.
    // It is taken before the body is read, so a request waiting for a slot holds no buffer, and
    // the body read is capped so a stalled sender cannot sit on a slot for the whole 30s window.
    let Ok(permit) = ATTEST_SLOTS.acquire().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let body = Bytes::from_request(request, &());
    let body = match tokio::time::timeout(BODY_READ_LIMIT, body).await {
        Ok(Ok(body)) => body,
        Ok(Err(rejection)) => return rejection.into_response(),
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    // Request bodies and loan terms are never logged. Parsing happens off the async runtime
    // too: a 7 MiB body is a measurable stall for /health.
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let request: AttestRequest =
            serde_json::from_slice(&body).map_err(|error| format!("invalid request: {error}"))?;
        attest(&config, &request)
    })
    .await
    {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        Ok(Err(error)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": error})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("attester task failed: {error}")})),
        )
            .into_response(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use verifier_schema::{CetTransactionInfo, OutcomeInfo};

    // The generator and twice the generator: real points, so the typed config parses them.
    const LYGOS: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const BORROWER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const ORACLE: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// Stand-in funding witness script; the lock's output is its P2WSH.
    const WITNESS_SCRIPT: [u8; 1] = [0x51];
    const LIQUIDATOR: &str = "liquidated-by-0x00000000000000000000000000000000000000aa";
    // The market in `midnight::tests`: chain 8453, maturing at 1798156800.
    const MARKET: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000210500000000000000000000000000000000000000000000000000000000000000a100000000000000000000000000000000000000000000000000000000000000b20000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000006b2db200000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c30000000000000000000000000000000000000000000000000bef55718ad6000000000000000000000000000000000000000000000000000003782dace9d9000000000000000000000000000000000000000000000000000000000000000000d4";
    const MATURITY: u32 = 1_798_156_800;
    const BLOCK_TIME: u32 = 1_790_000_000;

    fn config() -> Config {
        Config {
            network: Network::Bitcoin,
            lygos_funding_pubkey: LYGOS.parse().expect("key"),
            oracle_pubkey: ORACLE.parse().expect("key"),
            key: SigningKey::from_slice(&[7; 32]).expect("key"),
            allow_insecure_network: false,
            min_confirmations: 1,
        }
    }

    fn terms() -> LoanTerms {
        LoanTerms {
            market: hex::decode(MARKET).expect("market"),
            chain_id: 8453,
            originator: [0x56; 20],
            controller: [0xc0; 20],
            mint_deadline: 1_790_000_000,
            announced_at: 1_789_000_000,
        }
    }

    fn lock() -> Lock {
        Lock {
            txid: Txid::from_byte_array([1; 32]),
            script_pubkey: ScriptBuf::from_bytes(WITNESS_SCRIPT.to_vec()).to_p2wsh(),
            claim_id: [2; 32],
            input_claim_ids: vec![[3; 32]],
            sats: 50_010_000,
            confirmations: 1,
            block_time: BLOCK_TIME,
        }
    }

    fn announcement(terms: &LoanTerms) -> OfferAnnouncement {
        let market = midnight::market(&terms.market).expect("market");
        let event_id = midnight::event_id(
            terms.chain_id,
            &terms.originator,
            &market.id,
            BORROWER,
            &[&LIQUIDATOR["liquidated-by-".len()..]],
            &terms.controller,
            terms.mint_deadline,
            terms.announced_at,
        );
        OfferAnnouncement {
            bytes: vec![9; 100],
            event_id: midnight::event_name(market.maturity, &event_id),
            chain_hash: *Network::Bitcoin.chain_hash().as_bytes(),
            contract_flags: REFUND_TO_ACCEPTER_FLAG,
            outcomes: ["not-minted", "released", LIQUIDATOR]
                .map(str::to_owned)
                .to_vec(),
        }
    }

    fn dlc() -> DlcVerifyResult {
        let cet = |outcome: &str, byte: u8| CetTransactionInfo {
            outcome: outcome.to_owned(),
            txid: Txid::from_byte_array([byte; 32]).to_string(),
            locktime: 0,
            outputs: Vec::new(),
        };
        DlcVerifyResult {
            verification_status: VerificationStatus::Pass,
            offerer_funding_pubkey: Some(BORROWER.to_owned()),
            accepter_funding_pubkey: Some(LYGOS.to_owned()),
            refund_locktime: Some(MATURITY + 14 * 24 * 60 * 60),
            fund_tx_id: Some(lock().txid.to_string()),
            funding_value_sats: Some("50010000".to_owned()),
            witness_script: Some(hex::encode(WITNESS_SCRIPT)),
            total_collateral: Some("50000000".to_owned()),
            offer_collateral: Some("50000000".to_owned()),
            accept_collateral: Some("0".to_owned()),
            outcomes: [
                ("not-minted", false),
                ("released", false),
                (LIQUIDATOR, true),
            ]
            .map(|(label, liquidated)| {
                let (lygos, borrower) = if liquidated {
                    ("50000000", "0")
                } else {
                    ("0", "50000000")
                };
                OutcomeInfo {
                    label: label.to_owned(),
                    offerer_sats: borrower.to_owned(),
                    accepter_sats: lygos.to_owned(),
                }
            })
            .to_vec(),
            cet_locktime: Some(BLOCK_TIME),
            // Deliberately not in outcome order: the hash must follow the oracle's order.
            cets: vec![cet(LIQUIDATOR, 6), cet("not-minted", 4), cet("released", 5)],
            refund_tx_id: Some(Txid::from_byte_array([7; 32]).to_string()),
            ..DlcVerifyResult::default()
        }
    }

    #[test]
    fn issues_a_receipt_for_a_midnight_dlc() {
        let terms = terms();
        let receipt = receipt_for(&config(), &dlc(), &announcement(&terms), &lock(), &terms)
            .expect("receipt");
        assert_eq!(receipt.sats, 50_000_000);
        assert_eq!(receipt.expires_at, terms.mint_deadline);
        assert_eq!(receipt.claim_id, [2; 32]);
        assert_eq!(
            hex::encode(receipt.market_id),
            "e7d2aa696b1fa2e75e4afc253f5b8ee8b2ca0b0103328d248f8bd5572a56a353"
        );
        assert_eq!(
            receipt.terms_hash,
            Terms {
                claim_id: &[2; 32],
                event_id: &receipt.event_id,
                lygos_funding_pubkey: &hex::decode(LYGOS).expect("key"),
                borrower_funding_pubkey: &hex::decode(BORROWER).expect("key"),
                announcement: &[9; 100],
                cet_txids: &[[4; 32], [5; 32], [6; 32]],
                refund_txid: &[7; 32],
            }
            .hash()
        );
    }

    #[test]
    fn refuses_anything_else() {
        let refused = |edit: fn(&mut DlcVerifyResult, &mut LoanTerms, &mut Lock)| {
            let (mut dlc, mut terms, mut lock) = (dlc(), terms(), lock());
            // The announcement is fixed before the edit, as the oracle signs it before the request.
            let announcement = announcement(&terms);
            edit(&mut dlc, &mut terms, &mut lock);
            receipt_for(&config(), &dlc, &announcement, &lock, &terms).expect_err("must be refused")
        };
        assert!(
            refused(|d, _, _| d.verification_status = VerificationStatus::Incomplete)
                .contains("did not verify")
        );
        assert!(
            refused(|d, _, _| d.offerer_funding_pubkey = Some(LYGOS.to_owned()))
                .contains("funding key")
        );
        assert!(
            refused(|d, _, _| d.accepter_funding_pubkey = Some(BORROWER.to_owned()))
                .contains("funding key")
        );
        assert!(
            refused(|d, _, _| d.refund_locktime = Some(MATURITY + 14 * 24 * 60 * 60 - 1))
                .contains("refund locktime")
        );
        assert!(refused(|_, t, _| t.chain_id = 1).contains("another chain"));
        assert!(refused(|_, _, l| l.confirmations = 0).contains("confirmation"));
        let strict = Config {
            min_confirmations: 6,
            ..config()
        };
        assert!(
            receipt_for(&strict, &dlc(), &announcement(&terms()), &lock(), &terms())
                .expect_err("one confirmation is below the floor")
                .contains("at least 6")
        );
        assert!(refused(|_, t, _| t.controller = [0xbd; 20]).contains("event id"));
        assert!(refused(|_, t, _| t.originator = [0xbd; 20]).contains("event id"));
        assert!(refused(|_, t, _| t.mint_deadline += 1).contains("event id"));
        assert!(refused(|_, t, _| t.mint_deadline = 0).contains("released"));
        assert!(
            refused(|_, _, l| l.txid = Txid::from_byte_array([8; 32]))
                .contains("funding transaction")
        );
        assert!(refused(|_, _, l| l.sats += 1).contains("funding transaction"));
        assert!(refused(|_, _, l| l.script_pubkey = ScriptBuf::new()).contains("funding output"));
        assert!(refused(|d, _, _| d.witness_script = None).contains("funding output"));
        assert!(refused(|d, _, _| drop(d.cets.pop())).contains("missing a CET"));
        let mut each_party = announcement(&terms());
        each_party.contract_flags = 0;
        assert!(
            receipt_for(&config(), &dlc(), &each_party, &lock(), &terms())
                .expect_err("must be refused")
                .contains("refund to the accepter")
        );
        assert!(refused(|d, _, _| d.accept_collateral = Some("1".to_owned())).contains("stake"));
        // A liquidation that pays the borrower, a release that pays Lygos, and a short payout.
        assert!(refused(|d, _, _| d.outcomes[2].accepter_sats = "0".to_owned()).contains("payout"));
        assert!(
            refused(|d, _, _| d.outcomes[1].offerer_sats = "49999999".to_owned())
                .contains("payout")
        );
        assert!(refused(|d, _, _| drop(d.outcomes.pop())).contains("payout"));
        assert!(refused(|d, _, _| d.cet_locktime = Some(BLOCK_TIME + 1)).contains("CET locktime"));
        assert!(refused(|d, _, _| d.cet_locktime = Some(900_000)).contains("CET locktime"));
    }

    #[test]
    fn refuses_a_forged_announced_at() {
        let mut terms = terms();
        let announcement = announcement(&terms);
        terms.announced_at += 1;
        let error = receipt_for(&config(), &dlc(), &announcement, &lock(), &terms)
            .expect_err("announcedAt is under the oracle's signature");
        assert!(error.contains("event id"), "{error}");
    }

    #[test]
    fn refuses_a_forgeable_network_unless_allowed() {
        let terms = terms();
        let regtest = Config {
            network: Network::Regtest,
            ..config()
        };
        let error = receipt_for(&regtest, &dlc(), &announcement(&terms), &lock(), &terms)
            .expect_err("regtest proofs are free");
        assert!(error.contains("--allow-insecure-network"), "{error}");
        let allowed = Config {
            allow_insecure_network: true,
            ..regtest
        };
        let error = receipt_for(&allowed, &dlc(), &announcement(&terms), &lock(), &terms)
            .expect_err("the fixture announcement is for mainnet");
        assert!(error.contains("another Bitcoin network"), "{error}");
    }

    #[test]
    fn refuses_a_real_dlc_from_another_product() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../verifier-core/tests/fixtures/testnet-loan-118c9fc9.json"
        ))
        .expect("fixture");
        let field = |name: &str| fixture[name].as_str().expect("field");
        let dlc = verify_dlc_compatibility(
            field("offer"),
            field("accept"),
            Some(field("sign")),
            Some(field("oraclePubkey")),
            Some("testnet"),
        );
        assert_eq!(dlc.verification_status, VerificationStatus::Pass);
        let announcement = offer_announcement(field("offer")).expect("announcement");
        assert_eq!(Some(&announcement.event_id), dlc.oracle_event_id.as_ref());

        let mut config = config();
        let attempt = |config: &Config| {
            receipt_for(config, &dlc, &announcement, &lock(), &terms()).expect_err("refused")
        };
        assert!(attempt(&config).contains("network"));
        config.network = Network::Regtest;
        assert!(attempt(&config).contains("--allow-insecure-network"));
        config.allow_insecure_network = true;
        assert!(attempt(&config).contains("funding key"));
        // Even with its own key pinned, it does not refund to the accepter.
        config.lygos_funding_pubkey = dlc
            .accepter_funding_pubkey
            .as_deref()
            .expect("key")
            .parse()
            .expect("key");
        assert!(
            attempt(&config).contains("refund to the accepter"),
            "{}",
            attempt(&config)
        );
    }

    /// `attest` end to end up to the policy: the real mainnet lock proof in explorer byte order
    /// passes SPV, and the real testnet transcript is then refused for being on another network.
    #[test]
    fn attest_reaches_the_policy_with_an_explorer_order_proof() {
        use crate::spv::fixture::{BRANCH, HEADERS, TX, TX_INDEX};
        let fixture: Value = serde_json::from_str(include_str!(
            "../../verifier-core/tests/fixtures/testnet-loan-118c9fc9.json"
        ))
        .expect("fixture");
        let field = |name: &str| fixture[name].as_str().expect("field").to_owned();
        let mut config = config();
        config.oracle_pubkey = field("oraclePubkey").parse().expect("oracle key");
        let hex0x = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));
        let request = AttestRequest {
            offer: field("offer"),
            accept: field("accept"),
            sign: field("sign"),
            tx: TX.to_owned(),
            tx_index: TX_INDEX,
            merkle_branch: BRANCH.iter().map(|node| (*node).to_owned()).collect(),
            headers: HEADERS.iter().map(|header| (*header).to_owned()).collect(),
            market: MARKET.to_owned(),
            chain_id: 8453,
            originator: hex0x(&[0x56; 20]),
            controller: hex0x(&[0xc0; 20]),
            mint_deadline: 1_790_000_000,
            announced_at: 1_789_000_000,
            verifier: hex0x(&[0x11; 20]),
        };
        let error = attest(&config, &request).expect_err("a testnet DLC is refused on mainnet");
        assert!(error.contains("another Bitcoin network"), "{error}");

        let mut unreversed = request;
        unreversed.merkle_branch = unreversed
            .merkle_branch
            .iter()
            .map(|node| {
                let mut bytes = hex::decode(node).expect("hex");
                bytes.reverse();
                hex::encode(bytes)
            })
            .collect();
        let error = attest(&config, &unreversed).expect_err("internal byte order is wrong");
        assert!(error.contains("lock proof refused: NotInBlock"), "{error}");
    }

    #[tokio::test]
    async fn the_endpoint_refuses_unknown_fields_and_bad_json() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let app = router(config());
        let post = |body: &'static str| {
            Request::post("/v1/attest")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request")
        };
        let response = app
            .clone()
            .oneshot(post(r#"{"nope":1}"#))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let response = app.oneshot(post("{")).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
