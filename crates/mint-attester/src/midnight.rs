//! What makes a DLC a Midnight DLC: the market, the outcome list, the event id, and `termsHash`.

use crate::keccak;
use sha2::{Digest, Sha256};

/// The refund locktime must sit at least this long after the market's maturity.
pub const REFUND_GAP_SECS: u64 = 14 * 24 * 60 * 60;

/// `SSTORE2_PREFIX` in Midnight's `IdLib`.
const SSTORE2_PREFIX: [u8; 11] = [
    0x60, 0x0b, 0x38, 0x03, 0x80, 0x60, 0x0b, 0x5f, 0x39, 0x5f, 0xf3,
];

/// The parts of a Midnight market the enclave reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Market {
    /// Midnight's market id, `IdLib.toId`.
    pub id: [u8; 32],
    /// EVM chain the market is on.
    pub chain_id: u64,
    /// Maturity as a Unix timestamp.
    pub maturity: u64,
}

/// Read a market from `abi.encode(Market)`, the bytes Midnight stores at the market's address.
///
/// Only the canonical encoding of a market hashes to that market's id, so a blob that lies about
/// the maturity names a market that does not exist and the Originator refuses the receipt.
///
/// # Errors
///
/// Fails when the bytes are not shaped like an encoded market.
pub fn market(encoded: &[u8]) -> Result<Market, String> {
    // Offset word, eight fields, and the collateral array's length.
    if encoded.len() < 10 * 32 || !encoded.len().is_multiple_of(32) {
        return Err("market is not an ABI-encoded Market".to_owned());
    }
    let word = |index: usize| &encoded[index * 32..(index + 1) * 32];
    let number = |index: usize| {
        let (high, low) = word(index).split_at(24);
        let low: [u8; 8] = low.try_into().ok()?;
        high.iter()
            .all(|byte| *byte == 0)
            .then(|| u64::from_be_bytes(low))
    };
    if number(0) != Some(32) {
        return Err("market is not an ABI-encoded Market".to_owned());
    }
    let chain_id = number(1).ok_or("market chain id is out of range")?;
    let maturity = number(5).ok_or("market maturity is out of range")?;
    let midnight = &word(2)[12..];
    Ok(Market {
        id: keccak(&[
            &[0xff],
            midnight,
            &[0; 32],
            &keccak(&[&SSTORE2_PREFIX, encoded]),
        ]),
        chain_id,
        maturity,
    })
}

/// Check the oracle's outcome list is the canonical Midnight list and return its liquidators.
///
/// The list is `not-minted` (first mints only), `released`, then `liquidated-by-<address>` for
/// each liquidator, addresses as lowercase `0x` hex in strictly ascending order.
///
/// # Errors
///
/// Fails on any other list.
pub fn liquidators(outcomes: &[String], first_mint: bool) -> Result<Vec<&str>, String> {
    let mut rest = outcomes.iter().map(String::as_str);
    if first_mint && rest.next() != Some("not-minted") {
        return Err("a first mint's first outcome must be not-minted".to_owned());
    }
    if rest.next() != Some("released") {
        return Err("released is missing or out of place".to_owned());
    }
    let mut liquidators = Vec::new();
    for outcome in rest {
        let address = outcome
            .strip_prefix("liquidated-by-")
            .filter(|address| is_address(address))
            .ok_or_else(|| format!("unexpected outcome {outcome:?}"))?;
        if liquidators.last().is_some_and(|last| *last >= address) {
            return Err("liquidators must be in strictly ascending order".to_owned());
        }
        liquidators.push(address);
    }
    if liquidators.is_empty() {
        return Err("the outcome list names no liquidator".to_owned());
    }
    Ok(liquidators)
}

fn is_address(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|digits| {
        digits.len() == 40
            && digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The Midnight oracle event id as the receipt carries it: the SHA-256 digest alone. The
/// announcement names the event `"midnight-"` followed by this digest in lowercase hex.
///
/// Terms are canonical strings joined with `//`: decimal integers, lowercase `0x` hex for EVM
/// values, lowercase hex for the compressed funding key, and liquidators joined with `,`.
#[must_use]
pub fn event_id(
    chain_id: u64,
    originator: &[u8; 20],
    market_id: &[u8; 32],
    borrower_funding_pubkey: &str,
    liquidators: &[&str],
    controller: &[u8; 20],
    mint_deadline: u64,
) -> [u8; 32] {
    let preimage = [
        "lygos-midnight-v1",
        &chain_id.to_string(),
        &format!("0x{}", hex::encode(originator)),
        &format!("0x{}", hex::encode(market_id)),
        borrower_funding_pubkey,
        &liquidators.join(","),
        &format!("0x{}", hex::encode(controller)),
        &mint_deadline.to_string(),
    ]
    .join("//");
    Sha256::digest(preimage.as_bytes()).into()
}

/// Everything `termsHash` commits to.
#[derive(Clone, Copy, Debug)]
pub struct Terms<'a> {
    /// Commitment to the funding outpoint, as in the receipt.
    pub claim_id: &'a [u8; 32],
    /// Oracle event id, as in the receipt.
    pub event_id: &'a [u8; 32],
    /// The pinned Lygos funding key, 33 bytes compressed.
    pub lygos_funding_pubkey: &'a [u8],
    /// The borrower's funding key, 33 bytes compressed.
    pub borrower_funding_pubkey: &'a [u8],
    /// The oracle announcement as the offer serializes it.
    pub announcement: &'a [u8],
    /// CET txids in the oracle's outcome order, internal byte order.
    pub cet_txids: &'a [[u8; 32]],
    /// Refund txid, internal byte order.
    pub refund_txid: &'a [u8; 32],
}

impl Terms<'_> {
    /// `keccak256(abi.encode(keccak256("LygosMidnightTerms v1"), claimId, eventId,
    /// keccak256(lygosFundingPubkey), keccak256(borrowerFundingPubkey), sha256(announcement),
    /// sha256(cetTxids ‖ refundTxid)))`.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut transactions = Sha256::new();
        for txid in self.cet_txids {
            transactions.update(txid);
        }
        transactions.update(self.refund_txid);
        keccak(&[
            &keccak(&[b"LygosMidnightTerms v1"]),
            self.claim_id,
            self.event_id,
            &keccak(&[self.lygos_funding_pubkey]),
            &keccak(&[self.borrower_funding_pubkey]),
            &Sha256::digest(self.announcement),
            &transactions.finalize(),
        ])
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    // `cast abi-encode` of a Market on chain 8453 maturing at 1798156800, and its `IdLib.toId`.
    const MARKET: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000210500000000000000000000000000000000000000000000000000000000000000a100000000000000000000000000000000000000000000000000000000000000b20000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000006b2db200000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c30000000000000000000000000000000000000000000000000bef55718ad6000000000000000000000000000000000000000000000000000003782dace9d9000000000000000000000000000000000000000000000000000000000000000000d4";
    const MARKET_ID: &str = "e7d2aa696b1fa2e75e4afc253f5b8ee8b2ca0b0103328d248f8bd5572a56a353";

    #[test]
    fn market_id_matches_midnight() {
        let market = market(&hex::decode(MARKET).expect("hex")).expect("market");
        assert_eq!(hex::encode(market.id), MARKET_ID);
        assert_eq!(market.chain_id, 8453);
        assert_eq!(market.maturity, 1_798_156_800);
        assert!(super::market(&[0; 64]).is_err());
    }

    #[test]
    fn only_the_canonical_outcome_list_passes() {
        let list = |outcomes: &[&str]| -> Vec<String> {
            outcomes
                .iter()
                .map(|outcome| (*outcome).to_owned())
                .collect()
        };
        let a = "liquidated-by-0x00000000000000000000000000000000000000aa";
        let b = "liquidated-by-0x00000000000000000000000000000000000000bb";
        assert_eq!(
            liquidators(&list(&["not-minted", "released", a, b]), true).map(|l| l.len()),
            Ok(2)
        );
        assert!(liquidators(&list(&["released", a]), false).is_ok());
        for (outcomes, first_mint) in [
            (list(&["released", a]), true),
            (list(&["not-minted", "released", a]), false),
            (list(&["not-minted", "released"]), true),
            (list(&["not-minted", "released", b, a]), true),
            (list(&["not-minted", "released", a, a]), true),
            (list(&["not-minted", "released", a, "funded"]), true),
            (
                list(&[
                    "released",
                    "liquidated-by-0x00000000000000000000000000000000000000AA",
                ]),
                false,
            ),
        ] {
            assert!(liquidators(&outcomes, first_mint).is_err(), "{outcomes:?}");
        }
    }
}
