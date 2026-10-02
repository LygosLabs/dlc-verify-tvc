//! The lock receipt and its signature, byte-for-byte as `lygos-contracts/src/Verifier.sol` checks them.

use crate::keccak;
use p256::ecdsa::{Error, Signature, SigningKey, signature::hazmat::PrehashSigner};

const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const RECEIPT_TYPE: &[u8] = b"Receipt(bytes32 claimId,bytes32 termsHash,bytes32 eventId,bytes32 marketId,address controller,uint64 sats,uint32 confirmations,uint64 announcedAt,uint64 expiresAt,bytes32[] inputClaimIds,uint256 chainId,address originator)";

/// `LockReceipt` in `Verifier.sol`. Field order is the EIP-712 type order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Commitment to the funding outpoint.
    pub claim_id: [u8; 32],
    /// Hash of the transcript terms.
    pub terms_hash: [u8; 32],
    /// Oracle event id.
    pub event_id: [u8; 32],
    /// Midnight market id.
    pub market_id: [u8; 32],
    /// The borrower's EVM key.
    pub controller: [u8; 20],
    /// Value of the funding output.
    pub sats: u64,
    /// Number of headers after the funding block.
    pub confirmations: u32,
    /// Timestamp of the block the oracle froze the liquidator set at.
    pub announced_at: u64,
    /// Mint deadline on a first mint; 0 on a successor.
    pub expires_at: u64,
    /// Claim-id commitment of every funding input.
    pub input_claim_ids: Vec<[u8; 32]>,
    /// Chain the receipt is for. `uint256` on-chain; no EVM chain id exceeds a `u64`.
    pub chain_id: u64,
    /// Originator the receipt is for.
    pub originator: [u8; 20],
}

/// The `Verifier` deployment a receipt is signed for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Domain {
    /// Chain the `Verifier` is deployed on.
    pub chain_id: u64,
    /// Address of the `Verifier`.
    pub verifier: [u8; 20],
}

impl Receipt {
    /// The EIP-712 digest, equal to `Verifier.digest`.
    #[must_use]
    pub fn digest(&self, domain: &Domain) -> [u8; 32] {
        let domain_separator = keccak(&[
            &keccak(&[DOMAIN_TYPE]),
            &keccak(&[b"Lygos Verifier"]),
            &keccak(&[b"1"]),
            &word(&domain.chain_id.to_be_bytes()),
            &word(&domain.verifier),
        ]);
        let struct_hash = keccak(&[
            &keccak(&[RECEIPT_TYPE]),
            &self.claim_id,
            &self.terms_hash,
            &self.event_id,
            &self.market_id,
            &word(&self.controller),
            &word(&self.sats.to_be_bytes()),
            &word(&self.confirmations.to_be_bytes()),
            &word(&self.announced_at.to_be_bytes()),
            &word(&self.expires_at.to_be_bytes()),
            &keccak(&[&self.input_claim_ids.concat()]),
            &word(&self.chain_id.to_be_bytes()),
            &word(&self.originator),
        ]);
        keccak(&[b"\x19\x01", &domain_separator, &struct_hash])
    }
}

/// Sign a receipt digest as `r ‖ s` with low `s`. The digest is the message hash; nothing is hashed again.
///
/// # Errors
///
/// Fails only if the signing primitive does.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
    let signature: Signature = key.sign_prehash(digest)?;
    Ok(signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into())
}

/// Left-pad a big-endian value to an ABI word.
fn word(value: &[u8]) -> [u8; 32] {
    let mut word = [0; 32];
    word[32 - value.len()..].copy_from_slice(value);
    word
}
