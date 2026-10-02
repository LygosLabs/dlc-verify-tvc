//! SPV check of a funding output: proof of work, header linkage, and Merkle inclusion.
//!
//! The enclave carries no Bitcoin state except [`MAINNET_MIN_DIFFICULTY_BITS`], so a forged bundle
//! costs real blocks mined at that difficulty.

use crate::keccak;
use bitcoin::{
    CompactTarget, Network, OutPoint, ScriptBuf, Target, Transaction, Txid,
    block::Header,
    consensus::Params,
    hashes::{Hash, HashEngine, sha256d},
};
use std::fmt;

/// Easiest mainnet target the enclave accepts, as compact bits: half the difficulty at height
/// 969,476 (bits `0x17021ec5`, October 2026). Raise it with enclave releases as difficulty grows.
pub const MAINNET_MIN_DIFFICULTY_BITS: u32 = 0x1704_3d8a;

/// Evidence the relayer submits for one funding output.
#[derive(Clone, Debug)]
pub struct LockProof {
    /// The funding transaction.
    pub tx: Transaction,
    /// Index of the funding output in `tx`.
    pub vout: u32,
    /// Position of `tx` in its block.
    pub tx_index: u32,
    /// Merkle siblings from leaf to root, in internal byte order.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The header of the block containing `tx`, then the headers confirming it, in chain order.
    pub headers: Vec<Header>,
}

/// What a valid [`LockProof`] establishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lock {
    /// Funding transaction id. The caller binds it to the DLC transcript.
    pub txid: Txid,
    /// Script of the funding output. The caller binds it to the DLC transcript.
    pub script_pubkey: ScriptBuf,
    /// Commitment to the funding outpoint.
    pub claim_id: [u8; 32],
    /// The same commitment for every input of the funding transaction, in input order.
    pub input_claim_ids: Vec<[u8; 32]>,
    /// Value of the funding output.
    pub sats: u64,
    /// Number of headers after the funding block.
    pub confirmations: u32,
}

/// Why a [`LockProof`] was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpvError {
    /// No header was supplied.
    NoHeaders,
    /// More headers than a confirmation count can hold.
    TooManyHeaders,
    /// The header at this position claims less work than the compiled-in minimum.
    TargetTooEasy(usize),
    /// The header at this position does not meet its own target.
    BadProofOfWork(usize),
    /// The header at this position does not build on the one before it.
    BrokenLink(usize),
    /// A 64-byte transaction is indistinguishable from an inner Merkle node.
    AmbiguousTransaction,
    /// `tx_index` does not fit a tree of the branch's depth.
    IndexOutOfRange,
    /// The branch does not lead to the first header's Merkle root.
    NotInBlock,
    /// The transaction has no output at `vout`.
    NoSuchOutput,
}

impl fmt::Display for SpvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SpvError {}

/// `keccak256(chain hash ‖ txid ‖ vout)`: both hashes in internal byte order, `vout` as a
/// big-endian `uint32`. Equals Solidity's `keccak256(abi.encodePacked(bytes32, bytes32, uint32))`.
#[must_use]
pub fn claim_id(network: Network, outpoint: &OutPoint) -> [u8; 32] {
    keccak(&[
        network.chain_hash().as_bytes(),
        outpoint.txid.as_byte_array(),
        &outpoint.vout.to_be_bytes(),
    ])
}

/// Check `proof` against `network` and derive the receipt's Bitcoin fields.
///
/// # Errors
///
/// Returns the first check that fails.
pub fn verify_lock(network: Network, proof: &LockProof) -> Result<Lock, SpvError> {
    let first = proof.headers.first().ok_or(SpvError::NoHeaders)?;
    let confirmations =
        u32::try_from(proof.headers.len() - 1).map_err(|_| SpvError::TooManyHeaders)?;

    let max_target = max_target(network);
    let mut previous = None;
    for (position, header) in proof.headers.iter().enumerate() {
        let target = header.target();
        if target > max_target {
            return Err(SpvError::TargetTooEasy(position));
        }
        let hash = header
            .validate_pow(target)
            .map_err(|_| SpvError::BadProofOfWork(position))?;
        if previous.is_some_and(|previous| header.prev_blockhash != previous) {
            return Err(SpvError::BrokenLink(position));
        }
        previous = Some(hash);
    }

    if proof.tx.base_size() == 64 {
        return Err(SpvError::AmbiguousTransaction);
    }
    let txid = proof.tx.compute_txid();
    let mut node = txid.to_byte_array();
    let mut index = proof.tx_index;
    for sibling in &proof.merkle_branch {
        let mut engine = sha256d::Hash::engine();
        let (left, right) = if index & 1 == 0 {
            (&node, sibling)
        } else {
            (sibling, &node)
        };
        engine.input(left);
        engine.input(right);
        node = sha256d::Hash::from_engine(engine).to_byte_array();
        index >>= 1;
    }
    if index != 0 {
        return Err(SpvError::IndexOutOfRange);
    }
    if node != first.merkle_root.to_byte_array() {
        return Err(SpvError::NotInBlock);
    }

    let output = usize::try_from(proof.vout)
        .ok()
        .and_then(|vout| proof.tx.output.get(vout))
        .ok_or(SpvError::NoSuchOutput)?;
    Ok(Lock {
        txid,
        script_pubkey: output.script_pubkey.clone(),
        claim_id: claim_id(network, &OutPoint::new(txid, proof.vout)),
        input_claim_ids: proof
            .tx
            .input
            .iter()
            .map(|input| claim_id(network, &input.previous_output))
            .collect(),
        sats: output.value.to_sat(),
        confirmations,
    })
}

// ponytail: only mainnet has a difficulty floor. Test networks accept their proof-of-work limit, so
// an SPV proof there costs nothing to forge; give them a floor if a test network ever backs value.
fn max_target(network: Network) -> Target {
    match network {
        Network::Bitcoin => {
            Target::from_compact(CompactTarget::from_consensus(MAINNET_MIN_DIFFICULTY_BITS))
        }
        other => Params::new(other).max_attainable_target,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::{TxMerkleNode, blockdata::constants::genesis_block, consensus::encode};

    // Mainnet block 969,476 and the two blocks after it.
    const HEADERS: [&str; 3] = [
        "0080a0214070df70e93c153fef7dcb4071fe284621bd115985a300000000000000000000828958afe1c1ff1375116858748f96124fb1d7b81cad025ff38c9430f7c08da14ba7be6ac51e021718966236",
        "00c00520e34fc66c9307a8ae60525d5ec76649a1e5ccc15099c00100000000000000000052f9e942af4e81845d8d22c20d787e0266563e3263f03daba94fbace8a1b4aa802a8be6ac51e021706769862",
        "000000300b4a452a897d5d69e9bf02678b2c32dbc7ce55afa76f0100000000000000000033e20bd465b63241d5cd1fda79785dc4b68e26940e7b562b9fd50e8440104aa550a9be6ac51e0217f2272b4a",
    ];
    // Transaction 0679ab3a…0995, at position 1452 of block 969,476.
    const TX: &str = "0200000001c80855c075b73710cc4809ceb6360f91b66841650645f171055857c06db65730000000006a473044022045df57200844828ed973e9ee4289afba0964d1000a6870b4cf73554c949228f902206ceb2ee3834e9af15ae5adc5af8544d5e149456cb3c3598ee3181dea67c4d94d01210210e3117cd0c4d2d62da092922caa8079c95ff441cc95f0d5d84feded1ff39419fdffffff0216604c01000000001600144ca5ceb6727f9b56bf4fddec0a4cca96d2059dd7e5d301000000000016001480a41ae8f432d3dd20e9e0f05827b5d5e19cc84903cb0e00";
    const BRANCH: [&str; 12] = [
        "94f29a14afb647af594d9a2d45d5368bdccd24acc128d46ccb41122badbd0745",
        "41b50fd8d2efc0fb9aabeeb948c21921891872f3e86796536bc35233029acb49",
        "b1dbcab004fb684d5935ed1edce3b7208623d2435205c1100ece3283bd655b72",
        "99a728b3d5b25602336298c096d900b44a47028e854e6bc46308cedc70e075f6",
        "6b2ae084b92a9a725f749ee7d0631603ad128884dbc8b4ad412936e877dc51a5",
        "3d898e57a86c317a4ffcf6f456df43fcddfa3a601cca5d7d235a0d950abbeacc",
        "3ecd7fbffccba285e1bf14194f59e17123e3a195abc06cc1ac2ad096aabe1fa0",
        "e79639b69edd78ea71c7a3820d4879da3bf4024b001766dc4ca2a297b37afde2",
        "d5d2076d9a5b56f7b0330b7c0aa7c284c81ba4a44ba3f08bda627832301709c9",
        "402a87fc978b0d09d302979c9fb3e29a6f84ce1af94a83c3783f07cb513f9bdd",
        "d5eb6ffea62370787bf53dbe7d863ee3ec0b9938b2cb7e9c50eb02735b7b671c",
        "7718f449e836cbcda1c9a6f7fa1901caaf9ae3c6b965587aa7f933b8aee1bc58",
    ];

    fn proof() -> LockProof {
        LockProof {
            tx: encode::deserialize_hex(TX).expect("tx"),
            vout: 0,
            tx_index: 1452,
            merkle_branch: BRANCH
                .iter()
                .map(|node| node.parse::<TxMerkleNode>().expect("node").to_byte_array())
                .collect(),
            headers: HEADERS
                .iter()
                .map(|header| encode::deserialize_hex(header).expect("header"))
                .collect(),
        }
    }

    #[test]
    fn accepts_a_mainnet_lock() {
        let lock = verify_lock(Network::Bitcoin, &proof()).expect("valid proof");
        assert_eq!(lock.confirmations, 2);
        assert_eq!(lock.sats, 21_782_550);
        assert_eq!(lock.input_claim_ids.len(), 1);
        // Computed independently with lygos-contracts' gen_receipt_vectors.py keccak.
        assert_eq!(
            hex::encode(lock.claim_id),
            "0a0897b60d5b2a6ee95e5ba2f08bf5847c0f62e2ac528bd4a62b8bdb31e4eb4f"
        );
    }

    #[test]
    fn refuses_bad_proofs() {
        let check = |edit: fn(&mut LockProof)| {
            let mut proof = proof();
            edit(&mut proof);
            verify_lock(Network::Bitcoin, &proof)
        };
        assert_eq!(check(|p| p.headers.clear()), Err(SpvError::NoHeaders));
        assert_eq!(
            check(|p| p.headers[0] = genesis_block(Network::Regtest).header),
            Err(SpvError::TargetTooEasy(0))
        );
        assert_eq!(
            check(|p| p.headers[1].nonce += 1),
            Err(SpvError::BadProofOfWork(1))
        );
        assert_eq!(
            check(|p| {
                p.headers.remove(1);
            }),
            Err(SpvError::BrokenLink(1))
        );
        assert_eq!(check(|p| p.tx_index = 1453), Err(SpvError::NotInBlock));
        assert_eq!(
            check(|p| p.tx_index |= 1 << 12),
            Err(SpvError::IndexOutOfRange)
        );
        assert_eq!(
            check(|p| p.merkle_branch[3][0] ^= 1),
            Err(SpvError::NotInBlock)
        );
        assert_eq!(
            check(|p| p.tx.output[0].value += bitcoin::Amount::ONE_SAT),
            Err(SpvError::NotInBlock)
        );
        assert_eq!(check(|p| p.vout = 2), Err(SpvError::NoSuchOutput));
    }
}
