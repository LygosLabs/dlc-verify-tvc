//! Lygos mint attester: checks a Midnight DLC and its Bitcoin lock, then signs the receipt
//! `Verifier.sol` accepts.

pub mod midnight;
pub mod receipt;
pub mod service;
pub mod spv;

use sha3::{Digest, Keccak256};

pub(crate) fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
