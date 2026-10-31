//! The Midnight authorization: the Lygos authorizer's EIP-712 signature over a DLC's offer and
//! accept.
//!
//! Lygos funds every DLC from a fresh key, so the enclave pins who may approve a Midnight DLC
//! rather than which key funds it. See WP §5. The offer and accept fix everything `termsHash`
//! names (the funding outpoint, both funding keys, the announcement, every CET and the refund),
//! and unlike `termsHash` they exist before any verification, so the enclave checks the approval
//! first and spends nothing on a request Lygos did not approve.

use crate::{
    keccak,
    receipt::{DOMAIN_TYPE, word},
};
use secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use sha2::{Digest, Sha256};

const AUTHORIZATION_TYPE: &[u8] = b"MidnightAuthorization(bytes32 offerHash,bytes32 acceptHash)";

/// A message's hash in the authorization: SHA-256 of its raw bytes, not of its hex.
#[must_use]
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

/// The EIP-712 digest the authorizer signs: `MidnightAuthorization(offerHash, acceptHash)` under
/// the domain `("Lygos Midnight Authorizer", "1", chainId, originator)`, each hash a
/// [`message_hash`].
#[must_use]
pub fn digest(
    chain_id: u64,
    originator: &[u8; 20],
    offer_hash: &[u8; 32],
    accept_hash: &[u8; 32],
) -> [u8; 32] {
    let domain_separator = keccak(&[
        &keccak(&[DOMAIN_TYPE]),
        &keccak(&[b"Lygos Midnight Authorizer"]),
        &keccak(&[b"1"]),
        &word(&chain_id.to_be_bytes()),
        &word(originator),
    ]);
    let struct_hash = keccak(&[&keccak(&[AUTHORIZATION_TYPE]), offer_hash, accept_hash]);
    keccak(&[b"\x19\x01", &domain_separator, &struct_hash])
}

/// The address that signed `digest`, from a 65-byte `r ‖ s ‖ v` signature, `v` 27/28 or 0/1.
///
/// # Errors
///
/// Fails when the signature does not parse or recovers no key.
pub fn signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], String> {
    let v = match signature[64] {
        v @ (27 | 28) => v - 27,
        v @ (0 | 1) => v,
        _ => return Err("the authorization's v must be 27, 28, 0 or 1".to_owned()),
    };
    let signature = RecoveryId::from_i32(i32::from(v))
        .and_then(|id| RecoverableSignature::from_compact(&signature[..64], id))
        .map_err(|error| format!("invalid authorization: {error}"))?;
    let key = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(*digest), &signature)
        .map_err(|error| format!("invalid authorization: {error}"))?;
    let hash = keccak(&[&key.serialize_uncompressed()[1..]]);
    let mut address = [0; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

/// Sign `digest` as the authorizer would, `v` as 27/28.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn sign(digest: &[u8; 32], secret: &[u8; 32]) -> [u8; 65] {
    let key = secp256k1::SecretKey::from_slice(secret).expect("key");
    let (id, compact) = Secp256k1::signing_only()
        .sign_ecdsa_recoverable(&Message::from_digest(*digest), &key)
        .serialize_compact();
    let mut signature = [0; 65];
    signature[..64].copy_from_slice(&compact);
    signature[64] = 27 + u8::try_from(id.to_i32()).expect("0 or 1");
    signature
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Anvil's first account.
    pub const AUTHORIZER: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    /// `cast wallet sign --data` of `MidnightAuthorization(0xabab…, 0xcdcd…)` on chain 8453 with
    /// `verifyingContract` 0x5656…, by Anvil's first key. Pins the digest and the recovery
    /// against an independent EIP-712 implementation.
    #[test]
    fn recovers_a_cast_signature() {
        let signature: [u8; 65] = hex::decode("40281d8e49e0f75a7b4bc12b14e9c11bbb81bc7ab98dceaa65a11c66b09097fd18d450555df544a7b5087496904be632f3a2338268f508f53f5609a5cb4e11a81b")
            .expect("hex")
            .try_into()
            .expect("65 bytes");
        let digest = digest(8453, &[0x56; 20], &[0xab; 32], &[0xcd; 32]);
        assert_eq!(
            hex::encode(signer(&digest, &signature).expect("signer")),
            AUTHORIZER
        );

        let mut zero_one = signature;
        zero_one[64] -= 27;
        assert_eq!(
            hex::encode(signer(&digest, &zero_one).expect("signer")),
            AUTHORIZER
        );

        // Another originator, or the two hashes swapped, is another approval.
        for other in [
            super::digest(8453, &[0x57; 20], &[0xab; 32], &[0xcd; 32]),
            super::digest(8453, &[0x56; 20], &[0xcd; 32], &[0xab; 32]),
        ] {
            assert_ne!(
                hex::encode(signer(&other, &signature).expect("signer")),
                AUTHORIZER
            );
        }
        let mut bad_v = signature;
        bad_v[64] = 29;
        assert!(signer(&digest, &bad_v).is_err());
    }

    /// The hash is over the raw bytes: the hex spelling of a message is not what is approved.
    #[test]
    fn a_message_hash_is_sha256_of_its_bytes() {
        assert_eq!(
            hex::encode(message_hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(message_hash(&[0xab]), message_hash(b"ab"));
    }

    #[test]
    fn sign_round_trips() {
        let digest = digest(1, &[1; 20], &[2; 32], &[3; 32]);
        let a = signer(&digest, &sign(&digest, &[5; 32])).expect("signer");
        let b = signer(&digest, &sign(&digest, &[6; 32])).expect("signer");
        assert_ne!(a, b);
    }
}
