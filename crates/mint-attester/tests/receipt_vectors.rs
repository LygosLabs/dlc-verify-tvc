//! Golden vectors copied from `lygos-contracts/test/fixtures/receipt_vectors.json`.
#![allow(clippy::expect_used, clippy::panic)]

use mint_attester::receipt::{Domain, Receipt, sign_digest};
use p256::ecdsa::SigningKey;
use serde_json::Value;

// `ENCLAVE_KEY` in gen_receipt_vectors.py. A test key, public in that repo.
const ENCLAVE_KEY: &str = "164dbd5822793c6ab36eab60cd94ec371762069f7907576d744d0671c8129905";

fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value.as_str().expect("hex string");
    hex::decode(&text[2..])
        .expect("hex")
        .try_into()
        .expect("length")
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("number")
}

#[test]
fn matches_contract_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/receipt_vectors.json")).expect("vectors");
    let key = SigningKey::from_slice(&hex::decode(ENCLAVE_KEY).expect("key")).expect("key");
    assert!(!vectors.is_empty());

    for vector in &vectors {
        let name = vector["name"].as_str().expect("name");
        let receipt = Receipt {
            claim_id: bytes(&vector["claimId"]),
            terms_hash: bytes(&vector["termsHash"]),
            event_id: bytes(&vector["eventId"]),
            market_id: bytes(&vector["marketId"]),
            controller: bytes(&vector["controller"]),
            sats: number(&vector["sats"]),
            confirmations: u32::try_from(number(&vector["confirmations"])).expect("u32"),
            announced_at: number(&vector["announcedAt"]),
            expires_at: number(&vector["expiresAt"]),
            input_claim_ids: vector["inputClaimIds"]
                .as_array()
                .expect("inputs")
                .iter()
                .map(bytes)
                .collect(),
            chain_id: number(&vector["chainId"]),
            originator: bytes(&vector["originator"]),
        };
        // The generator fixes the Verifier's own chain at 31337 whatever the receipt says.
        let domain = Domain {
            chain_id: 31337,
            verifier: bytes(&vector["verifier"]),
        };

        let digest = receipt.digest(&domain);
        assert_eq!(digest, bytes::<32>(&vector["digest"]), "{name}: digest");

        // RFC 6979 makes signing deterministic, so the enclave key reproduces every signature the
        // contract accepts, and none of the ones it refuses.
        let signature = sign_digest(&key, &digest).expect("sign");
        let accepted = vector["valid"].as_bool().expect("valid")
            || !vector["rejectedBy"]
                .as_str()
                .expect("rejectedBy")
                .is_empty();
        assert_eq!(
            signature == bytes::<64>(&vector["signature"]),
            accepted,
            "{name}: signature"
        );
    }

    let point = key.verifying_key().to_encoded_point(false);
    assert_eq!(
        point.x().expect("x").as_slice(),
        bytes::<32>(&vectors[0]["signerX"])
    );
    assert_eq!(
        point.y().expect("y").as_slice(),
        bytes::<32>(&vectors[0]["signerY"])
    );
}
