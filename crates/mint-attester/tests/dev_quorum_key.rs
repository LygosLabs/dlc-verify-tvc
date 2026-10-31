//! The dev-only quorum key the orange-grove dev stack runs the attester with.
#![allow(clippy::expect_used)]

use qos_p256::P256Pair;

/// The file is a QOS master seed; QOS derives the signing key from it. The dev stack deploys
/// the `Verifier` with this scalar (`ENCLAVE_P256_KEY`), or with x and y (`ENCLAVE_X`,
/// `ENCLAVE_Y`), so a change to the file or to the derivation must change the README too.
#[test]
fn the_dev_quorum_key_signs_with_the_documented_scalar() {
    let key = P256Pair::from_hex_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dev/mint-attester/dev-only-quorum.key"
    ))
    .expect("dev quorum key");
    let signing = key.signing_key();
    let point = signing.verifying_key().to_encoded_point(false);
    assert_eq!(
        hex::encode(signing.to_bytes()),
        "1c61464af96b6a97655f9a0c51bf5c59ef12a98f56c216e14360875ebb70aa2e"
    );
    assert_eq!(
        hex::encode(point.x().expect("x")),
        "eab1fb2e525b4744a49e099469697402f422646db4747e0cb2340d35c3b0b9c1"
    );
    assert_eq!(
        hex::encode(point.y().expect("y")),
        "4b839e4f3117435cdc62dd8e63c147130f8adef488482af54746e591b4c35941"
    );
}
