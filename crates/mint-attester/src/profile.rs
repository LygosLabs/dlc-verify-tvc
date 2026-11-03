//! What one Lygos environment pins, and which environments may share an enclave.
//!
//! An enclave serves one or more profiles under one quorum key. Each profile names the `Verifier`
//! it signs for, so a request is routed by the receipt's signing domain, `(chainId, verifier)`,
//! and every check after that uses the routed profile's pins alone. Test environments share an
//! enclave to save its cost; mainnet runs alone.

use crate::{midnight::OracleKeys, service::parse_address, service::parse_network};
use bitcoin::{Network, secp256k1::PublicKey};
use serde::Deserialize;
use std::collections::BTreeSet;

/// The `Verifier` a profile signs receipts for, and the `Originator` that consumes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Destination {
    /// EVM chain of the `Verifier` and `Originator`.
    pub chain_id: u64,
    /// The `Verifier` address: with `chain_id`, the receipt's EIP-712 domain.
    pub verifier: [u8; 20],
    /// The `Originator` proxy. `OriginatorExt` is never one: it only runs by delegatecall, so a
    /// receipt's originator is always the proxy.
    pub originator: [u8; 20],
}

/// One environment's pins. All of it comes from launch arguments the QOS manifest measures.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Name, for logs and `/health`.
    pub name: String,
    /// Bitcoin network the locks are on.
    pub network: Network,
    /// The Midnight authorizer's EVM address: every DLC's `termsHash` must carry its signature.
    pub lygos_authorizer: [u8; 20],
    /// The Lygos Midnight funding key: every DLC's accepter must be this key. A Fordefi lender
    /// co-signs every DLC from one vault key, so production pins it. Staging co-signs with dlcd-rs,
    /// which derives a key per contract, so it runs without a pin. Mainnet will not start without
    /// one.
    pub lygos_funding_pubkey: Option<PublicKey>,
    /// The Midnight oracle's keys, one per calendar quarter. An announcement must be signed by
    /// the key of its market's maturity quarter.
    pub oracle_keys: OracleKeys,
    /// Sign receipts for a network whose proof of work is free to forge. Test deployments only.
    pub allow_insecure_network: bool,
    /// Fewest headers that must confirm the funding block before a receipt is signed. The SPV
    /// check proves work, not membership in the real chain, so this is the enclave's own floor on
    /// how much work a forged lock costs; the `Verifier` contract may require more.
    pub min_confirmations: u32,
    /// Where receipts may go. `None` signs for any `Verifier`, which only the single-profile
    /// flat flags allow, and never on mainnet.
    pub destination: Option<Destination>,
}

/// A `--profile` argument as JSON. Keys and addresses are strings parsed like the flat flags.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileJson {
    name: String,
    network: String,
    #[serde(default)]
    allow_insecure_network: bool,
    lygos_authorizer: String,
    #[serde(default)]
    lygos_funding_pubkey: Option<String>,
    midnight_oracle_keys: String,
    #[serde(default = "default_min_confirmations")]
    min_confirmations: u32,
    chain_id: u64,
    verifier: String,
    originator: String,
}

/// The confirmation floor when a launch does not set one.
pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;

const fn default_min_confirmations() -> u32 {
    DEFAULT_MIN_CONFIRMATIONS
}

/// Parse one `--profile` argument. A profile always names its destination.
///
/// # Errors
///
/// Fails for malformed JSON, an unknown field, or a value the flat flag would refuse.
pub fn parse_profile(raw: &str) -> Result<Profile, String> {
    let json: ProfileJson =
        serde_json::from_str(raw).map_err(|error| format!("invalid profile: {error}"))?;
    let at = |field: &str, error: String| format!("profile {:?}: {field}: {error}", json.name);
    Ok(Profile {
        network: parse_network(&json.network).map_err(|error| at("network", error))?,
        lygos_authorizer: parse_address(&json.lygos_authorizer)
            .map_err(|error| at("lygosAuthorizer", error))?,
        lygos_funding_pubkey: json
            .lygos_funding_pubkey
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|error| at("lygosFundingPubkey", format!("{error}")))?,
        oracle_keys: json
            .midnight_oracle_keys
            .parse()
            .map_err(|error| at("midnightOracleKeys", error))?,
        allow_insecure_network: json.allow_insecure_network,
        min_confirmations: json.min_confirmations,
        destination: Some(Destination {
            chain_id: json.chain_id,
            verifier: parse_address(&json.verifier).map_err(|error| at("verifier", error))?,
            originator: parse_address(&json.originator).map_err(|error| at("originator", error))?,
        }),
        name: json.name,
    })
}

/// Check a set of profiles may run together in one enclave.
///
/// - At least one, with distinct non-empty names.
/// - A mainnet profile runs alone, pins the Lygos funding key and its destination, and is not
///   marked insecure.
/// - Several profiles each pin a destination, and no two share a `(chainId, verifier)`, so every
///   receipt domain routes to exactly one profile.
///
/// # Errors
///
/// Returns the first rule broken.
pub fn validate(profiles: &[Profile]) -> Result<(), String> {
    if profiles.is_empty() {
        return Err("no profile is configured".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for profile in profiles {
        if profile.name.is_empty() {
            return Err("a profile has an empty name".to_owned());
        }
        if !names.insert(profile.name.as_str()) {
            return Err(format!("profile {:?} is configured twice", profile.name));
        }
        if profile.network == Network::Bitcoin {
            if profiles.len() > 1 {
                return Err(format!(
                    "mainnet profile {:?} must be the enclave's only profile",
                    profile.name
                ));
            }
            if profile.lygos_funding_pubkey.is_none() {
                return Err("a mainnet profile must pin the Lygos funding key".to_owned());
            }
            if profile.destination.is_none() {
                return Err(
                    "a mainnet profile must pin its chainId, verifier and originator".to_owned(),
                );
            }
            if profile.allow_insecure_network {
                return Err("a mainnet profile cannot allow an insecure network".to_owned());
            }
        }
        match profile.destination {
            Some(destination) => {
                if !domains.insert((destination.chain_id, destination.verifier)) {
                    return Err(format!(
                        "two profiles sign for verifier 0x{} on chain {}",
                        hex::encode(destination.verifier),
                        destination.chain_id
                    ));
                }
            }
            None if profiles.len() > 1 => {
                return Err(format!(
                    "profile {:?} shares the enclave, so it must pin its chainId, verifier and originator",
                    profile.name
                ));
            }
            None => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const KEYS: &str =
        "midnight-2026Q4-test-v1:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const LYGOS: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn json(name: &str, network: &str, verifier: &str) -> String {
        format!(
            r#"{{"name":"{name}","network":"{network}","allowInsecureNetwork":true,
                "lygosAuthorizer":"0x1111111111111111111111111111111111111111",
                "midnightOracleKeys":"{KEYS}","chainId":84532,
                "verifier":"{verifier}","originator":"0x2222222222222222222222222222222222222222"}}"#
        )
    }

    fn profile(name: &str, network: &str, verifier: &str) -> Profile {
        parse_profile(&json(name, network, verifier)).expect("profile")
    }

    fn mainnet() -> Profile {
        Profile {
            allow_insecure_network: false,
            lygos_funding_pubkey: Some(LYGOS.parse().expect("key")),
            ..profile(
                "production",
                "mainnet",
                "0x3333333333333333333333333333333333333333",
            )
        }
    }

    #[test]
    fn parses_a_profile_with_defaults() {
        let parsed = profile(
            "staging",
            "mutinynet",
            "0xb468495e3A960E3fB95694d9f0400cba4AD3e0f6",
        );
        assert_eq!(parsed.network, Network::Signet);
        assert_eq!(parsed.min_confirmations, DEFAULT_MIN_CONFIRMATIONS);
        assert!(parsed.lygos_funding_pubkey.is_none());
        let destination = parsed.destination.expect("pinned");
        assert_eq!(destination.chain_id, 84532);
        assert_eq!(destination.verifier[0], 0xb4);
    }

    #[test]
    fn refuses_a_malformed_profile() {
        let unknown = json(
            "x",
            "testnet4",
            "0x3333333333333333333333333333333333333333",
        )
        .replacen('{', r#"{"extra":1,"#, 1);
        assert!(parse_profile(&unknown).is_err());
        let zero = json(
            "x",
            "testnet4",
            "0x0000000000000000000000000000000000000000",
        );
        assert!(parse_profile(&zero).expect_err("zero").contains("verifier"));
        let no_destination = r#"{"name":"x","network":"testnet4","lygosAuthorizer":"0x1111111111111111111111111111111111111111","midnightOracleKeys":"bad"}"#;
        assert!(parse_profile(no_destination).is_err());
    }

    #[test]
    fn staging_and_testnet4_share_an_enclave() {
        let staging = profile(
            "staging",
            "mutinynet",
            "0xb468495e3A960E3fB95694d9f0400cba4AD3e0f6",
        );
        let testnet4 = profile(
            "testnet4",
            "testnet4",
            "0x33D4E3058FB653D9263CbC1ca51CF146Cd282E58",
        );
        assert_eq!(validate(&[staging, testnet4]), Ok(()));
    }

    #[test]
    fn mainnet_runs_alone_and_fully_pinned() {
        assert_eq!(validate(&[mainnet()]), Ok(()));
        let other = profile(
            "staging",
            "mutinynet",
            "0x4444444444444444444444444444444444444444",
        );
        for set in [vec![mainnet(), other.clone()], vec![other, mainnet()]] {
            let error = validate(&set).expect_err("mainnet shares");
            assert!(error.contains("only profile"), "{error}");
        }
        let unpinned_key = Profile {
            lygos_funding_pubkey: None,
            ..mainnet()
        };
        assert!(validate(&[unpinned_key]).is_err());
        let unpinned_destination = Profile {
            destination: None,
            ..mainnet()
        };
        assert!(validate(&[unpinned_destination]).is_err());
        let insecure = Profile {
            allow_insecure_network: true,
            ..mainnet()
        };
        assert!(validate(&[insecure]).is_err());
    }

    #[test]
    fn shared_profiles_route_to_exactly_one() {
        let verifier = "0x4444444444444444444444444444444444444444";
        let error = validate(&[
            profile("a", "mutinynet", verifier),
            profile("b", "testnet4", verifier),
        ])
        .expect_err("one domain, two profiles");
        assert!(error.contains("two profiles sign"), "{error}");
        let error = validate(&[
            profile("a", "mutinynet", verifier),
            profile(
                "a",
                "testnet4",
                "0x5555555555555555555555555555555555555555",
            ),
        ])
        .expect_err("duplicate name");
        assert!(error.contains("twice"), "{error}");
        let unpinned = Profile {
            destination: None,
            ..profile("a", "regtest", verifier)
        };
        assert_eq!(validate(std::slice::from_ref(&unpinned)), Ok(()));
        let error = validate(&[
            unpinned,
            profile(
                "b",
                "testnet4",
                "0x5555555555555555555555555555555555555555",
            ),
        ])
        .expect_err("an unpinned profile cannot share");
        assert!(error.contains("must pin"), "{error}");
        assert!(validate(&[]).is_err());
    }
}
