//! Launch arguments. Every one is fixed by the QOS manifest.

use crate::{
    midnight::OracleKeys,
    profile::{DEFAULT_MIN_CONFIRMATIONS, Profile, parse_profile, validate},
    service::{parse_address, parse_network},
};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

/// Lygos mint attester TVC application.
///
/// Either one or more `--profile`s, each pinning the `Verifier` it signs for, or the flat flags
/// for a single profile that signs for any `Verifier`, which local runs use. Mainnet takes
/// exactly one `--profile`.
#[derive(Debug, Parser)]
#[command(name = "mint-attester", version)]
pub struct Cli {
    /// Address on which the enclave service listens.
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    /// Port exposed by the TVC application.
    #[arg(long, default_value = "3000")]
    pub port: u16,
    /// QOS-managed quorum key; its signing half is every profile's `Verifier` signer.
    #[arg(long, default_value = qos_core::QUORUM_FILE)]
    pub quorum_file: String,
    /// One environment the enclave serves, as JSON: `name`, `network`, `lygosAuthorizer`,
    /// `midnightOracleKeys`, `chainId`, `verifier`, `originator`, and optionally
    /// `lygosFundingPubkey`, `allowInsecureNetwork` and `minConfirmations`. Repeat for each
    /// environment sharing the enclave; a mainnet profile must be the only one.
    #[arg(long = "profile", value_parser = parse_profile, conflicts_with_all = FLAT)]
    pub profiles: Vec<Profile>,
    /// Bitcoin network: mainnet, testnet, testnet4, signet (alias mutinynet), or regtest.
    #[arg(long, value_parser = parse_network, required_unless_present = "profiles")]
    pub network: Option<bitcoin::Network>,
    /// The Midnight authorizer's EVM address, which signs every Midnight DLC's terms.
    #[arg(long, value_parser = parse_address, required_unless_present = "profiles")]
    pub lygos_authorizer: Option<[u8; 20]>,
    /// The Lygos Midnight funding key every DLC's accepter must use, compressed hex. Staging omits
    /// it because dlcd-rs derives a funding key per contract.
    #[arg(long)]
    pub lygos_funding_pubkey: Option<PublicKey>,
    /// The Midnight oracle's keys, one per calendar quarter, in orange-grove's
    /// `MIDNIGHT_ORACLE_KEYS` format: comma-separated `keyVersion:xonlyHex`, e.g.
    /// `midnight-2027Q1-mainnet-v1:<key>`.
    #[arg(long, required_unless_present = "profiles")]
    pub midnight_oracle_keys: Option<OracleKeys>,
    /// Sign receipts on a network other than mainnet, whose proof of work is free to forge.
    #[arg(long, default_value_t = false)]
    pub allow_insecure_network: bool,
    /// Fewest headers that must confirm the funding block before a receipt is signed.
    #[arg(long, default_value_t = DEFAULT_MIN_CONFIRMATIONS)]
    pub min_confirmations: u32,
}

/// The single-profile flags `--profile` replaces.
const FLAT: [&str; 6] = [
    "network",
    "lygos_authorizer",
    "lygos_funding_pubkey",
    "midnight_oracle_keys",
    "allow_insecure_network",
    "min_confirmations",
];

impl Cli {
    /// The profiles this launch serves, checked to be allowed to share an enclave.
    ///
    /// # Errors
    ///
    /// Returns the rule in [`validate`] the profiles break; the flat flags on mainnet break one,
    /// because they pin no destination.
    pub fn profiles(&self) -> Result<Vec<Profile>, String> {
        let profiles =
            match (
                self.profiles.is_empty(),
                self.network,
                self.lygos_authorizer,
                &self.midnight_oracle_keys,
            ) {
                (false, ..) => self.profiles.clone(),
                (true, Some(network), Some(lygos_authorizer), Some(oracle_keys)) => vec![Profile {
                    name: network.to_string(),
                    network,
                    lygos_authorizer,
                    lygos_funding_pubkey: self.lygos_funding_pubkey,
                    oracle_keys: oracle_keys.clone(),
                    allow_insecure_network: self.allow_insecure_network,
                    min_confirmations: self.min_confirmations,
                    destination: None,
                }],
                _ => return Err(
                    "pass --profile, or --network, --lygos-authorizer and --midnight-oracle-keys"
                        .to_owned(),
                ),
            };
        validate(&profiles)?;
        Ok(profiles)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::Cli;
    use clap::{Parser, error::ErrorKind};

    const AUTHORIZER: &str = "0x1111111111111111111111111111111111111111";
    const ORACLE_KEYS: &str =
        "midnight-2026Q4-test-v1:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const LYGOS: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn flat(extra: &[&str]) -> Result<Cli, clap::Error> {
        let base = [
            "mint-attester",
            "--lygos-authorizer",
            AUTHORIZER,
            "--midnight-oracle-keys",
            ORACLE_KEYS,
        ];
        Cli::try_parse_from(base.iter().chain(extra))
    }

    fn profile(name: &str, network: &str, verifier: u8) -> String {
        format!(
            r#"{{"name":"{name}","network":"{network}","allowInsecureNetwork":true,
                "lygosAuthorizer":"{AUTHORIZER}","midnightOracleKeys":"{ORACLE_KEYS}",
                "chainId":84532,"verifier":"0x{v}","originator":"0x{v}"}}"#,
            v = format!("{verifier:02x}").repeat(20)
        )
    }

    #[test]
    fn flat_flags_name_their_network_and_never_run_mainnet() {
        assert_eq!(
            flat(&[]).expect_err("no network").kind(),
            ErrorKind::MissingRequiredArgument
        );
        let staging = flat(&["--network", "mutinynet", "--allow-insecure-network"])
            .expect("flags")
            .profiles()
            .expect("staging needs no pin");
        assert_eq!(staging.len(), 1);
        assert!(staging[0].destination.is_none());
        let mainnet = flat(&["--network", "mainnet", "--lygos-funding-pubkey", LYGOS])
            .expect("flags")
            .profiles()
            .expect_err("mainnet pins a destination");
        assert!(
            mainnet.contains("chainId, verifier and originator"),
            "{mainnet}"
        );
    }

    #[test]
    fn profiles_share_and_exclude_the_flat_flags() {
        let staging = profile("staging", "mutinynet", 0x11);
        let testnet4 = profile("testnet4", "testnet4", 0x22);
        let cli = Cli::try_parse_from([
            "mint-attester",
            "--profile",
            &staging,
            "--profile",
            &testnet4,
        ])
        .expect("two profiles");
        let names: Vec<_> = cli
            .profiles()
            .expect("they share")
            .into_iter()
            .map(|profile| profile.name)
            .collect();
        assert_eq!(names, ["staging", "testnet4"]);

        for flag in [
            &["--network", "testnet4"][..],
            &["--allow-insecure-network"],
            &["--min-confirmations", "1"],
        ] {
            let error =
                Cli::try_parse_from(["mint-attester", "--profile", &staging].iter().chain(flag))
                    .expect_err("flat flags conflict");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn mainnet_takes_one_profile() {
        let mainnet = format!(
            r#"{{"name":"production","network":"mainnet","lygosAuthorizer":"{AUTHORIZER}",
                "lygosFundingPubkey":"{LYGOS}","midnightOracleKeys":"{ORACLE_KEYS}",
                "chainId":8453,"verifier":"0x{v}","originator":"0x{v}"}}"#,
            v = "33".repeat(20)
        );
        let alone = Cli::try_parse_from(["mint-attester", "--profile", &mainnet]).expect("cli");
        assert_eq!(alone.profiles().expect("alone").len(), 1);
        let shared = Cli::try_parse_from([
            "mint-attester",
            "--profile",
            &mainnet,
            "--profile",
            &profile("staging", "mutinynet", 0x11),
        ])
        .expect("cli");
        assert!(
            shared
                .profiles()
                .expect_err("shared")
                .contains("only profile")
        );
    }
}
