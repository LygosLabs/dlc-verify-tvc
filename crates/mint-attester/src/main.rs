//! Lygos mint attester TVC binary.

use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use mint_attester::{
    midnight::OracleKeys,
    service::{Config, parse_network, router},
};
use qos_p256::P256Pair;
use std::io;
use tracing_subscriber::EnvFilter;

/// Lygos mint attester TVC application. Every argument is fixed by the QOS manifest.
#[derive(Debug, Parser)]
#[command(name = "mint-attester", version)]
struct Cli {
    /// Address on which the enclave service listens.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// Port exposed by the TVC application.
    #[arg(long, default_value = "3000")]
    port: u16,
    /// QOS-managed quorum key; its signing half is the `Verifier` contract's signer.
    #[arg(long, default_value = qos_core::QUORUM_FILE)]
    quorum_file: String,
    /// Bitcoin network: mainnet, testnet, testnet4, signet (alias mutinynet), or regtest.
    #[arg(long, value_parser = parse_network)]
    network: bitcoin::Network,
    /// The Lygos Fordefi vault's Bitcoin key, compressed hex. Every DLC's accepter must be this
    /// key, and its CET adaptor and refund signatures are checked under it.
    #[arg(long)]
    lygos_funding_pubkey: PublicKey,
    /// The Midnight oracle's keys, one per calendar quarter, in orange-grove's
    /// `MIDNIGHT_ORACLE_KEYS` format: comma-separated `keyVersion:xonlyHex`, e.g.
    /// `midnight-2027Q1-mainnet-v1:<key>`.
    #[arg(long)]
    midnight_oracle_keys: OracleKeys,
    /// Sign receipts on a network other than mainnet, whose proof of work is free to forge.
    #[arg(long, default_value_t = false)]
    allow_insecure_network: bool,
    /// Fewest headers after the funding block's that must confirm it before a receipt is signed.
    /// At least 1: an unconfirmed lock is never attested.
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(1..))]
    min_confirmations: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let quorum_key = P256Pair::from_hex_file(cli.quorum_file)
        .map_err(|error| io::Error::other(format!("failed to load quorum key: {error:?}")))?;
    let app = router(Config {
        network: cli.network,
        lygos_funding_pubkey: cli.lygos_funding_pubkey,
        oracle_keys: cli.midnight_oracle_keys,
        key: quorum_key.signing_key().clone(),
        allow_insecure_network: cli.allow_insecure_network,
        min_confirmations: cli.min_confirmations,
    });

    let address = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Lygos mint attester listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::Cli;
    use clap::{Parser, error::ErrorKind};

    const ORACLE_KEYS: &str =
        "midnight-2026Q4-test-v1:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const LYGOS: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn parse(extra: &[&str]) -> Result<Cli, clap::Error> {
        let base = ["mint-attester", "--midnight-oracle-keys", ORACLE_KEYS];
        Cli::try_parse_from(base.iter().chain(extra))
    }

    #[test]
    fn every_network_needs_the_funding_key_and_names_itself() {
        let refused = |extra: &[&str]| parse(extra).expect_err("refused").kind();
        assert_eq!(
            refused(&["--lygos-funding-pubkey", LYGOS]),
            ErrorKind::MissingRequiredArgument
        );
        for network in ["mainnet", "mutinynet"] {
            assert_eq!(
                refused(&["--network", network]),
                ErrorKind::MissingRequiredArgument,
                "{network}"
            );
            let cli = parse(&["--network", network, "--lygos-funding-pubkey", LYGOS])
                .expect("a pinned launch");
            assert_eq!(cli.lygos_funding_pubkey.to_string(), LYGOS);
        }
        assert_eq!(
            refused(&["--network", "mainnet", "--lygos-funding-pubkey", "02ab"]),
            ErrorKind::ValueValidation
        );
    }

    #[test]
    fn an_unconfirmed_lock_is_never_enough() {
        let pinned = ["--network", "mutinynet", "--lygos-funding-pubkey", LYGOS];
        let with = |confirmations: &str| {
            parse(&[&pinned[..], &["--min-confirmations", confirmations]].concat())
        };
        assert_eq!(
            with("0").expect_err("zero confirmations").kind(),
            ErrorKind::ValueValidation
        );
        assert_eq!(with("1").expect("one").min_confirmations, 1);
        assert_eq!(parse(&pinned).expect("default").min_confirmations, 6);
    }
}
