//! Lygos mint attester TVC binary.

use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use mint_attester::{
    midnight::OracleKeys,
    service::{Config, parse_address, parse_network, router},
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
    /// Bitcoin network: mainnet, testnet, testnet4, signet (alias mutinynet), or regtest. No
    /// default, so a mainnet enclave names its network and cannot skip the funding key pin.
    #[arg(long, value_parser = parse_network)]
    network: bitcoin::Network,
    /// The Midnight authorizer's EVM address, which signs every Midnight DLC's offer and accept.
    #[arg(long, value_parser = parse_address)]
    lygos_authorizer: [u8; 20],
    /// The Lygos Midnight funding key every DLC's accepter must use, compressed hex. Required on
    /// mainnet; staging omits it because dlcd-rs derives a funding key per contract.
    #[arg(long, required_if_eq("network", "mainnet"))]
    lygos_funding_pubkey: Option<PublicKey>,
    /// The Midnight oracle's keys, one per calendar quarter, in orange-grove's
    /// `MIDNIGHT_ORACLE_KEYS` format: comma-separated `keyVersion:xonlyHex`, e.g.
    /// `midnight-2027Q1-mainnet-v1:<key>`.
    #[arg(long)]
    midnight_oracle_keys: OracleKeys,
    /// Sign receipts on a network other than mainnet, whose proof of work is free to forge.
    #[arg(long, default_value_t = false)]
    allow_insecure_network: bool,
    /// Fewest headers that must confirm the funding block before a receipt is signed.
    #[arg(long, default_value_t = 6)]
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
        lygos_authorizer: cli.lygos_authorizer,
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

    const AUTHORIZER: &str = "0x1111111111111111111111111111111111111111";
    const ORACLE_KEYS: &str =
        "midnight-2026Q4-test-v1:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const LYGOS: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn parse(extra: &[&str]) -> Result<Cli, clap::Error> {
        let base = [
            "mint-attester",
            "--lygos-authorizer",
            AUTHORIZER,
            "--midnight-oracle-keys",
            ORACLE_KEYS,
        ];
        Cli::try_parse_from(base.iter().chain(extra))
    }

    #[test]
    fn mainnet_needs_the_funding_key_and_every_launch_names_its_network() {
        let missing = |extra: &[&str]| parse(extra).expect_err("refused").kind();
        assert_eq!(missing(&[]), ErrorKind::MissingRequiredArgument);
        assert_eq!(
            missing(&["--network", "mainnet"]),
            ErrorKind::MissingRequiredArgument
        );
        let mainnet = parse(&["--network", "mainnet", "--lygos-funding-pubkey", LYGOS])
            .expect("mainnet with a pin");
        assert_eq!(mainnet.network, bitcoin::Network::Bitcoin);
        assert!(mainnet.lygos_funding_pubkey.is_some());
        let staging = parse(&["--network", "mutinynet"]).expect("staging needs no pin");
        assert!(staging.lygos_funding_pubkey.is_none());
    }
}
