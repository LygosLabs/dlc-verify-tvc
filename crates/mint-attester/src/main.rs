//! Lygos mint attester TVC binary.

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
    /// Bitcoin network: mainnet, testnet, testnet4, signet (alias mutinynet), or regtest.
    #[arg(long, default_value = "mainnet", value_parser = parse_network)]
    network: bitcoin::Network,
    /// The Midnight authorizer's EVM address, which signs every Midnight DLC's terms.
    #[arg(long, value_parser = parse_address)]
    lygos_authorizer: [u8; 20],
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
