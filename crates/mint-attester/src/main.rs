//! Lygos mint attester TVC binary.

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use clap::Parser;
use mint_attester::service::{Config, parse_network, router};
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
    /// Bitcoin network: mainnet, testnet, testnet4, or regtest.
    #[arg(long, default_value = "mainnet", value_parser = parse_network)]
    network: bitcoin::Network,
    /// The Midnight Lygos funding key, compressed hex.
    #[arg(long)]
    lygos_funding_pubkey: PublicKey,
    /// The Midnight oracle's x-only public key, hex.
    #[arg(long)]
    oracle_pubkey: XOnlyPublicKey,
    /// Sign receipts on a network other than mainnet, whose proof of work is free to forge.
    #[arg(long, default_value_t = false)]
    allow_insecure_network: bool,
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
        lygos_funding_pubkey: cli.lygos_funding_pubkey.to_string(),
        oracle_pubkey: cli.oracle_pubkey.to_string(),
        key: quorum_key.signing_key().clone(),
        allow_insecure_network: cli.allow_insecure_network,
    });

    let address = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Lygos mint attester listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}
