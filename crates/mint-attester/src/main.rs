//! Lygos mint attester TVC binary.

use clap::Parser;
use mint_attester::{
    cli::Cli,
    service::{Config, router},
};
use qos_p256::P256Pair;
use std::io;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    // The profiles are checked before the key is touched: a set that may not share an enclave,
    // such as mainnet beside a test network, never starts.
    let profiles = cli.profiles().map_err(io::Error::other)?;
    let quorum_key = P256Pair::from_hex_file(&cli.quorum_file)
        .map_err(|error| io::Error::other(format!("failed to load quorum key: {error:?}")))?;
    let names: Vec<&str> = profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    tracing::info!("serving profiles {names:?}");
    let app =
        router(Config::new(quorum_key.signing_key().clone(), profiles).map_err(io::Error::other)?);

    let address = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Lygos mint attester listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}
