//! Lygos DLC verifier TVC binary.

use clap::Parser;
use dlc_verify_tvc::{AppState, cli::Cli, router};
use metrics::MetricsLayer;
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
    let ephemeral_key = P256Pair::from_hex_file(cli.ephemeral_file)
        .map_err(|error| io::Error::other(format!("failed to load ephemeral key: {error:?}")))?;
    let metrics_layer = MetricsLayer::builder().namespace("tvc").build()?;
    let collector = metrics_layer.collector();
    let app = router::router_with_state(AppState::new(ephemeral_key))
        .layer(metrics_layer)
        .route("/metrics", metrics::handler(collector));

    let address = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Lygos DLC verifier listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}
