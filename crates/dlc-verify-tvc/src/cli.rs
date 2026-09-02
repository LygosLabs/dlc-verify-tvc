//! Command-line arguments supplied by the QOS manifest.

use clap::Parser;

/// Lygos DLC verifier TVC application.
#[derive(Debug, Parser)]
#[command(name = "dlc-verify-tvc", version)]
pub struct Cli {
    /// Address on which the enclave service listens.
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    /// Port exposed by the TVC application.
    #[arg(long, default_value = "3000")]
    pub port: u16,
    /// QOS-managed ephemeral key used exclusively for App Proofs.
    #[arg(long, default_value = qos_core::EPHEMERAL_KEY_FILE)]
    pub ephemeral_file: String,
}
