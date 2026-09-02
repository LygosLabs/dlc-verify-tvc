//! HTTP boundary for the deterministic Lygos DLC verifier running in TVC.

pub mod cli;
mod handler;
pub mod router;
mod state;

pub use state::AppState;
