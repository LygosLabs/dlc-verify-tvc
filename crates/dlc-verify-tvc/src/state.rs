//! Immutable process state.

use qos_p256::P256Pair;
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_VERIFICATIONS: usize = 8;

/// Shared application state containing the QOS-managed ephemeral proof key.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
    /// Held by the blocking task itself so an HTTP timeout cannot prematurely
    /// release computational capacity while the task continues running.
    pub(crate) verifier_permits: Arc<Semaphore>,
}

impl AppState {
    /// Create state from the QOS-managed ephemeral key.
    #[must_use]
    pub fn new(ephemeral_key: P256Pair) -> Self {
        Self {
            ephemeral_key: Arc::new(ephemeral_key),
            verifier_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
        }
    }
}
