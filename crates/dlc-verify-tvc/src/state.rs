//! Immutable process state.

use qos_p256::P256Pair;
use std::sync::Arc;

/// Shared application state containing the QOS-managed ephemeral proof key.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
}

impl AppState {
    /// Create state from the QOS-managed ephemeral key.
    #[must_use]
    pub fn new(ephemeral_key: P256Pair) -> Self {
        Self {
            ephemeral_key: Arc::new(ephemeral_key),
        }
    }
}
