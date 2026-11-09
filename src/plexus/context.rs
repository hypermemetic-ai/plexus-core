//! Global Plexus RPC context for sharing state with activations
//!
//! This module provides a thread-safe way to share the Plexus RPC server hash
//! with all activations. The hash is set once during hub initialization
//! and can be read by any activation when creating stream items.

use std::sync::RwLock;

/// Global Plexus RPC context: the hash set once at the service's start
/// (NEST-15: and moved when that service's root changes while it serves).
static PLEXUS_CONTEXT: RwLock<Option<String>> = RwLock::new(None);

/// Shared Plexus RPC context accessible to all activations
#[derive(Debug, Clone)]
pub struct PlexusContext {
    /// Hash of all activations for cache invalidation
    pub hash: String,
}

impl PlexusContext {
    /// Initialize the global Plexus RPC context
    ///
    /// This should be called once during hub initialization.
    /// Subsequent calls will be ignored.
    pub fn init(hash: String) {
        let mut ctx = PLEXUS_CONTEXT.write().unwrap_or_else(|p| p.into_inner());
        if ctx.is_none() {
            *ctx = Some(hash);
        }
    }

    /// NEST-15: the service whose hash was `from` now serves `to` (its
    /// root's table changed): items carry `to` from now on. A hash another
    /// service set is left as it is.
    pub(crate) fn moved(from: &str, to: &str) {
        let mut ctx = PLEXUS_CONTEXT.write().unwrap_or_else(|p| p.into_inner());
        if ctx.as_deref() == Some(from) {
            *ctx = Some(to.to_string());
        }
    }

    /// Get the global Plexus RPC server hash
    ///
    /// Returns an empty string if the context hasn't been initialized yet.
    pub fn hash() -> String {
        PLEXUS_CONTEXT.read().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default()
    }
}
