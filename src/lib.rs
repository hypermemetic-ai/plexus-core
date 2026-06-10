//! Hub Core - Core infrastructure for building Plexus RPC servers
//!
//! This crate provides:
//! - `DynamicHub` - Dynamic routing hub for activations (implements Plexus RPC protocol)
//! - `Activation` - Trait for implementing activations
//! - `PlexusMcpBridge` - MCP server integration
//! - `Handle` - Typed references to activation method results
//!
//! # Example
//!
//! ```rust,no_run
//! use plexus_core::plexus::DynamicHub;
//! use plexus_core::activations::echo::Echo;
//! use plexus_core::activations::health::Health;
//! use std::sync::Arc;
//!
//! let hub = Arc::new(
//!     DynamicHub::new("myapp")
//!         .register(Health::new())
//!         .register(Echo::new())
//! );
//! ```

/// Crate version, populated at compile time from `CARGO_PKG_VERSION`.
///
/// Exposed so the `plexus-rpc` umbrella can stamp it into the
/// `Capabilities` manifest backends embed in `_info`. See UMB-2.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod activations;
pub mod builder;
pub mod mcp_bridge;
pub mod plexus;
pub mod plugin_system;
pub mod request;
pub mod serde_helpers;
pub mod types;

// Re-export commonly used items
pub use builder::build_example_hub;
pub use mcp_bridge::PlexusMcpBridge;
#[allow(deprecated)]
pub use plexus::{
    Activation, AuthzDenyReason, ChildCapabilities, ChildRouter, DeprecationInfo, DynamicHub,
    MethodRole, PlexusError, ReturnShape, PLEXUS_NOTIF_METHOD,
};
pub use types::{Envelope, Handle, HandleParseError, HandleResolutionParams, Origin};

// Re-export schemars under a stable private path so PlexusRequest derive-generated code
// can reference the real schemars::JsonSchema trait without requiring the caller to have
// schemars in their own dependencies.
#[doc(hidden)]
pub use schemars as __schemars;

// Proc-macro re-exports.
// Use as `plexus_core::activation` / `plexus_core::method`, or via a
// `plexus = { package = "plexus-core" }` Cargo alias as `plexus::activation` / `plexus::method`.
pub use plexus_macros::activation;
pub use plexus_macros::method;
#[allow(deprecated)]
#[deprecated(since = "0.5.0", note = "Use `plexus_core::activation` instead")]
pub use plexus_macros::hub_methods;
#[allow(deprecated)]
#[deprecated(since = "0.5.0", note = "Use `plexus_core::method` instead")]
pub use plexus_macros::hub_method;
