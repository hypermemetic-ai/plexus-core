//! `ForwardPolicyRegistry` — per-hub map from callee namespace to the
//! [`ForwardPolicy`] that the framework consults when dispatching across the
//! boundary into that callee.
//!
//! AUTHLANG-3 wires this into the canonical edge-crossing point
//! ([`super::plexus::route_to_child`]). The registry holds
//! `Arc<dyn ForwardPolicy>` keyed by the lowercased callee namespace string
//! (matching the `child_routers` key convention on
//! [`super::plexus::DynamicHub`]). Without an entry, the framework treats the
//! lookup as "no opinion declared" and falls back to
//! [`plexus_auth_core::IdentityOnly`] — the safe default per the spike.
//!
//! AUTHLANG-4 (the `#[plexus::activation(forward_policy = ...)]` macro) is
//! the supported declarative path that populates the registry. Imperative
//! registration is intentionally exposed (via [`Self::register`]) so
//! integration tests and hand-rolled wiring can drive the same code path
//! without going through the macro.
//!
//! # Vocabulary
//!
//! Per AUTHZ-0: `caller` and `callee`, not `parent` and `child`. The
//! existing `ChildRouter` API name is preserved as legacy; the spike's
//! decision to keep that name is documented in
//! `plans/AUTHLANG/AUTHLANG-S01-output.md`.

use plexus_auth_core::ForwardPolicy;
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of [`ForwardPolicy`] implementations keyed by callee namespace.
///
/// `Clone` is cheap: every policy is wrapped in `Arc`, and the underlying
/// `HashMap` clones the key strings + the `Arc` handles. The registry is
/// designed to be built at hub-construction time and read at dispatch time;
/// mutating after the hub is shared across tasks requires going through
/// [`DynamicHub::with_forward_policy`](super::plexus::DynamicHub) at builder
/// time.
///
/// [`DynamicHub::with_forward_policy`]: super::plexus::DynamicHub::with_forward_policy
#[derive(Clone, Default)]
pub struct ForwardPolicyRegistry {
    inner: HashMap<String, Arc<dyn ForwardPolicy>>,
}

impl ForwardPolicyRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Register a policy for a callee namespace.
    ///
    /// The namespace is the same lowercased token used to look up
    /// [`super::plexus::ChildRouter::get_child`] (e.g. `"solar"`,
    /// `"echo"`). If a policy is already registered for the namespace, it
    /// is replaced.
    pub fn register(&mut self, callee_ns: impl Into<String>, policy: Arc<dyn ForwardPolicy>) {
        self.inner.insert(callee_ns.into(), policy);
    }

    /// Look up the policy declared for a callee namespace.
    ///
    /// Returns `None` when no policy is registered; the dispatch path
    /// interprets that as "fall back to [`plexus_auth_core::IdentityOnly`]"
    /// — the spike-pinned safe default.
    pub fn get(&self, callee_ns: &str) -> Option<Arc<dyn ForwardPolicy>> {
        self.inner.get(callee_ns).cloned()
    }

    /// Returns `true` when the registry contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of registered policies.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl std::fmt::Debug for ForwardPolicyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid printing the trait-object pointer; surface only the keys so
        // logs/snapshots stay deterministic.
        let mut keys: Vec<&String> = self.inner.keys().collect();
        keys.sort();
        f.debug_struct("ForwardPolicyRegistry")
            .field("entries", &keys)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plexus_auth_core::{Anonymous, IdentityOnly, PassThrough};

    #[test]
    fn empty_registry_returns_none_for_any_key() {
        let r = ForwardPolicyRegistry::new();
        assert!(r.is_empty());
        assert!(r.get("solar").is_none());
        assert!(r.get("nonexistent").is_none());
    }

    #[test]
    fn register_then_lookup_returns_arc() {
        let mut r = ForwardPolicyRegistry::new();
        r.register("solar", Arc::new(PassThrough));
        r.register("echo", Arc::new(Anonymous));
        assert_eq!(r.len(), 2);
        assert_eq!(r.get("solar").unwrap().name().as_str(), "pass_through");
        assert_eq!(r.get("echo").unwrap().name().as_str(), "anonymous");
        assert!(r.get("missing").is_none());
    }

    #[test]
    fn register_replaces_existing_entry() {
        let mut r = ForwardPolicyRegistry::new();
        r.register("solar", Arc::new(IdentityOnly));
        r.register("solar", Arc::new(PassThrough));
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("solar").unwrap().name().as_str(), "pass_through");
    }

    #[test]
    fn default_is_empty() {
        let r = ForwardPolicyRegistry::default();
        assert!(r.is_empty());
    }

    #[test]
    fn debug_lists_keys_alphabetically() {
        let mut r = ForwardPolicyRegistry::new();
        r.register("solar", Arc::new(PassThrough));
        r.register("echo", Arc::new(Anonymous));
        let dbg = format!("{:?}", r);
        // Keys are sorted in Debug so snapshots are stable.
        assert!(dbg.contains("echo"));
        assert!(dbg.contains("solar"));
        let echo_pos = dbg.find("echo").unwrap();
        let solar_pos = dbg.find("solar").unwrap();
        assert!(echo_pos < solar_pos);
    }
}
