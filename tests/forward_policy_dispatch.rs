//! AUTHLANG-3 — integration tests for the forwarding-policy dispatch
//! wire-in in [`plexus_core::plexus::route_to_child`].
//!
//! These tests stand up a two-node hub (caller activation + callee
//! activation) and assert that, when dispatching across the boundary, the
//! framework runs the registered [`plexus_auth_core::ForwardPolicy`] and
//! constructs the callee `AuthContext` via the framework-only
//! [`plexus_auth_core::AuthContext::derive_callee_context`] constructor.
//!
//! Coverage maps to AUTHLANG-3 §"Acceptance criteria":
//!
//! 1. (workspace-wide) `cargo test -p plexus-core` passes green.
//! 2. (here) Two-node hub: no policy registered → callee receives an
//!    `AuthContext` whose `roles` are empty (identity-only default
//!    applied). Verified user (`user_id`, `session_id`) is preserved.
//! 3. (DEFERRED — PRIVACY-1) Exactly one `AuditRecord` per cross-boundary
//!    call lands in a test broadcast audit sink with `kind:
//!    ForwardPolicyApplied`.
//! 4. (DEFERRED — PRIVACY-1) Policy-name field matches the registered
//!    policy; reads `"identity_only"` when none is registered.
//! 5. (here) Pre-existing `ChildRouter` impl with no override continues
//!    to compile and dispatch correctly. The "echo callee" used below is
//!    such an impl: it overrides none of the three new
//!    default-implemented methods.
//! 6. (DEFERRED — PRIVACY-1) Existing scope-check `AuditRecord`
//!    deserializes via serde-default for `AuditRecordKind`.
//!
//! Audit-record assertions are deferred because `AuditRecord`, `AuditSink`,
//! and `AuditRecordKind::ForwardPolicyApplied` are owned by the sibling
//! ticket PRIVACY-1, which has not yet merged. The dispatch wire-in itself
//! emits a `tracing::trace!` at `target = "plexus::audit"` so operators
//! still see the policy invocation; the structured-record assertion lands
//! when PRIVACY-1 merges. See run-notes on the AUTHLANG-3 ticket.

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use plexus_auth_core::{
    Anonymous, AuthContext, ForwardPolicy, IdentityOnly, PassThrough, Principal,
};
use plexus_core::plexus::{
    plexus::{route_to_child, ChildRouter, PlexusError},
    streaming::{done_stream, PlexusStream},
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

// ── Fixture: a callee that records what AuthContext it received ─────────

/// An echo callee that captures the `Option<&AuthContext>` it was handed.
///
/// This is the witness: by inspecting [`Self::captured`] after a call
/// through [`route_to_child`], we can assert what context the framework
/// derived for the callee.
///
/// Per AUTHLANG-3 acceptance criterion 5, this impl does NOT override any
/// of the three new default-implemented `ChildRouter` methods
/// (`forward_policy_for`, `framework_stamped_principal`,
/// future `audit_sink`). It inherits the defaults — proving the trait
/// addition is non-breaking.
#[derive(Clone)]
struct EchoCallee {
    namespace: String,
    captured: Arc<Mutex<Option<AuthContext>>>,
}

impl EchoCallee {
    fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            captured: Arc::new(Mutex::new(None)),
        }
    }

    fn captured(&self) -> Option<AuthContext> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait]
impl ChildRouter for EchoCallee {
    fn router_namespace(&self) -> &str {
        &self.namespace
    }

    async fn router_call(
        &self,
        _method: &str,
        _params: Value,
        auth: Option<&AuthContext>,
        _raw_ctx: Option<&plexus_core::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        *self.captured.lock().unwrap() = auth.cloned();
        Ok(done_stream(vec![]))
    }

    async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
        None
    }
    // Intentionally NOT overriding forward_policy_for /
    // framework_stamped_principal — that's criterion 5's assertion.
}

// ── Fixture: a parent that holds a single child and an optional policy ──

/// A minimal hub-like parent that exposes `EchoCallee` as `solar`.
///
/// Like a real `DynamicHub` it can be configured with a per-callee
/// forward policy; unlike `DynamicHub` it carries no other state, so the
/// tests stay focused on the dispatch sequence.
#[derive(Clone)]
struct TestParent {
    child: EchoCallee,
    policy: Option<Arc<dyn ForwardPolicy>>,
    /// What `framework_stamped_principal` should return. Tests vary this
    /// to assert the CallSite reaches the policy.
    stamped: Principal,
}

impl TestParent {
    fn new(child: EchoCallee) -> Self {
        Self {
            child,
            policy: None,
            stamped: Principal::Anonymous,
        }
    }

    fn with_policy(mut self, policy: Arc<dyn ForwardPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }
}

#[async_trait]
impl ChildRouter for TestParent {
    fn router_namespace(&self) -> &str {
        "parent"
    }

    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&plexus_core::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        route_to_child(self, method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        if name == self.child.namespace {
            Some(Box::new(self.child.clone()) as Box<dyn ChildRouter>)
        } else {
            None
        }
    }

    fn forward_policy_for(&self, _callee_ns: &str) -> Option<Arc<dyn ForwardPolicy>> {
        self.policy.clone()
    }

    fn framework_stamped_principal(&self) -> Principal {
        self.stamped.clone()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

fn caller_ctx() -> AuthContext {
    AuthContext::new(
        "alice".to_string(),
        "sess-7".to_string(),
        vec!["admin".to_string(), "operator".to_string()],
        serde_json::json!({"tenant_id": "acme"}),
    )
}

/// Acceptance criterion 2: with no policy registered, the callee receives
/// an `AuthContext` whose `roles` are empty (identity-only default).
///
/// The verified user fields (`user_id`, `session_id`) survive — that's
/// what `identity_only` means: identity flows, authority does not.
#[tokio::test]
async fn default_identity_only_strips_roles_and_metadata() {
    let echo = EchoCallee::new("solar");
    let parent = TestParent::new(echo.clone());

    let caller = caller_ctx();
    let _ = parent
        .router_call("solar.info", Value::Null, Some(&caller), None)
        .await
        .expect("dispatch succeeded");

    let derived = echo.captured().expect("callee received some AuthContext");

    // identity flows
    assert_eq!(derived.user_id, "alice");
    assert_eq!(derived.session_id, "sess-7");

    // authority does NOT flow under the identity-only default
    assert!(
        derived.roles.is_empty(),
        "expected empty roles under IdentityOnly default, got {:?}",
        derived.roles
    );
    assert_eq!(
        derived.metadata,
        Value::Null,
        "expected null metadata under IdentityOnly default"
    );
}

/// Acceptance criterion 4 (positive side, observable today): when a
/// `PassThrough` policy is registered, the callee receives the full
/// caller context — roles and metadata included.
///
/// The audit-record policy-name assertion is deferred until PRIVACY-1.
/// Here we observe the policy ran by its visible side effect: the
/// derivation kept everything.
#[tokio::test]
async fn registered_pass_through_keeps_roles_and_metadata() {
    let echo = EchoCallee::new("solar");
    let parent = TestParent::new(echo.clone()).with_policy(Arc::new(PassThrough));

    let caller = caller_ctx();
    let _ = parent
        .router_call("solar.info", Value::Null, Some(&caller), None)
        .await
        .expect("dispatch succeeded");

    let derived = echo.captured().expect("callee received some AuthContext");
    assert_eq!(derived.user_id, "alice");
    assert_eq!(derived.session_id, "sess-7");
    assert_eq!(derived.roles, vec!["admin".to_string(), "operator".to_string()]);
    assert_eq!(derived.metadata, serde_json::json!({"tenant_id": "acme"}));
}

/// Symmetric counter-test: an `Anonymous` policy strips identity too,
/// not just authority. Observable by the callee's `user_id` resetting
/// to `"anonymous"`.
#[tokio::test]
async fn registered_anonymous_drops_everything() {
    let echo = EchoCallee::new("solar");
    let parent = TestParent::new(echo.clone()).with_policy(Arc::new(Anonymous));

    let caller = caller_ctx();
    let _ = parent
        .router_call("solar.info", Value::Null, Some(&caller), None)
        .await
        .expect("dispatch succeeded");

    let derived = echo.captured().expect("callee received some AuthContext");
    assert_eq!(derived.user_id, "anonymous");
    assert_eq!(derived.session_id, "");
    assert!(derived.roles.is_empty());
    assert_eq!(derived.metadata, Value::Null);
}

/// AUTHLANG-3 §"Required behavior" row 3: caller dispatches with no
/// `AuthContext` (anonymous edge). The policy still runs against the
/// sealed anonymous context; the callee receives `None` for its
/// `AuthContext` (the framework only mints a callee context when the
/// caller had one).
#[tokio::test]
async fn no_caller_context_no_callee_context() {
    let echo = EchoCallee::new("solar");
    let parent = TestParent::new(echo.clone()).with_policy(Arc::new(IdentityOnly));

    let _ = parent
        .router_call("solar.info", Value::Null, None, None)
        .await
        .expect("dispatch succeeded");

    assert!(
        echo.captured().is_none(),
        "callee should receive None when caller had None"
    );
}

/// Acceptance criterion 5: a `ChildRouter` impl that does NOT override
/// the new default methods still compiles and dispatches. The `EchoCallee`
/// fixture above is exactly such an impl — it overrides none of
/// `forward_policy_for`, `framework_stamped_principal`. This test asserts
/// that, when used directly (no parent in front), it can still be
/// invoked. The behavior is a smoke test: the call returns Ok with no
/// auth captured.
#[tokio::test]
async fn unmodified_child_router_impl_still_compiles_and_dispatches() {
    let echo = EchoCallee::new("solar");

    // Default `forward_policy_for` returns None.
    assert!(
        ChildRouter::forward_policy_for(&echo, "solar").is_none(),
        "default forward_policy_for should return None"
    );
    // Default `framework_stamped_principal` returns Principal::Anonymous.
    assert!(
        matches!(echo.framework_stamped_principal(), Principal::Anonymous),
        "default framework_stamped_principal should be Anonymous"
    );

    // And direct dispatch onto the callee still works through the trait.
    let dyn_router: &dyn ChildRouter = &echo;
    let _ = dyn_router
        .router_call("info", Value::Null, None, None)
        .await
        .expect("direct dispatch succeeds");
}

/// AUTHLANG-3 §"Required behavior" row 5: pre-existing `ChildRouter`
/// impls compile unchanged. This is a compile-time witness: we declare a
/// minimal trait impl that uses ONLY the original surface (the four
/// pre-AUTHLANG methods: `router_namespace`, `router_call`, `get_child`,
/// plus the `capabilities` / `list_children` / `search_children` defaults
/// from before this ticket). It must compile.
#[allow(dead_code)]
mod compile_witness_pre_authlang_router {
    use super::*;

    struct LegacyRouter;

    #[async_trait]
    impl ChildRouter for LegacyRouter {
        fn router_namespace(&self) -> &str {
            "legacy"
        }
        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&AuthContext>,
            _raw_ctx: Option<&plexus_core::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Ok(done_stream(vec![]))
        }
        async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
            None
        }
        // Note: no override of the AUTHLANG-3 defaults — compiles because
        // defaults exist.
    }

    fn _trait_object(r: LegacyRouter) -> Box<dyn ChildRouter> {
        Box::new(r)
    }

    // Unused boxstream import suppression — referenced via async_trait
    // bound elsewhere.
    fn _unused(_: BoxStream<'_, String>) {}
}

// ── DynamicHub integration ──────────────────────────────────────────────

/// Acceptance criterion: `DynamicHub`'s [`ChildRouter`] override consults
/// the registered [`plexus_core::plexus::ForwardPolicyRegistry`]. When
/// nothing is registered, lookup returns `None` and the framework falls
/// back to `IdentityOnly`. When a policy is registered via the
/// [`plexus_core::plexus::DynamicHub::with_forward_policy`] builder,
/// lookup returns it.
#[test]
fn dynamic_hub_forward_policy_registry_round_trip() {
    use plexus_core::plexus::DynamicHub;

    let hub = DynamicHub::new("test")
        .with_forward_policy("solar", Arc::new(PassThrough));

    // Direct registry view.
    assert_eq!(hub.forward_policies().len(), 1);
    assert_eq!(
        hub.forward_policies().get("solar").unwrap().name().as_str(),
        "pass_through"
    );

    // Through the ChildRouter trait — the path that `route_to_child`
    // actually consults.
    let trait_view: &dyn ChildRouter = &hub;
    assert_eq!(
        trait_view
            .forward_policy_for("solar")
            .unwrap()
            .name()
            .as_str(),
        "pass_through"
    );
    assert!(trait_view.forward_policy_for("unregistered").is_none());
}
