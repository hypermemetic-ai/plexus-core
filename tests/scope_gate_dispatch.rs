//! R-5 — integration tests for the scope-enforcement gate in
//! [`DynamicHub`] dispatch (revives AUTHZ-CORE-1 + AUTHZ-CORE-5; trak
//! facet `ea4dd433-3bb9-4339-bf29-5e8e58922cb2`).
//!
//! Coverage maps to the R-5 verification contract:
//!
//! - no-registry passthrough (the hard backward-safety constraint)
//! - `public` bypass (schema flag AND registry declaration)
//! - matching-scope pass / missing-scope forbidden
//! - wildcard role grants (`*`, `vault.*`)
//! - `default_deny` off/on (incl. fail-closed with no registry)
//! - `ScopeCheck` audit emission (decision, roles, scope_required,
//!   correlation-id uniqueness, panicking-sink resilience —
//!   AUTHZ-CORE-5 acceptance 9)
//! - registry-overlay precedence over schema-declared scopes
//! - multi-scope conjunction (first unmet scope reported)
//!
//! Per AUTHZ-CORE-1's Tier B resolution there is NO test-only relaxation
//! of the gate: every test that exercises a gated method constructs a
//! satisfying [`AuthContext`] and passes it through dispatch the same way
//! production callers do.

use async_stream::stream;
use async_trait::async_trait;
use futures::stream::Stream;
use plexus_auth_core::{
    AuditDecision, AuditDenyReason, AuditRecord, AuditRecordKind, AuditSink, AuthContext,
    MethodPath, Scope, ScopeRegistry,
};
use plexus_core::{AuthzDenyReason, DynamicHub, PlexusError};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fixture activation: one method per authz shape.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Vault;

#[plexus_macros::activation(
    namespace = "vault",
    version = "1.0.0",
    description = "R-5 scope-gate fixture",
    crate_path = "plexus_core"
)]
impl Vault {
    /// Schema-declared single scope.
    #[plexus_macros::method(scope = "vault.write")]
    async fn write(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "wrote".to_string(); }
    }

    /// Schema-declared conjunction — BOTH scopes required.
    #[plexus_macros::method(scope = "vault.write", scope = "vault.admin")]
    async fn admin_write(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "admin-wrote".to_string(); }
    }

    /// Explicitly public — exempt from the gate, default_deny included.
    #[plexus_macros::method(public)]
    async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "pong".to_string(); }
    }

    /// No authz annotation — today's behavior with default_deny OFF;
    /// implicit full-path scope (`vault.plain`) under default_deny ON.
    #[plexus_macros::method]
    async fn plain(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "plain".to_string(); }
    }
}

// ---------------------------------------------------------------------------
// Test audit sinks.
// ---------------------------------------------------------------------------

/// Captures every record so tests can assert the gate's audit trail.
#[derive(Default)]
struct CaptureSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl CaptureSink {
    fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuditSink for CaptureSink {
    async fn write(&self, record: AuditRecord) {
        self.records.lock().unwrap().push(record);
    }
}

/// Panics on every write — AUTHZ-CORE-5 acceptance 9's hostile sink.
struct PanicSink;

#[async_trait]
impl AuditSink for PanicSink {
    async fn write(&self, _record: AuditRecord) {
        panic!("audit sink deliberately panicking");
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn authed(roles: &[&str]) -> AuthContext {
    AuthContext::new(
        "user-1".to_string(),
        "sess-1".to_string(),
        roles.iter().map(|r| (*r).to_string()).collect(),
        serde_json::Value::Null,
    )
}

/// A hub with the fixture registered, a capture sink, and optional gate
/// configuration. Returns the sink so tests can read the audit trail.
fn hub(registry: Option<ScopeRegistry>, default_deny: bool) -> (DynamicHub, Arc<CaptureSink>) {
    let sink = Arc::new(CaptureSink::default());
    let mut hub = DynamicHub::new("testhub")
        .register(Vault)
        .with_audit_sink(sink.clone())
        .with_default_deny(default_deny);
    if let Some(registry) = registry {
        hub = hub.with_scope_registry(registry);
    }
    (hub, sink)
}

/// The empty taxonomy: gate active, no roles, no overlays, no publics.
fn empty_registry() -> ScopeRegistry {
    ScopeRegistry::builder().build().expect("empty registry builds")
}

/// `Result::expect_err` needs `T: Debug` and `PlexusStream` is not —
/// unwrap the error side by hand.
fn expect_err(
    result: Result<plexus_core::plexus::streaming::PlexusStream, PlexusError>,
    msg: &str,
) -> PlexusError {
    match result {
        Err(err) => err,
        Ok(_) => panic!("{msg}"),
    }
}

fn assert_missing_scope(err: PlexusError, expected: &str) {
    match err {
        PlexusError::Forbidden {
            reason: AuthzDenyReason::MissingScope { scope },
        } => assert_eq!(scope.as_str(), expected, "wrong unmet scope reported"),
        other => panic!("expected Forbidden/MissingScope({expected}), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. The hard backward-safety constraint: no registry, no default_deny.
// ---------------------------------------------------------------------------

/// A hub with NO registry and default_deny off dispatches a
/// scope-CARRYING method to an anonymous caller exactly as today — and
/// the gate writes nothing to the audit sink (it never ran).
#[tokio::test]
async fn no_registry_passthrough_is_byte_for_byte_todays_behavior() {
    let (hub, sink) = hub(None, false);

    for method in ["vault.write", "vault.admin_write", "vault.ping", "vault.plain"] {
        let result = hub.route(method, serde_json::json!({}), None).await;
        assert!(result.is_ok(), "{method} must pass through with no gate configured");
    }
    assert!(
        sink.records().is_empty(),
        "an unconfigured gate must not emit audit records"
    );
}

// ---------------------------------------------------------------------------
// 2. Public bypass.
// ---------------------------------------------------------------------------

/// Schema `public` flag bypasses the gate for anonymous callers, with an
/// `Allow` ScopeCheck record for forensic completeness (AUTHZ-CORE-5 §1).
#[tokio::test]
async fn schema_public_flag_bypasses_anonymously() {
    let (hub, sink) = hub(Some(empty_registry()), false);

    let result = hub.route("vault.ping", serde_json::json!({}), None).await;
    assert!(result.is_ok(), "public method must bypass the gate");

    let records = sink.records();
    assert_eq!(records.len(), 1, "public bypass writes exactly one Allow record");
    assert_eq!(records[0].kind, AuditRecordKind::ScopeCheck);
    assert_eq!(records[0].decision, AuditDecision::Allow);
    assert_eq!(records[0].method, MethodPath::try_new("vault.ping").unwrap());
}

/// Registry-declared public methods bypass too — even when the schema
/// carries scopes (deployment-level exemption).
#[tokio::test]
async fn registry_public_declaration_bypasses_scoped_method() {
    let registry = ScopeRegistry::builder()
        .public_method(MethodPath::try_new("vault.write").unwrap())
        .build()
        .unwrap();
    let (hub, sink) = hub(Some(registry), false);

    let result = hub.route("vault.write", serde_json::json!({}), None).await;
    assert!(result.is_ok(), "registry-public method must bypass the gate");
    assert_eq!(sink.records().last().unwrap().decision, AuditDecision::Allow);
}

/// Public bypass survives default_deny ON (the explicit exemption).
#[tokio::test]
async fn public_bypass_survives_default_deny() {
    let (hub, _sink) = hub(Some(empty_registry()), true);

    let result = hub.route("vault.ping", serde_json::json!({}), None).await;
    assert!(result.is_ok(), "public method must bypass under default_deny");
}

// ---------------------------------------------------------------------------
// 3. Layer 1: authentication.
// ---------------------------------------------------------------------------

/// Anonymous caller on a scope-carrying method: Unauthenticated, with a
/// Deny{Unauthenticated} record carrying the resolved requirement.
#[tokio::test]
async fn scoped_method_anonymous_is_unauthenticated() {
    let (hub, sink) = hub(Some(empty_registry()), false);

    let err = expect_err(
        hub.route("vault.write", serde_json::json!({}), None).await,
        "anonymous caller must be rejected",
    );
    assert!(
        matches!(err, PlexusError::Unauthenticated(_)),
        "expected Unauthenticated, got {err:?}"
    );

    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].decision,
        AuditDecision::Deny { reason: AuditDenyReason::Unauthenticated }
    );
    assert_eq!(records[0].scope_required, vec![Scope::new("vault.write")]);
    assert!(records[0].originator.is_none(), "anonymous record has no originator");
}

/// An AuthContext that fails `is_authenticated()` (anonymous sentinel) is
/// treated as anonymous — no privilege from merely carrying a context.
#[tokio::test]
async fn unauthenticated_context_is_rejected_like_anonymous() {
    let (hub, _sink) = hub(Some(empty_registry()), false);

    let anon = AuthContext::anonymous();
    let err = expect_err(
        hub.route("vault.write", serde_json::json!({}), Some(&anon)).await,
        "anonymous-sentinel context must be rejected",
    );
    assert!(matches!(err, PlexusError::Unauthenticated(_)));
}

// ---------------------------------------------------------------------------
// 4. Layer 2: method authorization.
// ---------------------------------------------------------------------------

/// Matching scope passes; the Allow record carries the caller's roles.
#[tokio::test]
async fn matching_scope_passes() {
    let registry = ScopeRegistry::builder()
        .role("writer", &["vault.write"])
        .build()
        .unwrap();
    let (hub, sink) = hub(Some(registry), false);

    let ctx = authed(&["writer"]);
    let result = hub.route("vault.write", serde_json::json!({}), Some(&ctx)).await;
    assert!(result.is_ok(), "satisfying role must pass the gate");

    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, AuditDecision::Allow);
    assert_eq!(records[0].roles, vec![plexus_auth_core::RoleName::new("writer")]);
    assert!(records[0].originator.is_some());
}

/// Missing scope: Forbidden naming the unmet scope; the rendered error
/// never leaks the registry's taxonomy (no-enumeration posture).
#[tokio::test]
async fn missing_scope_is_forbidden_naming_only_the_unmet_scope() {
    let registry = ScopeRegistry::builder()
        .role("reader", &["vault.read"])
        .role("secret_role", &["vault.secret"])
        .build()
        .unwrap();
    let (hub, sink) = hub(Some(registry), false);

    let ctx = authed(&["reader"]);
    let err = expect_err(
        hub.route("vault.write", serde_json::json!({}), Some(&ctx)).await,
        "insufficient role must be rejected",
    );

    let rendered = err.to_string();
    assert!(rendered.contains("vault.write"), "error must name the unmet scope: {rendered}");
    assert!(
        !rendered.contains("secret_role") && !rendered.contains("vault.secret") && !rendered.contains("reader"),
        "error must not leak the registry: {rendered}"
    );
    assert_missing_scope(err, "vault.write");

    let records = sink.records();
    assert_eq!(
        records[0].decision,
        AuditDecision::Deny { reason: AuditDenyReason::MissingScope }
    );
}

/// Multi-scope conjunction: holding ONE of two required scopes fails,
/// reporting the FIRST unmet scope; holding both passes.
#[tokio::test]
async fn multi_scope_conjunction_reports_first_unmet() {
    let registry = ScopeRegistry::builder()
        .role("writer", &["vault.write"])
        .role("admin", &["vault.write", "vault.admin"])
        .build()
        .unwrap();
    let (hub, _sink) = hub(Some(registry), false);

    let writer = authed(&["writer"]);
    let err = expect_err(
        hub.route("vault.admin_write", serde_json::json!({}), Some(&writer)).await,
        "partial conjunction must be rejected",
    );
    assert_missing_scope(err, "vault.admin");

    let admin = authed(&["admin"]);
    let result = hub.route("vault.admin_write", serde_json::json!({}), Some(&admin)).await;
    assert!(result.is_ok(), "full conjunction must pass");
}

/// Wildcard role grants: bare `*` and segment-bounded `vault.*` both
/// satisfy `vault.write`.
#[tokio::test]
async fn wildcard_roles_satisfy_scopes() {
    let registry = ScopeRegistry::builder()
        .role("superuser", &["*"])
        .role("vault_admin", &["vault.*"])
        .build()
        .unwrap();
    let (hub, _sink) = hub(Some(registry), false);

    for role in ["superuser", "vault_admin"] {
        let ctx = authed(&[role]);
        let result = hub.route("vault.write", serde_json::json!({}), Some(&ctx)).await;
        assert!(result.is_ok(), "wildcard role '{role}' must satisfy vault.write");
    }
}

/// Registry overlay wins over schema-declared scopes
/// (requirement-source precedence rule 1).
#[tokio::test]
async fn registry_overlay_takes_precedence_over_schema_scopes() {
    let registry = ScopeRegistry::builder()
        .role("writer", &["vault.write"])
        .role("special", &["vault.special"])
        .method_scopes(
            MethodPath::try_new("vault.write").unwrap(),
            &[Scope::try_new("vault.special").unwrap()],
        )
        .build()
        .unwrap();
    let (hub, _sink) = hub(Some(registry), false);

    // The schema scope holder no longer satisfies the overlaid requirement.
    let writer = authed(&["writer"]);
    let err = expect_err(
        hub.route("vault.write", serde_json::json!({}), Some(&writer)).await,
        "overlay must supersede the schema scope",
    );
    assert_missing_scope(err, "vault.special");

    // The overlay scope holder passes.
    let special = authed(&["special"]);
    let result = hub.route("vault.write", serde_json::json!({}), Some(&special)).await;
    assert!(result.is_ok(), "overlay-satisfying role must pass");
}

// ---------------------------------------------------------------------------
// 5. default_deny posture (mechanism ON in tests only — R-S01 Q4 open).
// ---------------------------------------------------------------------------

/// OFF (the shipped default): an unannotated method passes anonymously
/// with NO audit record — the gate evaluated nothing (not a decision).
#[tokio::test]
async fn default_deny_off_unannotated_method_passes_without_audit() {
    let (hub, sink) = hub(Some(empty_registry()), false);

    let result = hub.route("vault.plain", serde_json::json!({}), None).await;
    assert!(result.is_ok(), "unannotated method must pass with default_deny off");
    assert!(sink.records().is_empty(), "pass-through is not a decision; no record");
}

/// ON: the unannotated method is enforced against the implicit full-path
/// scope — anonymous denied, insufficient role denied (naming
/// `vault.plain`), holder of the implicit scope passes.
#[tokio::test]
async fn default_deny_on_enforces_implicit_full_path_scope() {
    let registry = ScopeRegistry::builder()
        .role("opener", &["vault.plain"])
        .role("bystander", &["vault.read"])
        .build()
        .unwrap();
    let (hub, _sink) = hub(Some(registry), true);

    let err = expect_err(
        hub.route("vault.plain", serde_json::json!({}), None).await,
        "anonymous must be denied under default_deny",
    );
    assert!(matches!(err, PlexusError::Unauthenticated(_)));

    let bystander = authed(&["bystander"]);
    let err = expect_err(
        hub.route("vault.plain", serde_json::json!({}), Some(&bystander)).await,
        "insufficient role must be denied under default_deny",
    );
    assert_missing_scope(err, "vault.plain");

    let opener = authed(&["opener"]);
    let result = hub.route("vault.plain", serde_json::json!({}), Some(&opener)).await;
    assert!(result.is_ok(), "implicit-scope holder must pass under default_deny");
}

/// ON with NO registry configured: fail closed. Anonymous is
/// unauthenticated; authenticated callers hold no scopes (empty registry
/// expands every role to {}) and are forbidden.
#[tokio::test]
async fn default_deny_on_without_registry_fails_closed() {
    let (hub, _sink) = hub(None, true);

    let err = expect_err(
        hub.route("vault.plain", serde_json::json!({}), None).await,
        "anonymous must be denied (fail closed)",
    );
    assert!(matches!(err, PlexusError::Unauthenticated(_)));

    let ctx = authed(&["admin"]);
    let err = expect_err(
        hub.route("vault.plain", serde_json::json!({}), Some(&ctx)).await,
        "no registry means no grants — fail closed",
    );
    assert_missing_scope(err, "vault.plain");
}

// ---------------------------------------------------------------------------
// 6. Audit trail mechanics.
// ---------------------------------------------------------------------------

/// Each gate decision mints a fresh correlation id (CORE-5 acceptance 7).
#[tokio::test]
async fn audit_correlation_ids_are_unique_per_invocation() {
    let (hub, sink) = hub(Some(empty_registry()), false);

    for _ in 0..2 {
        let _ = hub.route("vault.ping", serde_json::json!({}), None).await;
    }
    let records = sink.records();
    assert_eq!(records.len(), 2);
    assert_ne!(
        records[0].correlation_id, records[1].correlation_id,
        "consecutive invocations must mint distinct correlation ids"
    );
}

/// A panicking audit sink does not block dispatch — the gate's decision
/// stands (AUTHZ-CORE-5 acceptance 9).
#[tokio::test]
async fn panicking_sink_does_not_block_dispatch() {
    let registry = ScopeRegistry::builder()
        .role("writer", &["vault.write"])
        .build()
        .unwrap();
    let hub = DynamicHub::new("testhub")
        .register(Vault)
        .with_scope_registry(registry)
        .with_audit_sink(Arc::new(PanicSink));

    // Allow path: dispatch proceeds despite the sink panic.
    let ctx = authed(&["writer"]);
    let result = hub.route("vault.write", serde_json::json!({}), Some(&ctx)).await;
    assert!(result.is_ok(), "allow decision must survive a panicking sink");

    // Deny path: the typed error comes through despite the sink panic.
    let err = expect_err(
        hub.route("vault.write", serde_json::json!({}), None).await,
        "deny decision must survive a panicking sink",
    );
    assert!(matches!(err, PlexusError::Unauthenticated(_)));
}
