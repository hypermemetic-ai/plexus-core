//! PLX-127 (M4·C) — the tenants mount, and the gate that keeps it from being a
//! traversal vector.
//!
//! The bar this file is written to: **verify before instantiate, and absence
//! rather than denial.** A test that shows a cross-tenant request is refused
//! proves only the weaker half. So:
//!
//! - every negative test asserts an **instrumented factory was never called**,
//!   not merely that an `Err` came back;
//! - the absence tests assert tenant A is **missing from the bytes** of tenant
//!   B's rendered surface, not that B is refused when it asks;
//! - the ordering test uses a resolver that **panics if consulted**, so
//!   "the segment check runs before the resolver" is a fact the test would
//!   fail on rather than a comment.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::{json, Value};

use plexus_auth_core::{
    AuthContext, ClaimTenantResolver, Tenant, TenantError, TenantId, TenantResolver,
};
use plexus_core::activations::echo::Echo;
use plexus_core::activations::health::Health;
use plexus_core::ir::{ActivationIr, ChildEdge, StopKind};
use plexus_core::plexus::{
    mount_segment_is_safe, AdmittedTenant, ChildRouter, DynamicHub, MountRefusal, PlexusError,
    TenantMount, TenantMountGate,
};

// ============================================================================
// Fixtures
// ============================================================================

/// Records every per-tenant subtree construction. This is the instrumented
/// constructor c1 asks for: if the gate ran late, this would have entries.
#[derive(Default)]
struct ConstructionLog {
    calls: AtomicUsize,
    tenants: Mutex<Vec<String>>,
}

impl ConstructionLog {
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn tenants(&self) -> Vec<String> {
        self.tenants.lock().unwrap().clone()
    }

    fn record(&self, id: &TenantId) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.tenants.lock().unwrap().push(id.as_str().to_string());
    }
}

/// The shape shared by every tenant. Built from the same registration list the
/// factory uses, and it names no tenant.
fn tenant_subtree_shape() -> Arc<DynamicHub> {
    Arc::new(DynamicHub::new("substrate").register(Echo::new()))
}

fn tenant_template_ir() -> ActivationIr {
    tenant_subtree_shape().connectome()
}

/// A resolver that blows up if anything consults it. Used to prove that the
/// segment-safety check happens *before* the caller's tenant is resolved.
struct ExplodingResolver;

#[async_trait]
impl TenantResolver for ExplodingResolver {
    async fn resolve(&self, _auth: &AuthContext) -> Result<Tenant, TenantError> {
        panic!("the resolver was consulted for a segment that is not mount-safe");
    }
}

/// `single_user_fallback` off: a caller with no tenancy claim resolves to
/// nothing, rather than silently to their own user id. The mount must refuse
/// such a caller, so the tests need the strict posture.
fn strict_resolver() -> Arc<dyn TenantResolver> {
    let mut r = ClaimTenantResolver::new();
    r.single_user_fallback = false;
    Arc::new(r)
}

struct Fixture {
    hub: DynamicHub,
    log: Arc<ConstructionLog>,
}

fn fixture_with_resolver(resolver: Arc<dyn TenantResolver>) -> Fixture {
    let log = Arc::new(ConstructionLog::default());
    let log_for_factory = Arc::clone(&log);

    let gate = Arc::new(TenantMountGate::new(resolver));
    let factory: plexus_core::plexus::TenantSubtreeFactory =
        Arc::new(move |admitted: &AdmittedTenant| {
            // The only place a per-tenant object comes into existence.
            log_for_factory.record(admitted.id());
            Some(tenant_subtree_shape())
        });

    let mount = TenantMount::new(gate, factory, tenant_template_ir());
    let hub = DynamicHub::new("hub").register(Health::new()).register(mount);

    Fixture { hub, log }
}

fn fixture() -> Fixture {
    fixture_with_resolver(strict_resolver())
}

fn caller_of(tenant: &str) -> AuthContext {
    AuthContext::new(
        format!("user-of-{tenant}"),
        "sess".to_string(),
        vec!["user".to_string()],
        json!({ "org_id": tenant }),
    )
}

/// A caller who is authenticated but carries no tenancy claim at all.
fn untenanted_caller() -> AuthContext {
    AuthContext::new(
        "nomad".to_string(),
        "sess".to_string(),
        vec!["user".to_string()],
        json!({}),
    )
}

/// `PlexusStream` is not `Debug`, so `expect_err` is unavailable on a routing
/// result. These two say the same thing with a usable panic message.
fn err_of(r: Result<plexus_core::plexus::streaming::PlexusStream, PlexusError>, what: &str) -> PlexusError {
    match r {
        Ok(_) => panic!("expected a refusal ({what}), got a stream"),
        Err(e) => e,
    }
}

fn ok_of(
    r: Result<plexus_core::plexus::streaming::PlexusStream, PlexusError>,
    what: &str,
) -> plexus_core::plexus::streaming::PlexusStream {
    match r {
        Ok(s) => s,
        Err(e) => panic!("expected success ({what}), got {e:?}"),
    }
}

async fn drain(stream: plexus_core::plexus::streaming::PlexusStream) -> Vec<Value> {
    stream
        .map(|item| serde_json::to_value(item).expect("serialize stream item"))
        .collect()
        .await
}

// ============================================================================
// c1 — verify precedes instantiate
// ============================================================================

#[tokio::test]
async fn c1_a_cross_tenant_descent_never_reaches_the_constructor() {
    let f = fixture();
    let b = caller_of("tenant-b");

    // NON-VACUITY, first: the identical call shape against B's OWN tenant
    // succeeds and DOES construct. If this failed, the negative below would
    // prove nothing — it would only prove the method string was wrong.
    let _ = ok_of(
        f.hub.route("tenants.tenant-b.echo.once", json!({"message": "hi"}), Some(&b)).await,
        "a tenant may descend into its own mount",
    );
    assert_eq!(f.log.count(), 1, "the caller's own descent constructs once");
    assert_eq!(f.log.tenants(), vec!["tenant-b".to_string()]);

    // The negative. Same shape, one segment changed.
    let err = err_of(f.hub.route("tenants.tenant-a.echo.once", json!({"message": "hi"}), Some(&b)).await, "tenant B must not reach tenant A's mount");

    // The weaker half.
    assert!(matches!(err, PlexusError::MethodNotFound { .. }), "got {err:?}");

    // THE HALF THIS TICKET EXISTS FOR: nothing was built. The counter is
    // still 1 — the count from B's own legitimate descent — and `tenant-a`
    // never appears in the construction log.
    assert_eq!(
        f.log.count(),
        1,
        "the per-tenant subtree constructor ran for a cross-tenant request"
    );
    assert!(
        !f.log.tenants().iter().any(|t| t == "tenant-a"),
        "an object bound to tenant A's identity was constructed: {:?}",
        f.log.tenants()
    );
}

#[tokio::test]
async fn c1_an_anonymous_caller_constructs_nothing() {
    let f = fixture();

    let err = err_of(f.hub.route("tenants.tenant-a.echo.once", json!({"message": "hi"}), None).await, "an anonymous caller has no tenant to descend into");
    assert!(matches!(err, PlexusError::Unauthenticated(_)), "got {err:?}");
    assert_eq!(f.log.count(), 0);
}

#[tokio::test]
async fn c1_an_authenticated_caller_with_no_tenancy_claim_constructs_nothing() {
    let f = fixture();

    let err = err_of(f.hub.route(
            "tenants.tenant-a.echo.once",
            json!({"message": "hi"}),
            Some(&untenanted_caller()),
        ).await, "a caller with no resolved tenant may not descend");
    assert!(matches!(err, PlexusError::Unauthenticated(_)), "got {err:?}");
    assert_eq!(f.log.count(), 0);
}

/// PLX-151 residual 2, made mechanical: `TenantId::try_new` validates only
/// non-empty / length / control characters, so a traversal segment is a
/// perfectly valid `TenantId`. Anything that joins a tenant id onto a path —
/// and this mount joins one onto `tenants/{id}` — must check separately.
#[tokio::test]
async fn c1_a_traversal_segment_is_refused_before_the_resolver_is_consulted() {
    // Pin the upstream fact this defence exists for. If auth-core ever
    // tightens `try_new`, this line fails and the reason for
    // `mount_segment_is_safe` should be re-examined rather than assumed.
    assert!(
        TenantId::try_new("../tenant-a").is_ok(),
        "TenantId::try_new no longer accepts a traversal id; re-check the mount's own guard"
    );
    assert!(TenantId::try_new("a/b").is_ok());
    assert!(TenantId::try_new("a.b").is_ok());

    for hostile in ["../tenant-a", "..", "a/b", "/etc", "a\\b", ".", "a b", "a:b"] {
        assert!(
            !mount_segment_is_safe(hostile),
            "{hostile:?} must not be usable as a mount segment"
        );
    }
    assert!(mount_segment_is_safe("tenant-a"));
    assert!(mount_segment_is_safe("018f2c1e-9d3a-7b21-b0f5-2c9a7e6d1a44"));

    // Ordering, proved rather than asserted: this fixture's resolver panics
    // the moment it is consulted. The call below must return cleanly, which
    // is only possible if the segment check ran first.
    let f = fixture_with_resolver(Arc::new(ExplodingResolver));
    let err = err_of(f.hub.route(
            "tenants.../tenant-a.echo.once",
            json!({"message": "hi"}),
            Some(&caller_of("tenant-b")),
        ).await, "a path-unsafe segment is refused");
    assert!(matches!(err, PlexusError::InvalidParams(_)), "got {err:?}");
    assert_eq!(f.log.count(), 0);
}

/// The structural half of "verify before instantiate": the auth-less descent
/// door does not open at all.
///
/// `ChildRouter::get_child` takes no `AuthContext`, and `route_to_child` calls
/// it *before* the forwarding-policy step. A mount that resolved a tenant
/// there would instantiate with nobody to check against. So it returns `None`
/// — even for a tenant that exists and even for the caller's own.
#[tokio::test]
async fn c1_the_auth_less_descent_door_is_nailed_shut() {
    let log = Arc::new(ConstructionLog::default());
    let log_for_factory = Arc::clone(&log);
    let factory: plexus_core::plexus::TenantSubtreeFactory =
        Arc::new(move |admitted: &AdmittedTenant| {
            log_for_factory.record(admitted.id());
            Some(tenant_subtree_shape())
        });
    let mount = TenantMount::new(
        Arc::new(TenantMountGate::new(strict_resolver())),
        factory,
        tenant_template_ir(),
    );

    assert!(
        mount.get_child("tenant-b").await.is_none(),
        "get_child has no AuthContext; it must never yield a per-tenant subtree"
    );
    assert!(mount.get_child("tenant-a").await.is_none());
    assert!(mount.get_child("anything").await.is_none());
    assert_eq!(log.count(), 0);
}

/// A miss is a clean, specific error — not a panic and not an empty descent.
#[tokio::test]
async fn c1_misses_are_clean_errors() {
    let f = fixture();
    let b = caller_of("tenant-b");

    // A bare mount address with no method after it.
    let err = err_of(f.hub.route("tenants.tenant-b", json!({}), Some(&b)).await, "a bare tenant segment addresses a mount, not a method");
    assert!(matches!(err, PlexusError::MethodNotFound { .. }), "got {err:?}");
    // And it did not admit — so it cannot be used to probe which ids exist.
    assert_eq!(f.log.count(), 0);

    // A real descent into a method that does not exist inside the subtree
    // still admits (correctly — the caller owns that tenant) and then misses.
    let err = err_of(f.hub.route("tenants.tenant-b.echo.nope", json!({}), Some(&b)).await, "a missing method inside the subtree is a clean miss");
    assert!(
        matches!(err, PlexusError::MethodNotFound { .. } | PlexusError::InvalidParams(_)),
        "got {err:?}"
    );
}

// ============================================================================
// c2 — absence, not just denial
// ============================================================================

/// The rendered Connectome is caller-independent (`connectome()` takes no
/// auth), so the only way tenant A can be absent from tenant B's view is for
/// no tenant identity to be in it at all. Assert that on the bytes.
#[tokio::test]
async fn c2_no_tenant_identity_appears_in_the_rendered_connectome() {
    let f = fixture();
    let b = caller_of("tenant-b");

    // Make both tenants live first: A and B have each descended, so any
    // implementation that memoised instances would now have two to leak.
    let _ = ok_of(
        f.hub.route("tenants.tenant-b.echo.once", json!({"message": "x"}), Some(&b)).await,
        "B descends",
    );
    let _ = ok_of(
        f.hub.route(
            "tenants.tenant-a.echo.once",
            json!({"message": "x"}),
            Some(&caller_of("tenant-a")),
        ).await,
        "A descends",
    );
    assert_eq!(f.log.count(), 2, "both tenants really were instantiated");

    let rendered = serde_json::to_string(&f.hub.connectome()).expect("serialize connectome");
    assert!(
        !rendered.contains("tenant-a"),
        "tenant A leaked into the rendered Connectome"
    );
    assert!(
        !rendered.contains("tenant-b"),
        "tenant B leaked into the rendered Connectome"
    );
    // Non-vacuity: the mount IS in there, as a template.
    assert!(rendered.contains("tenants/{id}"), "the mount is not rendered at all");

    // The other two caller-independent surfaces, same assertion.
    let methods = f.hub.list_methods();
    assert!(
        methods.iter().all(|m| !m.contains("tenant-a") && !m.contains("tenant-b")),
        "a tenant identity leaked into list_methods: {methods:?}"
    );
    assert!(methods.contains(&"tenants.list".to_string()));

    let schemas = serde_json::to_string(&f.hub.list_plugin_schemas()).expect("serialize schemas");
    assert!(!schemas.contains("tenant-a") && !schemas.contains("tenant-b"));
}

/// The one enumeration that exists *is* auth-aware, because it is a dispatched
/// method rather than a schema render. Tenant B's listing cannot contain
/// tenant A no matter how many tenants exist.
#[tokio::test]
async fn c2_the_listing_discloses_only_the_callers_own_tenant() {
    let f = fixture();

    let b = drain(ok_of(f.hub.route("tenants.list", json!({}), Some(&caller_of("tenant-b"))).await, "list"))
    .await;
    let b = serde_json::to_string(&b).unwrap();
    assert!(b.contains("tenant-b"), "B cannot see its own tenant: {b}");
    assert!(!b.contains("tenant-a"), "B enumerated tenant A: {b}");

    let a = drain(ok_of(f.hub.route("tenants.list", json!({}), Some(&caller_of("tenant-a"))).await, "list"))
    .await;
    let a = serde_json::to_string(&a).unwrap();
    assert!(a.contains("tenant-a"));
    assert!(!a.contains("tenant-b"), "A enumerated tenant B: {a}");

    let anon = drain(ok_of(f.hub.route("tenants.list", json!({}), None).await, "list")).await;
    let anon = serde_json::to_string(&anon).unwrap();
    assert!(!anon.contains("tenant-a") && !anon.contains("tenant-b"), "{anon}");

    // Listing never instantiates anything.
    assert_eq!(f.log.count(), 0);
}

/// A cross-tenant reach must be indistinguishable from a reach at a tenant
/// that was never minted. Otherwise the denial is an existence oracle and the
/// gate leaks the tenant list one probe at a time.
#[tokio::test]
async fn c2_a_cross_tenant_reach_is_indistinguishable_from_a_miss() {
    let f = fixture();
    let b = caller_of("tenant-b");

    let cross = err_of(f.hub.route("tenants.tenant-a.echo.once", json!({"message": "x"}), Some(&b)).await, "cross-tenant");
    let absent = err_of(f.hub.route(
            "tenants.no-tenant-was-ever-minted-here.echo.once",
            json!({"message": "x"}),
            Some(&b),
        ).await, "nonexistent");

    assert_eq!(
        format!("{cross:?}"),
        format!("{absent:?}"),
        "the denial distinguishes an existing foreign tenant from a nonexistent one"
    );
    assert_eq!(f.log.count(), 0);
}

/// The mount renders as an indexed family carrying RFC 002 §5.1's facts —
/// and, decisively for c2, a `template` rather than an enumeration.
#[tokio::test]
async fn c2_the_mount_renders_as_an_indexed_family_with_no_instances() {
    let f = fixture();
    let ir = f.hub.connectome();

    let edge = ir
        .children
        .iter()
        .find(|e| e.namespace() == "tenants")
        .expect("the mount is rendered as a child edge");

    match edge {
        ChildEdge::Indexed {
            list_method,
            id_field,
            path_template,
            template,
            search_method,
            ..
        } => {
            assert_eq!(list_method, "tenants.list");
            assert_eq!(id_field, "tenant_id");
            assert_eq!(path_template, "tenants/{id}");
            assert_eq!(search_method, &None);
            // The template is the shape of EVERY tenant and is bound to none.
            let rendered = serde_json::to_string(template).unwrap();
            assert!(rendered.contains("echo"), "the template has no content: {rendered}");
            assert!(!rendered.contains("tenant-a") && !rendered.contains("tenant-b"));
        }
        other => panic!("the mount must render as ChildEdge::Indexed, got {other:?}"),
    }
}

/// The new `connectome_edge` seam is opt-in: an activation that does not
/// implement it renders exactly as before.
#[tokio::test]
async fn the_indexed_seam_does_not_disturb_ordinary_children() {
    let plain = DynamicHub::new("hub").register(Health::new()).connectome();
    let with_mount = fixture().hub.connectome();

    let health_plain = plain.children.iter().find(|e| e.namespace() == "health");
    let health_mounted = with_mount.children.iter().find(|e| e.namespace() == "health");
    assert_eq!(
        serde_json::to_string(&health_plain).unwrap(),
        serde_json::to_string(&health_mounted).unwrap(),
        "adding a mount changed how an unrelated child renders"
    );
}

// ============================================================================
// The refusal, and where it loses its spelling (PLX-112)
// ============================================================================

#[test]
fn a_mount_refusal_has_a_refused_spelling_on_the_turn_surface() {
    for refusal in [
        MountRefusal::Unauthenticated,
        MountRefusal::NoSuchTenant,
        MountRefusal::UnsafeSegment,
    ] {
        let stop = refusal.clone().stop_reason();
        assert_eq!(
            stop.kind(),
            StopKind::Refused,
            "a considered no must be Refused, not Failed"
        );
        assert!(!stop.is_success());
    }
}

/// The honest half: on `Result<PlexusStream, PlexusError>` there is no
/// terminal, so `StopKind` cannot be carried. This test pins *where* the
/// refusal degrades so the loss is a recorded fact rather than a surprise.
#[test]
fn the_refusal_degrades_to_plexus_error_on_the_dispatch_surface() {
    assert!(matches!(
        PlexusError::from(MountRefusal::NoSuchTenant),
        PlexusError::MethodNotFound { .. }
    ));
    assert!(matches!(
        PlexusError::from(MountRefusal::Unauthenticated),
        PlexusError::Unauthenticated(_)
    ));
    assert!(matches!(
        PlexusError::from(MountRefusal::UnsafeSegment),
        PlexusError::InvalidParams(_)
    ));
}
