//! `tenants/<id>` — the mount, and the gate that keeps it from being a
//! traversal vector (PLX-127, M4·C).
//!
//! # The easy half and the hard half
//!
//! The easy half is that `tenants/<id>` is structurally the same
//! [`ChildEdge::Indexed`](crate::ir::ChildEdge::Indexed) family as
//! `session/<id>`: one shape, many instances, a `path_template` and a
//! `list_method`.
//!
//! The hard half is that the `<id>` segment is **caller-supplied**. A mount
//! that instantiates the per-tenant subtree and *then* checks has already
//! leaked: it constructed an object bound to another tenant's data. PLX-111
//! rejected upward dispatch for precisely this shape — resolution of a
//! caller-supplied id through a global registry, reachable from a public RPC
//! method. So the gate is a named deliverable here, not an implementation
//! detail.
//!
//! # Verify before instantiate, structurally
//!
//! Two properties carry the guarantee, and neither is a convention:
//!
//! 1. **The subtree is behind a factory.** [`TenantMount`] holds a
//!    [`TenantSubtreeFactory`], not a map of built hubs. The factory takes
//!    `&`[`AdmittedTenant`] — a value whose only mint path is
//!    [`TenantMountGate::admit`]. There is no way to *call* the factory
//!    without first holding the gate's verdict, because there is no other way
//!    to obtain its argument.
//!
//! 2. **The auth-less descent door is nailed shut.**
//!    [`ChildRouter::get_child`](crate::plexus::ChildRouter::get_child) has
//!    signature `async fn get_child(&self, name: &str) -> Option<Box<dyn
//!    ChildRouter>>` — **no `AuthContext`** — and
//!    [`route_to_child`](crate::plexus::route_to_child) calls it *before* the
//!    forwarding-policy step. A mount that resolved a tenant there would be
//!    instantiating with no caller to check against. [`TenantMount`] therefore
//!    returns `None` from `get_child` unconditionally and routes only through
//!    [`ChildRouter::router_call`](crate::plexus::ChildRouter::router_call) /
//!    [`Activation::call`](crate::plexus::Activation::call), which do receive
//!    the caller's context.
//!
//! # Absence, not denial
//!
//! M4's exit gate requires tenant A to be **absent** from tenant B's visible
//! Connectome, not merely refused when B asks. Enumeration is disclosure.
//!
//! [`DynamicHub::list_methods`](crate::plexus::DynamicHub::list_methods),
//! [`Activation::plugin_schema`](crate::plexus::Activation::plugin_schema)
//! and [`DynamicHub::connectome`](crate::plexus::DynamicHub::connectome) take
//! **no auth context at all** — the advertised surface is caller-independent.
//! A scope gate therefore denies without hiding, which is why PLX-130 put
//! mount composition first and scope gating second.
//!
//! This mount satisfies absence by never putting a tenant identity into the
//! caller-independent surface in the first place:
//!
//! - the rendered edge is `Indexed`, which carries a `path_template`
//!   (`tenants/{id}`) and one `template` subtree — **no instance ids**. RFC 002
//!   is explicit that instances stay live and are correctly not in the IR;
//! - the only enumeration is [`TenantMount::LIST_METHOD`] (`tenants.list`),
//!   which *is* a dispatched method and *does* receive the caller's context.
//!   It answers with the caller's own resolved tenant and nothing else, so
//!   tenant B's listing cannot contain tenant A regardless of how many tenants
//!   exist.
//!
//! # Where the refusal loses its spelling
//!
//! RFC 002 §6.6 and PLX-112 make a refusal a distinct terminal
//! ([`StopKind::Refused`](crate::ir::StopKind)), not a failure. The mount gate
//! produces a real one: [`MountRefusal::stop_reason`] renders
//! [`StopReason::Refused`](crate::ir::StopReason) with a stable code, and any
//! turn-path handler can surface it faithfully.
//!
//! **It degrades at the dispatch surface, and that is stated rather than
//! papered over.** `Activation::call` returns
//! `Result<PlexusStream, PlexusError>`; that surface has no terminal, so it
//! cannot carry a `StopKind` — the exact residual PLX-112 recorded for the
//! legacy subscription path. On that surface a refusal arrives as
//! [`PlexusError`], via [`From<MountRefusal>`](MountRefusal). See
//! [`MountRefusal`] for the mapping and why the cross-tenant case deliberately
//! renders as *not found* rather than *forbidden*.

use std::sync::Arc;

use serde_json::Value;

use plexus_auth_core::{TenantGate, TenantId, TenantResolver};

use super::auth::AuthContext;
use super::plexus::{Activation, AuthzDenyReason, ChildRouter, DynamicHub, PlexusError};
use super::streaming::PlexusStream;
use crate::ir::{ActivationIr, ChildEdge, StopDetail, StopReason};
use crate::plexus::method_enum::MethodEnumSchema;

// ============================================================================
// The verdict
// ============================================================================

/// Why the mount gate turned a descent away.
///
/// # Not found, not forbidden
///
/// A cross-tenant reach renders as [`MountRefusal::NoSuchTenant`], which maps
/// onto [`PlexusError::MethodNotFound`] — **byte-identical to the answer a
/// caller gets for a tenant that does not exist at all**. That is deliberate
/// and it is the same choice `plexus_auth_core`'s resource-level
/// [`TenantGate`] already makes for reads ("reads scoped `not_found` — a
/// cross-tenant read denial is indistinguishable from *does not exist*, so a
/// foreign-tenant probe cannot use the gate as an existence oracle").
///
/// [`AuthzDenyReason::TenantBoundary`] exists and is tempting here. It is
/// **not** used for the cross-tenant reach, because emitting it would confirm
/// that the named tenant exists — a denial that discloses. It stays where its
/// docs put it: the tenant-scoped storage layer, where existence was already
/// conceded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountRefusal {
    /// The caller has no resolved tenant at all (anonymous, or a context
    /// carrying no tenancy claim). Every descent requires one.
    Unauthenticated,

    /// The segment is well-formed and names a tenant that is not the
    /// caller's — or names nothing. The two are indistinguishable on purpose.
    NoSuchTenant,

    /// The segment cannot be a mount segment at all: it is empty, over-long,
    /// reserved, or contains a byte that would change the meaning of a path
    /// or a dotted method id. See [`mount_segment_is_safe`].
    ///
    /// This is checked **first**, before the resolver is consulted and long
    /// before anything is constructed.
    UnsafeSegment,
}

impl MountRefusal {
    /// The stable refusal code, used both as the [`StopDetail`] code and in
    /// the dispatch-surface message.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "tenant_mount:unauthenticated",
            Self::NoSuchTenant => "tenant_mount:no_such_tenant",
            Self::UnsafeSegment => "tenant_mount:unsafe_segment",
        }
    }

    /// Render this refusal the way RFC 002 §6.6 says a considered "no" is
    /// rendered: a [`StopKind::Refused`](crate::ir::StopKind) terminal, not an
    /// error.
    ///
    /// The dispatch surface cannot carry this (see the module docs); the turn
    /// surface can, and this is what a turn-path caller should emit.
    pub fn stop_reason(self) -> StopReason {
        StopReason::refused(StopDetail::new(self.code()))
    }
}

impl From<MountRefusal> for PlexusError {
    /// The lossy half, stated plainly.
    ///
    /// `Refused` has no spelling on `Result<PlexusStream, PlexusError>` — that
    /// surface has no terminal. Use [`MountRefusal::stop_reason`] wherever a
    /// terminal exists.
    fn from(refusal: MountRefusal) -> Self {
        match refusal {
            MountRefusal::Unauthenticated => {
                PlexusError::Unauthenticated(refusal.code().to_string())
            }
            // Not `Forbidden { TenantBoundary }`: see the type docs. A
            // cross-tenant reach must be indistinguishable from a miss.
            MountRefusal::NoSuchTenant => PlexusError::MethodNotFound {
                activation: "tenants".to_string(),
                method: refusal.code().to_string(),
            },
            // A malformed segment is the caller's own input and discloses
            // nothing about any tenant, so it may be honest.
            MountRefusal::UnsafeSegment => PlexusError::InvalidParams(format!(
                "{}: the tenant segment is empty, over-long, reserved, or contains \
                 a path- or route-significant byte",
                refusal.code()
            )),
        }
    }
}

/// Proof that [`TenantMountGate::admit`] verified a caller-supplied segment
/// against the caller's own resolved tenant.
///
/// The field is private and there is no public constructor, so this type
/// cannot be forged outside this module: **holding one is the check**. It is
/// the argument of [`TenantSubtreeFactory`], which is how "verify before
/// instantiate" stops being a rule someone has to remember.
///
/// Note the deliberate asymmetry with PLX-125's vocabulary: this is *not* a
/// `TenantRecord`. `TenantRecord` is the sealed proof that a row exists, and
/// it lives in plexus-idp, which sits **above** plexus-core — depending on it
/// would invert the dependency order, the same constraint PLX-144 recorded for
/// `TenantRoot`. What `AdmittedTenant` proves is narrower and exactly what the
/// mount needs: *the caller's authenticated context resolved to this
/// identifier*. Existence and activity are the composer's obligation, and the
/// composer discharges it by making its factory refuse (see PLX-151 c4).
#[derive(Debug, Clone)]
pub struct AdmittedTenant {
    id: TenantId,
}

impl AdmittedTenant {
    /// The verified tenant identifier. Equal, by construction, to the segment
    /// the caller supplied *and* to the tenant the caller's context resolved
    /// to.
    pub fn id(&self) -> &TenantId {
        &self.id
    }
}

// ============================================================================
// Segment safety
// ============================================================================

/// Segments this mount refuses to treat as a tenant id, because they mean
/// something else in the surface the mount is part of.
const RESERVED_SEGMENTS: &[&str] = &[TenantMount::LIST_METHOD_NAME, "schema", "connectome"];

/// Whether a caller-supplied segment may be used as a mount segment.
///
/// **This exists because `TenantId::try_new` is not enough.** PLX-151 recorded
/// the finding and PLX-127 is a join site: `TenantId::try_new` validates only
/// non-empty, ≤ 256 bytes, and printable ASCII, so
/// `TenantId::try_new("../tenant-a")` is **valid**, as are `"a/b"`, `".."` and
/// `"/etc"`. Anything joining a tenant id onto a base path must check, and this
/// mount joins one onto `tenants/{id}`.
///
/// It also rejects two bytes that are *route*-significant rather than
/// path-significant, which is specific to this join site:
///
/// - `.` — dispatch splits dotted method ids on the first dot
///   (`DynamicHub::parse_method`, `route_to_child`). A tenant literally named
///   `a.b` would be parsed as tenant `a` with method `b....`: confusable, and
///   confusable resolution of a caller-supplied id is the whole hazard.
/// - `:` and whitespace — `Principal` grammar and audit-field separators.
///
/// Rejecting is the right treatment rather than escaping: a tenant that cannot
/// be named unambiguously must not be mintable, and PLX-125 owns the mint.
pub fn mount_segment_is_safe(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 256 {
        return false;
    }
    if RESERVED_SEGMENTS.contains(&segment) {
        return false;
    }
    if segment == "." || segment == ".." {
        return false;
    }
    !segment.bytes().any(|b| {
        matches!(b, b'/' | b'\\' | b'.' | b':' | b'\0')
            || b.is_ascii_whitespace()
            || b < 0x20
            || b == 0x7f
    })
}

// ============================================================================
// The gate
// ============================================================================

/// Verifies a caller-supplied mount segment against the caller's own resolved
/// tenant, and mints the [`AdmittedTenant`] that unlocks instantiation.
///
/// The gate holds a [`TenantResolver`] — the framework's *only* mint path for
/// the sealed `plexus_auth_core::Tenant` — so a caller cannot pre-load it with
/// a tenant of their choosing.
pub struct TenantMountGate {
    resolver: Arc<dyn TenantResolver>,
}

impl std::fmt::Debug for TenantMountGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantMountGate").finish_non_exhaustive()
    }
}

impl TenantMountGate {
    /// Build a gate over a resolver.
    pub fn new(resolver: Arc<dyn TenantResolver>) -> Self {
        Self { resolver }
    }

    /// Verify `segment` against the caller's context.
    ///
    /// Order matters and is part of the contract:
    ///
    /// 1. [`mount_segment_is_safe`] — cheapest, caller-input-only, and it runs
    ///    before the resolver so a hostile segment never reaches a claim
    ///    lookup;
    /// 2. `TenantId::try_new` — shape;
    /// 3. resolve the caller's sealed tenant from their context;
    /// 4. compare.
    ///
    /// **Nothing per-tenant is constructed anywhere in this function.** The
    /// only value it produces on success is [`AdmittedTenant`], which is an
    /// identifier and a proof, not a resource.
    pub async fn admit(
        &self,
        auth: Option<&AuthContext>,
        segment: &str,
    ) -> Result<AdmittedTenant, MountRefusal> {
        if !mount_segment_is_safe(segment) {
            return Err(MountRefusal::UnsafeSegment);
        }
        let requested = TenantId::try_new(segment).map_err(|_| MountRefusal::UnsafeSegment)?;

        // The resource-level gate from plexus-auth-core, reused rather than
        // re-derived: `from_auth` is one of only two constructors and it
        // routes through the resolver, so the caller-tenant slot cannot hold
        // an attacker-chosen value.
        let gate = TenantGate::from_auth(&*self.resolver, auth).await;
        if gate.is_anonymous() {
            return Err(MountRefusal::Unauthenticated);
        }
        // `can_see` is the read predicate; a mismatch is scoped not-found by
        // the same no-existence-oracle argument.
        if !gate.can_see(Some(&requested)) {
            return Err(MountRefusal::NoSuchTenant);
        }
        Ok(AdmittedTenant { id: requested })
    }

    /// The caller's own resolved tenant, if any — the whole of what
    /// [`TenantMount::LIST_METHOD`] is allowed to disclose.
    pub async fn caller_tenant(&self, auth: Option<&AuthContext>) -> Option<TenantId> {
        let gate = TenantGate::from_auth(&*self.resolver, auth).await;
        gate.caller_tenant().map(TenantId::from)
    }
}

// ============================================================================
// The mount
// ============================================================================

/// Builds the subtree for one admitted tenant.
///
/// It takes `&`[`AdmittedTenant`] and nothing else, which is the point: the
/// argument is unforgeable, so the factory is uncallable before the gate has
/// run. An implementation is free to be fallible — return `None` to refuse a
/// tenant whose record does not exist or is suspended (PLX-151 c4's
/// obligation, discharged at the composer where the record actually lives).
pub type TenantSubtreeFactory =
    Arc<dyn Fn(&AdmittedTenant) -> Option<Arc<DynamicHub>> + Send + Sync>;

/// The `tenants/<id>` mount.
///
/// Register it on a hub like any other activation; it occupies one namespace
/// (conventionally `tenants`) and renders as a
/// [`ChildEdge::Indexed`](crate::ir::ChildEdge::Indexed) family.
///
/// See the module docs for the two structural properties that make this a gate
/// rather than a hole.
#[derive(Clone)]
pub struct TenantMount {
    namespace: Arc<str>,
    version: Arc<str>,
    description: Arc<str>,
    gate: Arc<TenantMountGate>,
    factory: TenantSubtreeFactory,
    template: Arc<ActivationIr>,
}

/// `TenantMount` has no schema-bearing method enum of its own: its surface is
/// one reserved listing method plus an unbounded family of instance paths,
/// which is what the `Indexed` edge is for.
#[derive(schemars::JsonSchema)]
pub struct TenantMountMethods;

impl MethodEnumSchema for TenantMountMethods {
    fn method_names() -> &'static [&'static str] {
        &[TenantMount::LIST_METHOD_NAME]
    }

    fn schema_with_consts() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": { "method": { "const": TenantMount::LIST_METHOD_NAME } }
        })
    }
}

impl TenantMount {
    /// The bare name of the listing method.
    pub const LIST_METHOD_NAME: &'static str = "list";

    /// The dotted id of the listing method, as it appears in the `Indexed`
    /// edge's `list_method`.
    pub const LIST_METHOD: &'static str = "tenants.list";

    /// The field of a listing element that carries the instance id.
    pub const ID_FIELD: &'static str = "tenant_id";

    /// How an instance path is formed.
    pub const PATH_TEMPLATE: &'static str = "tenants/{id}";

    /// Compose a mount.
    ///
    /// `template` is the shape shared by *every* tenant — the composer builds
    /// it from the same registration list its factory uses. It must not be
    /// derived from any particular tenant, and it carries no instance id;
    /// that is what makes tenant A absent from tenant B's rendered surface.
    pub fn new(
        gate: Arc<TenantMountGate>,
        factory: TenantSubtreeFactory,
        template: ActivationIr,
    ) -> Self {
        Self {
            namespace: Arc::from("tenants"),
            version: Arc::from("1.0.0"),
            description: Arc::from("Per-tenant mounts, gated on the caller's resolved tenant"),
            gate,
            factory,
            template: Arc::new(template),
        }
    }

    /// The gate, for composers that want to admit on another path.
    pub fn gate(&self) -> &Arc<TenantMountGate> {
        &self.gate
    }

    /// The `Indexed` edge this mount renders as.
    ///
    /// Note what is **not** here: any tenant identifier. The edge carries the
    /// template, the path template and the name of the listing method, exactly
    /// RFC 002 §5.1's five facts, and instances stay live.
    pub fn indexed_edge(&self) -> ChildEdge {
        ChildEdge::Indexed {
            namespace: self.namespace.to_string(),
            list_method: Self::LIST_METHOD.to_string(),
            search_method: None,
            id_field: Self::ID_FIELD.to_string(),
            path_template: Self::PATH_TEMPLATE.to_string(),
            template: Box::new((*self.template).clone()),
            description: self.description.to_string(),
        }
    }

    /// `tenants.list` — the only enumeration, and it is auth-aware.
    async fn list(&self, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        let mine = self.gate.caller_tenant(auth).await;
        let items: Vec<Value> = mine
            .into_iter()
            .map(|id| serde_json::json!({ Self::ID_FIELD: id.as_str() }))
            .collect();
        Ok(super::streaming::wrap_stream(
            futures::stream::once(async move { serde_json::json!({ "tenants": items }) }),
            "tenants.list",
            vec!["tenants".to_string()],
        ))
    }

    /// The dispatch body, shared by `Activation::call` and
    /// `ChildRouter::router_call`.
    async fn dispatch(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        if method == Self::LIST_METHOD_NAME {
            return self.list(auth).await;
        }

        let Some((segment, rest)) = method.split_once('.') else {
            // A bare `tenants.<id>` addresses a mount, not a method. Say so
            // specifically rather than descending into an empty path — and say
            // it without admitting the segment, so this cannot be used to
            // probe which ids exist.
            return Err(PlexusError::MethodNotFound {
                activation: self.namespace.to_string(),
                method: format!(
                    "{method}: a tenant mount is addressed as \
                     '{ns}.<tenant>.<activation>.<method>'",
                    ns = self.namespace
                ),
            });
        };

        // ── The gate. Everything above this line is string handling; nothing
        //    per-tenant has been constructed, and nothing will be unless this
        //    returns Ok. ──────────────────────────────────────────────────
        let admitted = self.gate.admit(auth, segment).await?;

        // ── Only now. The factory cannot be reached without `admitted`. ──
        let Some(subtree) = (self.factory)(&admitted) else {
            // The composer refused this tenant (no record, or suspended).
            // Same shape as a miss, same reason.
            return Err(MountRefusal::NoSuchTenant.into());
        };

        subtree.route_with_ctx(rest, params, auth, raw_ctx).await
    }
}

impl std::fmt::Debug for TenantMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantMount")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Activation for TenantMount {
    type Methods = TenantMountMethods;

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn methods(&self) -> Vec<&str> {
        vec![Self::LIST_METHOD_NAME]
    }

    fn method_help(&self, method: &str) -> Option<String> {
        (method == Self::LIST_METHOD_NAME)
            .then(|| "List the tenants the caller belongs to".to_string())
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        self.dispatch(method, params, auth, raw_ctx).await
    }

    fn into_rpc_methods(self) -> jsonrpsee::core::server::Methods {
        // Deliberately empty. The instance family is unbounded, so it cannot
        // be pre-registered as jsonrpsee method names; the mount is reached
        // through `DynamicHub::route_with_ctx` (which is what `<hub>.call` and
        // the MCP gateway's route function both use). Registering only
        // `tenants.list` here would advertise a listing endpoint on a path
        // that bypasses the hub's own scope gate, so it is not done.
        jsonrpsee::core::server::Methods::new()
    }

    /// Render as the `Indexed` family, not as a `Static`/`Dynamic` child.
    fn connectome_edge(&self) -> Option<ChildEdge> {
        Some(self.indexed_edge())
    }
}

#[async_trait::async_trait]
impl ChildRouter for TenantMount {
    fn router_namespace(&self) -> &str {
        &self.namespace
    }

    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        self.dispatch(method, params, auth, raw_ctx).await
    }

    /// Always `None`, and this is load-bearing.
    ///
    /// `get_child` receives no [`AuthContext`], and
    /// [`route_to_child`](crate::plexus::route_to_child) calls it before the
    /// forwarding-policy step. Resolving a tenant here would mean
    /// instantiating a per-tenant object with no caller to verify it against —
    /// the exact traversal vector this mount exists to close. Descent goes
    /// through [`Self::router_call`], which has the caller.
    async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
        None
    }
}

// Suppress the unused-import warning when the `AuthzDenyReason` reference in
// the docs is the only mention: the type is named deliberately in
// `MountRefusal`'s documentation to record why it is NOT used.
#[allow(dead_code)]
fn _tenant_boundary_is_deliberately_not_used() -> AuthzDenyReason {
    AuthzDenyReason::TenantBoundary
}
