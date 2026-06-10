//! R-5 — the scope-enforcement gate: dispatch consults the
//! [`ScopeRegistry`].
//!
//! Revives AUTHZ-CORE-1 (default-deny posture) + AUTHZ-CORE-5 (dispatch
//! consults the registry; emits the layered-denial errors; writes the
//! `ScopeCheck` audit record) as part of the ROLES+AP merged wave (trak
//! facet `ea4dd433-3bb9-4339-bf29-5e8e58922cb2`).
//!
//! # Activation
//!
//! The gate is **inactive unless configured**. A [`DynamicHub`] that never
//! calls [`DynamicHub::with_scope_registry`] or
//! [`DynamicHub::with_default_deny`] dispatches byte-for-byte as before
//! this module existed: no enforcement, no audit emission, no per-call
//! overhead beyond one `Option` check. This is the hard backward-safety
//! constraint — no in-flight backend regresses by upgrading plexus-core.
//!
//! # Decision table (gate active)
//!
//! | Method | `default_deny` OFF | `default_deny` ON |
//! |---|---|---|
//! | `public` (schema flag or [`ScopeRegistry::is_public`]) | pass (`Allow` audit) | pass (`Allow` audit) |
//! | registry overlay declared ([`ScopeRegistryBuilder::method_scopes`]) | enforced | enforced |
//! | schema-declared scopes (`MethodSchema.requires_credential`) | enforced | enforced |
//! | no declared requirement | pass (today's behavior, no audit) | enforced against the implicit full-path scope |
//!
//! "Enforced" means: anonymous / unauthenticated callers are rejected with
//! [`PlexusError::Unauthenticated`]; authenticated callers have their
//! role-set expanded via [`ScopeRegistry::effective_scopes`] and every
//! required scope checked via [`Scope::matches`] (conjunction — ALL
//! required scopes must be satisfied). The first unsatisfied scope is
//! reported via [`PlexusError::Forbidden`] with
//! [`AuthzDenyReason::MissingScope`]. The error names ONLY the unmet scope
//! — never the registry's role taxonomy or the method's full requirement
//! set beyond what the caller already failed (no-enumeration posture; the
//! full wire-side rendering policy is AUTHZ-PRIVACY-4's, which owns
//! `plexus_error_to_jsonrpc`).
//!
//! # Requirement-source precedence
//!
//! 1. **Registry overlay** — an explicit
//!    [`ScopeRegistryBuilder::method_scopes`] declaration is the
//!    deployment-level override and wins. (Detection note: the registry
//!    API does not expose overlay-vs-implicit directly; an overlay is
//!    detected as [`ScopeRegistry::required_scopes_for`] differing from
//!    the implicit full-path scope. An overlay that is literally the
//!    single full-path scope is indistinguishable from the implicit rule
//!    and therefore behaves like it — i.e., it is enforced only under
//!    `default_deny`, or falls through to the schema-declared scopes.)
//!    An overlay of the **empty** scope set means "authentication
//!    required, no specific scope" — anonymous callers are still
//!    rejected; any authenticated caller passes.
//! 2. **Schema-declared scopes** — `MethodSchema.requires_credential`
//!    populated by the R-1 macro emission (`scope = "..."`) or the
//!    `with_requires_credential` builder.
//! 3. **Implicit full-path scope** — only under `default_deny`:
//!    [`ScopeRegistry::required_scopes_for`]'s implicit rule (the method's
//!    full dotted path as a scope).
//!
//! # `default_deny` ships OFF — open human decision (R-S01 Q4)
//!
//! The mechanism is implemented per AUTHZ-CORE-1's posture, but whether /
//! when each backend flips it ON is an **open human decision** (R-S01 open
//! question 4: is the per-backend flip inside the ROLES wave's completion
//! gate, or left to backend epics à la AUTHZ-FLOWS-4?). Until that call is
//! made, no backend should enable it in production. With it OFF, methods
//! without declared requirements behave exactly as today; methods WITH
//! requirements (schema scopes or registry overlay) are enforced once a
//! registry is configured.
//!
//! Deviation from AUTHZ-CORE-1 §"Required behavior": CORE-1 pinned a
//! **Cargo feature flag** named `default_deny`; this implementation makes
//! it a **runtime builder option** ([`DynamicHub::with_default_deny`]).
//! Rationale: R-5's enforcement model is registry-driven and runtime-
//! configured (the registry itself arrives via a builder call), so a
//! compile-time flag would split one logical posture across two
//! configuration planes; and the off/on behavior must be testable in a
//! single test run. The auditability CORE-1 wanted from the lockfile is
//! preserved at the same granularity — one explicit builder call per
//! deployment binary.
//!
//! # Audit
//!
//! Every gate **decision** (public bypass, allow, deny) writes one
//! [`AuditRecord`] with `kind: ScopeCheck` to the hub's configured
//! [`AuditSink`] (default [`TracingAuditSink`]) and awaits the write
//! BEFORE the dispatch responds (AUTHZ-S01-output §8 "audit before
//! respond"). A pass-through on an ungated method with `default_deny` OFF
//! is not a decision — the gate evaluated nothing — and writes no record.
//! A panicking sink is caught, logged at `tracing::error` with the
//! record's correlation id, and does NOT block the dispatch
//! (AUTHZ-CORE-5 acceptance 9).
//!
//! # Layer ownership (AUTHZ-CORE-5 risk 2)
//!
//! This gate emits layer-1 (`Unauthenticated`) and layer-2
//! (`Forbidden { MissingScope }`) denials only. `InvalidSession` is NOT
//! emitted here: token validation happens upstream in the transport's
//! `SessionValidator` before an `AuthContext` is minted — by the time
//! dispatch runs, the caller either has a verified context or none.
//! `TenantBoundary` belongs to the tenant-scoped storage layer
//! (AUTHZ-DATA), `NotAccepted` to AUTHLANG-3's action gate.
//!
//! [`DynamicHub`]: super::plexus::DynamicHub
//! [`DynamicHub::with_scope_registry`]: super::plexus::DynamicHub::with_scope_registry
//! [`DynamicHub::with_default_deny`]: super::plexus::DynamicHub::with_default_deny
//! [`ScopeRegistryBuilder::method_scopes`]: plexus_auth_core::ScopeRegistryBuilder::method_scopes
//! [`TracingAuditSink`]: plexus_auth_core::TracingAuditSink

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use chrono::Utc;
use futures::FutureExt;
use plexus_auth_core::{
    AuditDecision, AuditDenyReason, AuditRecord, AuditRecordKind, AuditSink, AuthContext,
    MethodPath, RoleName, Scope, ScopeRegistry, SessionId, UserId,
};
use uuid::Uuid;

use super::plexus::{AuthzDenyReason, PlexusError};
use super::schema::MethodSchema;

/// The per-method facts the gate needs, projected out of a
/// [`MethodSchema`] once (at index-build time) so dispatch never re-walks
/// full plugin schemas on the hot path.
#[derive(Debug, Clone, Default)]
pub(crate) struct MethodGateInfo {
    /// `MethodSchema.public` — the explicit default-deny exemption (R-2).
    pub(crate) public: bool,
    /// `MethodSchema.requires_credential.scopes` — the schema-declared
    /// requirement (empty when none declared).
    pub(crate) scopes: Vec<Scope>,
}

impl MethodGateInfo {
    /// Project the gate-relevant facts out of a [`MethodSchema`].
    pub(crate) fn from_schema(schema: &MethodSchema) -> Self {
        Self {
            public: schema.public,
            scopes: schema
                .requires_credential
                .as_ref()
                .map(|rc| rc.scopes.clone())
                .unwrap_or_default(),
        }
    }
}

/// The shared empty registry used when `default_deny` is enabled without a
/// configured [`ScopeRegistry`]. Per the registry's own docs: "a hub
/// without a registry is treated as this empty registry — with
/// default-deny ON every gated method denies" (fail closed).
pub(crate) fn empty_registry() -> &'static ScopeRegistry {
    static EMPTY: OnceLock<ScopeRegistry> = OnceLock::new();
    EMPTY.get_or_init(ScopeRegistry::default)
}

/// Run the scope gate for one dispatch. Returns `Ok(())` when the call may
/// proceed; the typed layered-denial error otherwise. Awaits the audit
/// write before returning in every decision branch.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enforce(
    registry: &ScopeRegistry,
    default_deny: bool,
    sink: &Arc<dyn AuditSink>,
    full_path: &str,
    schema_info: Option<&MethodGateInfo>,
    auth: Option<&AuthContext>,
    client_ip: Option<IpAddr>,
) -> Result<(), PlexusError> {
    let started = Instant::now();

    // The audit record (and the registry) speak validated MethodPath. A
    // dispatched name that fails the dotted-path grammar cannot carry a
    // registry declaration (public / overlay) at all: with default_deny
    // OFF it passes through (today's behavior — such names exist only for
    // hand-rolled activations outside the macro grammar); with
    // default_deny ON it fails closed. The deny branch cannot emit an
    // audit record (no valid MethodPath to put in it); it logs at error
    // instead.
    let mpath = match MethodPath::try_new(full_path) {
        Ok(p) => p,
        Err(_) => {
            if default_deny {
                tracing::error!(
                    target: "plexus::audit",
                    method = full_path,
                    "scope gate: method name fails MethodPath grammar under default_deny — \
                     denying (fail closed); no audit record can be built for it"
                );
                return Err(PlexusError::Forbidden {
                    reason: AuthzDenyReason::MissingScope {
                        scope: Scope::new(full_path),
                    },
                });
            }
            return Ok(());
        }
    };

    // ── Public bypass (schema flag OR registry declaration) ────────────
    let schema_public = schema_info.map(|i| i.public).unwrap_or(false);
    if schema_public || registry.is_public(&mpath) {
        emit(sink, mpath, auth, &[], AuditDecision::Allow, started, client_ip).await;
        return Ok(());
    }

    // ── Requirement resolution (see module docs for precedence) ────────
    let implicit = vec![Scope::new(mpath.as_str())];
    let registry_resolved = registry.required_scopes_for(&mpath);
    let overlay = if registry_resolved != implicit {
        Some(registry_resolved)
    } else {
        None
    };
    let schema_scopes = schema_info
        .map(|i| i.scopes.clone())
        .filter(|s| !s.is_empty());

    let required: Vec<Scope> = match (overlay, schema_scopes) {
        // Deployment-level overlay wins.
        (Some(overlay), _) => overlay,
        // Schema-declared (macro-emitted) requirement.
        (None, Some(scopes)) => scopes,
        // No declared requirement: implicit full-path scope under
        // default_deny; today's pass-through (no decision, no audit)
        // otherwise.
        (None, None) => {
            if default_deny {
                implicit
            } else {
                return Ok(());
            }
        }
    };

    // ── Layer 1: authentication ─────────────────────────────────────────
    let authenticated = auth.map(|a| a.is_authenticated()).unwrap_or(false);
    if !authenticated {
        emit(
            sink,
            mpath,
            auth,
            &required,
            AuditDecision::Deny {
                reason: AuditDenyReason::Unauthenticated,
            },
            started,
            client_ip,
        )
        .await;
        return Err(PlexusError::Unauthenticated(format!(
            "method '{}' requires authentication",
            full_path
        )));
    }
    let auth_ctx = auth.expect("authenticated implies Some(auth)");

    // ── Layer 2: method authorization ───────────────────────────────────
    let roles: Vec<RoleName> = auth_ctx.roles.iter().map(RoleName::new).collect();
    let held = registry.effective_scopes(&roles);
    let unmet = required
        .iter()
        .find(|req| !held.iter().any(|h| h.matches(req)));

    match unmet {
        Some(scope) => {
            let scope = scope.clone();
            emit(
                sink,
                mpath,
                auth,
                &required,
                AuditDecision::Deny {
                    reason: AuditDenyReason::MissingScope,
                },
                started,
                client_ip,
            )
            .await;
            Err(PlexusError::Forbidden {
                reason: AuthzDenyReason::MissingScope { scope },
            })
        }
        None => {
            emit(sink, mpath, auth, &required, AuditDecision::Allow, started, client_ip).await;
            Ok(())
        }
    }
}

/// Build and write one `ScopeCheck` [`AuditRecord`], awaiting the sink
/// BEFORE the caller responds. A panicking sink is caught and logged at
/// `tracing::error` with the record's correlation id — dispatch proceeds
/// with the gate's decision regardless (AUTHZ-CORE-5 acceptance 9).
async fn emit(
    sink: &Arc<dyn AuditSink>,
    method: MethodPath,
    auth: Option<&AuthContext>,
    required: &[Scope],
    decision: AuditDecision,
    started: Instant,
    client_ip: Option<IpAddr>,
) {
    let (originator, session_id) = match auth {
        Some(a) if a.is_authenticated() => (
            Some(UserId::new(a.user_id.clone())),
            if a.session_id.is_empty() {
                None
            } else {
                Some(SessionId::new(a.session_id.clone()))
            },
        ),
        _ => (None, None),
    };
    let roles: Vec<RoleName> = auth
        .map(|a| a.roles.iter().map(RoleName::new).collect())
        .unwrap_or_default();
    let correlation_id = Uuid::new_v4();

    let record = AuditRecord {
        timestamp: Utc::now(),
        kind: AuditRecordKind::ScopeCheck,
        originator,
        session_id,
        // AuthContext carries no invocation chain at this layer; the
        // forward-policy path (AUTHLANG-3) owns chain stamping.
        invocation_chain: Vec::new(),
        roles,
        method,
        scope_required: required.to_vec(),
        decision,
        latency_us: started.elapsed().as_micros() as u64,
        origin: None,
        client_ip,
        correlation_id,
        policy_name: None,
        derivation: None,
        caller_ns: None,
    };

    if let Err(panic) = std::panic::AssertUnwindSafe(sink.write(record))
        .catch_unwind()
        .await
    {
        tracing::error!(
            target: "plexus::audit",
            correlation_id = %correlation_id,
            "audit sink panicked during ScopeCheck write; dispatch proceeds: {:?}",
            panic
        );
    }
}
