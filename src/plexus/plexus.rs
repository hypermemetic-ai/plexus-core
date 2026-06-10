//! DynamicHub - the central routing layer for activations
//!
//! DynamicHub IS an activation that also serves as the registry for other activations.
//! It implements the Plexus RPC protocol for routing and introspection.
//! It uses hub-macro for its methods, with the `call` method using the streaming
//! pattern to forward responses from routed methods.

use super::{
    context::PlexusContext,
    method_enum::MethodEnumSchema,
    schema::{ChildSummary, MethodSchema, PluginSchema, Schema},
    streaming::PlexusStream,
};
use crate::types::Handle;
use async_stream::stream;
use async_trait::async_trait;
use bitflags::bitflags;
use futures::Stream;
use futures_core::stream::BoxStream;
use jsonrpsee::core::server::Methods;
use jsonrpsee::RpcModule;

/// The JSON-RPC method name used in all plexus subscription notifications.
///
/// Every subscription registered by plexus (`.call`, `.hash`, `.schema`, `_info`)
/// sends notifications with `"method": PLEXUS_NOTIF_METHOD` on the wire.
/// Clients must match against this value when dispatching raw subscription frames.
pub const PLEXUS_NOTIF_METHOD: &str = "result";
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum PlexusError {
    ActivationNotFound(String),
    MethodNotFound { activation: String, method: String },
    InvalidParams(String),
    ExecutionError(String),
    HandleNotSupported(String),
    TransportError(TransportErrorKind),
    Unauthenticated(String),
    /// Layer-2+ denial from the layered denial model (AUTHZ-0 §4, R-5):
    /// the caller is authenticated but the call is not authorized.
    ///
    /// Produced by the scope gate ([`super::scope_gate`]) when a required
    /// scope is unmet. The full wire-side rendering policy is
    /// AUTHZ-PRIVACY-4's (`plexus_error_to_jsonrpc`); this variant only
    /// commits to the typed server-side value.
    Forbidden { reason: AuthzDenyReason },
}

/// Why a [`PlexusError::Forbidden`] denial fired — the layered denial
/// model's typed discriminator (AUTHZ-S01-output §1, R-5).
///
/// No-enumeration posture per AUTHZ-CORE-1/5: each variant carries at most
/// the single fact the caller already failed. The registry's role taxonomy
/// and the method's full requirement set are never rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDenyReason {
    /// Layer 2 (method authorization): the caller's effective scope set
    /// does not satisfy `scope` — the FIRST unmet required scope.
    /// Emitted by the scope gate (R-5 / AUTHZ-CORE-5).
    MissingScope { scope: plexus_auth_core::Scope },
    /// Layer 4 (data isolation): typed here per AUTHZ-S01-output §1 but
    /// NOT emitted by the scope gate — the tenant-scoped storage layer
    /// (AUTHZ-DATA) owns its emission.
    TenantBoundary,
    /// Layer 3 (action context): typed here but NOT emitted by the scope
    /// gate — AUTHLANG-3's action gate owns its emission.
    NotAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error_kind", rename_all = "snake_case")]
pub enum TransportErrorKind {
    ConnectionRefused { host: String, port: u16 },
    ConnectionTimeout { host: String, port: u16 },
    ProtocolError { message: String },
    NetworkError { message: String },
}

impl std::fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportErrorKind::ConnectionRefused { host, port } => {
                write!(f, "Connection refused to {}:{}", host, port)
            }
            TransportErrorKind::ConnectionTimeout { host, port } => {
                write!(f, "Connection timeout to {}:{}", host, port)
            }
            TransportErrorKind::ProtocolError { message } => {
                write!(f, "Protocol error: {}", message)
            }
            TransportErrorKind::NetworkError { message } => {
                write!(f, "Network error: {}", message)
            }
        }
    }
}

impl std::fmt::Display for PlexusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlexusError::ActivationNotFound(name) => write!(f, "Activation not found: {}", name),
            PlexusError::MethodNotFound { activation, method } => {
                write!(f, "Method not found: {}.{}", activation, method)
            }
            PlexusError::InvalidParams(msg) => write!(f, "Invalid params: {}", msg),
            PlexusError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            PlexusError::HandleNotSupported(activation) => {
                write!(f, "Handle resolution not supported by activation: {}", activation)
            }
            PlexusError::TransportError(kind) => match kind {
                TransportErrorKind::ConnectionRefused { host, port } => {
                    write!(f, "Connection refused to {}:{}", host, port)
                }
                TransportErrorKind::ConnectionTimeout { host, port } => {
                    write!(f, "Connection timeout to {}:{}", host, port)
                }
                TransportErrorKind::ProtocolError { message } => {
                    write!(f, "Protocol error: {}", message)
                }
                TransportErrorKind::NetworkError { message } => {
                    write!(f, "Network error: {}", message)
                }
            }
            PlexusError::Unauthenticated(msg) => write!(f, "Authentication required: {}", msg),
            PlexusError::Forbidden { reason } => match reason {
                // Names ONLY the unmet scope — never the registry's
                // taxonomy or the method's full requirement set
                // (no-enumeration posture, AUTHZ-CORE-1/5).
                AuthzDenyReason::MissingScope { scope } => {
                    write!(f, "Forbidden: missing required scope '{}'", scope)
                }
                AuthzDenyReason::TenantBoundary => write!(f, "Forbidden: tenant boundary"),
                AuthzDenyReason::NotAccepted => write!(f, "Forbidden: call not accepted"),
            },
        }
    }
}

impl std::error::Error for PlexusError {}

/// Convert PlexusError to a JSON-RPC ErrorObject with semantic error codes.
///
/// Codes:
/// - `-32001`: Authentication required (custom app-level error)
/// - `-32003`: Forbidden — authenticated but not authorized (custom app-level error)
/// - `-32601`: Method/activation not found (standard JSON-RPC)
/// - `-32602`: Invalid parameters (standard JSON-RPC)
/// - `-32000`: Generic server error (execution, transport, handle errors)
/// Get the semantic JSON-RPC error code for a PlexusError.
fn plexus_error_code(e: &PlexusError) -> i32 {
    match e {
        PlexusError::Unauthenticated(_) => -32001,
        PlexusError::Forbidden { .. } => -32003,
        PlexusError::InvalidParams(_) => -32602,
        PlexusError::MethodNotFound { .. } | PlexusError::ActivationNotFound(_) => -32601,
        _ => -32000,
    }
}

/// Convert PlexusError to a JSON-RPC ErrorObject with semantic error codes.
fn plexus_error_to_jsonrpc(e: &PlexusError) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(plexus_error_code(e), e.to_string(), None::<()>)
}

// ============================================================================
// Schema Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActivationInfo {
    pub namespace: String,
    pub version: String,
    pub description: String,
    pub methods: Vec<String>,
}

// ============================================================================
// Activation Trait
// ============================================================================

#[async_trait]
pub trait Activation: Send + Sync + 'static {
    type Methods: MethodEnumSchema;

    fn namespace(&self) -> &str;
    fn version(&self) -> &str;
    /// Short description (max 15 words)
    fn description(&self) -> &str { "No description available" }
    /// Long description (optional, for detailed documentation)
    fn long_description(&self) -> Option<&str> { None }
    fn methods(&self) -> Vec<&str>;
    fn method_help(&self, _method: &str) -> Option<String> { None }
    /// Stable activation instance ID for handle routing
    /// By default generates a deterministic UUID from namespace+major_version
    /// Using major version only ensures handles survive minor/patch upgrades (semver)
    fn plugin_id(&self) -> uuid::Uuid {
        let major_version = self.version().split('.').next().unwrap_or("0");
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, format!("{}@{}", self.namespace(), major_version).as_bytes())
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&super::auth::AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError>;
    async fn resolve_handle(&self, _handle: &Handle) -> Result<PlexusStream, PlexusError> {
        Err(PlexusError::HandleNotSupported(self.namespace().to_string()))
    }

    fn into_rpc_methods(self) -> Methods where Self: Sized;

    /// Return this activation's schema (methods + optional children)
    fn plugin_schema(&self) -> PluginSchema {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let methods: Vec<MethodSchema> = self.methods().iter().map(|name| {
            let desc = self.method_help(name).unwrap_or_default();
            // Compute a simple hash for methods not using hub-macro
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            desc.hash(&mut hasher);
            let hash = format!("{:016x}", hasher.finish());
            MethodSchema::new(name.to_string(), desc, hash)
        }).collect();

        if let Some(long_desc) = self.long_description() {
            PluginSchema::leaf_with_long_description(
                self.namespace(),
                self.version(),
                self.description(),
                long_desc,
                methods,
            )
        } else {
            PluginSchema::leaf(
                self.namespace(),
                self.version(),
                self.description(),
                methods,
            )
        }
    }
}

// ============================================================================
// Child Routing for Hub Plugins
// ============================================================================

bitflags! {
    /// Opt-in capability flags advertising which optional `ChildRouter`
    /// operations a router supports.
    ///
    /// The Plexus RPC network is a *graph*, not a tree: children may be
    /// remote, infinite, or deliberately private. Listing and searching
    /// children are therefore opt-in — routers must declare them here
    /// before callers can rely on them.
    ///
    /// # Contract
    ///
    /// | Condition | Expected |
    /// |---|---|
    /// | `capabilities().contains(LIST)` is `true` | `list_children().await` returns `Some(stream)` |
    /// | `capabilities().contains(LIST)` is `false` | `list_children().await` returns `None` |
    /// | `capabilities().contains(SEARCH)` is `true` | `search_children(q).await` returns `Some(stream)` for every `q` |
    /// | `capabilities().contains(SEARCH)` is `false` | `search_children(q).await` returns `None` for every `q` |
    ///
    /// These rules are not runtime-enforced; advertising a capability you
    /// do not implement is a correctness bug in the router.
    ///
    /// # Deprecated (IR-4)
    ///
    /// This bitflags type is superseded by the `MethodRole::DynamicChild {
    /// list_method, search_method }` tag on the corresponding gate method.
    /// Consumers that want to know whether a child router supports list /
    /// search operations should inspect the gate method's role instead of
    /// calling `ChildRouter::capabilities()`. The type stays on the wire for
    /// the 0.5 transition window and is slated for removal in 0.7.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    #[deprecated(
        since = "0.5",
        note = "Use MethodRole::DynamicChild { list_method, search_method } instead. Removed in 0.7."
    )]
    pub struct ChildCapabilities: u32 {
        /// The router promises `list_children()` returns `Some(stream)`.
        const LIST = 0b0000_0001;
        /// The router promises `search_children(query)` returns
        /// `Some(stream)` for any query.
        const SEARCH = 0b0000_0010;
    }
}

/// Trait for activations that can route to child activations
///
/// Hub activations implement this to support nested method routing.
/// When a method like "mercury.info" is called on a solar activation,
/// this trait enables routing to the mercury child.
///
/// This trait is separate from Activation to avoid associated type issues
/// with dynamic dispatch.
///
/// # Optional capabilities
///
/// In addition to the required `router_namespace` + `get_child` surface,
/// routers may opt in to advertising enumerable and searchable children
/// via [`ChildCapabilities`]. When a flag is set, the corresponding
/// `list_children` / `search_children` method must return `Some(stream)`.
/// The default implementations report no capabilities and return `None`.
#[async_trait]
pub trait ChildRouter: Send + Sync {
    /// Get the namespace of this router (for error messages)
    fn router_namespace(&self) -> &str;

    /// Call a method on this router
    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError>;

    /// Get a child activation instance by name for nested routing
    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>>;

    /// Which optional operations (list / search) this router supports.
    ///
    /// Defaults to [`ChildCapabilities::empty()`]: a router that only
    /// exposes `get_child` for exact-name lookup.
    #[allow(deprecated)]
    fn capabilities(&self) -> ChildCapabilities {
        ChildCapabilities::empty()
    }

    /// Stream every child name the router is willing to enumerate.
    ///
    /// Returns `None` when the router does not support listing — callers
    /// should check [`ChildRouter::capabilities`] first.
    ///
    /// Routers that implement this **must** set
    /// [`ChildCapabilities::LIST`] in [`ChildRouter::capabilities`].
    async fn list_children(&self) -> Option<BoxStream<'_, String>> {
        None
    }

    /// Stream child names matching the router-defined query semantics.
    ///
    /// Returns `None` when the router does not support searching — callers
    /// should check [`ChildRouter::capabilities`] first.
    ///
    /// Routers that implement this **must** set
    /// [`ChildCapabilities::SEARCH`] in [`ChildRouter::capabilities`].
    async fn search_children(&self, _query: &str) -> Option<BoxStream<'_, String>> {
        None
    }

    // AUTHLANG-3 — three default-implemented methods that the framework's
    // dispatch path (`route_to_child` below) consults. Existing impls keep
    // compiling unchanged: they inherit the defaults below. Hub-level impls
    // (DynamicHub) override them to consult the registry/principal/sink the
    // hub holds.

    /// Look up the forward policy declared for a callee namespace.
    ///
    /// Default: returns `None`, which the framework interprets as
    /// [`plexus_auth_core::IdentityOnly`] — the safe default per
    /// `AUTHLANG-S01-output` §5. Macro-emitted impls (AUTHLANG-4) override
    /// this from the `#[plexus::activation(forward_policy = ...)]`
    /// attribute; the [`DynamicHub`] override consults its
    /// [`ForwardPolicyRegistry`](super::forward_registry::ForwardPolicyRegistry).
    fn forward_policy_for(
        &self,
        _callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        None
    }

    /// Framework-stamped immediate-caller [`plexus_auth_core::Principal`] of
    /// this router.
    ///
    /// Default: [`plexus_auth_core::Principal::Anonymous`]. The dispatch
    /// path passes this into the [`plexus_auth_core::CallSite`] handed to
    /// the policy so policies can implement callee-and-caller-aware
    /// decisions (e.g., "PassThrough only when callee is in `audit.*`").
    /// Hub-level impls override to return the per-connection stamp.
    fn framework_stamped_principal(&self) -> plexus_auth_core::Principal {
        plexus_auth_core::Principal::Anonymous
    }
}

/// Route a method call to a child activation
///
/// This is called from generated code when a hub activation receives
/// a method that doesn't match its local methods. If the method
/// contains a dot (e.g., "mercury.info"), it routes to the child.
///
/// # AUTHLANG-3 dispatch sequence
///
/// Between callee resolution (`get_child`) and the actual dispatch
/// (`router_call`), the framework runs the forwarding-policy step pinned
/// in `plans/AUTHLANG/AUTHLANG-S01-output.md` §3:
///
/// 1. Resolve the policy registered for the callee namespace via
///    [`ChildRouter::forward_policy_for`]; default
///    [`plexus_auth_core::IdentityOnly`] when none is declared.
/// 2. Build a [`plexus_auth_core::CallSite`] from the parent router's
///    framework-stamped principal and the callee's [`MethodPath`].
/// 3. Invoke [`plexus_auth_core::ForwardPolicy::forward`] to obtain a
///    [`plexus_auth_core::ForwardDerivation`].
/// 4. *(deferred — PRIVACY-1)* Emit one `AuditRecord` with
///    `kind: ForwardPolicyApplied` to the configured `AuditSink`.
/// 5. Mint the callee `AuthContext` via the framework-only constructor
///    [`plexus_auth_core::AuthContext::derive_callee_context`].
/// 6. Dispatch to `child.router_call(...)` with the derived context.
///
/// The policy step is invisible to activation authors per AUTHZ-0
/// principle 1 ("trust is structural, not procedural"). The
/// [`plexus_auth_core::ForwardPolicy::forward`] surface returns
/// *parameters*, never a constructed `AuthContext`; the framework is the
/// only entity that can mint one, per the sealed-type pattern.
pub async fn route_to_child<T: ChildRouter + ?Sized>(
    parent: &T,
    method: &str,
    params: Value,
    auth: Option<&super::auth::AuthContext>,
    raw_ctx: Option<&crate::request::RawRequestContext>,
) -> Result<PlexusStream, PlexusError> {
    // Try to split on first dot for nested routing
    if let Some((child_name, rest)) = method.split_once('.') {
        if let Some(child) = parent.get_child(child_name).await {
            // ── AUTHLANG-3: forwarding-policy dispatch sequence ───────────
            // Steps 1–3, 5–6 per the pinned spike §3. Step 4 (audit
            // emission) is deferred until PRIVACY-1 lands `AuditRecord` /
            // `AuditSink` / `ForwardPolicyApplied`; the TODO below marks
            // the exact insertion point. See run-notes on the ticket.

            // Step 1: resolve the policy registered for the callee
            // namespace; default to IdentityOnly per the spike-pinned safe
            // default (AUTHLANG-S01-output §5).
            let policy: std::sync::Arc<dyn plexus_auth_core::ForwardPolicy> = parent
                .forward_policy_for(child_name)
                .unwrap_or_else(|| {
                    std::sync::Arc::new(plexus_auth_core::IdentityOnly)
                        as std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>
                });

            // Step 2: build the CallSite. The framework-built path string
            // is always a valid MethodPath because the caller already
            // validated the inbound method on its way in; if validation
            // ever fails here it indicates a framework bug, not a user
            // input error.
            let callee_method_str = format!("{}.{}", child_name, rest);
            let callee_method = plexus_auth_core::MethodPath::try_new(callee_method_str.as_str())
                .map_err(|e| PlexusError::ExecutionError(format!(
                    "framework-built MethodPath rejected: {} ({:?})",
                    callee_method_str, e
                )))?;
            let site = plexus_auth_core::CallSite::new(
                parent.framework_stamped_principal(),
                callee_method,
            );

            // Step 3: invoke the policy. When the caller has no
            // AuthContext (anonymous edge), feed the policy the anonymous
            // sealed context so the policy contract is honored uniformly.
            let anonymous_owned;
            let caller_ctx: &super::auth::AuthContext = match auth {
                Some(ctx) => ctx,
                None => {
                    anonymous_owned = super::auth::AuthContext::anonymous();
                    &anonymous_owned
                }
            };
            let derivation = policy.forward(caller_ctx, &site);

            // Step 4 (DEFERRED — PRIVACY-1): emit AuditRecord with
            // kind: ForwardPolicyApplied before dispatch. When PRIVACY-1
            // lands `AuditRecord`, `AuditSink`, and `ForwardPolicyApplied`
            // in `plexus_auth_core`, add a `ChildRouter::audit_sink()`
            // default method (returning a no-op sink) and call:
            //
            //     parent.audit_sink().write(
            //         AuditRecord::for_forward(
            //             &site.callee_method,
            //             &site.caller,
            //             policy.name(),
            //             derivation,
            //             auth.and_then(|c| c.verified_user_id()),
            //         )
            //     ).await;
            //
            // Sink failure must be logged at WARN and NOT propagated
            // (acceptance-criteria row 4 in AUTHLANG-3 §"Required
            // behavior"). Until then, log a structured trace event so
            // operators can confirm the policy step ran:
            tracing::trace!(
                target: "plexus::audit",
                policy = policy.name().as_str(),
                callee_method = %site.callee_method.as_str(),
                derivation_keep_verified_user = derivation.keep_verified_user,
                derivation_keep_roles = derivation.keep_roles,
                derivation_keep_capabilities = derivation.keep_capabilities,
                derivation_keep_metadata = derivation.keep_metadata,
                "forward_policy_applied (audit-record emission stubbed pending PRIVACY-1)"
            );

            // Step 5+6: framework-blessed derivation of the callee sealed
            // AuthContext, and dispatch with it. The policy NEVER sees the
            // constructed value — it returned *parameters*; the framework
            // consumed them via `with_callee_context`, which scopes the
            // callee to the dispatch closure (the raw constructor remains
            // pub(crate) to plexus-auth-core).
            return match auth {
                Some(caller_ctx) => {
                    caller_ctx
                        .with_callee_context(&derivation, &site.caller, |callee_ctx| async move {
                            child
                                .router_call(rest, params, Some(&callee_ctx), raw_ctx)
                                .await
                        })
                        .await
                }
                None => child.router_call(rest, params, None, raw_ctx).await,
            };
        }
        return Err(PlexusError::ActivationNotFound(child_name.to_string()));
    }

    // No dot - method simply not found
    Err(PlexusError::MethodNotFound {
        activation: parent.router_namespace().to_string(),
        method: method.to_string(),
    })
}

/// Wrapper to implement ChildRouter for Arc<dyn ChildRouter>
///
/// This allows DynamicHub to return its stored Arc<dyn ChildRouter> from get_child()
struct ArcChildRouter(Arc<dyn ChildRouter>);

#[async_trait]
impl ChildRouter for ArcChildRouter {
    fn router_namespace(&self) -> &str {
        self.0.router_namespace()
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        self.0.router_call(method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.0.get_child(name).await
    }

    #[allow(deprecated)]
    fn capabilities(&self) -> ChildCapabilities {
        self.0.capabilities()
    }

    async fn list_children(&self) -> Option<BoxStream<'_, String>> {
        self.0.list_children().await
    }

    async fn search_children(&self, query: &str) -> Option<BoxStream<'_, String>> {
        self.0.search_children(query).await
    }

    // AUTHLANG-3 — forward the new ChildRouter trait methods through the
    // Arc wrapper so a `DynamicHub` reached via `get_child` keeps its
    // overrides (especially `forward_policy_for`).
    fn forward_policy_for(
        &self,
        callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        self.0.forward_policy_for(callee_ns)
    }

    fn framework_stamped_principal(&self) -> plexus_auth_core::Principal {
        self.0.framework_stamped_principal()
    }
}

// ============================================================================
// Internal Type-Erased Activation
// ============================================================================

#[async_trait]
#[allow(dead_code)] // Methods exist for completeness but some aren't called post-erasure yet
trait ActivationObject: Send + Sync + 'static {
    fn namespace(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn long_description(&self) -> Option<&str>;
    fn methods(&self) -> Vec<&str>;
    fn method_help(&self, method: &str) -> Option<String>;
    fn plugin_id(&self) -> uuid::Uuid;
    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError>;
    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError>;
    fn plugin_schema(&self) -> PluginSchema;
    fn schema(&self) -> Schema;
}

struct ActivationWrapper<A: Activation> {
    inner: A,
}

#[async_trait]
impl<A: Activation> ActivationObject for ActivationWrapper<A> {
    fn namespace(&self) -> &str { self.inner.namespace() }
    fn version(&self) -> &str { self.inner.version() }
    fn description(&self) -> &str { self.inner.description() }
    fn long_description(&self) -> Option<&str> { self.inner.long_description() }
    fn methods(&self) -> Vec<&str> { self.inner.methods() }
    fn method_help(&self, method: &str) -> Option<String> { self.inner.method_help(method) }
    fn plugin_id(&self) -> uuid::Uuid { self.inner.plugin_id() }

    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        self.inner.call(method, params, auth, raw_ctx).await
    }

    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        self.inner.resolve_handle(handle).await
    }

    fn plugin_schema(&self) -> PluginSchema { self.inner.plugin_schema() }

    fn schema(&self) -> Schema {
        let schema = schemars::schema_for!(A::Methods);
        serde_json::from_value(serde_json::to_value(schema).expect("serialize"))
            .expect("parse schema")
    }
}

// ============================================================================
// Plexus Event Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HashEvent {
    Hash { value: String },
}

/// Event for schema() RPC method - returns plugin schema
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SchemaEvent {
    /// This plugin's schema
    Schema(PluginSchema),
}

/// Lightweight hash information for cache validation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginHashes {
    pub namespace: String,
    pub self_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,
    pub hash: String,
    /// Child plugin hashes (for recursive checking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ChildHashes>>,
}

/// Hash information for a child plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildHashes {
    pub namespace: String,
    pub hash: String,
}


// ============================================================================
// Activation Registry
// ============================================================================

/// Entry in the activation registry
#[derive(Debug, Clone)]
pub struct PluginEntry {
    /// Stable activation instance ID
    pub id: uuid::Uuid,
    /// Current path/namespace for this activation
    pub path: String,
    /// Activation type (e.g., "cone", "bash", "arbor")
    pub plugin_type: String,
}

/// Registry mapping activation UUIDs to their current paths
///
/// This enables handle routing without path dependency - handles reference
/// activations by their stable UUID, and the registry maps to the current path.
#[derive(Default)]
pub struct PluginRegistry {
    /// Lookup by plugin UUID
    by_id: HashMap<uuid::Uuid, PluginEntry>,
    /// Lookup by current path (for reverse lookup)
    by_path: HashMap<String, uuid::Uuid>,
}

/// Read-only snapshot of the activation registry
///
/// Safe to use outside of DynamicHub locks.
#[derive(Clone)]
pub struct PluginRegistrySnapshot {
    by_id: HashMap<uuid::Uuid, PluginEntry>,
    by_path: HashMap<String, uuid::Uuid>,
}

impl PluginRegistrySnapshot {
    /// Look up an activation's path by its UUID
    pub fn lookup(&self, id: uuid::Uuid) -> Option<&str> {
        self.by_id.get(&id).map(|e| e.path.as_str())
    }

    /// Look up an activation's UUID by its path
    pub fn lookup_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.by_path.get(path).copied()
    }

    /// Get an activation entry by its UUID
    pub fn get(&self, id: uuid::Uuid) -> Option<&PluginEntry> {
        self.by_id.get(&id)
    }

    /// List all registered activations
    pub fn list(&self) -> impl Iterator<Item = &PluginEntry> {
        self.by_id.values()
    }

    /// Get the number of registered plugins
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl PluginRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up an activation's path by its UUID
    pub fn lookup(&self, id: uuid::Uuid) -> Option<&str> {
        self.by_id.get(&id).map(|e| e.path.as_str())
    }

    /// Look up an activation's UUID by its path
    pub fn lookup_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.by_path.get(path).copied()
    }

    /// Get an activation entry by its UUID
    pub fn get(&self, id: uuid::Uuid) -> Option<&PluginEntry> {
        self.by_id.get(&id)
    }

    /// Register an activation
    pub fn register(&mut self, id: uuid::Uuid, path: String, plugin_type: String) {
        let entry = PluginEntry { id, path: path.clone(), plugin_type };
        self.by_id.insert(id, entry);
        self.by_path.insert(path, id);
    }

    /// List all registered activations
    pub fn list(&self) -> impl Iterator<Item = &PluginEntry> {
        self.by_id.values()
    }

    /// Get the number of registered plugins
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

// ============================================================================
// DynamicHub (formerly Plexus)
// ============================================================================

/// Build the JSON payload for the `_info` well-known endpoint.
///
/// The shape is `{"backend": "<ns>", "auth_capabilities": {…}}` per
/// AUTHZ-S01-output §2 / AUTHZ-CORE-3. When the backend has not declared its
/// capabilities via [`DynamicHub::with_auth_capabilities`], the field falls
/// back to [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
/// (a single `Anonymous` mechanism). The `_info` endpoint itself remains
/// public — no authentication is required to read it.
fn build_info_payload(
    namespace: &str,
    caps: Option<&plexus_auth_core::BackendAuthCapabilities>,
) -> serde_json::Value {
    let advertised = match caps {
        Some(c) => c.clone(),
        None => plexus_auth_core::BackendAuthCapabilities::anonymous_default(),
    };
    serde_json::json!({
        "backend": namespace,
        "auth_capabilities": advertised,
    })
}

struct DynamicHubInner {
    /// Custom namespace for this hub instance (defaults to "plexus")
    namespace: String,
    activations: HashMap<String, Arc<dyn ActivationObject>>,
    /// Child routers for direct nested routing (e.g., hub.solar.mercury.info)
    child_routers: HashMap<String, Arc<dyn ChildRouter>>,
    /// Activation registry mapping UUIDs to paths
    registry: std::sync::RwLock<PluginRegistry>,
    pending_rpc: std::sync::Mutex<Vec<Box<dyn FnOnce() -> Methods + Send>>>,
    /// What this backend advertises at `_info`'s `auth_capabilities` field.
    ///
    /// `None` means the backend has not called
    /// [`DynamicHub::with_auth_capabilities`]; `_info` falls back to
    /// [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
    /// (a single `Anonymous` mechanism, no default). This preserves today's
    /// no-auth substrate behavior while signaling "no auth wired" to
    /// capability-aware clients.
    ///
    /// Per AUTHZ-CORE-3 and AUTHZ-S01-output §2.
    auth_capabilities: Option<plexus_auth_core::BackendAuthCapabilities>,
    /// AUTHLANG-3 — per-hub mapping from callee namespace to the
    /// [`plexus_auth_core::ForwardPolicy`] consulted at every
    /// cross-boundary call routed through this hub. Populated declaratively
    /// (by the AUTHLANG-4 macro emission) or imperatively (via
    /// [`DynamicHub::with_forward_policy`]). When the registry has no entry
    /// for a callee namespace, the framework falls back to
    /// [`plexus_auth_core::IdentityOnly`] per the spike-pinned safe
    /// default. See `plans/AUTHLANG/AUTHLANG-S01-output.md` §3.
    forward_policies: super::forward_registry::ForwardPolicyRegistry,
    /// R-5 (AUTHZ-CORE-4 acceptance 8) — the deployment's role→scope
    /// taxonomy, consulted by the scope gate at every dispatch through
    /// [`DynamicHub::route_with_ctx`]. `None` means no registry is
    /// configured: with `default_deny` also off (the default), dispatch
    /// behaves byte-for-byte as before the gate existed.
    scope_registry: Option<Arc<plexus_auth_core::ScopeRegistry>>,
    /// R-5 (AUTHZ-CORE-1) — the default-deny posture. **Ships OFF.**
    ///
    /// Whether / when each backend flips this ON is an open human decision
    /// (R-S01 open question 4); see [`super::scope_gate`] module docs for
    /// the full decision table and the deviation note (runtime builder
    /// option here vs CORE-1's Cargo feature flag).
    default_deny: bool,
    /// Where the scope gate writes its `ScopeCheck` [`AuditRecord`]s
    /// (AUTHZ-CORE-5). Defaults to [`plexus_auth_core::TracingAuditSink`];
    /// override via [`DynamicHub::with_audit_sink`].
    ///
    /// [`AuditRecord`]: plexus_auth_core::AuditRecord
    audit_sink: Arc<dyn plexus_auth_core::AuditSink>,
    /// Lazily-built index from full dotted method path
    /// (`<activation>.<method>`, hub-own methods under
    /// `<hub-ns>.<method>`) to the gate-relevant schema facts. Built once
    /// on the first gated dispatch so the gate never re-walks plugin
    /// schemas on the hot path; activations registered after the first
    /// gated dispatch are not in the index (registration is builder-time,
    /// before serving, in every supported composition).
    gate_index: std::sync::OnceLock<HashMap<String, super::scope_gate::MethodGateInfo>>,
}

/// DynamicHub - an activation that routes to dynamically registered child activations
///
/// Unlike hub activations with hardcoded children (like Solar),
/// DynamicHub allows registering activations at runtime via `.register()`.
///
/// # Direct Hosting
///
/// For a single activation, host it directly:
/// ```ignore
/// let solar = Arc::new(Solar::new());
/// TransportServer::builder(solar, converter).serve().await?;
/// ```
///
/// # Composition
///
/// For multiple top-level activations, use DynamicHub:
/// ```ignore
/// let hub = DynamicHub::with_namespace("myapp")
///     .register(Solar::new())
///     .register(Echo::new());
/// ```
#[derive(Clone)]
pub struct DynamicHub {
    inner: Arc<DynamicHubInner>,
}

// ============================================================================
// DynamicHub Infrastructure (non-RPC methods)
// ============================================================================

impl DynamicHub {
    /// Create a new DynamicHub with explicit namespace
    ///
    /// Unlike single activations which have fixed namespaces, DynamicHub is a
    /// composition tool that can be named based on your application. Common choices:
    /// - "hub" - generic default
    /// - "substrate" - for substrate server
    /// - "myapp" - for your application name
    ///
    /// The namespace appears in method calls: `{namespace}.call`, `{namespace}.schema`
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(DynamicHubInner {
                namespace: namespace.into(),
                activations: HashMap::new(),
                child_routers: HashMap::new(),
                registry: std::sync::RwLock::new(PluginRegistry::new()),
                pending_rpc: std::sync::Mutex::new(Vec::new()),
                auth_capabilities: None,
                forward_policies: super::forward_registry::ForwardPolicyRegistry::new(),
                scope_registry: None,
                default_deny: false,
                audit_sink: Arc::new(plexus_auth_core::TracingAuditSink),
                gate_index: std::sync::OnceLock::new(),
            }),
        }
    }

    /// Configure the deployment's [`ScopeRegistry`] — the scope gate's
    /// source of truth for role→scope expansion, public-method
    /// declarations, and per-method scope overlays (R-5 / AUTHZ-CORE-4
    /// acceptance 8).
    ///
    /// Once a registry is configured, every dispatch through this hub
    /// consults the gate: methods whose [`MethodSchema`] carries
    /// `requires_credential` scopes (or that have a registry overlay) are
    /// enforced; `public` methods bypass; methods with no declared
    /// requirement pass through unchanged unless
    /// [`DynamicHub::with_default_deny`] is also set.
    ///
    /// A hub that never calls this (and never sets `default_deny`)
    /// dispatches byte-for-byte as before the gate existed.
    ///
    /// See [`super::scope_gate`] for the full decision table.
    ///
    /// [`ScopeRegistry`]: plexus_auth_core::ScopeRegistry
    /// [`MethodSchema`]: super::schema::MethodSchema
    pub fn with_scope_registry(mut self, registry: plexus_auth_core::ScopeRegistry) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot set scope_registry: DynamicHub has multiple references");
        inner.scope_registry = Some(Arc::new(registry));
        self
    }

    /// Set the default-deny posture (R-5 / AUTHZ-CORE-1). **Ships OFF.**
    ///
    /// With it ON, methods with NO declared requirement are enforced
    /// against the implicit full-path scope
    /// ([`ScopeRegistry::required_scopes_for`]'s implicit rule) — fail
    /// closed, including when no registry is configured at all. With it
    /// OFF (the default), such methods behave exactly as today.
    ///
    /// **Open human decision (R-S01 Q4):** whether / when each backend
    /// flips this ON (inside the ROLES wave's completion gate vs left to
    /// backend epics à la AUTHZ-FLOWS-4) is unresolved. Until that call is
    /// made, no backend should enable it in production.
    ///
    /// Deviation from AUTHZ-CORE-1: this is a runtime builder option, not
    /// the Cargo feature flag CORE-1 pinned — see [`super::scope_gate`]
    /// module docs for the rationale.
    ///
    /// [`ScopeRegistry::required_scopes_for`]: plexus_auth_core::ScopeRegistry::required_scopes_for
    pub fn with_default_deny(mut self, default_deny: bool) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot set default_deny: DynamicHub has multiple references");
        inner.default_deny = default_deny;
        self
    }

    /// Override where the scope gate writes its `ScopeCheck`
    /// [`AuditRecord`]s (AUTHZ-CORE-5). Default:
    /// [`plexus_auth_core::TracingAuditSink`] (`tracing::info!` events on
    /// the `plexus::audit` target).
    ///
    /// The gate awaits the sink's write BEFORE the dispatch responds
    /// ("audit before respond", AUTHZ-S01-output §8). Sink implementors
    /// are responsible for low-latency writes.
    ///
    /// [`AuditRecord`]: plexus_auth_core::AuditRecord
    pub fn with_audit_sink(mut self, sink: Arc<dyn plexus_auth_core::AuditSink>) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot set audit_sink: DynamicHub has multiple references");
        inner.audit_sink = sink;
        self
    }

    /// Read-only view of the configured [`ScopeRegistry`], if any.
    /// Test-side accessor.
    ///
    /// [`ScopeRegistry`]: plexus_auth_core::ScopeRegistry
    pub fn scope_registry(&self) -> Option<&plexus_auth_core::ScopeRegistry> {
        self.inner.scope_registry.as_deref()
    }

    /// The gate's path→schema-facts index; built once on first gated
    /// dispatch. See the field docs on `DynamicHubInner::gate_index`.
    fn gate_index(&self) -> &HashMap<String, super::scope_gate::MethodGateInfo> {
        self.inner.gate_index.get_or_init(|| {
            let mut index = HashMap::new();
            // The hub's own methods, addressable as "<hub-ns>.<method>".
            for m in &Activation::plugin_schema(self).methods {
                index.insert(
                    format!("{}.{}", self.inner.namespace, m.name),
                    super::scope_gate::MethodGateInfo::from_schema(m),
                );
            }
            // Each registered activation's methods, addressable as
            // "<activation-ns>.<method>". Deeper nested paths (an
            // activation's own children) are not indexed here — they have
            // no MethodSchema at this hub's level; the gate treats them as
            // schema-less (registry overlay / default_deny still apply).
            for activation in self.inner.activations.values() {
                let schema = activation.plugin_schema();
                for m in &schema.methods {
                    index.insert(
                        format!("{}.{}", schema.namespace, m.name),
                        super::scope_gate::MethodGateInfo::from_schema(m),
                    );
                }
            }
            index
        })
    }

    /// Register a [`plexus_auth_core::ForwardPolicy`] for a callee
    /// namespace.
    ///
    /// AUTHLANG-3 — every cross-boundary call through this hub consults
    /// the registry at dispatch time. When `callee_ns` has no entry, the
    /// framework falls back to [`plexus_auth_core::IdentityOnly`].
    ///
    /// AUTHLANG-4's `#[plexus::activation(forward_policy = ...)]`
    /// attribute is the declarative path; this builder is the imperative
    /// escape hatch used by integration tests and hand-rolled wiring.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use plexus_auth_core::PassThrough;
    /// use std::sync::Arc;
    ///
    /// let hub = DynamicHub::new("my-backend")
    ///     .with_forward_policy("solar", Arc::new(PassThrough));
    /// ```
    pub fn with_forward_policy(
        mut self,
        callee_ns: impl Into<String>,
        policy: std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>,
    ) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot register forward policy: DynamicHub has multiple references");
        inner.forward_policies.register(callee_ns, policy);
        self
    }

    /// Read-only view of the registered forward policies.
    ///
    /// Test-side accessor; production dispatch consults the registry via
    /// the [`ChildRouter::forward_policy_for`] override.
    pub fn forward_policies(&self) -> &super::forward_registry::ForwardPolicyRegistry {
        &self.inner.forward_policies
    }

    /// Declare the backend's authentication capabilities, served at `_info`.
    ///
    /// Backends call this at builder time to advertise which auth mechanisms
    /// they support (Bearer, Cookie, OIDC, Anonymous). Generic clients
    /// (synapse CLI, gamma, generated SDKs) read the advertisement to decide
    /// which authentication flow to drive.
    ///
    /// Without calling this method, `_info` emits the
    /// [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
    /// fallback: a single `Anonymous` mechanism, no default. This preserves
    /// today's no-auth substrate behavior.
    ///
    /// Per AUTHZ-CORE-3 / AUTHZ-S01-output §2.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use plexus_core::DynamicHub;
    /// use plexus_auth_core::{
    ///     AuthMechanism, BackendAuthCapabilities, CookieName, MethodPath,
    /// };
    ///
    /// let caps = BackendAuthCapabilities::new(
    ///     vec![AuthMechanism::Cookie {
    ///         cookie: CookieName::try_new("plexus_session").unwrap(),
    ///         login: MethodPath::try_new("auth.login").unwrap(),
    ///         refresh: None,
    ///         logout: None,
    ///     }],
    ///     Some(0),
    /// )
    /// .unwrap();
    ///
    /// let hub = DynamicHub::new("my-backend").with_auth_capabilities(caps);
    /// ```
    pub fn with_auth_capabilities(
        mut self,
        caps: plexus_auth_core::BackendAuthCapabilities,
    ) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot set auth_capabilities: DynamicHub has multiple references");
        inner.auth_capabilities = Some(caps);
        self
    }

    /// Returns the configured [`BackendAuthCapabilities`], or `None` if the
    /// backend has not called [`Self::with_auth_capabilities`].
    ///
    /// Test-side accessor; production code reads the advertisement off `_info`.
    ///
    /// [`BackendAuthCapabilities`]: plexus_auth_core::BackendAuthCapabilities
    pub fn auth_capabilities(&self) -> Option<&plexus_auth_core::BackendAuthCapabilities> {
        self.inner.auth_capabilities.as_ref()
    }

    /// Deprecated: Use new() with explicit namespace instead
    #[deprecated(since = "0.3.0", note = "Use DynamicHub::new(namespace) instead")]
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self::new(namespace)
    }

    /// Get the runtime namespace for this DynamicHub instance
    pub fn runtime_namespace(&self) -> &str {
        &self.inner.namespace
    }

    /// Get access to the activation registry
    pub fn registry(&self) -> std::sync::RwLockReadGuard<'_, PluginRegistry> {
        self.inner.registry.read().unwrap()
    }

    /// Register an activation
    pub fn register<A: Activation + ChildRouter + Clone + 'static>(mut self, activation: A) -> Self {
        let namespace = activation.namespace().to_string();
        let plugin_id = activation.plugin_id();
        let activation_for_rpc = activation.clone();
        let activation_for_router = activation.clone();

        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot register: DynamicHub has multiple references");

        // Register in the activation registry
        inner.registry.write().unwrap().register(
            plugin_id,
            namespace.clone(),
            namespace.clone(), // Use namespace as plugin_type for now
        );

        inner.activations.insert(namespace.clone(), Arc::new(ActivationWrapper { inner: activation }));
        inner.child_routers.insert(namespace.clone(), Arc::new(activation_for_router));
        inner.pending_rpc.lock().unwrap()
            .push(Box::new(move || activation_for_rpc.into_rpc_methods()));
        self
    }

    /// Register a hub activation that supports nested routing
    ///
    /// Hub activations implement `ChildRouter`, enabling direct nested method calls
    /// like `hub.solar.mercury.info` at the RPC layer (no hub.call indirection).
    #[deprecated(since = "0.5.0", note = "Use register() — it now handles both leaf and hub activations")]
    pub fn register_hub<A: Activation + ChildRouter + Clone + 'static>(mut self, activation: A) -> Self {
        let namespace = activation.namespace().to_string();
        let plugin_id = activation.plugin_id();
        let activation_for_rpc = activation.clone();
        let activation_for_router = activation.clone();

        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot register: DynamicHub has multiple references");

        // Register in the activation registry
        inner.registry.write().unwrap().register(
            plugin_id,
            namespace.clone(),
            namespace.clone(), // Use namespace as plugin_type for now
        );

        inner.activations.insert(namespace.clone(), Arc::new(ActivationWrapper { inner: activation }));
        inner.child_routers.insert(namespace, Arc::new(activation_for_router));
        inner.pending_rpc.lock().unwrap()
            .push(Box::new(move || activation_for_rpc.into_rpc_methods()));
        self
    }

    /// List all methods across all activations
    pub fn list_methods(&self) -> Vec<String> {
        let mut methods = Vec::new();

        // Include hub's own methods
        for m in Activation::methods(self) {
            methods.push(format!("{}.{}", self.inner.namespace, m));
        }

        // Include registered activation methods
        for (ns, act) in &self.inner.activations {
            for m in act.methods() {
                methods.push(format!("{}.{}", ns, m));
            }
        }
        methods.sort();
        methods
    }

    /// List all activations (including this hub itself)
    pub fn list_activations_info(&self) -> Vec<ActivationInfo> {
        let mut activations = Vec::new();

        // Include this hub itself
        activations.push(ActivationInfo {
            namespace: Activation::namespace(self).to_string(),
            version: Activation::version(self).to_string(),
            description: Activation::description(self).to_string(),
            methods: Activation::methods(self).iter().map(|s| s.to_string()).collect(),
        });

        // Include registered activations
        for a in self.inner.activations.values() {
            activations.push(ActivationInfo {
                namespace: a.namespace().to_string(),
                version: a.version().to_string(),
                description: a.description().to_string(),
                methods: a.methods().iter().map(|s| s.to_string()).collect(),
            });
        }

        activations
    }

    /// Compute hash for cache invalidation
    ///
    /// Returns the hash from the recursive plugin schema. This hash changes
    /// whenever any method definition or child plugin changes.
    pub fn compute_hash(&self) -> String {
        Activation::plugin_schema(self).hash
    }

    /// Route a call to the appropriate activation
    pub async fn route(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.route_with_ctx(method, params, auth, None).await
    }

    /// Route a call to the appropriate activation, with optional raw HTTP request context.
    pub async fn route_with_ctx(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        // R-5 scope gate (AUTHZ-CORE-1 + CORE-5). Inactive unless a
        // ScopeRegistry is configured or default_deny is set — a hub with
        // neither pays exactly this one branch and dispatches as before
        // the gate existed (the hard backward-safety constraint).
        if self.inner.scope_registry.is_some() || self.inner.default_deny {
            let registry = self
                .inner
                .scope_registry
                .as_deref()
                .unwrap_or_else(|| super::scope_gate::empty_registry());
            super::scope_gate::enforce(
                registry,
                self.inner.default_deny,
                &self.inner.audit_sink,
                method,
                self.gate_index().get(method),
                auth,
                raw_ctx.and_then(|ctx| ctx.peer.map(|peer| peer.ip())),
            )
            .await?;
        }

        let (namespace, method_name) = self.parse_method(method)?;

        // Handle plexus's own methods
        if namespace == self.inner.namespace {
            return Activation::call(self, method_name, params, auth, raw_ctx).await;
        }

        let activation = self.inner.activations.get(namespace)
            .ok_or_else(|| PlexusError::ActivationNotFound(namespace.to_string()))?;

        activation.call(method_name, params, auth, raw_ctx).await
    }

    /// Resolve a handle using the activation registry
    ///
    /// Looks up the activation by its UUID in the registry.
    pub async fn do_resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        let path = self.inner.registry.read().unwrap()
            .lookup(handle.plugin_id)
            .map(|s| s.to_string())
            .ok_or_else(|| PlexusError::ActivationNotFound(handle.plugin_id.to_string()))?;

        let activation = self.inner.activations.get(&path)
            .ok_or_else(|| PlexusError::ActivationNotFound(path.clone()))?;
        activation.resolve_handle(handle).await
    }

    /// Get activation schema
    pub fn get_activation_schema(&self, namespace: &str) -> Option<Schema> {
        self.inner.activations.get(namespace).map(|a| a.schema())
    }

    /// Get a snapshot of the activation registry (safe to use outside locks)
    pub fn registry_snapshot(&self) -> PluginRegistrySnapshot {
        let guard = self.inner.registry.read().unwrap();
        PluginRegistrySnapshot {
            by_id: guard.by_id.clone(),
            by_path: guard.by_path.clone(),
        }
    }

    /// Look up an activation path by its UUID
    pub fn lookup_plugin(&self, id: uuid::Uuid) -> Option<String> {
        self.inner.registry.read().unwrap().lookup(id).map(|s| s.to_string())
    }

    /// Look up an activation UUID by its path
    pub fn lookup_plugin_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.inner.registry.read().unwrap().lookup_by_path(path)
    }

    /// Get activation schemas for all activations (including this hub itself)
    pub fn list_plugin_schemas(&self) -> Vec<PluginSchema> {
        let mut schemas = Vec::new();

        // Include this hub itself
        schemas.push(Activation::plugin_schema(self));

        // Include registered activations
        for a in self.inner.activations.values() {
            schemas.push(a.plugin_schema());
        }

        schemas
    }

    /// Deprecated: use list_plugin_schemas instead
    #[deprecated(note = "Use list_plugin_schemas instead")]
    pub fn list_full_schemas(&self) -> Vec<PluginSchema> {
        self.list_plugin_schemas()
    }

    /// Get help for a method
    pub fn get_method_help(&self, method: &str) -> Option<String> {
        let (namespace, method_name) = self.parse_method(method).ok()?;
        let activation = self.inner.activations.get(namespace)?;
        activation.method_help(method_name)
    }

    fn parse_method<'a>(&self, method: &'a str) -> Result<(&'a str, &'a str), PlexusError> {
        let parts: Vec<&str> = method.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(PlexusError::InvalidParams(format!("Invalid method format: {}", method)));
        }
        Ok((parts[0], parts[1]))
    }

    /// Get child activation summaries (for hub functionality)
    /// Called by hub-macro when `hub` flag is set
    pub fn plugin_children(&self) -> Vec<ChildSummary> {
        self.inner.activations.values()
            .map(|a| {
                let schema = a.plugin_schema();
                ChildSummary {
                    namespace: schema.namespace,
                    description: schema.description,
                    hash: schema.hash,
                }
            })
            .collect()
    }

    /// Convert to RPC module
    pub fn into_rpc_module(self) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let mut module = RpcModule::new(());

        PlexusContext::init(self.compute_hash());

        // Register hub methods with runtime namespace using dot notation (e.g., "plexus.call" or "hub.call")
        // Note: we leak these strings to get 'static lifetime required by jsonrpsee
        let ns = self.runtime_namespace();
        let call_method: &'static str = Box::leak(format!("{}.call", ns).into_boxed_str());
        let call_unsub: &'static str = Box::leak(format!("{}.call_unsub", ns).into_boxed_str());
        let hash_method: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let hash_unsub: &'static str = Box::leak(format!("{}.hash_unsub", ns).into_boxed_str());
        let schema_method: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let schema_unsub: &'static str = Box::leak(format!("{}.schema_unsub", ns).into_boxed_str());
        let hash_content_type: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let schema_content_type: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let ns_static: &'static str = Box::leak(ns.to_string().into_boxed_str());

        // Register {ns}.call subscription
        let plexus_for_call = self.clone();
        module.register_subscription(
            call_method,
            PLEXUS_NOTIF_METHOD,
            call_unsub,
            move |params, pending, _ctx, _ext| {
                let plexus = plexus_for_call.clone();
                Box::pin(async move {
                    let p: CallParams = params.parse()?;
                    match plexus.route(&p.method, p.params.unwrap_or_default(), None).await {
                        Ok(stream) => pipe_stream_to_subscription(pending, stream).await,
                        Err(e) => {
                            let sink = pending.accept().await?;
                            let error_item = super::types::PlexusStreamItem::Error {
                                metadata: super::types::StreamMetadata::new(
                                    vec![ns_static.into()],
                                    PlexusContext::hash(),
                                ),
                                message: e.to_string(),
                                code: Some(plexus_error_code(&e).to_string()),
                                recoverable: false,
                            };
                            if let Ok(raw) = serde_json::value::to_raw_value(&error_item) {
                                let _ = sink.send(raw).await;
                            }
                            Ok(())
                        }
                    }
                })
            }
        )?;

        // Register {ns}.hash subscription
        let plexus_for_hash = self.clone();
        module.register_subscription(
            hash_method,
            PLEXUS_NOTIF_METHOD,
            hash_unsub,
            move |_params, pending, _ctx, _ext| {
                let plexus = plexus_for_hash.clone();
                Box::pin(async move {
                    let schema = Activation::plugin_schema(&plexus);
                    let stream = async_stream::stream! {
                        yield HashEvent::Hash { value: schema.hash };
                    };
                    let wrapped = super::streaming::wrap_stream(stream, hash_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Register {ns}.schema subscription
        let plexus_for_schema = self.clone();
        module.register_subscription(
            schema_method,
            PLEXUS_NOTIF_METHOD,
            schema_unsub,
            move |params, pending, _ctx, _ext| {
                let plexus = plexus_for_schema.clone();
                Box::pin(async move {
                    let p: SchemaParams = params.parse().unwrap_or_default();
                    let plugin_schema = Activation::plugin_schema(&plexus);

                    let result = if let Some(ref name) = p.method {
                        plugin_schema.methods.iter()
                            .find(|m| m.name == *name)
                            .map(|m| super::SchemaResult::Method(m.clone()))
                            .ok_or_else(|| jsonrpsee::types::ErrorObject::owned(
                                -32602,
                                format!("Method '{}' not found", name),
                                None::<()>,
                            ))?
                    } else {
                        super::SchemaResult::Plugin(plugin_schema)
                    };

                    let stream = async_stream::stream! { yield result; };
                    let wrapped = super::streaming::wrap_stream(stream, schema_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Register _info well-known endpoint (no namespace prefix).
        // Returns backend name + auth_capabilities (AUTHZ-CORE-3) as a
        // single-item stream with automatic Done event. Backends that have not
        // called with_auth_capabilities get the anonymous-default fallback so
        // capability-aware clients can still discover the auth surface.
        let info_payload = build_info_payload(
            self.runtime_namespace(),
            self.inner.auth_capabilities.as_ref(),
        );
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, _ext| {
                let payload = info_payload.clone();
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move { payload });

                    // Wrap to auto-append Done event
                    let wrapped = super::streaming::wrap_stream(
                        info_stream,
                        "_info",
                        vec![]
                    );

                    // Pipe to subscription (handles Done automatically)
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Add all registered activation RPC methods
        let pending = std::mem::take(&mut *self.inner.pending_rpc.lock().unwrap());
        for factory in pending {
            module.merge(factory())?;
        }

        // CHILD-WIRE: for each registered child router with capability bits set,
        // register {ns}.list_children / {ns}.search_children as subscriptions.
        // Per-activation namespaced (not top-level _list_children).
        for (ns, router) in self.inner.child_routers.iter() {
            register_child_capability_methods(&mut module, ns, router.clone())?;
        }

        Ok(module)
    }

    /// Convert Arc<DynamicHub> to RPC module while keeping the Arc alive
    ///
    /// Unlike `into_rpc_module`, this keeps the Arc<DynamicHub> reference alive,
    /// which is necessary when activations hold Weak<DynamicHub> references that
    /// need to remain upgradeable.
    pub fn arc_into_rpc_module(hub: Arc<Self>) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let mut module = RpcModule::new(());

        PlexusContext::init(hub.compute_hash());

        // Register hub methods with runtime namespace using dot notation (e.g., "plexus.call" or "hub.call")
        // Note: we leak these strings to get 'static lifetime required by jsonrpsee
        let ns = hub.runtime_namespace();
        let call_method: &'static str = Box::leak(format!("{}.call", ns).into_boxed_str());
        let call_unsub: &'static str = Box::leak(format!("{}.call_unsub", ns).into_boxed_str());
        let hash_method: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let hash_unsub: &'static str = Box::leak(format!("{}.hash_unsub", ns).into_boxed_str());
        let schema_method: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let schema_unsub: &'static str = Box::leak(format!("{}.schema_unsub", ns).into_boxed_str());
        let hash_content_type: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let schema_content_type: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let ns_static: &'static str = Box::leak(ns.to_string().into_boxed_str());

        // Register {ns}.call subscription - clone Arc to keep reference alive
        let hub_for_call = hub.clone();
        module.register_subscription(
            call_method,
            call_method,
            call_unsub,
            move |params, pending, _ctx, ext| {
                let hub = hub_for_call.clone();
                Box::pin(async move {
                    let p: CallParams = params.parse()?;
                    // Extract auth context from Extensions (if present)
                    let auth = ext.get::<std::sync::Arc<super::auth::AuthContext>>()
                        .map(|arc| arc.as_ref());
                    match hub.route(&p.method, p.params.unwrap_or_default(), auth).await {
                        Ok(stream) => pipe_stream_to_subscription(pending, stream).await,
                        Err(e) => {
                            // Accept the subscription, then send the error as a stream item.
                            // This preserves the error message and code — returning Err(...)
                            // from a subscription handler causes jsonrpsee to wrap it as
                            // generic -32603, discarding our semantic error code.
                            let sink = pending.accept().await?;
                            let error_item = super::types::PlexusStreamItem::Error {
                                metadata: super::types::StreamMetadata::new(
                                    vec![ns_static.into()],
                                    PlexusContext::hash(),
                                ),
                                message: e.to_string(),
                                code: Some(plexus_error_code(&e).to_string()),
                                recoverable: false,
                            };
                            if let Ok(raw) = serde_json::value::to_raw_value(&error_item) {
                                let _ = sink.send(raw).await;
                            }
                            Ok(())
                        }
                    }
                })
            }
        )?;

        // Register {ns}.hash subscription
        let hub_for_hash = hub.clone();
        module.register_subscription(
            hash_method,
            PLEXUS_NOTIF_METHOD,
            hash_unsub,
            move |_params, pending, _ctx, _ext| {
                let hub = hub_for_hash.clone();
                Box::pin(async move {
                    let schema = Activation::plugin_schema(&*hub);
                    let stream = async_stream::stream! {
                        yield HashEvent::Hash { value: schema.hash };
                    };
                    let wrapped = super::streaming::wrap_stream(stream, hash_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Register {ns}.schema subscription
        let hub_for_schema = hub.clone();
        module.register_subscription(
            schema_method,
            PLEXUS_NOTIF_METHOD,
            schema_unsub,
            move |params, pending, _ctx, _ext| {
                let hub = hub_for_schema.clone();
                Box::pin(async move {
                    let p: SchemaParams = params.parse().unwrap_or_default();
                    let plugin_schema = Activation::plugin_schema(&*hub);

                    let result = if let Some(ref name) = p.method {
                        plugin_schema.methods.iter()
                            .find(|m| m.name == *name)
                            .map(|m| super::SchemaResult::Method(m.clone()))
                            .ok_or_else(|| jsonrpsee::types::ErrorObject::owned(
                                -32602,
                                format!("Method '{}' not found", name),
                                None::<()>,
                            ))?
                    } else {
                        super::SchemaResult::Plugin(plugin_schema)
                    };

                    let stream = async_stream::stream! {
                        yield result;
                    };
                    let wrapped = super::streaming::wrap_stream(stream, schema_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Register _info well-known endpoint (no namespace prefix).
        // Returns backend name + auth_capabilities (AUTHZ-CORE-3) as a
        // single-item stream with automatic Done event. Same payload shape as
        // the sibling registration in into_rpc_module.
        let info_payload = build_info_payload(
            hub.runtime_namespace(),
            hub.inner.auth_capabilities.as_ref(),
        );
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, _ext| {
                let payload = info_payload.clone();
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move { payload });

                    // Wrap to auto-append Done event
                    let wrapped = super::streaming::wrap_stream(
                        info_stream,
                        "_info",
                        vec![]
                    );

                    // Pipe to subscription (handles Done automatically)
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            }
        )?;

        // Register {ns}.respond method for WebSocket bidirectional responses
        // This allows clients to respond to server-initiated requests (like confirmations/prompts)
        let respond_method: &'static str = Box::leak(format!("{}.respond", ns).into_boxed_str());
        module.register_async_method(respond_method, |params, _ctx, _ext| async move {
            use super::bidirectional::{handle_pending_response, BidirError};

            let p: RespondParams = params.parse()?;

            tracing::debug!(
                request_id = %p.request_id,
                "Handling {}.respond via WebSocket",
                "plexus"
            );

            match handle_pending_response(&p.request_id, p.response_data) {
                Ok(()) => Ok(serde_json::json!({"success": true})),
                Err(BidirError::UnknownRequest) => {
                    tracing::warn!(request_id = %p.request_id, "Unknown request ID in respond");
                    Err(jsonrpsee::types::ErrorObject::owned(
                        -32602,
                        format!("Unknown request ID: {}. The request may have timed out or been cancelled.", p.request_id),
                        None::<()>,
                    ))
                }
                Err(BidirError::ChannelClosed) => {
                    tracing::warn!(request_id = %p.request_id, "Channel closed in respond");
                    Err(jsonrpsee::types::ErrorObject::owned(
                        -32000,
                        "Response channel was closed (request may have timed out)",
                        None::<()>,
                    ))
                }
                Err(e) => {
                    tracing::error!(request_id = %p.request_id, error = ?e, "Error in respond");
                    Err(jsonrpsee::types::ErrorObject::owned(
                        -32000,
                        format!("Failed to deliver response: {}", e),
                        None::<()>,
                    ))
                }
            }
        })?;

        // Register pending RPC methods from activations
        let pending = std::mem::take(&mut *hub.inner.pending_rpc.lock().unwrap());
        tracing::trace!(factories = pending.len(), "merging activation RPC factories");
        for (idx, factory) in pending.into_iter().enumerate() {
            tracing::trace!(factory_idx = idx, "calling factory to get Methods");
            let methods = factory();
            let method_count = methods.method_names().count();
            tracing::trace!(factory_idx = idx, methods = method_count, "factory returned Methods; merging into module");
            module.merge(methods)?;
            tracing::trace!(factory_idx = idx, "successfully merged factory methods");
        }
        tracing::trace!("all activations merged successfully");

        // CHILD-WIRE: for each registered child router with capability bits set,
        // register {ns}.list_children / {ns}.search_children as subscriptions.
        for (ns, router) in hub.inner.child_routers.iter() {
            register_child_capability_methods(&mut module, ns, router.clone())?;
        }

        Ok(module)
    }
}

/// CHILD-WIRE: register per-activation namespaced `<ns>.list_children` and
/// `<ns>.search_children` as subscription methods when the router advertises
/// the corresponding capability bits.
///
/// Each name returned by `ChildRouter::list_children` / `search_children` is
/// emitted as a `data` envelope with `content_type` set to the method name
/// (`"list_children"` or `"search_children"`) and `content` carrying the name
/// string. Termination is `done`. Mirrors the standard `wrap_stream` shape
/// used by every other framework subscription.
///
/// Activations that advertise neither bit produce no registrations — calling
/// the methods returns standard `methodNotFound`. That's the wire-level
/// signal that the activation doesn't support enumeration / search.
#[allow(deprecated)] // ChildCapabilities is deprecated by IR-4 but still the wire-level signal
fn register_child_capability_methods(
    module: &mut RpcModule<()>,
    namespace: &str,
    router: Arc<dyn ChildRouter>,
) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    let caps = router.capabilities();
    if caps.is_empty() {
        return Ok(());
    }

    let ns_static: &'static str = Box::leak(namespace.to_string().into_boxed_str());

    if caps.contains(ChildCapabilities::LIST) {
        let list_method: &'static str =
            Box::leak(format!("{}.list_children", namespace).into_boxed_str());
        let list_unsub: &'static str =
            Box::leak(format!("{}.list_children_unsub", namespace).into_boxed_str());
        let router_for_list = router.clone();
        module.register_subscription(
            list_method,
            PLEXUS_NOTIF_METHOD,
            list_unsub,
            move |_params, pending, _ctx, _ext| {
                let router = router_for_list.clone();
                Box::pin(async move {
                    // Collect names eagerly so the BoxStream's borrow on the
                    // router doesn't outlive list_children's call. For v1 this
                    // matches the typical pattern (small finite child sets like
                    // Solar's eight planets). A future variant could keep the
                    // Arc-borrow alive across the stream by binding the BoxStream
                    // to the Arc directly — out of scope here.
                    let collected: Vec<String> = match router.list_children().await {
                        Some(mut s) => {
                            use futures::StreamExt;
                            let mut acc = Vec::new();
                            while let Some(name) = s.next().await {
                                acc.push(name);
                            }
                            acc
                        }
                        None => Vec::new(),
                    };
                    let stream = async_stream::stream! {
                        for name in collected {
                            yield name;
                        }
                    };
                    let wrapped = super::streaming::wrap_stream(
                        stream,
                        "list_children",
                        vec![ns_static.into()],
                    );
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            },
        )?;
    }

    if caps.contains(ChildCapabilities::SEARCH) {
        let search_method: &'static str =
            Box::leak(format!("{}.search_children", namespace).into_boxed_str());
        let search_unsub: &'static str =
            Box::leak(format!("{}.search_children_unsub", namespace).into_boxed_str());
        let router_for_search = router.clone();
        module.register_subscription(
            search_method,
            PLEXUS_NOTIF_METHOD,
            search_unsub,
            move |params, pending, _ctx, _ext| {
                let router = router_for_search.clone();
                Box::pin(async move {
                    let p: SearchChildrenParams = params.parse()?;
                    let collected: Vec<String> = match router.search_children(&p.query).await {
                        Some(mut s) => {
                            use futures::StreamExt;
                            let mut acc = Vec::new();
                            while let Some(name) = s.next().await {
                                acc.push(name);
                            }
                            acc
                        }
                        None => Vec::new(),
                    };
                    let stream = async_stream::stream! {
                        for name in collected {
                            yield name;
                        }
                    };
                    let wrapped = super::streaming::wrap_stream(
                        stream,
                        "search_children",
                        vec![ns_static.into()],
                    );
                    pipe_stream_to_subscription(pending, wrapped).await
                })
            },
        )?;
    }

    Ok(())
}

/// Params for `<ns>.search_children`
#[derive(Debug, serde::Deserialize)]
struct SearchChildrenParams {
    query: String,
}

/// Params for {ns}.call
#[derive(Debug, serde::Deserialize)]
struct CallParams {
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// Params for {ns}.schema
#[derive(Debug, Default, serde::Deserialize)]
struct SchemaParams {
    method: Option<String>,
}

/// Params for {ns}.respond (WebSocket bidirectional response)
#[derive(Debug, serde::Deserialize)]
struct RespondParams {
    request_id: String,
    response_data: Value,
}

/// Helper to pipe a PlexusStream to a subscription sink.
///
/// Notifications are sent with `method: PLEXUS_NOTIF_METHOD` on the wire,
/// as set by the `notif_method_name` arg in each `register_subscription` call.
async fn pipe_stream_to_subscription(
    pending: jsonrpsee::PendingSubscriptionSink,
    mut stream: PlexusStream,
) -> jsonrpsee::core::SubscriptionResult {
    use futures::StreamExt;

    let sink = pending.accept().await?;
    while let Some(item) = stream.next().await {
        let json = serde_json::value::to_raw_value(&item)?;
        sink.send(json).await?;
    }
    Ok(())
}

// ============================================================================
// DynamicHub RPC Methods (via plexus-macros)
// ============================================================================

#[plexus_macros::activation(
    namespace = "plexus",
    version = "1.0.0",
    description = "Central routing and introspection",
    hub,
    namespace_fn = "runtime_namespace"
)]
#[allow(deprecated)]
impl DynamicHub {
    /// Route a call to a registered activation
    #[plexus_macros::method(
        streaming,
        description = "Route a call to a registered activation",
        params(
            method = "The method to call (format: namespace.method)",
            params = "Parameters to pass to the method (optional, defaults to {})"
        )
    )]
    async fn call(
        &self,
        method: String,
        params: Option<Value>,
    ) -> impl Stream<Item = super::types::PlexusStreamItem> + Send + 'static {
        use super::context::PlexusContext;
        use super::types::{PlexusStreamItem, StreamMetadata};

        let result = self.route(&method, params.unwrap_or_default(), None).await;

        match result {
            Ok(plexus_stream) => {
                // Forward the routed stream directly - it already contains PlexusStreamItems
                plexus_stream
            }
            Err(e) => {
                // Return error as a PlexusStreamItem stream
                let metadata = StreamMetadata::new(
                    vec![self.inner.namespace.clone()],
                    PlexusContext::hash(),
                );
                Box::pin(futures::stream::once(async move {
                    PlexusStreamItem::Error {
                        metadata,
                        message: e.to_string(),
                        code: None,
                        recoverable: false,
                    }
                }))
            }
        }
    }

    /// Get Plexus RPC server configuration hash (from the recursive schema)
    ///
    /// This hash changes whenever any method or child activation changes.
    /// It's computed from the method hashes rolled up through the schema tree.
    #[plexus_macros::method(description = "Get plexus configuration hash (from the recursive schema)\n\n This hash changes whenever any method or child plugin changes.\n It's computed from the method hashes rolled up through the schema tree.")]
    async fn hash(&self) -> impl Stream<Item = HashEvent> + Send + 'static {
        let schema = Activation::plugin_schema(self);
        stream! { yield HashEvent::Hash { value: schema.hash }; }
    }

    /// Get plugin hashes for cache validation (lightweight alternative to full schema)
    #[plexus_macros::method(description = "Get plugin hashes for cache validation")]
    #[allow(deprecated)]
    async fn hashes(&self) -> impl Stream<Item = PluginHashes> + Send + 'static {
        let schema = Activation::plugin_schema(self);

        stream! {
            yield PluginHashes {
                namespace: schema.namespace.clone(),
                self_hash: schema.self_hash.clone(),
                children_hash: schema.children_hash.clone(),
                hash: schema.hash.clone(),
                children: schema.children.as_ref().map(|kids| {
                    kids.iter()
                        .map(|c| ChildHashes {
                            namespace: c.namespace.clone(),
                            hash: c.hash.clone(),
                        })
                        .collect()
                }),
            };
        }
    }

    // Note: schema() method is auto-generated by hub-macro for all activations
}

// ============================================================================
// HubContext Implementation for Weak<DynamicHub>
// ============================================================================

use super::hub_context::HubContext;
use std::sync::Weak;

/// HubContext implementation for Weak<DynamicHub>
///
/// This enables activations to receive a weak reference to their parent DynamicHub,
/// allowing them to resolve handles and route calls through the hub without
/// creating reference cycles.
#[async_trait]
impl HubContext for Weak<DynamicHub> {
    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        let hub = self.upgrade().ok_or_else(|| {
            PlexusError::ExecutionError("Parent hub has been dropped".to_string())
        })?;
        hub.do_resolve_handle(handle).await
    }

    async fn call(&self, method: &str, params: serde_json::Value) -> Result<PlexusStream, PlexusError> {
        let hub = self.upgrade().ok_or_else(|| {
            PlexusError::ExecutionError("Parent hub has been dropped".to_string())
        })?;
        hub.route(method, params, None).await
    }

    fn is_valid(&self) -> bool {
        self.upgrade().is_some()
    }
}

/// ChildRouter implementation for DynamicHub
///
/// This enables nested routing through registered activations.
/// e.g., hub.call("solar.mercury.info") routes to solar → mercury → info
#[async_trait]
impl ChildRouter for DynamicHub {
    fn router_namespace(&self) -> &str {
        &self.inner.namespace
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        // DynamicHub routes via its registered activations
        // Method format: "activation.method" or "activation.child.method"
        self.route_with_ctx(method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        // Look up registered activations that implement ChildRouter
        self.inner.child_routers.get(name)
            .map(|router| {
                // Clone the Arc and wrap in Box for the trait object
                Box::new(ArcChildRouter(router.clone())) as Box<dyn ChildRouter>
            })
    }

    /// AUTHLANG-3 — consult the hub's
    /// [`ForwardPolicyRegistry`](super::forward_registry::ForwardPolicyRegistry).
    fn forward_policy_for(
        &self,
        callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        self.inner.forward_policies.get(callee_ns)
    }

    // `framework_stamped_principal` retains the trait default
    // (`Principal::Anonymous`) for now. AUTHLANG-3 wires the dispatch path
    // to read this; populating it with the per-connection stamp lands
    // when the principal-minting service (post-AUTHZ-0 / future
    // CRED-CORE) is wired into the WS upgrade path. The current
    // anonymous return value is correct under today's no-auth substrate.
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_hub_implements_activation() {
        fn assert_activation<T: Activation>() {}
        assert_activation::<DynamicHub>();
    }

    #[test]
    fn dynamic_hub_methods() {
        let hub = DynamicHub::new("test");
        let methods = hub.methods();
        assert!(methods.contains(&"call"));
        assert!(methods.contains(&"hash"));
        assert!(methods.contains(&"schema"));
        // list_activations was removed - use schema() instead
    }

    #[test]
    fn dynamic_hub_hash_stable() {
        let h1 = DynamicHub::new("test");
        let h2 = DynamicHub::new("test");
        assert_eq!(h1.compute_hash(), h2.compute_hash());
    }

    #[test]
    fn dynamic_hub_is_hub() {
        use crate::activations::health::Health;
        let hub = DynamicHub::new("test").register(Health::new());
        let schema = hub.plugin_schema();

        // DynamicHub should be a hub (has children)
        assert!(schema.is_hub(), "dynamic hub should be a hub");
        assert!(!schema.is_leaf(), "dynamic hub should not be a leaf");

        // Should have children (as summaries)
        let children = schema.children.expect("dynamic hub should have children");
        assert!(!children.is_empty(), "dynamic hub should have at least one child");

        // Health should be in the children summaries
        let health = children.iter().find(|c| c.namespace == "health").expect("should have health child");
        assert!(!health.hash.is_empty(), "health should have a hash");
    }

    #[test]
    fn dynamic_hub_schema_structure() {
        use crate::activations::health::Health;
        let hub = DynamicHub::new("test").register(Health::new());
        let schema = hub.plugin_schema();

        // Pretty print the schema
        let json = serde_json::to_string_pretty(&schema).unwrap();
        println!("DynamicHub schema:\n{}", json);

        // Verify structure
        assert_eq!(schema.namespace, "test");
        assert!(schema.methods.iter().any(|m| m.name == "call"));
        assert!(schema.children.is_some());
    }

    // ========================================================================
    // INVARIANT: Handle routing - resolves to correct plugin
    // ========================================================================

    #[tokio::test]
    async fn invariant_resolve_handle_unknown_activation() {
        use crate::activations::health::Health;
        use crate::types::Handle;
        use uuid::Uuid;

        let hub = DynamicHub::new("test").register(Health::new());

        // Handle for an unregistered activation (random UUID)
        let unknown_plugin_id = Uuid::new_v4();
        let handle = Handle::new(unknown_plugin_id, "1.0.0", "some_method");

        let result = hub.do_resolve_handle(&handle).await;

        match result {
            Err(PlexusError::ActivationNotFound(_)) => {
                // Expected - activation not found
            }
            Err(other) => panic!("Expected ActivationNotFound, got {:?}", other),
            Ok(_) => panic!("Expected error for unknown activation"),
        }
    }

    #[tokio::test]
    async fn invariant_resolve_handle_unsupported() {
        use crate::activations::health::Health;
        use crate::types::Handle;

        let hub = DynamicHub::new("test").register(Health::new());

        // Handle for health activation (which doesn't support handle resolution)
        let handle = Handle::new(Health::PLUGIN_ID, "1.0.0", "check");

        let result = hub.do_resolve_handle(&handle).await;

        match result {
            Err(PlexusError::HandleNotSupported(name)) => {
                assert_eq!(name, "health");
            }
            Err(other) => panic!("Expected HandleNotSupported, got {:?}", other),
            Ok(_) => panic!("Expected error for unsupported handle"),
        }
    }

    #[tokio::test]
    async fn invariant_resolve_handle_routes_by_plugin_id() {
        use crate::activations::health::Health;
        use crate::activations::echo::Echo;
        use crate::types::Handle;
        use uuid::Uuid;

        let health = Health::new();
        let echo = Echo::new();
        let health_plugin_id = health.plugin_id();
        let echo_plugin_id = echo.plugin_id();

        let hub = DynamicHub::new("test")
            .register(health)
            .register(echo);

        // Health handle → health activation
        let health_handle = Handle::new(health_plugin_id, "1.0.0", "check");
        match hub.do_resolve_handle(&health_handle).await {
            Err(PlexusError::HandleNotSupported(name)) => assert_eq!(name, "health"),
            Err(other) => panic!("health handle should route to health activation, got {:?}", other),
            Ok(_) => panic!("health handle should return HandleNotSupported"),
        }

        // Echo handle → echo activation
        let echo_handle = Handle::new(echo_plugin_id, "1.0.0", "echo");
        match hub.do_resolve_handle(&echo_handle).await {
            Err(PlexusError::HandleNotSupported(name)) => assert_eq!(name, "echo"),
            Err(other) => panic!("echo handle should route to echo activation, got {:?}", other),
            Ok(_) => panic!("echo handle should return HandleNotSupported"),
        }

        // Unknown handle → ActivationNotFound (random UUID not registered)
        let unknown_handle = Handle::new(Uuid::new_v4(), "1.0.0", "method");
        match hub.do_resolve_handle(&unknown_handle).await {
            Err(PlexusError::ActivationNotFound(_)) => { /* expected */ },
            Err(other) => panic!("unknown handle should return ActivationNotFound, got {:?}", other),
            Ok(_) => panic!("unknown handle should return ActivationNotFound"),
        }
    }

    #[test]
    fn invariant_handle_plugin_id_determines_routing() {
        use crate::activations::health::Health;
        use crate::activations::echo::Echo;
        use crate::types::Handle;

        let health = Health::new();
        let echo = Echo::new();

        // Same meta, different activations → different routing targets (by plugin_id)
        let health_handle = Handle::new(health.plugin_id(), "1.0.0", "check")
            .with_meta(vec!["msg-123".into(), "user".into()]);
        let echo_handle = Handle::new(echo.plugin_id(), "1.0.0", "echo")
            .with_meta(vec!["msg-123".into(), "user".into()]);

        // Different plugin_ids ensure different routing
        assert_ne!(health_handle.plugin_id, echo_handle.plugin_id);
    }

    // ========================================================================
    // Plugin Registry Tests
    // ========================================================================

    #[test]
    fn plugin_registry_basic_operations() {
        let mut registry = PluginRegistry::new();
        let id = uuid::Uuid::new_v4();

        // Register an activation
        registry.register(id, "test_plugin".to_string(), "test".to_string());

        // Lookup by ID
        assert_eq!(registry.lookup(id), Some("test_plugin"));

        // Lookup by path
        assert_eq!(registry.lookup_by_path("test_plugin"), Some(id));

        // Get entry
        let entry = registry.get(id).expect("should have entry");
        assert_eq!(entry.path, "test_plugin");
        assert_eq!(entry.plugin_type, "test");
    }

    #[test]
    fn plugin_registry_populated_on_register() {
        use crate::activations::health::Health;

        let hub = DynamicHub::new("test").register(Health::new());

        let registry = hub.registry();
        assert!(!registry.is_empty(), "registry should not be empty after registration");

        // Health activation should be registered
        let health_id = registry.lookup_by_path("health");
        assert!(health_id.is_some(), "health should be registered by path");

        // Should be able to look up path by ID
        let health_uuid = health_id.unwrap();
        assert_eq!(registry.lookup(health_uuid), Some("health"));
    }

    #[test]
    fn plugin_registry_deterministic_uuid() {
        use crate::activations::health::Health;

        // Same activation registered twice should produce same UUID
        let health1 = Health::new();
        let health2 = Health::new();

        assert_eq!(health1.plugin_id(), health2.plugin_id(),
            "same activation type should have deterministic UUID");

        // UUID should be based on namespace+major_version (semver compatibility)
        let expected = uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            b"health@1"
        );
        assert_eq!(health1.plugin_id(), expected,
            "plugin_id should be deterministic from namespace@major_version");
    }

    // ========================================================================
    // CHILD-2: ChildRouter capabilities + opt-in list/search
    // ========================================================================

    /// A minimal `ChildRouter` that overrides only the required methods.
    /// Exercises default implementations of `capabilities`, `list_children`
    /// and `search_children`.
    struct MinimalRouter;

    #[async_trait]
    impl ChildRouter for MinimalRouter {
        fn router_namespace(&self) -> &str {
            "minimal"
        }

        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "minimal".into(),
                method: "none".into(),
            })
        }

        async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
            None
        }
    }

    #[tokio::test]
    async fn child_router_defaults_report_no_capabilities_and_none_streams() {
        let router = MinimalRouter;

        assert_eq!(
            router.capabilities(),
            ChildCapabilities::empty(),
            "default capabilities should be empty"
        );
        assert!(
            router.list_children().await.is_none(),
            "default list_children should be None"
        );
        assert!(
            router.search_children("anything").await.is_none(),
            "default search_children should be None"
        );
    }

    /// A `ChildRouter` that opts in to both LIST and SEARCH.
    struct ListingRouter {
        names: Vec<String>,
    }

    #[async_trait]
    impl ChildRouter for ListingRouter {
        fn router_namespace(&self) -> &str {
            "listing"
        }

        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "listing".into(),
                method: "none".into(),
            })
        }

        async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
            if self.names.iter().any(|n| n == name) {
                // Return the same type to keep the test simple; we only care
                // that the override compiles and is reachable.
                Some(Box::new(ListingRouter { names: vec![] }))
            } else {
                None
            }
        }

        fn capabilities(&self) -> ChildCapabilities {
            ChildCapabilities::LIST | ChildCapabilities::SEARCH
        }

        async fn list_children(&self) -> Option<BoxStream<'_, String>> {
            let stream = futures::stream::iter(self.names.iter().cloned());
            Some(Box::pin(stream))
        }

        async fn search_children(&self, query: &str) -> Option<BoxStream<'_, String>> {
            let q = query.to_string();
            let stream = futures::stream::iter(
                self.names
                    .iter()
                    .filter(move |n| n.contains(&q))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            Some(Box::pin(stream))
        }
    }

    #[tokio::test]
    async fn child_router_overrides_report_capabilities_and_yield_streams() {
        use futures::StreamExt;

        let router = ListingRouter {
            names: vec!["alpha".into(), "beta".into(), "alphabet".into()],
        };

        // Capabilities
        let caps = router.capabilities();
        assert!(caps.contains(ChildCapabilities::LIST));
        assert!(caps.contains(ChildCapabilities::SEARCH));
        assert_eq!(caps, ChildCapabilities::LIST | ChildCapabilities::SEARCH);

        // list_children yields the full, non-empty, finite sequence.
        let list_stream = router
            .list_children()
            .await
            .expect("LIST capability set — expected Some(stream)");
        let listed: Vec<String> = list_stream.collect().await;
        assert_eq!(listed, vec!["alpha".to_string(), "beta".into(), "alphabet".into()]);

        // search_children filters by the query string.
        let search_stream = router
            .search_children("alpha")
            .await
            .expect("SEARCH capability set — expected Some(stream)");
        let matched: Vec<String> = search_stream.collect().await;
        assert_eq!(matched, vec!["alpha".to_string(), "alphabet".into()]);
    }

    // ========================================================================
    // CHILD-WIRE: per-activation namespaced wire exposure for
    // <ns>.list_children / <ns>.search_children
    //
    // These tests exercise `register_child_capability_methods` directly with
    // hand-built fixtures, then drive the resulting RpcModule through the
    // in-process subscription path. Mirrors the existing
    // `auth_capabilities_info` integration pattern but verifies the
    // child-router wire registration instead of the _info payload.
    // ========================================================================

    /// Like `EnumerableRouter` above but with configurable capability bits +
    /// a fixed name set. Used to drive CHILD-WIRE registration through
    /// different capability combinations.
    struct WireFixture {
        names: Vec<String>,
        caps: ChildCapabilities,
    }

    #[async_trait]
    impl ChildRouter for WireFixture {
        fn router_namespace(&self) -> &str {
            "wirefixture"
        }
        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "wirefixture".into(),
                method: "none".into(),
            })
        }
        async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
            None
        }
        fn capabilities(&self) -> ChildCapabilities {
            self.caps
        }
        async fn list_children(&self) -> Option<futures_core::stream::BoxStream<'_, String>> {
            if !self.caps.contains(ChildCapabilities::LIST) {
                return None;
            }
            Some(Box::pin(futures::stream::iter(self.names.clone())))
        }
        async fn search_children(
            &self,
            query: &str,
        ) -> Option<futures_core::stream::BoxStream<'_, String>> {
            if !self.caps.contains(ChildCapabilities::SEARCH) {
                return None;
            }
            let q = query.to_lowercase();
            let filtered: Vec<String> = self
                .names
                .iter()
                .filter(|n| n.to_lowercase().contains(&q))
                .cloned()
                .collect();
            Some(Box::pin(futures::stream::iter(filtered)))
        }
    }

    fn build_module_for(router: WireFixture, ns: &str) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        let arc: Arc<dyn ChildRouter> = Arc::new(router);
        register_child_capability_methods(&mut module, ns, arc).expect("register");
        module
    }

    #[tokio::test]
    async fn child_wire_registers_both_methods_when_both_bits_set() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into(), "beta".into()],
                caps: ChildCapabilities::LIST | ChildCapabilities::SEARCH,
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(
            names.contains(&"fixture.list_children".to_string()),
            "expected fixture.list_children, got: {:?}",
            names
        );
        assert!(
            names.contains(&"fixture.search_children".to_string()),
            "expected fixture.search_children, got: {:?}",
            names
        );
    }

    #[tokio::test]
    async fn child_wire_registers_nothing_when_no_bits_set() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into()],
                caps: ChildCapabilities::empty(),
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(
            !names.contains(&"fixture.list_children".to_string()),
            "fixture.list_children should NOT be registered when cap absent"
        );
        assert!(
            !names.contains(&"fixture.search_children".to_string()),
            "fixture.search_children should NOT be registered when cap absent"
        );
    }

    #[tokio::test]
    async fn child_wire_registers_only_list_when_only_list_bit() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into()],
                caps: ChildCapabilities::LIST,
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(names.contains(&"fixture.list_children".to_string()));
        assert!(!names.contains(&"fixture.search_children".to_string()));
    }

    // Live wire-call behavior (subscription stream content, methodNotFound on
    // unregistered names, error envelopes) is verified end-to-end against
    // running substrate Solar — that's the canonical integration gate per
    // the CHILD-WIRE acceptance criteria. The unit-level introspection
    // tests above assert the registration shape; the substrate verification
    // asserts the live behavior. Splitting it that way avoids forcing the
    // unit test to construct a working RpcSubscriptionSink, which is not
    // straightforward in the bare jsonrpsee API.
}
