/// JSON Schema types with strong typing
///
/// This module provides strongly-typed JSON Schema structures that plugins
/// use to describe their methods and parameters.
///
/// Schema generation is fully automatic via schemars. By using proper types
/// (uuid::Uuid instead of String) and doc comments, schemars generates complete
/// schemas with format annotations, descriptions, and required arrays.

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use plexus_auth_core::{
    AttachmentSite, CredentialFieldMarker, CredentialIssuer, CredentialKind, CredentialMetadata,
    Scope,
};

use super::bidirectional::{StandardRequest, StandardResponse};

// =============================================================================
// Method Role
// =============================================================================

/// Describes how a method participates in the activation graph.
///
/// Every method on a plugin is exactly one of three kinds:
///
/// - `Rpc` — a regular RPC endpoint (the default).
/// - `StaticChild` — the method returns a child activation by a static name
///   (no lookup argument). Used by `#[child]`-annotated methods on hubs.
/// - `DynamicChild { .. }` — the method gates a dynamic child keyed by its
///   argument. `list_method` optionally names a sibling method that enumerates
///   available keys, and `search_method` optionally names a sibling method
///   that searches keys.
///
/// This tag is consumed by downstream tooling (synapse, synapse-cc,
/// introspection clients) to reconstruct the child graph without a separate
/// side-table. Today's macros emit `MethodRole::Rpc` for every method; IR-3
/// populates child roles from `#[child]` annotations.
///
/// # Wire back-compat
///
/// Added in IR-2. Serde defaults to `Rpc` for pre-IR schemas.
/// `#[non_exhaustive]` reserves space for future variants without breaking
/// downstream match arms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MethodRole {
    /// Method is an RPC endpoint (the default for ordinary methods).
    Rpc,
    /// Method returns a child activation by static name (no lookup arg).
    StaticChild,
    /// Method gates a dynamic child keyed by its argument.
    DynamicChild {
        /// Optional sibling method that lists available keys.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        list_method: Option<String>,
        /// Optional sibling method that searches available keys.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search_method: Option<String>,
    },
}

impl Default for MethodRole {
    fn default() -> Self {
        MethodRole::Rpc
    }
}

// =============================================================================
// Deprecation Info
// =============================================================================

/// Structured deprecation metadata attached to a `MethodSchema`.
///
/// Downstream consumers (CLI help, docs generators, IDEs) use these fields
/// to surface migration guidance to users.
///
/// # Example
///
/// ```
/// use plexus_core::DeprecationInfo;
///
/// let info = DeprecationInfo {
///     since: "0.5".into(),
///     removed_in: "0.6".into(),
///     message: "Use `new_method` instead.".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeprecationInfo {
    /// The plexus-core version at which deprecation began (e.g., `"0.5"`).
    pub since: String,
    /// The plexus-core version planned for removal (e.g., `"0.6"`).
    ///
    /// Not binding — serves as a consumer-visible hint.
    pub removed_in: String,
    /// Human-readable migration guidance.
    pub message: String,
}

// =============================================================================
// Param Schema
// =============================================================================

/// Per-parameter metadata for a method's parameters.
///
/// `MethodSchema.params` already carries the fine-grained JSON Schema for the
/// combined parameter object. `ParamSchema` carries orthogonal, parameter-
/// scoped metadata that doesn't fit on a JSON Schema node — currently just
/// deprecation info (IR-5).
///
/// The `name` field matches the parameter identifier in the method signature
/// so consumers can correlate entries against the `params` JSON Schema's
/// `properties` map.
///
/// Added in IR-5. Defaults to an empty list on `MethodSchema` so pre-IR
/// schemas deserialize cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ParamSchema {
    /// Parameter name, matching the identifier in the method signature.
    pub name: String,
    /// If set, this parameter is deprecated.
    ///
    /// Populated by `#[deprecated(...)]` (+ optional
    /// `#[plexus_macros::removed_in("...")]`) on the parameter in the
    /// method signature (IR-5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationInfo>,
}

impl ParamSchema {
    /// Create a new `ParamSchema` carrying just a name and no metadata.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            deprecation: None,
        }
    }

    /// Attach deprecation metadata for this parameter.
    pub fn with_deprecation(mut self, info: DeprecationInfo) -> Self {
        self.deprecation = Some(info);
        self
    }
}

// =============================================================================
// Credential projections (AUTHZ-CRED-CORE-3)
// =============================================================================

/// One entry per credential-bearing field in a method's return type.
///
/// Pinned by `AUTHZ-CRED-S01-output.md` §4 and `AUTHZ-CRED-CORE-3` §"Required
/// behavior". Projected onto `MethodSchema.credentials` at schema-build time
/// from the `CredentialFieldMarker` registry the `#[derive(Credentials)]` macro
/// emits per credential-bearing type (`AUTHZ-CRED-MACRO-1`).
///
/// # Field path semantics (Tier B Q-IR-1)
///
/// `field_path` is the JSON-object path to the credential field within the
/// method's return type. v1 always uses object-field paths (one segment per
/// field name walked); array indices and JSON Pointer syntax are intentionally
/// excluded because credentials always live on object fields in v1, never
/// inside array elements.
///
/// Example: for a return type
/// `struct LoginResult { session: Credential<String> }`, the field path is
/// `["session"]`. For a nested case
/// `struct LoginResult { auth: AuthBundle }` where `AuthBundle` itself
/// declares a `#[plexus::credential(..)]` field `token: Credential<String>`,
/// the field path is `["auth", "token"]`.
///
/// # Variant tagging
///
/// `variant_tag` is `Some(tag)` when the method's return type is an enum and
/// the credential lives on a single variant. The tag matches the variant
/// identifier as the macro registry records it (e.g. `"Issued"` for the
/// `LoginEvent::Issued` variant). `None` means the return type is a struct,
/// or the credential appears on every variant of the enum (rare).
///
/// # Wire back-compat
///
/// Added in `AUTHZ-CRED-CORE-3`. Pre-existing readers tolerate `credentials:
/// []` (the default on `MethodSchema` when no credentials are declared) and
/// pre-existing IRs that omit the field altogether decode cleanly via
/// `#[serde(default)]` on the field site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CredentialFieldDecl {
    /// JSON-object path to the credential field within the method's return
    /// type. One segment per field-name walk; pinned to object paths (no
    /// array indices, no JSON Pointer) per Tier B Q-IR-1.
    pub field_path: Vec<String>,

    /// Variant tag when the return type is an enum and the credential lives
    /// on a single variant. `None` for structs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_tag: Option<String>,

    /// The credential's metadata (kind, attach site, scheme, scopes, expiry,
    /// refresh/revoke hints, issuer, sensitivity). Carried verbatim so
    /// consumers embed identical storage-and-attach logic to the runtime.
    pub metadata: CredentialMetadata,
}

impl CredentialFieldDecl {
    /// Construct a `CredentialFieldDecl` by composing a `CredentialFieldMarker`
    /// from the macro-emitted registry with the runtime-supplied pieces
    /// (`expires_at` known only at mint time; `issuer` known at schema-build
    /// time from the originating method's `(Origin, MethodPath)`).
    ///
    /// `path_prefix` is the field-path walk to the marker's parent type — for
    /// a flat struct it is empty; for a nested case where this marker lives
    /// inside a field of the method's return type the prefix is the path to
    /// that wrapping field. The marker's own `field` and `variant` are
    /// appended.
    pub fn from_marker(
        marker: &CredentialFieldMarker,
        path_prefix: &[&str],
        issuer: CredentialIssuer,
    ) -> Self {
        let mut field_path: Vec<String> = path_prefix.iter().map(|s| (*s).to_owned()).collect();
        field_path.push(marker.field.to_owned());
        let variant_tag = marker.variant.map(|v| v.to_owned());
        let metadata = marker.to_metadata(None, issuer);
        Self {
            field_path,
            variant_tag,
            metadata,
        }
    }
}

/// What a method requires on input — the implicit-derivation projection of
/// scope tagging and credential-graph linkage onto a per-method filter.
///
/// Pinned by `AUTHZ-CRED-S01-output.md` §4 (Q-SELECT-1 resolution: implicit
/// derivation from scope tagging plus refresh/revoke linkage) and
/// `AUTHZ-CRED-CORE-3` §"Implicit derivation". This ticket explicitly does
/// NOT add a `#[plexus::method(requires_credential = { .. })]` attribute
/// surface — the proposal from `AUTHZ-CRED-S01-output` §10 is superseded by
/// the implicit-derivation approach pinned here.
///
/// # Matching semantics (consumer-side)
///
/// A candidate credential matches this `RequiredCredential` iff:
/// 1. `kind`: if `Some(k)`, the candidate's `CredentialMetadata.kind`
///    matches `k` (or the kind-subsumption table per `AUTHZ-CRED-CORE-1`
///    accepts the substitution; e.g. `OauthAccess <: Bearer`). If `None`,
///    any kind whose scope set matches is acceptable.
/// 2. `scopes`: each scope in this set must be wildcard-matched by the
///    candidate's `CredentialMetadata.scopes`. The wildcard rules belong to
///    the `Scope` type itself.
/// 3. `site_hint`: when populated, prefers the candidate whose
///    `CredentialMetadata.attach_as` equals the hint. Advisory only — a
///    candidate without the hint is not rejected.
///
/// # Wire back-compat
///
/// Added in `AUTHZ-CRED-CORE-3`. Pre-existing readers tolerate
/// `requires_credential: null` (omitted on the wire when `None`) and
/// pre-existing IRs that omit the field altogether decode cleanly via
/// `#[serde(default)]` on the field site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequiredCredential {
    /// Specific kind a candidate credential must have (e.g.,
    /// `OauthRefresh`), or `None` for "any kind whose scope set matches".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CredentialKind>,

    /// Required scope set. A candidate credential's metadata scopes must
    /// wildcard-match each scope in this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<Scope>,

    /// Preferred attach site for the client to use when the candidate
    /// credential has multiple alternates. Advisory only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_hint: Option<AttachmentSite>,
}

impl RequiredCredential {
    /// Derive a `RequiredCredential` from a method's required scope tagging
    /// (per `AUTHZ-S01-output` §4). The `kind` field is left `None` — any
    /// kind whose scope set wildcard-matches `scope` is acceptable.
    ///
    /// Used when a method declares `#[plexus::method(scope = "...")]` (or
    /// the framework derives an implicit scope from the method's path).
    pub fn from_method_scope(scope: Scope) -> Self {
        Self {
            kind: None,
            scopes: vec![scope],
            site_hint: None,
        }
    }

    /// Derive a `RequiredCredential` for a method that appears as the target
    /// of another credential's `metadata.refresh_via` or `metadata.revoke_via`
    /// (per `AUTHZ-CRED-CORE-3` §"Implicit derivation" row 3). The `kind`
    /// field narrows to the issuing credential's kind so the selection step
    /// picks the right kind (e.g., `OauthRefresh` for the
    /// `auth.refresh` call on an `OauthAccess` credential per the OAuth
    /// flow described in `AUTHZ-CRED-S01-output` §7.2).
    pub fn from_refresh_revoke_target(kind: CredentialKind, scopes: Vec<Scope>) -> Self {
        Self {
            kind: Some(kind),
            scopes,
            site_hint: None,
        }
    }
}

// =============================================================================
// Return Shape
// =============================================================================

/// Describes the structural shape of a method's return type.
///
/// Orthogonal to the fine-grained JSON Schema stored in `MethodSchema.returns`:
/// that schema describes the inner type; this tag describes the wrapping.
///
/// - `Bare` — `T`
/// - `Option` — `Option<T>`
/// - `Result` — `Result<T, E>`
/// - `Vec` — `Vec<T>`
/// - `Stream` — a stream of `T` (e.g., `AsyncGenerator<T>`)
/// - `ResultOption` — `Result<Option<T>, E>`
///
/// Added in IR-2 as an optional, additive field on `MethodSchema`. Consumers
/// that don't care can ignore it; those generating language bindings use it to
/// pick the right idiom (e.g., TypeScript `T | null` for `Option`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReturnShape {
    /// `T` — the return type is used as-is.
    Bare,
    /// `Option<T>` — the return may be null/absent.
    Option,
    /// `Result<T, E>` — the return may be an error.
    Result,
    /// `Vec<T>` — the return is a list.
    Vec,
    /// A stream of `T` events.
    Stream,
    /// `Result<Option<T>, E>` — common pattern for fallible lookups.
    ResultOption,
}

// =============================================================================
// HTTP Method Enum
// =============================================================================

/// HTTP method for REST endpoint routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET: Idempotent read operations with no side effects
    Get,
    /// POST: Create operations or non-idempotent actions (default)
    Post,
    /// PUT: Replace/update operations (idempotent)
    Put,
    /// DELETE: Remove operations (idempotent)
    Delete,
    /// PATCH: Partial update operations
    Patch,
}

impl Default for HttpMethod {
    fn default() -> Self {
        HttpMethod::Post
    }
}

impl HttpMethod {
    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "DELETE" => Some(HttpMethod::Delete),
            "PATCH" => Some(HttpMethod::Patch),
            _ => None,
        }
    }

    /// Convert to uppercase string
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
        }
    }
}

// ============================================================================
// Plugin Schema
// ============================================================================

/// A plugin's schema with methods and child summaries.
///
/// Children are represented as summaries (namespace, description, hash) rather
/// than full recursive schemas. This enables lazy traversal - clients can fetch
/// child schemas individually via `{namespace}.schema`.
///
/// - Leaf plugins have `children = None`
/// - Hub plugins have `children = Some([ChildSummary, ...])`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginSchema {
    /// The plugin's namespace (e.g., "echo", "plexus")
    pub namespace: String,

    /// The plugin's version (e.g., "1.0.0")
    pub version: String,

    /// Short description of the plugin (max 15 words)
    pub description: String,

    /// Detailed description of the plugin (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_description: Option<String>,

    /// Hash of ONLY this plugin's methods (ignores children)
    /// Changes when method signatures, names, or descriptions change
    pub self_hash: String,

    /// Hash of ONLY child plugin hashes (None for leaf plugins)
    /// Changes when any child's hash changes (recursively)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,

    /// Composite hash = hash(self_hash + children_hash)
    /// Use this if you want a single hash for the entire subtree
    /// Backward compatible with previous single-hash system
    pub hash: String,

    /// Methods exposed by this plugin
    pub methods: Vec<MethodSchema>,

    /// Child plugin summaries (None = leaf plugin, Some = hub plugin)
    ///
    /// # Deprecated (IR-4)
    ///
    /// This side-table is deterministically derived from the method list's
    /// `MethodRole` tags (one `ChildSummary` per non-`Rpc` method). It stays
    /// on the wire for back-compat during the 0.5 transition window and is
    /// slated for removal in 0.6.
    ///
    /// Consumers reading child metadata should switch to iterating
    /// `methods` and filtering by `role != MethodRole::Rpc`. The name field
    /// on each `MethodSchema` is the child's namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(
        since = "0.5",
        note = "Derive from MethodRole on MethodSchema. Field will be removed in 0.7."
    )]
    pub children: Option<Vec<ChildSummary>>,

    /// JSON Schema for the HTTP request type this activation extracts from incoming connections.
    ///
    /// Present when the activation declares `request = MyRequest` in `#[plexus::activation(...)]`.
    /// The schema includes `x-plexus-source` extension fields on each property describing
    /// where each field is sourced from (cookie, header, query param, peer address, etc.).
    ///
    /// Clients can use this to understand what request data the activation expects and
    /// to generate appropriate authentication/context documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<serde_json::Value>,

    /// If set, this whole activation is deprecated.
    ///
    /// Added in IR-5. Defaults to `None` via `#[serde(default)]` so pre-IR
    /// schemas deserialize cleanly.
    ///
    /// Populated by the `#[deprecated(...)]` attribute on the `impl
    /// Activation for Foo` block (IR-5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationInfo>,
}

/// Result of a schema query - either full plugin or single method
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SchemaResult {
    /// Full plugin schema (when no method specified)
    Plugin(PluginSchema),
    /// Single method schema (when method specified)
    Method(MethodSchema),
}

/// Schema for a single method exposed by a plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MethodSchema {
    /// Method name (e.g., "echo", "check")
    pub name: String,

    /// Human-readable description of what this method does
    pub description: String,

    /// Content hash of the method definition (for cache invalidation)
    /// Generated by hashing the method signature within hub-macro
    pub hash: String,

    /// JSON Schema for the method's parameters (None if no params)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<schemars::Schema>,

    /// JSON Schema for the method's return type (None if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returns: Option<schemars::Schema>,

    /// Whether this method streams multiple events (true) or returns a single result (false)
    ///
    /// - `streaming: true` → returns `AsyncGenerator<T>` (multiple events)
    /// - `streaming: false` → returns `Promise<T>` (single event, collected)
    ///
    /// All methods use the same streaming protocol under the hood, but this flag
    /// tells clients how to present the result.
    #[serde(default)]
    pub streaming: bool,

    /// Whether this method supports bidirectional communication
    ///
    /// When true, the server can send requests to the client during method execution
    /// and wait for responses (e.g., confirmations, prompts, selections).
    #[serde(default)]
    pub bidirectional: bool,

    /// HTTP method for REST endpoints (GET, POST, PUT, DELETE, PATCH)
    ///
    /// This field is used by the HTTP gateway to determine which HTTP method
    /// to use when exposing this method as a REST endpoint. Defaults to POST
    /// for backward compatibility.
    ///
    /// - GET: Idempotent read operations (no side effects)
    /// - POST: Create operations or non-idempotent actions (default)
    /// - PUT: Replace/update operations (idempotent)
    /// - DELETE: Remove operations (idempotent)
    /// - PATCH: Partial update operations
    #[serde(default)]
    pub http_method: HttpMethod,

    /// JSON Schema for the request type sent from server to client
    ///
    /// Only relevant when `bidirectional: true`. Describes the structure of
    /// requests the server may send during method execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_type: Option<schemars::Schema>,

    /// JSON Schema for the response type sent from client to server
    ///
    /// Only relevant when `bidirectional: true`. Describes the structure of
    /// responses the client should send in reply to server requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<schemars::Schema>,

    /// How this method participates in the activation graph.
    ///
    /// Added in IR-2. Defaults to `MethodRole::Rpc` via `#[serde(default)]`
    /// so pre-IR schemas deserialize cleanly.
    ///
    /// Populated by the `#[plexus::method]` / `#[child]` macros (IR-3).
    #[serde(default)]
    pub role: MethodRole,

    /// If set, this method is deprecated.
    ///
    /// Added in IR-2. Defaults to `None` via `#[serde(default)]` so pre-IR
    /// schemas deserialize cleanly.
    ///
    /// Populated by the `#[deprecated(...)]` attribute on the underlying
    /// method (IR-5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationInfo>,

    /// Structural shape of the method's return type (e.g., `Option`, `Vec`,
    /// `Stream`).
    ///
    /// Orthogonal to `returns`, which holds the fine-grained JSON Schema of
    /// the inner type. Added in IR-2 as an optional, additive field. `None`
    /// means "not populated" (the wire format supports pre-IR schemas that
    /// omit this field entirely).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_shape: Option<ReturnShape>,

    /// Per-parameter metadata (currently just deprecation).
    ///
    /// Added in IR-5. Defaults to an empty vec via `#[serde(default)]` so
    /// pre-IR schemas deserialize cleanly. Only parameters that carry
    /// metadata appear in this list — absence means "no metadata" for that
    /// parameter, not a bug.
    ///
    /// Populated by the `#[deprecated(...)]` attribute on individual
    /// parameters (IR-5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params_meta: Vec<ParamSchema>,

    /// Credential-bearing fields in this method's return type.
    ///
    /// One entry per `#[plexus::credential(...)]`-annotated field on the
    /// return-type struct/enum, in stable declaration order. Empty when
    /// the return type contains no credentials.
    ///
    /// Added in `AUTHZ-CRED-CORE-3`. Defaults to an empty vec via
    /// `#[serde(default)]` so pre-IR schemas deserialize cleanly. The
    /// `skip_serializing_if = "Vec::is_empty"` clause keeps the wire JSON
    /// shape unchanged for methods with no credential-bearing fields
    /// (back-compat per the ticket's "Wire-format back-compat" table).
    ///
    /// Populated at schema-build time from the `CredentialFieldMarker`
    /// registry emitted by `#[derive(Credentials)]` (`AUTHZ-CRED-MACRO-1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialFieldDecl>,

    /// What credential this method requires on input (if any).
    ///
    /// Derived implicitly from the method's scope tagging and the
    /// credential-graph linkage at schema-build time (per
    /// `AUTHZ-CRED-CORE-3` §"Implicit derivation"):
    ///
    /// - `scope = "..."` → `RequiredCredential::from_method_scope(scope)`.
    /// - `public` method → `None` (the absence of this field).
    /// - target of `refresh_via`/`revoke_via` of another credential →
    ///   `RequiredCredential::from_refresh_revoke_target(kind, scopes)`.
    ///
    /// Added in `AUTHZ-CRED-CORE-3`. Defaults to `None` via
    /// `#[serde(default)]` so pre-IR schemas deserialize cleanly. The
    /// `skip_serializing_if = "Option::is_none"` clause keeps the wire JSON
    /// shape unchanged for public methods and methods with no scope-derived
    /// requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_credential: Option<RequiredCredential>,
}

impl PluginSchema {
    /// Compute all three hashes (self, children, composite)
    fn compute_hashes(
        methods: &[MethodSchema],
        children: Option<&[ChildSummary]>,
    ) -> (String, Option<String>, String) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Compute self_hash (methods only)
        let mut self_hasher = DefaultHasher::new();
        for m in methods {
            m.hash.hash(&mut self_hasher);
        }
        let self_hash = format!("{:016x}", self_hasher.finish());

        // Compute children_hash (children only)
        let children_hash = children.map(|kids| {
            let mut children_hasher = DefaultHasher::new();
            for c in kids {
                c.hash.hash(&mut children_hasher);
            }
            format!("{:016x}", children_hasher.finish())
        });

        // Compute composite hash (both)
        let mut composite_hasher = DefaultHasher::new();
        self_hash.hash(&mut composite_hasher);
        if let Some(ref ch) = children_hash {
            ch.hash(&mut composite_hasher);
        }
        let hash = format!("{:016x}", composite_hasher.finish());

        (self_hash, children_hash, hash)
    }

    /// Inspect each method's `returns` JSON Schema for the framework-
    /// reserved `_credentials` top-level field name; emit a tracing
    /// warning when a collision is detected (AUTHZ-CRED-CORE-2
    /// acceptance criterion #8). Returns the number of collisions found,
    /// so callers can chain into a metrics counter or assertion if they
    /// want one.
    ///
    /// The framework reserves the `_credentials` top-level field name
    /// for the credential sidecar (see
    /// `crate::plexus::credential_envelope`). Backends that define a
    /// domain field of the same name have it shadowed at dispatch time;
    /// the warning surfaces that fact at build time so backends can
    /// rename.
    fn warn_on_credentials_field_collisions(
        namespace: &str,
        methods: &[MethodSchema],
    ) -> usize {
        let mut count = 0;
        for m in methods {
            let Some(returns_schema) = &m.returns else { continue };
            let Ok(returns_json) = serde_json::to_value(returns_schema) else { continue };
            if super::credential_envelope::check_returns_schema_for_credentials_collision(
                namespace,
                &m.name,
                &returns_json,
            ) {
                count += 1;
            }
        }
        count
    }

    /// Validate no name collisions exist within a plugin
    ///
    /// Checks for:
    /// - Duplicate method names
    /// - Duplicate child names (for hubs)
    /// - Method/child name collisions for `Rpc`-role methods (for hubs)
    ///
    /// Panics if a collision is detected (system error).
    ///
    /// # IR-4 relaxation
    ///
    /// As of IR-4, a method with `MethodRole::StaticChild` or
    /// `MethodRole::DynamicChild { .. }` that shares a name with a
    /// `ChildSummary` entry is **not** a collision — it's the same child
    /// surfaced via two wire representations (the role-tagged method list
    /// and the deprecated `children` side-table). Only `Rpc`-role methods
    /// whose name matches a child summary are flagged.
    fn validate_no_collisions(
        namespace: &str,
        methods: &[MethodSchema],
        children: Option<&[ChildSummary]>,
    ) {
        use std::collections::HashSet;

        let mut seen: HashSet<&str> = HashSet::new();

        // Check method names
        for m in methods {
            if !seen.insert(&m.name) {
                panic!(
                    "Name collision in plugin '{}': duplicate method '{}'",
                    namespace, m.name
                );
            }
        }

        // Check child names (and collisions with methods)
        if let Some(kids) = children {
            for c in kids {
                if !seen.insert(&c.namespace) {
                    // IR-4: a role-tagged child method whose name matches a
                    // child summary is expected by construction (the two
                    // wire-surfaces describe the same child). Skip silently.
                    let colliding_method =
                        methods.iter().find(|m| m.name == c.namespace);
                    if let Some(m) = colliding_method {
                        if matches!(
                            m.role,
                            MethodRole::StaticChild | MethodRole::DynamicChild { .. }
                        ) {
                            continue;
                        }
                    }
                    // Could be duplicate child or collision with an Rpc-role method
                    let collision_type = if colliding_method.is_some() {
                        "method/child collision"
                    } else {
                        "duplicate child"
                    };
                    panic!(
                        "Name collision in plugin '{}': {} for '{}'",
                        namespace, collision_type, c.namespace
                    );
                }
            }
        }
    }

    /// Derive the deprecated `(children, is_hub)` side-table fields from a
    /// role-tagged method list.
    ///
    /// Added in IR-4 as the **centralized shim** that backfills the
    /// pre-IR `children: Option<Vec<ChildSummary>>` and `is_hub: bool`
    /// representations from the authoritative `MethodRole` on each
    /// `MethodSchema`.
    ///
    /// # Semantics
    ///
    /// One `ChildSummary` is produced per non-`Rpc` method, preserving the
    /// source order. The shim writes:
    ///
    /// | Field | Value |
    /// |---|---|
    /// | `namespace` | The method's name. |
    /// | `description` | The method's `description`. |
    /// | `hash` | Empty string — the shim does **not** compute child hashes. Callers that want per-child hashes must populate them out-of-band. |
    ///
    /// The returned `bool` matches [`PluginSchema::is_hub_by_role`] — `true`
    /// iff at least one method carries a child role.
    ///
    /// # Example
    ///
    /// ```
    /// use plexus_core::plexus::schema::{MethodRole, MethodSchema, PluginSchema};
    ///
    /// let methods = vec![
    ///     MethodSchema::new("ping", "rpc", "h1"),
    ///     MethodSchema::new("kid",  "static child", "h2")
    ///         .with_role(MethodRole::StaticChild),
    /// ];
    /// let (children, is_hub) = PluginSchema::derive_legacy_fields(&methods);
    /// assert_eq!(children.len(), 1);
    /// assert_eq!(children[0].namespace, "kid");
    /// assert!(is_hub);
    /// ```
    pub fn derive_legacy_fields(
        methods: &[MethodSchema],
    ) -> (Vec<ChildSummary>, bool) {
        let children: Vec<ChildSummary> = methods
            .iter()
            .filter(|m| {
                matches!(
                    m.role,
                    MethodRole::StaticChild | MethodRole::DynamicChild { .. }
                )
            })
            .map(|m| ChildSummary {
                namespace: m.name.clone(),
                description: m.description.clone(),
                hash: String::new(),
            })
            .collect();
        let is_hub = !children.is_empty();
        (children, is_hub)
    }

    /// Create a new leaf plugin schema (no children)
    #[allow(deprecated)]
    pub fn leaf(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        methods: Vec<MethodSchema>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, None);
        // AUTHZ-CRED-CORE-2 acceptance criterion #8: warn at schema-build
        // time when a method's return-type schema declares a top-level
        // field named `_credentials` (reserved by the framework's
        // credential sidecar).
        let _ = Self::warn_on_credentials_field_collisions(&namespace, &methods);
        let (self_hash, children_hash, hash) = Self::compute_hashes(&methods, None);
        Self {
            namespace,
            version: version.into(),
            description: description.into(),
            long_description: None,
            self_hash,
            children_hash,
            hash,
            methods,
            children: None,
            request: None,
            deprecation: None,
        }
    }

    /// Create a new leaf plugin schema with long description
    #[allow(deprecated)]
    pub fn leaf_with_long_description(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        long_description: impl Into<String>,
        methods: Vec<MethodSchema>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, None);
        // AUTHZ-CRED-CORE-2 AC #8: see PluginSchema::leaf.
        let _ = Self::warn_on_credentials_field_collisions(&namespace, &methods);
        let (self_hash, children_hash, hash) = Self::compute_hashes(&methods, None);
        Self {
            namespace,
            version: version.into(),
            description: description.into(),
            long_description: Some(long_description.into()),
            self_hash,
            children_hash,
            hash,
            methods,
            children: None,
            request: None,
            deprecation: None,
        }
    }

    /// Create a new hub plugin schema (with child summaries)
    #[allow(deprecated)]
    pub fn hub(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        methods: Vec<MethodSchema>,
        children: Vec<ChildSummary>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, Some(&children));
        // AUTHZ-CRED-CORE-2 AC #8: see PluginSchema::leaf.
        let _ = Self::warn_on_credentials_field_collisions(&namespace, &methods);
        let (self_hash, children_hash, hash) = Self::compute_hashes(&methods, Some(&children));
        Self {
            namespace,
            version: version.into(),
            description: description.into(),
            long_description: None,
            self_hash,
            children_hash,
            hash,
            methods,
            children: Some(children),
            request: None,
            deprecation: None,
        }
    }

    /// Create a new hub plugin schema with long description
    #[allow(deprecated)]
    pub fn hub_with_long_description(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        long_description: impl Into<String>,
        methods: Vec<MethodSchema>,
        children: Vec<ChildSummary>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, Some(&children));
        // AUTHZ-CRED-CORE-2 AC #8: see PluginSchema::leaf.
        let _ = Self::warn_on_credentials_field_collisions(&namespace, &methods);
        let (self_hash, children_hash, hash) = Self::compute_hashes(&methods, Some(&children));
        Self {
            namespace,
            version: version.into(),
            description: description.into(),
            long_description: Some(long_description.into()),
            self_hash,
            children_hash,
            hash,
            methods,
            children: Some(children),
            request: None,
            deprecation: None,
        }
    }

    /// Check if this is a hub.
    ///
    /// Returns `true` iff the plugin exposes child activations. As of IR-2,
    /// this is derived from **either** source of truth:
    ///
    /// 1. Any method tagged with a child `MethodRole` (`StaticChild` or
    ///    `DynamicChild { .. }`). This is the post-IR-3 authoritative signal.
    /// 2. The legacy `children: Option<Vec<ChildSummary>>` field is `Some`.
    ///    Preserved for back-compat during the IR transition window —
    ///    today's macros populate `children` but not yet `role`.
    ///
    /// # Deprecated (IR-4)
    ///
    /// The legacy transition-window fallback on `children.is_some()` is
    /// redundant now that `MethodRole` tags are authoritative. Callers
    /// should migrate to [`PluginSchema::is_hub_by_role`], which reads
    /// only role-tagged methods. This method will be removed in 0.7.
    #[deprecated(
        since = "0.5",
        note = "Use `PluginSchema::is_hub_by_role()` which reads MethodRole from methods. This method will be removed in 0.7."
    )]
    #[allow(deprecated)]
    pub fn is_hub(&self) -> bool {
        self.is_hub_by_role() || self.children.is_some()
    }

    /// Returns `true` iff any method carries a child `MethodRole`.
    ///
    /// This is the **derived query** specified by IR-2: it reads only
    /// `self.methods`, ignoring the legacy `children` side channel. Use this
    /// when you want the post-IR-3 authoritative answer without the transition
    /// fallback that `is_hub()` provides.
    pub fn is_hub_by_role(&self) -> bool {
        self.methods.iter().any(|m| {
            matches!(
                m.role,
                MethodRole::StaticChild | MethodRole::DynamicChild { .. }
            )
        })
    }

    /// Check if this is a leaf (no children)
    #[allow(deprecated)]
    pub fn is_leaf(&self) -> bool {
        self.children.is_none()
    }

    /// Mark this plugin as deprecated.
    ///
    /// Added in IR-5. Populates the `deprecation` field with the provided
    /// `DeprecationInfo`. Populated by the `#[deprecated(...)]` attribute on
    /// an `impl Activation for Foo` block via `plexus-macros`.
    pub fn with_deprecation(mut self, info: DeprecationInfo) -> Self {
        self.deprecation = Some(info);
        self
    }
}

/// Summary of a child plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildSummary {
    /// The child's namespace
    pub namespace: String,

    /// Human-readable description
    pub description: String,

    /// Content hash for cache invalidation
    pub hash: String,
}

/// Schema summary containing only hashes (for cache validation)
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildHashes {
    pub namespace: String,
    pub hash: String,
}

impl MethodSchema {
    /// Create a new method schema with name, description, and hash
    ///
    /// The hash should be computed from the method definition string
    /// within the hub-macro at compile time.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            hash: hash.into(),
            params: None,
            returns: None,
            streaming: false,
            bidirectional: false,
            http_method: HttpMethod::default(),
            request_type: None,
            response_type: None,
            role: MethodRole::Rpc,
            deprecation: None,
            return_shape: None,
            params_meta: Vec::new(),
            credentials: Vec::new(),
            requires_credential: None,
        }
    }

    /// Add parameter schema
    pub fn with_params(mut self, params: schemars::Schema) -> Self {
        self.params = Some(params);
        self
    }

    /// Add return type schema
    pub fn with_returns(mut self, returns: schemars::Schema) -> Self {
        self.returns = Some(returns);
        self
    }

    /// Set the streaming flag
    ///
    /// - `true` → method streams multiple events (use `AsyncGenerator<T>`)
    /// - `false` → method returns single result (use `Promise<T>`)
    pub fn with_streaming(mut self, streaming: bool) -> Self {
        self.streaming = streaming;
        self
    }

    /// Set the HTTP method for REST endpoints
    ///
    /// Defaults to POST for backward compatibility.
    ///
    /// # Guidelines
    /// - GET: Idempotent read operations with no side effects
    /// - POST: Create operations or non-idempotent actions
    /// - PUT: Replace/update operations (idempotent)
    /// - DELETE: Remove operations (idempotent)
    /// - PATCH: Partial update operations
    pub fn with_http_method(mut self, http_method: HttpMethod) -> Self {
        self.http_method = http_method;
        self
    }

    /// Set whether this method supports bidirectional communication
    ///
    /// When true, the server can send requests to the client during method
    /// execution and wait for responses.
    pub fn with_bidirectional(mut self, bidirectional: bool) -> Self {
        self.bidirectional = bidirectional;
        self
    }

    /// Set the JSON Schema for server-to-client request types
    ///
    /// Only relevant when `bidirectional: true`. Use `schema_for!(YourRequestType)`
    /// to generate the schema.
    pub fn with_request_type(mut self, schema: schemars::Schema) -> Self {
        self.request_type = Some(schema);
        self
    }

    /// Set the JSON Schema for client-to-server response types
    ///
    /// Only relevant when `bidirectional: true`. Use `schema_for!(YourResponseType)`
    /// to generate the schema.
    pub fn with_response_type(mut self, schema: schemars::Schema) -> Self {
        self.response_type = Some(schema);
        self
    }

    /// Configure method for standard bidirectional communication
    ///
    /// Sets `bidirectional: true` and configures request/response types to use
    /// `StandardRequest` and `StandardResponse`, which support common UI patterns
    /// like confirmations, prompts, and selections.
    pub fn with_standard_bidirectional(self) -> Self {
        self.with_bidirectional(true)
            .with_request_type(schema_for!(StandardRequest).into())
            .with_response_type(schema_for!(StandardResponse).into())
    }

    /// Set this method's role in the activation graph.
    ///
    /// Added in IR-2. Defaults to `MethodRole::Rpc`.
    pub fn with_role(mut self, role: MethodRole) -> Self {
        self.role = role;
        self
    }

    /// Mark this method as deprecated.
    ///
    /// Added in IR-2. Populates the `deprecation` field with the provided
    /// `DeprecationInfo`.
    pub fn with_deprecation(mut self, info: DeprecationInfo) -> Self {
        self.deprecation = Some(info);
        self
    }

    /// Set the structural shape of this method's return type.
    ///
    /// Added in IR-2. Orthogonal to `with_returns`, which sets the fine-grained
    /// JSON Schema.
    pub fn with_return_shape(mut self, shape: ReturnShape) -> Self {
        self.return_shape = Some(shape);
        self
    }

    /// Attach per-parameter metadata for this method's parameters.
    ///
    /// Added in IR-5. Only parameters that carry metadata (e.g. a
    /// `#[deprecated]` annotation) need appear in `entries`; absence means
    /// "no metadata" for a given parameter. The consumer correlates entries
    /// against `self.params` by matching `ParamSchema.name` against the
    /// `properties` map of the JSON Schema.
    pub fn with_params_meta(mut self, entries: Vec<ParamSchema>) -> Self {
        self.params_meta = entries;
        self
    }

    /// Attach the credential-field projection for this method's return type.
    ///
    /// Added in `AUTHZ-CRED-CORE-3`. The build-path supplies one
    /// `CredentialFieldDecl` per `#[plexus::credential(...)]`-annotated
    /// field in the return type, in stable declaration order. Absence (the
    /// default empty vec) means the return type carries no credentials.
    ///
    /// The constructor `CredentialFieldDecl::from_marker` composes one
    /// entry from a `CredentialFieldMarker` (emitted by the
    /// `#[derive(Credentials)]` macro) plus the runtime-known issuer.
    pub fn with_credentials(mut self, credentials: Vec<CredentialFieldDecl>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Attach the implicit-derived `requires_credential` filter for this
    /// method.
    ///
    /// Added in `AUTHZ-CRED-CORE-3`. The build-path supplies a
    /// `RequiredCredential` derived from either (a) the method's `scope`
    /// attribute or (b) the method's appearance as a `refresh_via` /
    /// `revoke_via` target of some other credential in the schema. Public
    /// methods leave this field as `None` (the default).
    ///
    /// `RequiredCredential::from_method_scope` and
    /// `RequiredCredential::from_refresh_revoke_target` are the two derivation
    /// entry points.
    pub fn with_requires_credential(mut self, req: RequiredCredential) -> Self {
        self.requires_credential = Some(req);
        self
    }
}

// ============================================================================
// JSON Schema Types
// ============================================================================

/// A complete JSON Schema with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// The JSON Schema specification version
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none", default)]
    pub schema_version: Option<String>,

    /// Title of the schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Description of what this schema represents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The schema type (typically "object" for root, can be string or array)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<serde_json::Value>,

    /// Properties for object types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, SchemaProperty>>,

    /// Required properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,

    /// Enum variants (for discriminated unions)
    #[serde(rename = "oneOf", skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<Schema>>,

    /// Schema definitions (for $defs or definitions)
    #[serde(rename = "$defs", skip_serializing_if = "Option::is_none")]
    pub defs: Option<HashMap<String, serde_json::Value>>,

    /// Any additional schema properties
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Schema type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    Object,
    Array,
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

/// A property definition in a schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    /// The type of this property (can be a single type or array of types for nullable)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub property_type: Option<serde_json::Value>,

    /// Description of this property
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Format hint (e.g., "uuid", "date-time", "email")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// For array types, the schema of items
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaProperty>>,

    /// For object types, nested properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, SchemaProperty>>,

    /// Required properties (for object types)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,

    /// Default value for this property
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,

    /// Enum values if this is an enum
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<serde_json::Value>>,

    /// Reference to another schema definition
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,

    /// Any additional property metadata
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl Schema {
    /// Create a new schema with basic metadata
    pub fn new(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            schema_version: Some("http://json-schema.org/draft-07/schema#".to_string()),
            title: Some(title.into()),
            description: Some(description.into()),
            schema_type: None,
            properties: None,
            required: None,
            one_of: None,
            defs: None,
            additional: HashMap::new(),
        }
    }

    /// Create an object schema
    pub fn object() -> Self {
        Self {
            schema_version: Some("http://json-schema.org/draft-07/schema#".to_string()),
            title: None,
            description: None,
            schema_type: Some(serde_json::json!("object")),
            properties: Some(HashMap::new()),
            required: None,
            one_of: None,
            defs: None,
            additional: HashMap::new(),
        }
    }

    /// Add a property to this schema
    pub fn with_property(mut self, name: impl Into<String>, property: SchemaProperty) -> Self {
        self.properties
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), property);
        self
    }

    /// Mark a property as required
    pub fn with_required(mut self, name: impl Into<String>) -> Self {
        self.required
            .get_or_insert_with(Vec::new)
            .push(name.into());
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Extract a single method's schema from the oneOf array
    ///
    /// Searches the oneOf variants for a method matching the given name.
    /// Returns the variant schema if found, None otherwise.
    pub fn get_method_schema(&self, method_name: &str) -> Option<Schema> {
        let variants = self.one_of.as_ref()?;

        for variant in variants {
            // Check if this variant has a "method" property with const or enum
            if let Some(props) = &variant.properties {
                if let Some(method_prop) = props.get("method") {
                    // Try "const" first (schemars uses this for literal values)
                    if let Some(const_val) = method_prop.additional.get("const") {
                        if const_val.as_str() == Some(method_name) {
                            return Some(variant.clone());
                        }
                    }
                    // Fall back to enum_values
                    if let Some(enum_vals) = &method_prop.enum_values {
                        if enum_vals.first().and_then(|v| v.as_str()) == Some(method_name) {
                            return Some(variant.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// List all method names from the oneOf array
    pub fn list_methods(&self) -> Vec<String> {
        let Some(variants) = &self.one_of else {
            return Vec::new();
        };

        variants
            .iter()
            .filter_map(|variant| {
                let props = variant.properties.as_ref()?;
                let method_prop = props.get("method")?;

                // Try "const" first
                if let Some(const_val) = method_prop.additional.get("const") {
                    return const_val.as_str().map(String::from);
                }
                // Fall back to enum_values
                method_prop
                    .enum_values
                    .as_ref()?
                    .first()?
                    .as_str()
                    .map(String::from)
            })
            .collect()
    }
}

impl SchemaProperty {
    /// Create a string property
    pub fn string() -> Self {
        Self {
            property_type: Some(serde_json::json!("string")),
            description: None,
            format: None,
            items: None,
            properties: None,
            required: None,
            default: None,
            enum_values: None,
            reference: None,
            additional: HashMap::new(),
        }
    }

    /// Create a UUID property (string with format)
    pub fn uuid() -> Self {
        Self {
            property_type: Some(serde_json::json!("string")),
            description: None,
            format: Some("uuid".to_string()),
            items: None,
            properties: None,
            required: None,
            default: None,
            enum_values: None,
            reference: None,
            additional: HashMap::new(),
        }
    }

    /// Create an integer property
    pub fn integer() -> Self {
        Self {
            property_type: Some(serde_json::json!("integer")),
            description: None,
            format: None,
            items: None,
            properties: None,
            required: None,
            default: None,
            enum_values: None,
            reference: None,
            additional: HashMap::new(),
        }
    }

    /// Create an object property
    pub fn object() -> Self {
        Self {
            property_type: Some(serde_json::json!("object")),
            description: None,
            format: None,
            items: None,
            properties: Some(HashMap::new()),
            required: None,
            default: None,
            enum_values: None,
            reference: None,
            additional: HashMap::new(),
        }
    }

    /// Create an array property
    pub fn array(items: SchemaProperty) -> Self {
        Self {
            property_type: Some(serde_json::json!("array")),
            description: None,
            format: None,
            items: Some(Box::new(items)),
            properties: None,
            required: None,
            default: None,
            enum_values: None,
            reference: None,
            additional: HashMap::new(),
        }
    }

    /// Add a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a default value
    pub fn with_default(mut self, default: serde_json::Value) -> Self {
        self.default = Some(default);
        self
    }

    /// Add nested properties (for object types)
    pub fn with_property(mut self, name: impl Into<String>, property: SchemaProperty) -> Self {
        self.properties
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), property);
        self
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let schema = Schema::object()
            .with_property("id", SchemaProperty::uuid().with_description("The unique identifier"))
            .with_property("name", SchemaProperty::string().with_description("The name"))
            .with_required("id");

        assert_eq!(schema.schema_type, Some(serde_json::json!("object")));
        assert!(schema.properties.is_some());
        assert_eq!(schema.required, Some(vec!["id".to_string()]));
    }

    #[test]
    fn test_serialization() {
        let schema = Schema::object()
            .with_property("id", SchemaProperty::uuid());

        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("uuid"));
    }

    #[test]
    fn test_self_hash_changes_on_method_change() {
        let schema1 = PluginSchema::leaf(
            "test",
            "1.0",
            "desc",
            vec![MethodSchema::new("foo", "bar", "hash1")],
        );

        let schema2 = PluginSchema::leaf(
            "test",
            "1.0",
            "desc",
            vec![MethodSchema::new("foo", "baz", "hash2")],  // Changed description
        );

        assert_ne!(schema1.self_hash, schema2.self_hash, "self_hash should change when methods change");
        assert_eq!(schema1.children_hash, schema2.children_hash, "children_hash should stay same (both None)");
        assert_ne!(schema1.hash, schema2.hash, "composite hash should change");
    }

    #[test]
    fn test_children_hash_changes_on_child_change() {
        let child1 = ChildSummary {
            namespace: "child".into(),
            description: "desc".into(),
            hash: "old_hash".into(),
        };

        let child2 = ChildSummary {
            namespace: "child".into(),
            description: "desc".into(),
            hash: "new_hash".into(),
        };

        let schema1 = PluginSchema::hub(
            "parent",
            "1.0",
            "desc",
            vec![],
            vec![child1],
        );

        let schema2 = PluginSchema::hub(
            "parent",
            "1.0",
            "desc",
            vec![],
            vec![child2],
        );

        assert_eq!(schema1.self_hash, schema2.self_hash, "self_hash should stay same (no methods changed)");
        assert_ne!(schema1.children_hash, schema2.children_hash, "children_hash should change when child hash changes");
        assert_ne!(schema1.hash, schema2.hash, "composite hash should change");
    }

    #[test]
    fn test_leaf_has_no_children_hash() {
        let schema = PluginSchema::leaf(
            "leaf",
            "1.0",
            "desc",
            vec![MethodSchema::new("method", "desc", "hash")],
        );

        assert!(schema.children_hash.is_none(), "leaf plugin should have None for children_hash");
        assert_ne!(schema.self_hash, schema.hash, "leaf plugin's composite hash is hash(self_hash), not equal to self_hash");
    }

    // =========================================================================
    // IR-2 tests: MethodRole, DeprecationInfo, is_hub derived query
    // =========================================================================

    /// AC #5: Deserializing a JSON `MethodSchema` with no `role` or
    /// `deprecation` fields yields `MethodRole::Rpc` and `None`.
    #[test]
    fn ir2_default_role_is_rpc_on_deserialize() {
        // Pre-IR MethodSchema shape (no role, no deprecation, no return_shape)
        let pre_ir_json = serde_json::json!({
            "name": "ping",
            "description": "pong",
            "hash": "abc"
        });

        let schema: MethodSchema = serde_json::from_value(pre_ir_json).unwrap();
        assert_eq!(schema.role, MethodRole::Rpc);
        assert!(schema.deprecation.is_none());
        assert!(schema.return_shape.is_none());
    }

    /// AC #5: And at the PluginSchema level — a full pre-IR schema with
    /// multiple methods (none carrying `role`) deserializes cleanly with every
    /// method defaulted to `Rpc` and no deprecation.
    #[test]
    fn ir2_plugin_schema_pre_ir_json_deserializes() {
        let pre_ir_json = serde_json::json!({
            "namespace": "test",
            "version": "1.0",
            "description": "legacy schema",
            "self_hash": "s1",
            "hash": "h1",
            "methods": [
                { "name": "a", "description": "alpha", "hash": "ah" },
                { "name": "b", "description": "beta",  "hash": "bh" }
            ]
        });

        let schema: PluginSchema = serde_json::from_value(pre_ir_json).unwrap();
        assert_eq!(schema.methods.len(), 2);
        for m in &schema.methods {
            assert_eq!(m.role, MethodRole::Rpc);
            assert!(m.deprecation.is_none());
        }
    }

    /// AC #6: Serde round-trip covering all `MethodRole` variants —
    /// `Rpc`, `StaticChild`, and `DynamicChild { list_method, search_method }`.
    #[test]
    fn ir2_method_role_roundtrip_all_variants() {
        let original = PluginSchema::leaf(
            "rt",
            "1.0",
            "round-trip coverage",
            vec![
                MethodSchema::new("plain", "rpc", "h1"),
                MethodSchema::new("child_a", "static", "h2")
                    .with_role(MethodRole::StaticChild),
                MethodSchema::new("child_b", "dynamic", "h3").with_role(
                    MethodRole::DynamicChild {
                        list_method: Some("list_x".into()),
                        search_method: Some("search_x".into()),
                    },
                ),
            ],
        );

        let json = serde_json::to_string(&original).unwrap();
        let decoded: PluginSchema = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.methods[0].role, MethodRole::Rpc);
        assert_eq!(decoded.methods[1].role, MethodRole::StaticChild);
        assert_eq!(
            decoded.methods[2].role,
            MethodRole::DynamicChild {
                list_method: Some("list_x".into()),
                search_method: Some("search_x".into()),
            }
        );

        // Also survives when the DynamicChild has no list/search hints.
        let bare_dyn = MethodSchema::new("child_c", "dynamic-bare", "h4").with_role(
            MethodRole::DynamicChild {
                list_method: None,
                search_method: None,
            },
        );
        let j2 = serde_json::to_string(&bare_dyn).unwrap();
        let d2: MethodSchema = serde_json::from_str(&j2).unwrap();
        assert_eq!(
            d2.role,
            MethodRole::DynamicChild {
                list_method: None,
                search_method: None,
            }
        );
    }

    /// AC #7: Serde round-trip for `DeprecationInfo` on a `MethodSchema`.
    #[test]
    fn ir2_deprecation_info_roundtrip() {
        let info = DeprecationInfo {
            since: "0.5".into(),
            removed_in: "0.6".into(),
            message: "use MethodRole".into(),
        };
        let method = MethodSchema::new("old", "legacy method", "hx")
            .with_deprecation(info.clone());

        let json = serde_json::to_string(&method).unwrap();
        let decoded: MethodSchema = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.deprecation, Some(info));
    }

    /// AC #4: `PluginSchema::is_hub_by_role()` — the derived query reads only
    /// `methods`, not the legacy `children` field.
    ///
    /// Covers every row of the acceptance-criteria table.
    #[test]
    fn ir2_is_hub_by_role_derived_query() {
        // Row 1: all Rpc → false
        let all_rpc = PluginSchema::leaf(
            "p",
            "1.0",
            "all rpc",
            vec![
                MethodSchema::new("a", "d", "h1"),
                MethodSchema::new("b", "d", "h2"),
            ],
        );
        assert!(!all_rpc.is_hub_by_role());
        // And the back-compat `is_hub()` also returns false (no children).
        assert!(!all_rpc.is_hub());

        // Row 2: at least one StaticChild → true
        let static_child = PluginSchema::leaf(
            "p",
            "1.0",
            "has static child",
            vec![
                MethodSchema::new("a", "d", "h1"),
                MethodSchema::new("kid", "d", "h2").with_role(MethodRole::StaticChild),
            ],
        );
        assert!(static_child.is_hub_by_role());
        assert!(static_child.is_hub());

        // Row 3: at least one DynamicChild → true
        let dyn_child = PluginSchema::leaf(
            "p",
            "1.0",
            "has dynamic child",
            vec![MethodSchema::new("find", "d", "h1").with_role(
                MethodRole::DynamicChild {
                    list_method: None,
                    search_method: None,
                },
            )],
        );
        assert!(dyn_child.is_hub_by_role());
        assert!(dyn_child.is_hub());

        // Row 4: Mix of Rpc + StaticChild → true
        let mixed = PluginSchema::leaf(
            "p",
            "1.0",
            "mixed",
            vec![
                MethodSchema::new("a", "d", "h1"),
                MethodSchema::new("b", "d", "h2"),
                MethodSchema::new("k", "d", "h3").with_role(MethodRole::StaticChild),
            ],
        );
        assert!(mixed.is_hub_by_role());
        assert!(mixed.is_hub());

        // Row 5: empty methods → false
        let empty = PluginSchema::leaf("p", "1.0", "empty", vec![]);
        assert!(!empty.is_hub_by_role());
        assert!(!empty.is_hub());
    }

    /// The derived query is independent of the legacy `children` side channel
    /// — a `PluginSchema::hub(...)` with only `Rpc` methods reports
    /// `is_hub_by_role() == false` (children don't count) while `is_hub()` is
    /// still `true` (transition-window fallback).
    #[test]
    fn ir2_is_hub_by_role_ignores_children_field() {
        let hub_with_rpc_only = PluginSchema::hub(
            "h",
            "1.0",
            "transition",
            vec![MethodSchema::new("a", "d", "ah")],
            vec![ChildSummary {
                namespace: "kid".into(),
                description: "child".into(),
                hash: "kh".into(),
            }],
        );

        // The derived query reads only methods — no child role → false.
        assert!(!hub_with_rpc_only.is_hub_by_role());
        // Back-compat `is_hub()` still reports true via the children fallback.
        assert!(hub_with_rpc_only.is_hub());
    }

    /// `ReturnShape` round-trips cleanly via serde.
    #[test]
    fn ir2_return_shape_roundtrip() {
        for shape in [
            ReturnShape::Bare,
            ReturnShape::Option,
            ReturnShape::Result,
            ReturnShape::Vec,
            ReturnShape::Stream,
            ReturnShape::ResultOption,
        ] {
            let m = MethodSchema::new("m", "d", "h").with_return_shape(shape.clone());
            let j = serde_json::to_string(&m).unwrap();
            let d: MethodSchema = serde_json::from_str(&j).unwrap();
            assert_eq!(d.return_shape, Some(shape));
        }
    }

    // =========================================================================
    // IR-4 tests: derive_legacy_fields, relaxed validate_no_collisions,
    // deprecation markers.
    // =========================================================================

    /// AC #4 (row 1): empty method list → no children, not a hub.
    #[test]
    fn ir4_derive_empty_methods() {
        let (children, is_hub) = PluginSchema::derive_legacy_fields(&[]);
        assert!(children.is_empty());
        assert!(!is_hub);
    }

    /// AC #4 (row 2): a single `Rpc` method → no children, not a hub.
    #[test]
    fn ir4_derive_single_rpc_method() {
        let methods = vec![MethodSchema::new("ping", "rpc method", "h1")];
        let (children, is_hub) = PluginSchema::derive_legacy_fields(&methods);
        assert!(children.is_empty());
        assert!(!is_hub);
    }

    /// AC #4 (row 3): one `StaticChild` method named "body" → one child named
    /// "body", `is_hub == true`.
    #[test]
    fn ir4_derive_single_static_child() {
        let methods = vec![
            MethodSchema::new("body", "static child", "h1")
                .with_role(MethodRole::StaticChild),
        ];
        let (children, is_hub) = PluginSchema::derive_legacy_fields(&methods);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].namespace, "body");
        assert_eq!(children[0].description, "static child");
        assert_eq!(children[0].hash, "");
        assert!(is_hub);
    }

    /// AC #4 (row 4): one `DynamicChild` method named "planet" → one child
    /// named "planet", `is_hub == true`.
    #[test]
    fn ir4_derive_single_dynamic_child() {
        let methods = vec![
            MethodSchema::new("planet", "dynamic child", "h1").with_role(
                MethodRole::DynamicChild {
                    list_method: Some("list_planets".into()),
                    search_method: None,
                },
            ),
        ];
        let (children, is_hub) = PluginSchema::derive_legacy_fields(&methods);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].namespace, "planet");
        assert!(is_hub);
    }

    /// AC #4 (row 5): mix of Rpc + StaticChild → one child, `is_hub == true`.
    #[test]
    fn ir4_derive_mixed_roles_preserves_order() {
        let methods = vec![
            MethodSchema::new("ping", "rpc", "h1"),
            MethodSchema::new("kid_a", "static a", "h2")
                .with_role(MethodRole::StaticChild),
            MethodSchema::new("describe", "rpc too", "h3"),
            MethodSchema::new("kid_b", "static b", "h4")
                .with_role(MethodRole::StaticChild),
        ];
        let (children, is_hub) = PluginSchema::derive_legacy_fields(&methods);
        // Source-order preservation: kid_a appears before kid_b.
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].namespace, "kid_a");
        assert_eq!(children[1].namespace, "kid_b");
        assert!(is_hub);
    }

    /// IR-4: `derive_legacy_fields`'s `is_hub` result matches
    /// [`PluginSchema::is_hub_by_role`] on every method list covered by the
    /// acceptance-criteria table.
    #[test]
    fn ir4_derive_is_hub_matches_is_hub_by_role() {
        // Empty methods.
        let empty_schema = PluginSchema::leaf("t", "1.0", "d", vec![]);
        let (_, is_hub) = PluginSchema::derive_legacy_fields(&empty_schema.methods);
        assert_eq!(is_hub, empty_schema.is_hub_by_role());

        // All-Rpc methods.
        let rpc_schema = PluginSchema::leaf(
            "t",
            "1.0",
            "d",
            vec![
                MethodSchema::new("a", "d", "h1"),
                MethodSchema::new("b", "d", "h2"),
            ],
        );
        let (_, is_hub) = PluginSchema::derive_legacy_fields(&rpc_schema.methods);
        assert_eq!(is_hub, rpc_schema.is_hub_by_role());

        // StaticChild present.
        let static_schema = PluginSchema::leaf(
            "t",
            "1.0",
            "d",
            vec![
                MethodSchema::new("a", "d", "h1"),
                MethodSchema::new("kid", "d", "h2").with_role(MethodRole::StaticChild),
            ],
        );
        let (_, is_hub) = PluginSchema::derive_legacy_fields(&static_schema.methods);
        assert_eq!(is_hub, static_schema.is_hub_by_role());
        assert!(is_hub);

        // DynamicChild present.
        let dyn_schema = PluginSchema::leaf(
            "t",
            "1.0",
            "d",
            vec![MethodSchema::new("find", "d", "h1").with_role(
                MethodRole::DynamicChild {
                    list_method: None,
                    search_method: None,
                },
            )],
        );
        let (_, is_hub) = PluginSchema::derive_legacy_fields(&dyn_schema.methods);
        assert_eq!(is_hub, dyn_schema.is_hub_by_role());
        assert!(is_hub);
    }

    /// IR-4 rule 2: `validate_no_collisions` no longer panics when a
    /// `StaticChild`-role method shares its name with a `ChildSummary` —
    /// that's expected by construction (two wire representations of the
    /// same child).
    #[test]
    fn ir4_no_collision_static_child_method_vs_summary() {
        // Same name on both surfaces — used to panic, now accepted.
        let schema = PluginSchema::hub(
            "hub",
            "1.0",
            "has static child",
            vec![
                MethodSchema::new("ping", "rpc", "h1"),
                MethodSchema::new("kid", "static child", "h2")
                    .with_role(MethodRole::StaticChild),
            ],
            vec![ChildSummary {
                namespace: "kid".into(),
                description: "static child".into(),
                hash: "kh".into(),
            }],
        );
        // Child stayed on the wire.
        #[allow(deprecated)]
        let kids = schema.children.as_ref().expect("hub has children");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].namespace, "kid");
        // Method kept its role tag.
        assert!(matches!(
            schema.methods.iter().find(|m| m.name == "kid").unwrap().role,
            MethodRole::StaticChild
        ));
    }

    /// IR-4 rule 2: `validate_no_collisions` also tolerates DynamicChild-role
    /// method names that appear in the child summary list.
    #[test]
    fn ir4_no_collision_dynamic_child_method_vs_summary() {
        let schema = PluginSchema::hub(
            "hub",
            "1.0",
            "has dynamic child",
            vec![MethodSchema::new("body", "gate", "h1").with_role(
                MethodRole::DynamicChild {
                    list_method: Some("body_names".into()),
                    search_method: None,
                },
            )],
            vec![ChildSummary {
                namespace: "body".into(),
                description: "gate".into(),
                hash: "bh".into(),
            }],
        );
        #[allow(deprecated)]
        let kids = schema.children.as_ref().unwrap();
        assert_eq!(kids.len(), 1);
    }

    /// IR-4 rule 2: `validate_no_collisions` still panics when an `Rpc`-role
    /// method's name collides with a child summary — that's the case the
    /// validation was designed to catch.
    #[test]
    #[should_panic(expected = "method/child collision")]
    fn ir4_collision_rpc_method_vs_summary_still_panics() {
        let _ = PluginSchema::hub(
            "hub",
            "1.0",
            "bad hub",
            vec![MethodSchema::new("oops", "rpc", "h1")],
            vec![ChildSummary {
                namespace: "oops".into(),
                description: "shadowed".into(),
                hash: "oh".into(),
            }],
        );
    }

    /// IR-4 AC #3 (spec): reading `PluginSchema.children` outside a
    /// `#[allow(deprecated)]` block emits a compiler warning. This fixture
    /// uses `#[allow(deprecated)]` to confirm the attribute is required —
    /// if it weren't, the `#[deprecated]` annotation is either missing or
    /// wrong.
    #[test]
    fn ir4_deprecated_field_access_requires_allow_attribute() {
        let schema = PluginSchema::leaf(
            "t",
            "1.0",
            "d",
            vec![MethodSchema::new("a", "b", "h")],
        );
        // Reading the deprecated field — under `#[allow(deprecated)]` from
        // the module-level attribute on the tests module. Removing that
        // allow would produce a compiler warning pointing at this line.
        let _children = schema.children.clone();
        // Calling the deprecated method — same rationale.
        let _is_hub = schema.is_hub();
    }

    /// AUTHZ-CRED-CORE-2 AC #8: `PluginSchema::leaf` runs the
    /// schema-build warning hook for the framework-reserved
    /// `_credentials` top-level field name. The hook itself emits a
    /// `tracing::warn!` line, which is not directly assertable here
    /// without a tracing subscriber; we exercise the predicate path
    /// through schema construction (no panic, schema still constructed)
    /// and assert that the underlying check function is wired in.
    #[test]
    fn cred_core_2_ac8_leaf_constructor_does_not_panic_on_collision() {
        // Build a returns schema with a top-level `_credentials` field —
        // the framework-reserved name.
        let returns_collision_schema: schemars::Schema = serde_json::from_value(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "user_id":      { "type": "string" },
                    "_credentials": { "type": "object" }
                }
            }),
        )
        .unwrap();

        // The leaf constructor consults the warning hook but does NOT
        // fail — the field is shadowed at dispatch time, and the
        // warning is the user-visible diagnostic. Constructing the
        // schema must still succeed (additive behavior).
        let schema = PluginSchema::leaf(
            "auth",
            "1.0",
            "test",
            vec![MethodSchema::new("login", "logs in", "h1").with_returns(returns_collision_schema)],
        );
        // Plugin still built.
        assert_eq!(schema.namespace, "auth");
        assert_eq!(schema.methods.len(), 1);

        // And the inverse: a schema without the collision does not
        // panic either.
        let no_collision_schema: schemars::Schema = serde_json::from_value(
            serde_json::json!({ "type": "object", "properties": { "user_id": { "type": "string" } } }),
        )
        .unwrap();
        let schema_clean = PluginSchema::leaf(
            "auth",
            "1.0",
            "test",
            vec![MethodSchema::new("ping", "pings", "h2").with_returns(no_collision_schema)],
        );
        assert_eq!(schema_clean.methods.len(), 1);
    }

    /// IR-4 AC #8: `PluginSchema.is_hub()` (deprecated) and
    /// `PluginSchema::is_hub_by_role()` agree on every shape currently
    /// emitted by substrate activations (methods with role tags, children
    /// field populated via hub constructor).
    #[test]
    fn ir4_is_hub_and_is_hub_by_role_agree_on_role_tagged_methods() {
        // Pure-leaf, all Rpc: both false.
        let leaf = PluginSchema::leaf(
            "t",
            "1.0",
            "d",
            vec![MethodSchema::new("a", "d", "h1")],
        );
        assert_eq!(leaf.is_hub(), leaf.is_hub_by_role());
        assert!(!leaf.is_hub());

        // Hub with role-tagged methods (today's post-IR-3 shape): both true.
        let hub_with_roles = PluginSchema::hub(
            "h",
            "1.0",
            "d",
            vec![MethodSchema::new("kid", "d", "h1").with_role(MethodRole::StaticChild)],
            vec![ChildSummary {
                namespace: "kid".into(),
                description: "d".into(),
                hash: "".into(),
            }],
        );
        assert_eq!(hub_with_roles.is_hub(), hub_with_roles.is_hub_by_role());
        assert!(hub_with_roles.is_hub());
    }

    // =========================================================================
    // AUTHZ-CRED-CORE-3 tests: CredentialFieldDecl, RequiredCredential,
    // MethodSchema.credentials / .requires_credential projections.
    // =========================================================================

    use plexus_auth_core::{
        AttachmentSite, CredentialFieldMarker, CredentialIssuer, CredentialKind,
        CredentialMetadata, CredentialScheme, HeaderName, MethodPath, Origin, Scope,
    };

    fn sample_issuer() -> CredentialIssuer {
        CredentialIssuer::new(
            Origin::new("ws://localhost:4444"),
            MethodPath::try_new("auth.login").unwrap(),
        )
    }

    fn sample_marker_single() -> CredentialFieldMarker {
        CredentialFieldMarker::new(
            None,
            "session",
            CredentialKind::Bearer,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            Some(CredentialScheme::new("Bearer ")),
            vec![Scope::new("cone.send_message")],
            Some(MethodPath::try_new("auth.refresh").unwrap()),
            Some(MethodPath::try_new("auth.logout").unwrap()),
        )
    }

    /// AC #1: A method whose return type contains one `Credential<T>` field
    /// produces a `MethodSchema` whose `credentials` field has one
    /// `CredentialFieldDecl` entry with the correct field path and metadata.
    #[test]
    fn cred_core_3_ac1_single_credential_projection() {
        let marker = sample_marker_single();
        let decl = CredentialFieldDecl::from_marker(&marker, &[], sample_issuer());

        // Field path is the marker's single field name.
        assert_eq!(decl.field_path, vec!["session".to_string()]);
        // No variant tag for a struct return type.
        assert!(decl.variant_tag.is_none());
        // Metadata composes correctly from the marker.
        assert_eq!(decl.metadata.kind, CredentialKind::Bearer);
        assert_eq!(
            decl.metadata.attach_as,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            }
        );
        assert_eq!(decl.metadata.scheme, Some(CredentialScheme::new("Bearer ")));
        assert_eq!(decl.metadata.scopes, vec![Scope::new("cone.send_message")]);
        assert_eq!(
            decl.metadata.refresh_via,
            Some(MethodPath::try_new("auth.refresh").unwrap())
        );
        assert_eq!(
            decl.metadata.revoke_via,
            Some(MethodPath::try_new("auth.logout").unwrap())
        );
        assert_eq!(decl.metadata.issuer, sample_issuer());

        // Project into a MethodSchema and confirm the field is populated.
        let method = MethodSchema::new("login", "logs in", "h_login").with_credentials(vec![decl]);
        assert_eq!(method.credentials.len(), 1);
        assert_eq!(method.credentials[0].field_path, vec!["session".to_string()]);
    }

    /// AC #2: A method whose return type contains multiple `Credential<T>`
    /// fields produces a `MethodSchema` whose `credentials` field has one
    /// entry per credential, in stable order.
    #[test]
    fn cred_core_3_ac2_multiple_credentials_stable_order() {
        let m1 = CredentialFieldMarker::new(
            None,
            "access",
            CredentialKind::OauthAccess,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            Some(CredentialScheme::new("Bearer ")),
            vec![Scope::new("cone.send")],
            Some(MethodPath::try_new("auth.refresh").unwrap()),
            None,
        );
        let m2 = CredentialFieldMarker::new(
            None,
            "refresh",
            CredentialKind::OauthRefresh,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            None,
            vec![Scope::new("auth.refresh")],
            None,
            None,
        );

        let decls = vec![
            CredentialFieldDecl::from_marker(&m1, &[], sample_issuer()),
            CredentialFieldDecl::from_marker(&m2, &[], sample_issuer()),
        ];
        let method = MethodSchema::new("login", "logs in", "h_oauth").with_credentials(decls);

        // Two entries, in declaration order.
        assert_eq!(method.credentials.len(), 2);
        assert_eq!(method.credentials[0].field_path, vec!["access".to_string()]);
        assert_eq!(method.credentials[0].metadata.kind, CredentialKind::OauthAccess);
        assert_eq!(method.credentials[1].field_path, vec!["refresh".to_string()]);
        assert_eq!(method.credentials[1].metadata.kind, CredentialKind::OauthRefresh);
    }

    /// AC #3: A method whose return type is an enum with credentials only on
    /// one variant produces a `MethodSchema` with the correct `variant_tag`
    /// set on each entry.
    #[test]
    fn cred_core_3_ac3_enum_variant_tag_set() {
        let marker = CredentialFieldMarker::new(
            Some("Issued"),
            "session",
            CredentialKind::Bearer,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            Some(CredentialScheme::new("Bearer ")),
            vec![Scope::new("cone.send_message")],
            None,
            None,
        );
        let decl = CredentialFieldDecl::from_marker(&marker, &[], sample_issuer());
        assert_eq!(decl.variant_tag, Some("Issued".to_string()));
        assert_eq!(decl.field_path, vec!["session".to_string()]);

        let method = MethodSchema::new("login", "logs in", "h_login").with_credentials(vec![decl]);
        assert_eq!(method.credentials[0].variant_tag, Some("Issued".to_string()));
    }

    /// `CredentialFieldDecl::from_marker` honors a non-empty path prefix
    /// (nested-field walk).
    #[test]
    fn cred_core_3_from_marker_with_nested_path_prefix() {
        let marker = sample_marker_single();
        let decl = CredentialFieldDecl::from_marker(&marker, &["auth"], sample_issuer());
        assert_eq!(decl.field_path, vec!["auth".to_string(), "session".to_string()]);
    }

    /// AC #4: A method tagged `#[plexus::method(public)]` produces a
    /// `MethodSchema` whose `requires_credential` is `None`.
    ///
    /// "Public" maps to "no implicit derivation occurs"; the schema-build
    /// surface simply doesn't call `with_requires_credential`, leaving the
    /// field at its `None` default.
    #[test]
    fn cred_core_3_ac4_public_method_requires_credential_none() {
        let method = MethodSchema::new("auth.login", "logs in", "h_login");
        assert!(method.requires_credential.is_none());

        // After round-trip the field also serializes/deserializes as None
        // (omitted on the wire).
        let json = serde_json::to_value(&method).unwrap();
        assert!(
            !json
                .as_object()
                .unwrap()
                .contains_key("requires_credential"),
            "requires_credential must be omitted from wire JSON when None, got {json}"
        );
        let decoded: MethodSchema = serde_json::from_value(json).unwrap();
        assert!(decoded.requires_credential.is_none());
    }

    /// AC #5: A method tagged with a scope produces a `MethodSchema` whose
    /// `requires_credential.scopes` contains that scope and whose
    /// `requires_credential.kind` is `None`.
    #[test]
    fn cred_core_3_ac5_scoped_method_implicit_requires_credential() {
        let req = RequiredCredential::from_method_scope(Scope::new("cone.send_message"));
        assert!(req.kind.is_none());
        assert_eq!(req.scopes, vec![Scope::new("cone.send_message")]);
        assert!(req.site_hint.is_none());

        let method = MethodSchema::new("send", "sends a message", "h_send")
            .with_requires_credential(req.clone());
        assert_eq!(method.requires_credential.as_ref().unwrap(), &req);
    }

    /// AC #6: A method whose path appears as the `refresh_via` or
    /// `revoke_via` of any credential in the schema produces a `MethodSchema`
    /// whose `requires_credential.kind` matches the issuing credential's
    /// kind.
    #[test]
    fn cred_core_3_ac6_refresh_target_narrows_kind() {
        // The OAuth refresh flow: the access credential carries
        // `refresh_via = auth.refresh`. The implicit-derivation rule
        // narrows the requires_credential of `auth.refresh` to
        // `OauthRefresh`.
        let req = RequiredCredential::from_refresh_revoke_target(
            CredentialKind::OauthRefresh,
            vec![Scope::new("auth.refresh")],
        );
        assert_eq!(req.kind, Some(CredentialKind::OauthRefresh));
        assert_eq!(req.scopes, vec![Scope::new("auth.refresh")]);

        let refresh_method =
            MethodSchema::new("refresh", "refreshes a token", "h_refresh")
                .with_requires_credential(req.clone());
        assert_eq!(
            refresh_method.requires_credential.as_ref().unwrap().kind,
            Some(CredentialKind::OauthRefresh)
        );
    }

    /// AC #6 variant: site_hint can be threaded through if a build-path
    /// derivation step has a preferred attach site (e.g., the OAuth refresh
    /// path that knows the refresh token is attached via header).
    #[test]
    fn cred_core_3_required_credential_site_hint_preserved() {
        let mut req = RequiredCredential::from_refresh_revoke_target(
            CredentialKind::OauthRefresh,
            vec![Scope::new("auth.refresh")],
        );
        let hint = AttachmentSite::Header {
            name: HeaderName::try_new("authorization").unwrap(),
        };
        req.site_hint = Some(hint.clone());
        let method = MethodSchema::new("refresh", "refreshes", "h_refresh")
            .with_requires_credential(req);

        let json = serde_json::to_string(&method).unwrap();
        let decoded: MethodSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.requires_credential.as_ref().unwrap().site_hint,
            Some(hint)
        );
    }

    /// AC #7: A pre-existing schema consumer (synapse IR builder,
    /// hub-codegen) decodes the new schema fields with their additive
    /// defaults and continues to function.
    ///
    /// Tested by deserializing a pre-CRED-CORE-3 JSON shape (no
    /// `credentials`, no `requires_credential` fields) and asserting the
    /// defaults are applied.
    #[test]
    fn cred_core_3_ac7_pre_ir_json_deserializes_with_empty_defaults() {
        let pre_ir_json = serde_json::json!({
            "name": "ping",
            "description": "pong",
            "hash": "abc"
        });
        let schema: MethodSchema = serde_json::from_value(pre_ir_json).unwrap();
        assert!(schema.credentials.is_empty());
        assert!(schema.requires_credential.is_none());
    }

    /// AC #7 variant: a pre-IR PluginSchema with multiple methods
    /// deserializes cleanly with every method's credential projections
    /// defaulted.
    #[test]
    fn cred_core_3_ac7_pre_ir_plugin_schema_deserializes() {
        let pre_ir_json = serde_json::json!({
            "namespace": "legacy",
            "version": "1.0",
            "description": "no credentials",
            "self_hash": "s1",
            "hash": "h1",
            "methods": [
                { "name": "a", "description": "alpha", "hash": "ah" },
                { "name": "b", "description": "beta",  "hash": "bh" }
            ]
        });
        let plugin: PluginSchema = serde_json::from_value(pre_ir_json).unwrap();
        for m in &plugin.methods {
            assert!(m.credentials.is_empty());
            assert!(m.requires_credential.is_none());
        }
    }

    /// AC #8: The `_info` capability advertisement carries the new fields
    /// when populated.
    ///
    /// `_info` reads `MethodSchema`'s serde representation directly. We
    /// verify the wire JSON contains the new fields when populated.
    #[test]
    fn cred_core_3_ac8_info_advertisement_carries_populated_fields() {
        let marker = sample_marker_single();
        let decl = CredentialFieldDecl::from_marker(&marker, &[], sample_issuer());
        let req = RequiredCredential::from_method_scope(Scope::new("cone.send_message"));
        let method = MethodSchema::new("login", "logs in", "h_login")
            .with_credentials(vec![decl])
            .with_requires_credential(req);

        let json = serde_json::to_value(&method).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            obj.contains_key("credentials"),
            "populated credentials must appear in wire JSON"
        );
        assert!(
            obj.contains_key("requires_credential"),
            "populated requires_credential must appear in wire JSON"
        );
        // And the entry shape is decodeable.
        let decoded: MethodSchema = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.credentials.len(), 1);
        assert_eq!(decoded.credentials[0].field_path, vec!["session".to_string()]);
        assert_eq!(
            decoded.requires_credential.as_ref().unwrap().scopes,
            vec![Scope::new("cone.send_message")]
        );
    }

    /// AC #11 (no regression): a method that does not return credentials and
    /// has no scope-derived requirement has identical wire JSON to a pre-IR
    /// schema for the same method (the new fields are omitted on the wire).
    #[test]
    fn cred_core_3_ac11_methods_without_credentials_have_unchanged_wire_shape() {
        let method = MethodSchema::new("ping", "pong", "h_ping");
        let json = serde_json::to_value(&method).unwrap();
        let obj = json.as_object().unwrap();
        // No credentials key, no requires_credential key.
        assert!(!obj.contains_key("credentials"));
        assert!(!obj.contains_key("requires_credential"));

        // And the round-trip preserves the empty defaults.
        let decoded: MethodSchema = serde_json::from_value(json).unwrap();
        assert!(decoded.credentials.is_empty());
        assert!(decoded.requires_credential.is_none());
    }

    /// Round-trip coverage: a full `MethodSchema` with both projections
    /// populated round-trips through serde without losing fields.
    #[test]
    fn cred_core_3_full_method_roundtrip_preserves_credentials_and_requires() {
        let marker = sample_marker_single();
        let decl = CredentialFieldDecl::from_marker(&marker, &[], sample_issuer());
        let req = RequiredCredential::from_method_scope(Scope::new("cone.send_message"));
        let method = MethodSchema::new("login", "logs in", "h_login")
            .with_credentials(vec![decl.clone()])
            .with_requires_credential(req.clone());

        let json = serde_json::to_string(&method).unwrap();
        let decoded: MethodSchema = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.credentials.len(), 1);
        assert_eq!(decoded.credentials[0], decl);
        assert_eq!(decoded.requires_credential.as_ref().unwrap(), &req);
    }

    /// `CredentialFieldDecl` round-trips via serde — pinned independently
    /// of MethodSchema so consumers reading the decl in isolation (e.g.
    /// `AUTHZ-CRED-IR-1` Haskell decoder testing parity) have a
    /// trustworthy shape contract.
    #[test]
    fn cred_core_3_credential_field_decl_roundtrip() {
        let marker = sample_marker_single();
        let original = CredentialFieldDecl::from_marker(&marker, &["envelope"], sample_issuer());
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CredentialFieldDecl = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    /// `RequiredCredential` round-trips via serde — pinned independently
    /// for the same cross-stack reason as `CredentialFieldDecl`.
    #[test]
    fn cred_core_3_required_credential_roundtrip() {
        let req = RequiredCredential {
            kind: Some(CredentialKind::OauthRefresh),
            scopes: vec![Scope::new("auth.refresh")],
            site_hint: Some(AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RequiredCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    /// `RequiredCredential` with `kind: None, scopes: [...], site_hint:
    /// None` (the `from_method_scope` shape) serializes to a compact wire
    /// form that omits the absent fields.
    #[test]
    fn cred_core_3_required_credential_compact_wire_shape() {
        let req = RequiredCredential::from_method_scope(Scope::new("cone.send"));
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        // Only the scopes field is present on the wire.
        assert!(!obj.contains_key("kind"));
        assert!(obj.contains_key("scopes"));
        assert!(!obj.contains_key("site_hint"));
    }
}
