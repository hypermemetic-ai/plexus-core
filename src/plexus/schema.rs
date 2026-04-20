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
    #[serde(skip_serializing_if = "Option::is_none")]
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

    /// Validate no name collisions exist within a plugin
    ///
    /// Checks for:
    /// - Duplicate method names
    /// - Duplicate child names (for hubs)
    /// - Method/child name collisions (for hubs)
    ///
    /// Panics if a collision is detected (system error).
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
                    // Could be duplicate child or collision with method
                    let collision_type = if methods.iter().any(|m| m.name == c.namespace) {
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

    /// Create a new leaf plugin schema (no children)
    pub fn leaf(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        methods: Vec<MethodSchema>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, None);
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
        }
    }

    /// Create a new leaf plugin schema with long description
    pub fn leaf_with_long_description(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        long_description: impl Into<String>,
        methods: Vec<MethodSchema>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, None);
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
        }
    }

    /// Create a new hub plugin schema (with child summaries)
    pub fn hub(
        namespace: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        methods: Vec<MethodSchema>,
        children: Vec<ChildSummary>,
    ) -> Self {
        let namespace = namespace.into();
        Self::validate_no_collisions(&namespace, &methods, Some(&children));
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
        }
    }

    /// Create a new hub plugin schema with long description
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
    /// Once IR-3 lands and macros emit role tags on every child method, the
    /// second branch becomes redundant. IR-4 will drop the `children` side
    /// channel entirely.
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
    pub fn is_leaf(&self) -> bool {
        self.children.is_none()
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
}
