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
use futures::Stream;
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
        }
    }
}

impl std::error::Error for PlexusError {}

/// Convert PlexusError to a JSON-RPC ErrorObject with semantic error codes.
///
/// Codes:
/// - `-32001`: Authentication required (custom app-level error)
/// - `-32601`: Method/activation not found (standard JSON-RPC)
/// - `-32602`: Invalid parameters (standard JSON-RPC)
/// - `-32000`: Generic server error (execution, transport, handle errors)
/// Get the semantic JSON-RPC error code for a PlexusError.
fn plexus_error_code(e: &PlexusError) -> i32 {
    match e {
        PlexusError::Unauthenticated(_) => -32001,
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

    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError>;
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

/// Trait for activations that can route to child activations
///
/// Hub activations implement this to support nested method routing.
/// When a method like "mercury.info" is called on a solar activation,
/// this trait enables routing to the mercury child.
///
/// This trait is separate from Activation to avoid associated type issues
/// with dynamic dispatch.
#[async_trait]
pub trait ChildRouter: Send + Sync {
    /// Get the namespace of this router (for error messages)
    fn router_namespace(&self) -> &str;

    /// Call a method on this router
    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError>;

    /// Get a child activation instance by name for nested routing
    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>>;
}

/// Route a method call to a child activation
///
/// This is called from generated code when a hub activation receives
/// a method that doesn't match its local methods. If the method
/// contains a dot (e.g., "mercury.info"), it routes to the child.
pub async fn route_to_child<T: ChildRouter + ?Sized>(
    parent: &T,
    method: &str,
    params: Value,
    auth: Option<&super::auth::AuthContext>,
) -> Result<PlexusStream, PlexusError> {
    // Try to split on first dot for nested routing
    if let Some((child_name, rest)) = method.split_once('.') {
        if let Some(child) = parent.get_child(child_name).await {
            return child.router_call(rest, params, auth).await;
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

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.0.router_call(method, params, auth).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.0.get_child(name).await
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
    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError>;
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

    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.inner.call(method, params, auth).await
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

struct DynamicHubInner {
    /// Custom namespace for this hub instance (defaults to "plexus")
    namespace: String,
    activations: HashMap<String, Arc<dyn ActivationObject>>,
    /// Child routers for direct nested routing (e.g., hub.solar.mercury.info)
    child_routers: HashMap<String, Arc<dyn ChildRouter>>,
    /// Activation registry mapping UUIDs to paths
    registry: std::sync::RwLock<PluginRegistry>,
    pending_rpc: std::sync::Mutex<Vec<Box<dyn FnOnce() -> Methods + Send>>>,
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
            }),
        }
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
    pub fn register<A: Activation + Clone>(mut self, activation: A) -> Self {
        let namespace = activation.namespace().to_string();
        let plugin_id = activation.plugin_id();
        let activation_for_rpc = activation.clone();

        let inner = Arc::get_mut(&mut self.inner)
            .expect("Cannot register: DynamicHub has multiple references");

        // Register in the activation registry
        inner.registry.write().unwrap().register(
            plugin_id,
            namespace.clone(),
            namespace.clone(), // Use namespace as plugin_type for now
        );

        inner.activations.insert(namespace, Arc::new(ActivationWrapper { inner: activation }));
        inner.pending_rpc.lock().unwrap()
            .push(Box::new(move || activation_for_rpc.into_rpc_methods()));
        self
    }

    /// Register a hub activation that supports nested routing
    ///
    /// Hub activations implement `ChildRouter`, enabling direct nested method calls
    /// like `hub.solar.mercury.info` at the RPC layer (no hub.call indirection).
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
        let (namespace, method_name) = self.parse_method(method)?;

        // Handle plexus's own methods
        if namespace == self.inner.namespace {
            return Activation::call(self, method_name, params, auth).await;
        }

        let activation = self.inner.activations.get(namespace)
            .ok_or_else(|| PlexusError::ActivationNotFound(namespace.to_string()))?;

        activation.call(method_name, params, auth).await
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

        // Register _info well-known endpoint (no namespace prefix)
        // Returns backend name as a single-item stream with automatic Done event
        let backend_name = self.runtime_namespace().to_string();
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, _ext| {
                let name = backend_name.clone();
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move {
                        serde_json::json!({"backend": name})
                    });

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

        // Register _info well-known endpoint (no namespace prefix)
        // Returns backend name as a single-item stream with automatic Done event
        let backend_name = hub.runtime_namespace().to_string();
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, _ext| {
                let name = backend_name.clone();
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move {
                        serde_json::json!({"backend": name})
                    });

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
        eprintln!("[TRACE] arc_into_rpc_module: merging {} activation RPC factories", pending.len());
        for (idx, factory) in pending.into_iter().enumerate() {
            eprintln!("[TRACE] arc_into_rpc_module: calling factory {} to get Methods", idx);
            let methods = factory();
            eprintln!("[TRACE] arc_into_rpc_module: factory {} returned Methods with {} methods", idx, methods.method_names().count());
            eprintln!("[TRACE] arc_into_rpc_module: merging factory {} methods into module", idx);
            module.merge(methods)?;
            eprintln!("[TRACE] arc_into_rpc_module: successfully merged factory {} methods", idx);
        }
        eprintln!("[TRACE] arc_into_rpc_module: all activations merged successfully");

        Ok(module)
    }
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

#[plexus_macros::hub_methods(
    namespace = "plexus",
    version = "1.0.0",
    description = "Central routing and introspection",
    hub,
    namespace_fn = "runtime_namespace"
)]
impl DynamicHub {
    /// Route a call to a registered activation
    #[plexus_macros::hub_method(
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
    #[plexus_macros::hub_method(description = "Get plexus configuration hash (from the recursive schema)\n\n This hash changes whenever any method or child plugin changes.\n It's computed from the method hashes rolled up through the schema tree.")]
    async fn hash(&self) -> impl Stream<Item = HashEvent> + Send + 'static {
        let schema = Activation::plugin_schema(self);
        stream! { yield HashEvent::Hash { value: schema.hash }; }
    }

    /// Get plugin hashes for cache validation (lightweight alternative to full schema)
    #[plexus_macros::hub_method(description = "Get plugin hashes for cache validation")]
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

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError> {
        // DynamicHub routes via its registered activations
        // Method format: "activation.method" or "activation.child.method"
        self.route(method, params, auth).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        // Look up registered activations that implement ChildRouter
        self.inner.child_routers.get(name)
            .map(|router| {
                // Clone the Arc and wrap in Box for the trait object
                Box::new(ArcChildRouter(router.clone())) as Box<dyn ChildRouter>
            })
    }
}

#[cfg(test)]
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
}
