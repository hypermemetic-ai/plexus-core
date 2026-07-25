//! The activation IR data types (PLX-75 / M1·A).
//!
//! These are **inert data types**. Nothing in this module parses source,
//! generates code, or dispatches a call — the parser (M1·B), the sealed core
//! entry (M1·C) and the client generator (M1·E) each consume the shape defined
//! here. See [`super`] for the module-level contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::hash::Hasher;

/// Version of the IR *document format* itself.
///
/// Bumped when the IR's own shape changes in a way a consumer must notice.
/// Distinct from [`ActivationIr::version`], which is the version of the
/// *service* being described. PLX-73 `q-ir-completeness` item 18: there is no
/// handshake — a client reads this field plus [`ActivationIr::ir_hash`] and
/// decides for itself.
pub const IR_VERSION: u32 = 1;

fn default_ir_version() -> u32 {
    IR_VERSION
}

fn is_default_ir_version(v: &u32) -> bool {
    *v == IR_VERSION
}

// ===========================================================================
// SchemaRef — a type reference that cannot degrade
// ===========================================================================

/// Why a [`SchemaRef`] could not be constructed.
///
/// Every variant here is a case that today's `BidirType::Custom` would have
/// swallowed, re-parsed, and silently degraded to `()`. In the IR it is a
/// construction error instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaRefError {
    /// The type name was empty or whitespace-only.
    #[error("schema reference type name is empty")]
    EmptyTypeName,

    /// The type name denotes the Rust unit type.
    ///
    /// This is the exact silent-degradation target PLX-75 forbids: a bidir
    /// request/response type that "could not be represented" used to become
    /// `()`. A `SchemaRef` can never denote `()`; a turn with no meaningful
    /// terminal value expresses that as `MethodIr::terminal == None`, and a
    /// turn that emits no updates as `MethodIr::updates == None`.
    #[error("schema reference type name `{0}` denotes the unit type; a SchemaRef may never be `()`")]
    UnitTypeName(String),

    /// The JSON Schema carries no type information (`{}`, `true`, or `false`).
    #[error("schema reference for `{type_name}` carries no type information ({reason})")]
    UninformativeSchema {
        /// The type name that was being referenced.
        type_name: String,
        /// Which uninformative form was supplied.
        reason: &'static str,
    },

    /// The JSON Schema is the null/unit schema.
    #[error("schema reference for `{0}` is the null schema; a SchemaRef may never be `()`")]
    NullSchema(String),
}

/// A **typed** reference to a data type in the IR: its canonical name *and*
/// its resolved JSON Schema, together, validated at construction.
///
/// # Why this is a newtype and not a `String`
///
/// PLX-73 recorded the failure mode being designed out: `BidirType::Custom`
/// stored bidirectional request/response types as *type names* (`String`) and
/// re-parsed them at emission with a fallback that silently substituted `()`
/// when the name did not resolve. The wire then advertised a method whose
/// request type was a lie.
///
/// `SchemaRef` makes that unrepresentable rather than merely discouraged:
///
/// - the fields are private and there is **no** `Default`, no `FromStr`, and no
///   public struct literal — [`SchemaRef::new`] is the only constructor;
/// - `new` is fallible and rejects every degenerate form (see
///   [`SchemaRefError`]), including the unit type and the empty schema;
/// - `Deserialize` routes through the same validation via `#[serde(try_from)]`,
///   so a hand-written or tampered JSON document cannot smuggle one in.
///
/// Consequently *any* `SchemaRef` value that exists anywhere in a program is a
/// resolved, non-unit, informative type reference — which is what makes
/// [`CallbackIr`]'s non-optional `request`/`response` fields a static guarantee
/// rather than a convention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SchemaRefWire")]
pub struct SchemaRef {
    /// Canonical name of the referenced type, e.g. `"acp::PermissionRequest"`.
    type_name: String,
    /// The resolved JSON Schema for that type.
    schema: schemars::Schema,
}

/// Deserialization shim: the wire shape of a [`SchemaRef`], re-validated on the
/// way in so `serde` cannot construct an invalid one.
#[derive(Deserialize)]
struct SchemaRefWire {
    type_name: String,
    schema: schemars::Schema,
}

impl TryFrom<SchemaRefWire> for SchemaRef {
    type Error = SchemaRefError;

    fn try_from(w: SchemaRefWire) -> Result<Self, Self::Error> {
        SchemaRef::new(w.type_name, w.schema)
    }
}

impl SchemaRef {
    /// The only way to build a [`SchemaRef`].
    ///
    /// # Errors
    ///
    /// Returns [`SchemaRefError`] if the type name is empty or the unit type,
    /// or if the schema is `true` / `false` / `{}` / the null schema — i.e. if
    /// the reference would carry no usable type information.
    pub fn new(
        type_name: impl Into<String>,
        schema: schemars::Schema,
    ) -> Result<Self, SchemaRefError> {
        let type_name = type_name.into();
        let trimmed = type_name.trim();
        if trimmed.is_empty() {
            return Err(SchemaRefError::EmptyTypeName);
        }
        if matches!(trimmed, "()" | "unit" | "!") {
            return Err(SchemaRefError::UnitTypeName(type_name));
        }

        let value: &serde_json::Value = schema.as_value();
        match value {
            serde_json::Value::Bool(true) => {
                return Err(SchemaRefError::UninformativeSchema {
                    type_name,
                    reason: "schema is the always-valid `true` schema",
                })
            }
            serde_json::Value::Bool(false) => {
                return Err(SchemaRefError::UninformativeSchema {
                    type_name,
                    reason: "schema is the never-valid `false` schema",
                })
            }
            serde_json::Value::Object(map) if map.is_empty() => {
                return Err(SchemaRefError::UninformativeSchema {
                    type_name,
                    reason: "schema is the empty object schema `{}`",
                })
            }
            serde_json::Value::Object(map) => {
                if map.get("type") == Some(&serde_json::Value::String("null".to_string())) {
                    return Err(SchemaRefError::NullSchema(type_name));
                }
            }
            _ => {}
        }

        Ok(Self { type_name, schema })
    }

    /// Canonical name of the referenced type.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// The resolved JSON Schema of the referenced type.
    pub fn schema(&self) -> &schemars::Schema {
        &self.schema
    }

    fn hash_into(&self, h: &mut Hasher) {
        h.tag("plexus.ir.schema_ref.v1");
        h.str(&self.type_name);
        h.json(self.schema.as_value());
    }
}

// ===========================================================================
// Leaf enums
// ===========================================================================

/// HTTP verb for REST projections of a method — a real enum, never a `String`.
///
/// PLX-73: `http_method` becomes an enum end to end. Mirrors the variant set of
/// the legacy `plexus::HttpMethod` (and its `UPPERCASE` wire form) so a REST
/// gateway reading either sees the same tokens, but is a distinct type: the IR
/// does not depend on `schema.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethodIr {
    /// Idempotent read with no side effects.
    Get,
    /// Create or non-idempotent action. The default.
    #[default]
    Post,
    /// Idempotent replace/update.
    Put,
    /// Idempotent removal.
    Delete,
    /// Partial update.
    Patch,
}

impl HttpMethodIr {
    /// The uppercase wire token.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
        }
    }
}

/// Whether a method requires an authenticated caller.
///
/// The method-level counterpart of the activation-level `AuthPosture` in
/// `schema.rs`, collapsing that type's `public: bool` companion flag into the
/// same enum. Defaults to [`AuthRequirementIr::Required`] — the IR is
/// default-deny, matching AUTHZ-CORE-2, so a method is only reachable
/// unauthenticated if it *says* so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthRequirementIr {
    /// Affirmatively public — exempt from the auth gate.
    Public,
    /// Auth is accepted and surfaced if present, but not demanded.
    Optional,
    /// Auth is required. The default.
    #[default]
    Required,
}

impl AuthRequirementIr {
    fn tag(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

/// Deprecation notice attached to an activation, a method, or a parameter.
///
/// The IR's own copy of the concept carried by `plexus::DeprecationInfo`. It is
/// deliberately a separate type: PLX-75 adds no bridge between the IR and
/// `schema.rs` (PLX-73 `q-migration-bridge`: no shims).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecationIr {
    /// Version at which deprecation began, e.g. `"0.6"`.
    pub since: String,
    /// Version in which removal is planned. A hint, not a promise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_in: Option<String>,
    /// Human-readable migration guidance.
    pub message: String,
}

impl DeprecationIr {
    /// Build a deprecation notice.
    pub fn new(since: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            since: since.into(),
            removed_in: None,
            message: message.into(),
        }
    }

    /// Declare the version in which the surface is planned for removal.
    pub fn removed_in(mut self, v: impl Into<String>) -> Self {
        self.removed_in = Some(v.into());
        self
    }

    fn hash_into(&self, h: &mut Hasher) {
        h.tag("plexus.ir.deprecation.v1");
        h.str(&self.since);
        h.opt_str(self.removed_in.as_deref());
        h.str(&self.message);
    }
}

// ===========================================================================
// CallbackIr
// ===========================================================================

/// One server-to-client request a method may issue during its turn.
///
/// PLX-77 replaces PLX-75's `MethodShape::Bidirectional { request, response }`,
/// which could express exactly **one** callback shape per method. ACP's
/// `session/prompt` issues four distinct ones
/// (`session/request_permission`, `fs/read_text_file`, `fs/write_text_file`,
/// `terminal/create`), so callbacks are a **set**, not a pair.
///
/// Both halves are [`SchemaRef`]s, so PLX-75's no-silent-degradation guarantee
/// carries over unchanged: a callback whose request or response type could not
/// be resolved is a construction error, never a `()`.
///
/// The authoritative producer of these values is a capability marker's
/// descriptor — see [`crate::capability`]. A later build derives
/// [`MethodIr::callbacks`] from the `Client<C>` handle in a method signature,
/// which is what makes the declared set and the usable set the same thing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallbackIr {
    /// Wire name of the server-to-client request, e.g. `"fs/read_text_file"`.
    pub name: String,
    /// Type the *server* sends to the client.
    pub request: SchemaRef,
    /// Type the client sends back.
    pub response: SchemaRef,
}

impl CallbackIr {
    /// Build a callback descriptor.
    pub fn new(name: impl Into<String>, request: SchemaRef, response: SchemaRef) -> Self {
        Self {
            name: name.into(),
            request,
            response,
        }
    }

    pub(crate) fn hash_into(&self, h: &mut Hasher) {
        h.tag("plexus.ir.callback.v1");
        h.str(&self.name);
        self.request.hash_into(h);
        self.response.hash_into(h);
    }
}

// ===========================================================================
// ParamIr
// ===========================================================================

/// One parameter of a method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParamIr {
    /// Parameter name, matching the identifier in the method signature.
    pub name: String,
    /// Human-readable description. Empty when undocumented.
    #[serde(default)]
    pub description: String,
    /// The parameter's type reference.
    pub schema: SchemaRef,
    /// Whether the caller must supply it. Defaults to `true`; `Option<T>`
    /// parameters are the ones that set it to `false`.
    #[serde(default = "crate::ir::types::param_required_default")]
    pub required: bool,
}

pub(crate) fn param_required_default() -> bool {
    true
}

impl ParamIr {
    /// A required parameter with no description.
    pub fn new(name: impl Into<String>, schema: SchemaRef) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            schema,
            required: true,
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Mark the parameter optional.
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    fn hash_into(&self, h: &mut Hasher) {
        h.tag("plexus.ir.param.v1");
        h.str(&self.name);
        h.str(&self.description);
        self.schema.hash_into(h);
        h.bool(self.required);
    }
}

// ===========================================================================
// MethodIr
// ===========================================================================

/// One callable method — the single struct that replaces the two distinct
/// `HubMethodAttrs` types plus `MethodInfo` in the old macro.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MethodIr {
    /// Local method name, e.g. `"chat"`.
    pub name: String,

    /// The canonical dotted dispatch id, e.g. `"claudecode.session.chat"`.
    ///
    /// PLX-73 `q-ir-completeness` item 6: today this is a *convention* the
    /// client reconstructs by joining the navigation path. The IR states it
    /// explicitly so a generated client never has to rebuild it.
    pub dotted_id: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: String,

    /// Merkle content hash of this method. Filled by
    /// [`ActivationIr::recompute_hashes`].
    #[serde(default)]
    pub hash: String,

    /// Declared parameters, in signature order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<ParamIr>,

    /// Type of the items the turn streams *before* it terminates.
    ///
    /// `None` means the turn emits no updates — the unary case. A
    /// [`SchemaRef`] can never *be* `()`, so "emits nothing" and "emits
    /// something the IR failed to resolve" are not the same value (PLX-75
    /// residual #5, preserved).
    ///
    /// PLX-73 `q-ir-completeness` item 7 used to be carried by
    /// `MethodShape::Streaming`; it is now simply `updates.is_some()`, and the
    /// classifier [`MethodIr::is_streaming`] is *derived*, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<SchemaRef>,

    /// Type of the turn's single terminal value.
    ///
    /// `None` means the turn returns nothing meaningful (the old `()`), with
    /// the same never-`()`-`SchemaRef` property as [`updates`](Self::updates).
    ///
    /// PLX-75 conflated this with the update-item type in one `returns` field,
    /// which meant a streaming method had no way to describe what it finally
    /// resolved to. Adopting ACP turn semantics (PLX-73
    /// `q-acp-as-communication-model`) makes a turn *always* both: zero or more
    /// updates, then exactly one terminal carrying a
    /// [`StopReason`](crate::ir::StopReason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<SchemaRef>,

    /// Server-to-client requests this method may issue during its turn.
    ///
    /// PLX-73 `q-ir-completeness` item 8 (the reply channel) and PLX-76
    /// `q-acp-callbacks`. This is a **set**, not the single request/response
    /// pair `MethodShape::Bidirectional` allowed: one method routinely issues
    /// several distinct callbacks. Streaming and callbacks are independent
    /// axes — a method may have updates without callbacks, callbacks without
    /// updates, both, or neither.
    ///
    /// The union of this field across the IR is what a service advertises, so a
    /// peer that cannot serve a required callback is rejected pre-flight rather
    /// than surprised mid-turn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callbacks: Vec<CallbackIr>,

    /// HTTP verb for REST projections.
    #[serde(default)]
    pub http_method: HttpMethodIr,

    /// Whether the caller must be authenticated. Default-deny.
    #[serde(default)]
    pub auth: AuthRequirementIr,

    /// Set when the method is deprecated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationIr>,

    /// Open extension slot for per-method attributes that are not (yet)
    /// first-class typed fields — the long tail of `#[method(ext(...))]`.
    ///
    /// PLX-71 semantics, mirrored exactly (same type, same serde treatment).
    /// Each entry is a namespaced key (e.g. `"acp_role"`) mapped to a JSON
    /// value; gateways opt in by reading `method.extensions.get("acp_role")`,
    /// so a new per-method attribute costs zero core edits. Load-bearing typed
    /// attributes (`http_method`, `shape`, …) stay first-class; this map is
    /// strictly additive. A `BTreeMap` (not a `HashMap`) so its iteration order
    /// — and therefore the method hash — is insertion-order independent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl MethodIr {
    /// A unary, auth-required method with no params, no updates, no terminal
    /// value and no callbacks.
    pub fn new(name: impl Into<String>, dotted_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dotted_id: dotted_id.into(),
            description: String::new(),
            hash: String::new(),
            params: Vec::new(),
            updates: None,
            terminal: None,
            callbacks: Vec::new(),
            http_method: HttpMethodIr::default(),
            auth: AuthRequirementIr::default(),
            deprecation: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Append a parameter.
    pub fn with_param(mut self, p: ParamIr) -> Self {
        self.params.push(p);
        self
    }

    /// Declare the type of the items this turn streams.
    pub fn with_updates(mut self, u: SchemaRef) -> Self {
        self.updates = Some(u);
        self
    }

    /// Declare the type of this turn's terminal value.
    pub fn with_terminal(mut self, t: SchemaRef) -> Self {
        self.terminal = Some(t);
        self
    }

    /// Append one server-to-client callback this method may issue.
    pub fn with_callback(mut self, c: CallbackIr) -> Self {
        self.callbacks.push(c);
        self
    }

    /// Declare the whole callback set at once — the shape a later build uses
    /// when deriving it from a `Client<C>` handle
    /// (see [`crate::capability::CapabilitySet::callbacks`]).
    pub fn with_callbacks(mut self, cs: impl IntoIterator<Item = CallbackIr>) -> Self {
        self.callbacks.extend(cs);
        self
    }

    /// Derived classifier: does this turn emit updates before terminating?
    ///
    /// **Derived, never stored, never serialized.** PLX-75 stored a `streaming:
    /// bool` alongside a `MethodShape`, which is two sources of truth for one
    /// fact; the turn envelope has exactly one.
    pub fn is_streaming(&self) -> bool {
        self.updates.is_some()
    }

    /// Derived classifier: may this turn issue server-to-client requests?
    ///
    /// Independent of [`is_streaming`](Self::is_streaming) — that
    /// independence is the defect PLX-77 fixes.
    pub fn is_bidirectional(&self) -> bool {
        !self.callbacks.is_empty()
    }

    /// Look up one declared callback by wire name.
    pub fn callback(&self, name: &str) -> Option<&CallbackIr> {
        self.callbacks.iter().find(|c| c.name == name)
    }

    /// Set the REST verb.
    pub fn with_http_method(mut self, m: HttpMethodIr) -> Self {
        self.http_method = m;
        self
    }

    /// Set the auth requirement.
    pub fn with_auth(mut self, a: AuthRequirementIr) -> Self {
        self.auth = a;
        self
    }

    /// Mark the method deprecated.
    pub fn with_deprecation(mut self, d: DeprecationIr) -> Self {
        self.deprecation = Some(d);
        self
    }

    /// Insert one `ext(...)` entry.
    pub fn with_extension(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Recompute and store this method's content hash, returning it.
    ///
    /// `self.hash` is never an input to its own computation.
    pub fn recompute_hash(&mut self) -> String {
        let h = self.content_hash();
        self.hash = h.clone();
        h
    }

    /// The method's content hash, computed without mutating it.
    pub fn content_hash(&self) -> String {
        let mut h = Hasher::new();
        h.tag("plexus.ir.method.v1");
        h.str(&self.name);
        h.str(&self.dotted_id);
        h.str(&self.description);
        h.seq(&self.params, |h, p| p.hash_into(h));
        // Turn envelope: updates, terminal, callbacks. Each is content, so
        // mutating any of them changes this method's hash and every ancestor's.
        h.tag("plexus.ir.turn.v1");
        match &self.updates {
            None => {
                h.bool(false);
            }
            Some(u) => {
                h.bool(true);
                u.hash_into(&mut h);
            }
        }
        match &self.terminal {
            None => {
                h.bool(false);
            }
            Some(t) => {
                h.bool(true);
                t.hash_into(&mut h);
            }
        }
        h.seq(&self.callbacks, |h, c| c.hash_into(h));
        h.str(self.http_method.as_str());
        h.str(self.auth.tag());
        match &self.deprecation {
            None => {
                h.bool(false);
            }
            Some(d) => {
                h.bool(true);
                d.hash_into(&mut h);
            }
        }
        h.map(&self.extensions, |h, v| {
            h.json(v);
        });
        h.finish()
    }
}

// ===========================================================================
// ChildEdge
// ===========================================================================

/// The three ways an activation can have children — made explicit.
///
/// PLX-73: "recursion today is three mechanisms in a trenchcoat" (static
/// `#[child]`, runtime `DynamicHub::register`, and indexed `session/{id}`
/// families). `ChildSummary` flattened all three into
/// `{namespace, description, hash}`, which is what forces one `.schema`
/// round-trip per tree level. Each mechanism gets its own variant here, with
/// exactly the data a client needs to act without another fetch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "edge", rename_all = "snake_case")]
pub enum ChildEdge {
    /// A compile-time `#[child]`: the whole subtree is embedded.
    ///
    /// Retires PLX-73 `q-ir-completeness` items 1–4 (per-level drill-down, the
    /// two re-fetch scars, and the parent-deprecation re-fetch): the client
    /// already holds the child's methods, grandchildren, hash and deprecation.
    Static(ActivationIr),

    /// A runtime-registered child (`DynamicHub::register`).
    ///
    /// Deliberately *not* embedded: its content is live and may change after
    /// the document was produced. The client fetches it lazily and caches by
    /// `hash`; when the parent's advertised `hash` for the edge differs from
    /// the cached one, only that subtree is refetched.
    Dynamic {
        /// The child's namespace segment.
        namespace: String,
        /// Content hash of the child subtree as of document production — the
        /// cache key and the invalidation signal.
        hash: String,
        /// Human-readable description, so a listing needs no fetch.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        description: String,
    },

    /// An indexed family — `session/{id}`-style instances sharing one shape.
    ///
    /// PLX-73 `q-ir-completeness` items 16 and 17 are the *capability gaps*
    /// this variant closes. Today a client cannot walk `hub session <id>
    /// <method>` at all: nothing tells it how to enumerate instances, how to
    /// form an instance path, or what an instance looks like. This edge carries
    /// all three:
    ///
    /// - **(a) enumerate** — [`list_method`](Self::Indexed::list_method) and
    ///   [`search_method`](Self::Indexed::search_method) name the dotted
    ///   methods to call. Instances themselves stay *live*: they are correctly
    ///   not in the IR (inventory item 12).
    /// - **(b) form a path** — [`path_template`](Self::Indexed::path_template)
    ///   plus [`id_field`](Self::Indexed::id_field), which names the field of
    ///   the list response that holds the id. That replaces the client's
    ///   three-tolerated-shapes guess with a `"name"` fallback (item 17).
    /// - **(c) know the shape** — [`template`](Self::Indexed::template) is ONE
    ///   `ActivationIr` describing every instance of the family, so descending
    ///   into an instance costs zero round-trips.
    Indexed {
        /// The family's namespace segment, e.g. `"session"`.
        namespace: String,
        /// Dotted id of the method that lists instances.
        list_method: String,
        /// Dotted id of the method that searches instances, when one exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search_method: Option<String>,
        /// The field of a list-response element that carries the instance id.
        id_field: String,
        /// How an instance path is formed, e.g. `"session/{id}"`.
        path_template: String,
        /// The shape shared by every instance in the family.
        template: Box<ActivationIr>,
        /// Human-readable description of the family.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        description: String,
    },
}

impl ChildEdge {
    /// The namespace segment this edge occupies under its parent.
    pub fn namespace(&self) -> &str {
        match self {
            Self::Static(ir) => &ir.namespace,
            Self::Dynamic { namespace, .. } => namespace,
            Self::Indexed { namespace, .. } => namespace,
        }
    }

    /// The hash this edge contributes to its parent's hash.
    ///
    /// For [`ChildEdge::Static`] this is exactly the embedded subtree's hash —
    /// which is what makes the fold a Merkle fold rather than a re-hash.
    pub fn edge_hash(&self) -> String {
        let mut h = Hasher::new();
        h.tag("plexus.ir.edge.v1");
        match self {
            Self::Static(ir) => {
                h.str("static");
                h.str(&ir.hash);
            }
            Self::Dynamic {
                namespace,
                hash,
                description,
            } => {
                h.str("dynamic");
                h.str(namespace);
                h.str(hash);
                h.str(description);
            }
            Self::Indexed {
                namespace,
                list_method,
                search_method,
                id_field,
                path_template,
                template,
                description,
            } => {
                h.str("indexed");
                h.str(namespace);
                h.str(list_method);
                h.opt_str(search_method.as_deref());
                h.str(id_field);
                h.str(path_template);
                h.str(&template.hash);
                h.str(description);
            }
        }
        h.finish()
    }

    fn recompute_hashes(&mut self) {
        match self {
            Self::Static(ir) => ir.recompute_node_hashes(),
            Self::Dynamic { .. } => {}
            Self::Indexed { template, .. } => template.recompute_node_hashes(),
        }
    }
}

// ===========================================================================
// ActivationIr
// ===========================================================================

/// The recursive activation IR — one document describing a whole tree.
///
/// This is the type the macro emits (M1·B/F), the sealed core entry consumes
/// (M1·C) and the client generator walks (M1·E).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationIr {
    /// Version of the IR document format. See [`IR_VERSION`].
    #[serde(default = "default_ir_version", skip_serializing_if = "is_default_ir_version")]
    pub ir_version: u32,

    /// The **backend identity** of the document — the root activation's name.
    ///
    /// PLX-73 `q-ir-completeness` item 5: the client currently issues a
    /// dedicated `_info` probe before *every* invocation just to learn this.
    /// It is a document-level field: `Some` on the root, `None` on embedded
    /// subtree nodes (which inherit their parent document's identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_name: Option<String>,

    /// Digest of the whole document, for cache invalidation.
    ///
    /// PLX-73 `q-ir-completeness` item 18: there is no version handshake; a
    /// client keeps the last `ir_hash` it saw and refetches when it differs.
    /// Derived from [`hash`](Self::hash) — set on the root only, by
    /// [`recompute_hashes`](Self::recompute_hashes), and never an input to any
    /// node hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir_hash: Option<String>,

    /// Name of the method a client calls to answer a server-to-client request
    /// declared in [`MethodIr::callbacks`].
    ///
    /// PLX-73 `q-ir-completeness` item 8: today this is a hard-coded `respond`
    /// convention on the client side. Declaring it makes the reply channel a
    /// capability of the document rather than a client assumption. Root-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub respond_method: Option<String>,

    /// This node's namespace segment, e.g. `"claudecode"`.
    pub namespace: String,

    /// Version of the *service* this node describes.
    #[serde(default)]
    pub version: String,

    /// One-line description.
    #[serde(default)]
    pub description: String,

    /// Long-form documentation, when the source carries doc comments beyond
    /// the summary line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_description: Option<String>,

    /// Merkle hash of this node: its own content folded with its methods' and
    /// children's hashes. See [`super::hash`].
    ///
    /// PLX-73 `q-ir-completeness` item 2 — every embedded node carries one, for
    /// cycle detection and cache keying.
    #[serde(default)]
    pub hash: String,

    /// The methods callable on this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<MethodIr>,

    /// Child edges, one per sub-activation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ChildEdge>,

    /// Set when this whole activation is deprecated.
    ///
    /// PLX-73 `q-ir-completeness` item 4: the client used to re-fetch the
    /// parent it had just navigated away from in order to render this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationIr>,
}

impl ActivationIr {
    /// A leaf node with no methods and no children.
    pub fn new(namespace: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            ir_version: IR_VERSION,
            backend_name: None,
            ir_hash: None,
            respond_method: None,
            namespace: namespace.into(),
            version: version.into(),
            description: String::new(),
            long_description: None,
            hash: String::new(),
            methods: Vec::new(),
            children: Vec::new(),
            deprecation: None,
        }
    }

    /// Mark this node as the document root and give the document its identity.
    pub fn with_backend_name(mut self, n: impl Into<String>) -> Self {
        self.backend_name = Some(n.into());
        self
    }

    /// Declare the bidirectional reply method.
    pub fn with_respond_method(mut self, m: impl Into<String>) -> Self {
        self.respond_method = Some(m.into());
        self
    }

    /// Attach a one-line description.
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Attach long-form documentation.
    pub fn with_long_description(mut self, d: impl Into<String>) -> Self {
        self.long_description = Some(d.into());
        self
    }

    /// Append a method.
    pub fn with_method(mut self, m: MethodIr) -> Self {
        self.methods.push(m);
        self
    }

    /// Append a child edge.
    pub fn with_child(mut self, c: ChildEdge) -> Self {
        self.children.push(c);
        self
    }

    /// Mark the whole activation deprecated.
    pub fn with_deprecation(mut self, d: DeprecationIr) -> Self {
        self.deprecation = Some(d);
        self
    }

    /// Recompute every hash in the tree, bottom-up, then set the document's
    /// [`ir_hash`](Self::ir_hash).
    ///
    /// Call this on the **root**. Mutating anything anywhere in the tree and
    /// calling this again yields: a changed hash on the mutated node, changed
    /// hashes on all of its ancestors, a changed `ir_hash`, and byte-identical
    /// hashes on every subtree that did not change.
    pub fn recompute_hashes(&mut self) {
        self.recompute_node_hashes();
        let mut h = Hasher::new();
        h.tag("plexus.ir.document.v1");
        h.u64(self.ir_version as u64);
        h.str(&self.hash);
        self.ir_hash = Some(h.finish());
    }

    /// Bottom-up hash fold for this node and everything under it.
    ///
    /// Does **not** touch `ir_hash` — a `Static` child is a node, not a
    /// document, and must not acquire a document digest.
    fn recompute_node_hashes(&mut self) {
        for m in &mut self.methods {
            m.recompute_hash();
        }
        for c in &mut self.children {
            c.recompute_hashes();
        }
        self.hash = self.node_hash();
    }

    /// This node's Merkle hash, computed from already-current method and child
    /// hashes without mutating anything.
    pub fn node_hash(&self) -> String {
        let mut h = Hasher::new();
        h.tag("plexus.ir.activation.v1");
        h.u64(self.ir_version as u64);
        h.opt_str(self.backend_name.as_deref());
        h.opt_str(self.respond_method.as_deref());
        h.str(&self.namespace);
        h.str(&self.version);
        h.str(&self.description);
        h.opt_str(self.long_description.as_deref());
        // Methods and children contribute only their hashes: that is what makes
        // this a Merkle fold rather than a full re-serialization.
        h.seq(&self.methods, |h, m| {
            h.str(&m.hash);
        });
        h.seq(&self.children, |h, c| {
            h.str(&c.edge_hash());
        });
        match &self.deprecation {
            None => {
                h.bool(false);
            }
            Some(d) => {
                h.bool(true);
                d.hash_into(&mut h);
            }
        }
        h.finish()
    }

    /// Look up a direct child edge by namespace segment.
    pub fn child(&self, namespace: &str) -> Option<&ChildEdge> {
        self.children.iter().find(|c| c.namespace() == namespace)
    }

    /// Look up a method on this node by local name.
    pub fn method(&self, name: &str) -> Option<&MethodIr> {
        self.methods.iter().find(|m| m.name == name)
    }
}
