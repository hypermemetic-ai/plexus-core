//! The activation IR data types (PLX-75 / M1·A).
//!
//! These are **inert data types**. Nothing in this module parses source,
//! generates code, or dispatches a call — the parser (M1·B), the sealed core
//! entry (M1·C) and the client generator (M1·E) each consume the shape defined
//! here. See [`super`] for the module-level contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::hash::{
    text_or_absent, Encoder, DOMAIN_ACTIVATION, DOMAIN_CAPABILITY, DOMAIN_DEPRECATION,
    DOMAIN_DOCUMENT, DOMAIN_METHOD, DOMAIN_PARAM, DOMAIN_TYPEREF, HASH_ALGORITHM,
};

/// Version of the IR *document format* itself.
///
/// Bumped when the IR's own shape changes in a way a consumer must notice.
/// Distinct from [`ActivationIr::version`], which is the version of the
/// *service* being described. PLX-73 `q-ir-completeness` item 18: there is no
/// handshake — a client reads this field plus [`ActivationIr::ir_hash`] and
/// decides for itself.
///
/// RFC 002 §3.3 makes this a **mandatory** root fact that MUST be emitted even
/// at its default; §3.5 (omit absent optionals) does not apply to it. That is
/// the resolution of finding F-01, where §3.3 and §3.5 contradicted each other
/// and this encoder obeyed §3.5.
pub const IR_VERSION: u32 = 1;

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

    /// RFC 002 §4.6 — `typeref := domain("connectome/1:typeref") ‖ text(name) ‖
    /// json(schema)`.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.domain(DOMAIN_TYPEREF);
        e.text(&self.type_name);
        e.json(self.schema.as_value());
    }
}

/// RFC 002 §6.4 — the declaration tri-state, as a preimage component.
///
/// `NotDeclared` is tag 0, `Unresolved` is tag 1 (which this implementation
/// never produces — it cannot construct a degraded [`SchemaRef`] — but which
/// the tag space reserves so the three states can never collide), and
/// `Declared` is tag 2.
fn encode_declared(e: &mut Encoder, r: Option<&SchemaRef>) {
    match r {
        None => {
            e.tag(0);
        }
        Some(t) => {
            e.tag(2);
            t.encode_into(e);
        }
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

    /// RFC 002 §4.6 — `deprecation := domain("connectome/1:deprecation") ‖
    /// opt(since) ‖ opt(removed_in) ‖ opt(message)`.
    ///
    /// `since` and `message` are REQUIRED fields of the record (§3.6) and so are
    /// always present; they are nonetheless framed as optionals because the
    /// record's three fields share one shape, and a reader that models all three
    /// as optional must reach the same preimage.
    fn encode_into(&self, e: &mut Encoder) {
        e.domain(DOMAIN_DEPRECATION);
        e.opt_text(Some(self.since.as_str()));
        e.opt_text(self.removed_in.as_deref());
        e.opt_text(Some(self.message.as_str()));
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

    /// RFC 002 §4.6 — `capability := domain("connectome/1:capability") ‖
    /// text(wire name) ‖ typeref(request) ‖ typeref(response)`.
    ///
    /// §7.2 makes the wire name the capability's identity, so it is what the
    /// preimage leads with and therefore what the §4.6 set ordering sorts on.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.domain(DOMAIN_CAPABILITY);
        e.text(&self.name);
        self.request.encode_into(e);
        self.response.encode_into(e);
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
    ///
    /// RFC 002 §3.5 — an absent optional MUST be omitted rather than emitted as
    /// an empty placeholder, so an empty description does not reach the wire at
    /// all. (The §3.5 non-conformance found by PLX-86: this encoder used to emit
    /// `""` on every activation, method and param while correctly omitting
    /// `long_description`.)
    #[serde(default, skip_serializing_if = "String::is_empty")]
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

    /// RFC 002 §4.6 — `param := domain("connectome/1:param") ‖ text(name) ‖
    /// opt(description) ‖ typeref(schema) ‖ bool(required)`.
    fn encode_into(&self, e: &mut Encoder) {
        e.domain(DOMAIN_PARAM);
        e.text(&self.name);
        e.opt_text(text_or_absent(&self.description));
        self.schema.encode_into(e);
        e.bool(self.required);
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
    ///
    /// RFC 002 §3.5 — omitted from the wire when empty, never emitted as `""`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Merkle content hash of this method. Filled by
    /// [`ActivationIr::recompute_hashes`].
    #[serde(default)]
    pub hash: String,

    /// Declared parameters, in signature order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<ParamIr>,

    /// The **request context** this method depends on — RFC 002 §6.9.
    ///
    /// PLX-89 §2b. This is the IR's rendering of what plexus already had and
    /// the Connectome silently dropped: `MethodSchema::request_type`, the
    /// per-method override of the activation-level
    /// [`ActivationIr::request_context`], itself the IR rendering of
    /// `PluginSchema::request` and the `#[derive(PlexusRequest)]` type extracted
    /// from [`crate::request::RawRequestContext`].
    ///
    /// It is the transport-observable half of a call: headers, origin, peer
    /// address, trace identifiers, idempotency keys — the facts the *transport*
    /// knows, as opposed to [`params`](Self::params), which the caller sends
    /// deliberately. Declaring it is how a caller is told what to send: without
    /// it in the document, a generated client cannot know a method needs the
    /// `Origin` header and the transport contract lives only in Rust types.
    ///
    /// **Absent means "needs nothing", not "unspecified"** (§6.9): a method with
    /// no declaration of its own and on an activation with no declaration
    /// depends on no transport-observable fact. A declaration that was intended
    /// but could not be resolved is *not* expressible as absence — a
    /// [`SchemaRef`] can never denote `()`, so a failure to resolve is a
    /// construction error here, exactly as for
    /// [`updates`](Self::updates)/[`terminal`](Self::terminal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_context: Option<SchemaRef>,

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
            request_context: None,
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

    /// Declare this method's request context (RFC 002 §6.9), overriding any
    /// declaration on its activation.
    pub fn with_request_context(mut self, r: SchemaRef) -> Self {
        self.request_context = Some(r);
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
    ///
    /// RFC 002 §4.6:
    ///
    /// ```text
    /// method := SHA-256( domain("connectome/1:method")
    ///                  ‖ text(name) ‖ text(dotted_id) ‖ opt(description)
    ///                  ‖ seq(param, params)
    ///                  ‖ declared(request_context)
    ///                  ‖ declared(updates) ‖ declared(terminal)
    ///                  ‖ set(capability, callbacks)
    ///                  ‖ opt(http_method) ‖ opt(auth)
    ///                  ‖ opt(deprecation) ‖ map(extensions) )
    /// ```
    ///
    /// `params` is a **sequence** (position is meaningful to a positional
    /// caller) and `callbacks` is a **set** (§7.1 says the declaration is a SET,
    /// and a set has no canonical order, so §4.4 applies). Declaring the same
    /// two capabilities in the opposite order therefore produces the same hash —
    /// the §4.4+§7.1 non-conformance PLX-86 recorded, fixed here.
    pub fn content_hash(&self) -> String {
        let mut e = Encoder::with_domain(DOMAIN_METHOD);
        e.text(&self.name);
        e.text(&self.dotted_id);
        e.opt_text(text_or_absent(&self.description));
        e.seq(&self.params, |e, p| p.encode_into(e));
        // §6.9 — what the transport knows about the call, beside what the caller
        // sends deliberately.
        encode_declared(&mut e, self.request_context.as_ref());
        // Turn envelope: updates, terminal, callbacks. Each is content, so
        // mutating any of them changes this method's hash and every ancestor's.
        encode_declared(&mut e, self.updates.as_ref());
        encode_declared(&mut e, self.terminal.as_ref());
        e.set(&self.callbacks, |e, c| c.encode_into(e));
        e.opt_text(Some(self.http_method.as_str()));
        e.opt_text(Some(self.auth.tag()));
        e.opt_with(self.deprecation.is_some(), |e| {
            if let Some(d) = &self.deprecation {
                d.encode_into(e);
            }
        });
        // §9.1 extensions are keyed metadata: a map, canonicalized by key.
        // `BTreeMap` already iterates in ascending key order.
        let entries: Vec<(&String, &serde_json::Value)> = self.extensions.iter().collect();
        e.seq(&entries, |e, (k, v)| {
            e.text(k);
            e.json(v);
        });
        e.digest()
    }
}

// ===========================================================================
// ChildEdge
// ===========================================================================

/// **Axis 1 — SHAPE.** How many children does this edge name?
///
/// PLX-160. This is one of the two independent questions the old three-variant
/// `ChildEdge` answered with a single discriminant. It is a property of the
/// *declaration*: in `plexus-macros` it is exactly the presence or absence of
/// `#[child(list = "…")]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case")]
pub enum ChildShape {
    /// One named child occupying the edge's namespace segment.
    Single,

    /// A family of instances sharing one shape — `session/{id}`-shaped.
    ///
    /// RFC 002 §5.1 requires an indexed edge to carry enough for a consumer to
    /// **(a) enumerate** ([`list_method`](Self::Indexed::list_method) /
    /// [`search_method`](Self::Indexed::search_method)), **(b) construct an
    /// instance path** ([`path_template`](Self::Indexed::path_template) plus
    /// [`id_field`](Self::Indexed::id_field), which names the field of the
    /// enumeration response that holds the id), and **(c) know an instance's
    /// shape** — which is the *delivery* axis's job, not this one, and is the
    /// separation PLX-160 exists to make.
    Indexed {
        /// Dotted id of the method that lists instances.
        list_method: String,
        /// Dotted id of the method that searches instances, when one exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search_method: Option<String>,
        /// The field of a list-response element that carries the instance id.
        id_field: String,
        /// How an instance path is formed, e.g. `"session/{id}"`.
        path_template: String,
    },
}

/// **Axis 2 — DELIVERY.** Does this document carry the child's subtree, or only
/// its digest?
///
/// PLX-148 established this separation at the hub (`declare_ir` vs
/// `declare_ir_lazy`): *have it* and *embed it* are two questions. PLX-160
/// carries it into the type, where it belongs, so that it composes freely with
/// [`ChildShape`].
///
/// Both arms carry a hash — that is what makes this an axis rather than a
/// special case. [`Embedded`](Self::Embedded) has it as the embedded subtree's
/// stored hash; [`Lazy`](Self::Lazy) has it as the advertised one. See
/// [`ChildEdge::advertised_hash`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "delivery", rename_all = "snake_case")]
pub enum ChildDelivery {
    /// The subtree is embedded. Descending requires no additional round trip
    /// (§5.1).
    ///
    /// For an [`Indexed`](ChildShape::Indexed) edge this is §5.1(c)'s "one
    /// template subtree describing every instance of the family": the same
    /// field, doing the same job, which is why delivery does not need to know
    /// the shape.
    Embedded {
        /// The delivered subtree. For an indexed edge, the family template.
        child: Box<ActivationIr>,
    },

    /// The subtree is NOT embedded; the edge carries its advertised hash,
    /// sufficient to fetch and cache it lazily (§5.1).
    ///
    /// §5.2: a consumer MUST NOT synthesize a subtree here. There is
    /// deliberately no field in this arm that could hold one.
    Lazy {
        /// Content hash of the child subtree as of document production — the
        /// cache key and the invalidation signal.
        hash: String,
    },
}

/// A child edge: one namespace segment, one [shape](ChildShape), one
/// [delivery](ChildDelivery).
///
/// # Why this is a struct of two axes and not an enum of variants (PLX-160)
///
/// PLX-73 replaced `ChildSummary`'s flattened `{namespace, description, hash}`
/// with three named variants — `Static`, `Dynamic`, `Indexed`. That was right
/// about *what a client needs* and wrong about *how many questions were being
/// asked*. Three variants answer two independent questions:
///
/// |  | embedded | lazy |
/// |---|---|---|
/// | **single** | `Static` | `Dynamic` |
/// | **indexed** | `Indexed` | — **unrepresentable** — |
///
/// Three cells cannot cover four, and the missing one is the cell
/// `#[child(list = "…")] fn session(&self, id: &str) -> Option<S>` declares:
/// an enumerable family whose template the hub holds but does not embed. Before
/// PLX-160 `plexus-macros` resolved that declaration by **discarding**
/// `list_method`, `id_field` and `path_template` without a diagnostic.
///
/// Carrying the axes separately makes all four representable, makes a fifth
/// axis an added field rather than a doubled variant count, and makes
/// "somebody has to notice a cell is missing" impossible: the encoder matches
/// on the *pair*, and `rustc` checks that match for exhaustiveness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChildEdge {
    /// The namespace segment this edge occupies under its parent.
    ///
    /// Hoisted out of the variants: it is an edge-level fact under every
    /// combination of the two axes. For an [`Embedded`](ChildDelivery::Embedded)
    /// edge the child's own `namespace` is stamped to match, which is what keeps
    /// §4.6's `tag(1)` preimage — which covers the namespace only transitively,
    /// through the child's own hash — byte-identical to PLX-73's.
    pub namespace: String,

    /// Axis 1 — one named child, or an indexed family.
    #[serde(flatten)]
    pub shape: ChildShape,

    /// Axis 2 — embedded here, or fetched later.
    #[serde(flatten)]
    pub delivery: ChildDelivery,

    /// Human-readable description, so a listing needs no fetch.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl ChildEdge {
    /// A single child whose subtree is embedded — PLX-73's `Static`.
    ///
    /// The edge takes its namespace from the child, matching the old
    /// `ChildEdge::Static(ir)` exactly.
    pub fn embedded(child: ActivationIr) -> Self {
        Self {
            namespace: child.namespace.clone(),
            shape: ChildShape::Single,
            delivery: ChildDelivery::Embedded {
                child: Box::new(child),
            },
            description: String::new(),
        }
    }

    /// A single child that is advertised and not embedded — PLX-73's `Dynamic`.
    pub fn lazy(namespace: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            shape: ChildShape::Single,
            delivery: ChildDelivery::Lazy { hash: hash.into() },
            description: String::new(),
        }
    }

    /// Rename the edge's own namespace segment.
    ///
    /// Deliberately does **not** touch an embedded child's own `namespace`
    /// field: that participates in the child's node hash, and an indexed
    /// family's template legitimately carries a different name from the segment
    /// the family occupies.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Attach a description without naming the other three fields.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Turn a single edge into an indexed family, leaving delivery untouched.
    ///
    /// This is the operation that makes the axes orthogonal in practice: it is
    /// callable on an embedded edge and on a lazy one, and neither knows about
    /// the other.
    #[must_use]
    pub fn indexed(
        mut self,
        list_method: impl Into<String>,
        search_method: Option<String>,
        id_field: impl Into<String>,
        path_template: impl Into<String>,
    ) -> Self {
        self.shape = ChildShape::Indexed {
            list_method: list_method.into(),
            search_method,
            id_field: id_field.into(),
            path_template: path_template.into(),
        };
        self
    }

    /// The namespace segment this edge occupies under its parent.
    ///
    /// Kept as a method as well as a field so the ~30 `edge.namespace()` call
    /// sites PLX-73 created still read the same.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The embedded subtree, when there is one.
    ///
    /// `None` under [`ChildDelivery::Lazy`] — and §5.2 says a consumer MUST NOT
    /// invent one, so this is the only way to ask.
    pub fn child(&self) -> Option<&ActivationIr> {
        match &self.delivery {
            ChildDelivery::Embedded { child } => Some(child),
            ChildDelivery::Lazy { .. } => None,
        }
    }

    /// The hash of the child subtree this edge names — embedded or advertised.
    ///
    /// Deliberately **not** [`edge_hash`](Self::edge_hash), which is a different
    /// quantity: the digest of this edge's own §4.6 preimage tuple. The two are
    /// both 64 hex and neither equals the other; PLX-148's test helper existed
    /// only because the old enum gave no single place to put this.
    pub fn advertised_hash(&self) -> &str {
        match &self.delivery {
            ChildDelivery::Embedded { child } => &child.hash,
            ChildDelivery::Lazy { hash } => hash,
        }
    }

    /// Whether the subtree must be fetched (§5.1's lazy clause).
    pub fn is_lazy(&self) -> bool {
        matches!(self.delivery, ChildDelivery::Lazy { .. })
    }

    /// Whether this edge names a family rather than one child.
    pub fn is_indexed(&self) -> bool {
        matches!(self.shape, ChildShape::Indexed { .. })
    }

    /// The hash this edge contributes to its parent's hash.
    pub fn edge_hash(&self) -> String {
        let mut e = Encoder::new();
        self.encode_into(&mut e);
        e.digest()
    }

    /// RFC 002 §4.6 — an edge's preimage component. **Four cells, four tags:**
    ///
    /// ```text
    /// (single,  embedded) := tag(1) ‖ hash(child activation hash)
    /// (single,  lazy)     := tag(2) ‖ text(namespace) ‖ hash(advertised)
    ///                              ‖ opt(description)
    /// (indexed, embedded) := tag(3) ‖ text(namespace) ‖ text(list_method)
    ///                              ‖ opt(search_method) ‖ text(id_field)
    ///                              ‖ text(path_template) ‖ hash(template hash)
    ///                              ‖ opt(description)
    /// (indexed, lazy)     := tag(4) ‖ text(namespace) ‖ text(list_method)
    ///                              ‖ opt(search_method) ‖ text(id_field)
    ///                              ‖ text(path_template) ‖ hash(advertised)
    ///                              ‖ opt(description)
    /// ```
    ///
    /// # Why the preimage keeps ONE dense tag while the wire carries two fields
    ///
    /// §4.6's job is injectivity and determinism, not mirroring the wire — and
    /// it already does not mirror it: a `(single, embedded)` edge serializes its
    /// whole subtree and contributes only that subtree's stored hash, because
    /// "a Static edge contributes exactly the embedded subtree's hash — that is
    /// what makes the fold a Merkle fold rather than a re-hash". The preimage is
    /// a **Merkle projection**.
    ///
    /// So the tag here is a *dense enumeration of the product* `shape ×
    /// delivery`, computed by an exhaustive match rather than authored. It is
    /// not a fourth variant: no cell can be forgotten, because `rustc` rejects a
    /// non-exhaustive match on the pair. What it buys is that `tag(1)`,
    /// `tag(2)` and `tag(3)` are **byte-identical to PLX-73's**, so
    /// `CONNECTOME-HASH/1` remains the construction that produced every hash
    /// this project has ever published (§4.7), and the only node hashes that
    /// move are the ones whose edges genuinely changed cell.
    ///
    /// The rejected alternative — `tag(shape) ‖ tag(delivery)` — is more
    /// obviously two-axis and moves **every activation hash in the corpus**,
    /// forcing `CONNECTOME-HASH/2` and invalidating PLX-89's cross-implementation
    /// agreement evidence, to buy nothing §4.6 asks for.
    ///
    /// Note `tag(3)` and `tag(4)` carry identical field lists. They differ only
    /// in the tag, and in what the hash *means*: a fold of a present subtree, or
    /// an advertisement of an absent one. That is exactly §5.2's distinction,
    /// and the tag is what keeps the two injective.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        match (&self.shape, &self.delivery) {
            (ChildShape::Single, ChildDelivery::Embedded { child }) => {
                e.tag(1);
                e.hash_ref(&child.hash);
            }
            (ChildShape::Single, ChildDelivery::Lazy { hash }) => {
                e.tag(2);
                e.text(&self.namespace);
                e.hash_ref(hash);
                e.opt_text(text_or_absent(&self.description));
            }
            (
                ChildShape::Indexed {
                    list_method,
                    search_method,
                    id_field,
                    path_template,
                },
                delivery,
            ) => {
                e.tag(match delivery {
                    ChildDelivery::Embedded { .. } => 3,
                    ChildDelivery::Lazy { .. } => 4,
                });
                e.text(&self.namespace);
                e.text(list_method);
                e.opt_text(search_method.as_deref());
                e.text(id_field);
                e.text(path_template);
                e.hash_ref(self.advertised_hash());
                e.opt_text(text_or_absent(&self.description));
            }
        }
    }

    fn recompute_hashes(&mut self) {
        if let ChildDelivery::Embedded { child } = &mut self.delivery {
            child.recompute_node_hashes();
        }
    }

    /// §3.3 — strip the root facts from an embedded node and everything under
    /// it.
    fn strip_root_facts(&mut self) {
        if let ChildDelivery::Embedded { child } = &mut self.delivery {
            child.strip_root_facts();
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
    ///
    /// A **root fact** (RFC 002 §3.3): `Some` on the document root, `None` on
    /// every embedded node, which §3.3 forbids from carrying it.
    /// [`recompute_hashes`](Self::recompute_hashes) establishes both halves.
    /// §3.5 does not apply — once present it is emitted even at its default,
    /// which is finding F-01's resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir_version: Option<u32>,

    /// The identifier of the hash construction that produced this document's
    /// hashes — RFC 002 §4.7, always [`HASH_ALGORITHM`](super::hash::HASH_ALGORITHM).
    ///
    /// A root fact. Without it, "hashed differently" and "changed" are
    /// indistinguishable and there is no migration path off a construction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,

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
    ///
    /// RFC 002 §3.5 — omitted from the wire when empty, never emitted as `""`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// The **request context** every method on this activation depends on
    /// unless it declares its own — RFC 002 §6.9.
    ///
    /// PLX-89 §2b: the IR rendering of `PluginSchema::request`, the
    /// activation-level `request = MyRequest` declaration whose schema carries
    /// the `x-plexus-source` annotations naming where each field is extracted
    /// from (cookie, header, query, peer address, auth context). A method's own
    /// [`MethodIr::request_context`] REPLACES this for that method; there is no
    /// merge, mirroring the override `MethodSchema::request_type` already is.
    ///
    /// Absent at both levels means the method depends on no transport-observable
    /// fact (§6.9: absence is "needs nothing", not "unspecified").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_context: Option<SchemaRef>,

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
            ir_version: None,
            hash_algorithm: None,
            backend_name: None,
            ir_hash: None,
            respond_method: None,
            namespace: namespace.into(),
            version: version.into(),
            description: String::new(),
            request_context: None,
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

    /// Declare the activation-level request context (RFC 002 §6.9).
    pub fn with_request_context(mut self, r: SchemaRef) -> Self {
        self.request_context = Some(r);
        self
    }

    /// The request context a method on this activation actually depends on —
    /// RFC 002 §6.9's resolution rule, in one place.
    ///
    /// The method's own declaration if it has one, otherwise this activation's,
    /// otherwise `None` meaning the method needs nothing. Resolution does NOT
    /// walk to ancestors: the declaration belongs to the activation that owns
    /// the method, mirroring `PluginSchema::request`.
    pub fn effective_request_context<'a>(&'a self, m: &'a MethodIr) -> Option<&'a SchemaRef> {
        m.request_context.as_ref().or(self.request_context.as_ref())
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
        // §3.3 — the root carries the document-level facts and no other node
        // may. Both halves are established here rather than trusted, so a
        // `Static` child built with the same builder as a root cannot smuggle a
        // root fact into an embedded position.
        if self.ir_version.is_none() {
            self.ir_version = Some(IR_VERSION);
        }
        // §4.7 — a document MUST declare the construction that produced its
        // hashes.
        self.hash_algorithm = Some(HASH_ALGORITHM.to_string());
        for c in &mut self.children {
            c.strip_root_facts();
        }

        self.recompute_node_hashes();
        self.ir_hash = Some(self.document_hash());
    }

    /// RFC 002 §4.6 — the document preimage:
    ///
    /// ```text
    /// document := SHA-256( domain("connectome/1:document")
    ///                    ‖ opt(hash_algorithm) ‖ opt(backend_name)
    ///                    ‖ opt(ir_version) ‖ opt(respond_method)
    ///                    ‖ hash(root activation hash) )
    /// ```
    ///
    /// The §3.3 root facts enter the *document* hash and not the *activation*
    /// hash. That is what keeps an activation's hash identical whether it is
    /// read as a root or as an embedded subtree — and therefore what makes a
    /// Static child's advertised hash comparable with the hash it reports when
    /// fetched on its own.
    pub fn document_hash(&self) -> String {
        let mut e = Encoder::with_domain(DOMAIN_DOCUMENT);
        e.opt_text(self.hash_algorithm.as_deref());
        e.opt_text(self.backend_name.as_deref());
        e.opt_u64(self.ir_version.map(u64::from));
        e.opt_text(self.respond_method.as_deref());
        e.hash_ref(&self.hash);
        e.digest()
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

    /// §3.3 — "non-root activations MUST NOT carry these".
    fn strip_root_facts(&mut self) {
        self.ir_version = None;
        self.hash_algorithm = None;
        self.ir_hash = None;
        self.backend_name = None;
        self.respond_method = None;
        for c in &mut self.children {
            c.strip_root_facts();
        }
    }

    /// This node's Merkle hash, computed from already-current method and child
    /// hashes without mutating anything.
    ///
    /// RFC 002 §4.6:
    ///
    /// ```text
    /// activation := SHA-256( domain("connectome/1:activation")
    ///                      ‖ text(namespace) ‖ text(version)
    ///                      ‖ opt(description) ‖ opt(long_description)
    ///                      ‖ declared(request_context)
    ///                      ‖ opt(deprecation)
    ///                      ‖ set(hash(method), methods)
    ///                      ‖ set(edge, children) )
    /// ```
    ///
    /// Methods and child edges are **sets** (§4.8): §3.7 makes a method's local
    /// name and a child's namespace unique within an activation, so both
    /// collections are keyed, and a keyed collection's declaration order is
    /// exactly the "non-canonical ordering" §4.4 forbids the hash from
    /// depending on. Methods and children contribute only their hashes, which is
    /// what makes this a Merkle fold rather than a full re-serialization.
    pub fn node_hash(&self) -> String {
        let mut e = Encoder::with_domain(DOMAIN_ACTIVATION);
        e.text(&self.namespace);
        e.text(&self.version);
        e.opt_text(text_or_absent(&self.description));
        e.opt_text(self.long_description.as_deref());
        encode_declared(&mut e, self.request_context.as_ref());
        e.opt_with(self.deprecation.is_some(), |e| {
            if let Some(d) = &self.deprecation {
                d.encode_into(e);
            }
        });
        e.set(&self.methods, |e, m| {
            e.hash_ref(&m.hash);
        });
        e.set(&self.children, |e, c| c.encode_into(e));
        e.digest()
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
