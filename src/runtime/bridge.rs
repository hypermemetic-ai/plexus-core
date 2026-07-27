//! The bridge to today's world (PLX-80 / M1·C requirement 5).
//!
//! The vNext runtime is additive: nothing in `plexus.rs` changed, the
//! [`Activation`] trait is untouched, and `DynamicHub` still routes exactly as
//! it did. This module is how the two meet — [`IrActivation`] wraps an
//! [`ActivationIr`] plus a [`HandlerTable`] and *is* an `Activation`, so a
//! turn-native service can be `DynamicHub::register`ed today, before the macro
//! switchover.
//!
//! This is the seam build F targets: the macro's job becomes emitting an
//! `ActivationIr` and a `Vec<(&'static str, ErasedHandler)>`, and this type
//! carries them into the existing hub with no template plumbing in between.
//!
//! # How a turn is projected onto `PlexusStreamItem`
//!
//! The legacy wire has no turn vocabulary, so the projection is stated once,
//! here, rather than guessed at by each consumer:
//!
//! | Turn event | Legacy item |
//! |---|---|
//! | [`TurnEvent::Update`] | `Data { content_type: "<dotted_id>.update" }` |
//! | [`TurnEvent::Callback`] | `Request { request_id: "<turn>:<seq>" }` |
//! | [`TurnEvent::Terminal`] | `Data { content_type: "<dotted_id>.terminal" }`, then `Done` |
//!
//! The terminal keeps its full [`StopReason`](crate::ir::StopReason) — including a
//! `Failed`'s structured error — inside the `Data` payload, so nothing is
//! flattened on the way down. A legacy client that understands only `Data` and
//! `Done` still sees a well-formed stream; one that reads `content_type` gets
//! the whole turn model.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;

use crate::ir::ActivationIr;
use crate::plexus::streaming::PlexusStream;
use crate::plexus::types::{PlexusStreamItem, StreamMetadata};
use crate::plexus::PlexusError;
use crate::request::RawRequestContext;
use crate::plexus::MethodEnumSchema;
use crate::Activation;

use super::callback::PeerCapabilities;
use super::entry::{entry, TurnControl, TurnHandle, TurnRequest};
use super::error::{EntryError, RespondError};
use super::event::TurnEvent;
use super::handler::HandlerTable;
use super::ids::{CallbackId, TurnId};

/// Timeout advertised on projected [`PlexusStreamItem::Request`] items.
///
/// The turn model has no per-callback deadline — a callback resolves when the
/// peer answers or when the turn is cancelled — but the legacy item's field is
/// not optional. Zero is the honest encoding of "no deadline is being
/// asserted"; a legacy client that treats it as an actual timeout would be
/// reading a promise this build does not make.
const NO_ADVERTISED_TIMEOUT_MS: u64 = 0;

// ===========================================================================
// The schema shim
// ===========================================================================

/// Stand-in for the `Activation::Methods` associated type.
///
/// The trait requires a `MethodEnumSchema`, whose only real consumer is
/// `schemars::schema_for!` in the hub's `schema()` path. PLX-73 recorded that
/// the generated method enum was *schema-only cargo* — never used for dispatch
/// — so an IR-backed activation, whose schemas live in the IR itself, supplies
/// an empty one rather than reconstructing a type it has no use for.
#[derive(Debug, Clone, Copy, schemars::JsonSchema)]
pub struct IrMethods;

impl MethodEnumSchema for IrMethods {
    fn method_names() -> &'static [&'static str] {
        &[]
    }

    fn schema_with_consts() -> Value {
        serde_json::to_value(schemars::schema_for!(IrMethods)).unwrap_or(Value::Null)
    }
}

// ===========================================================================
// IrActivation
// ===========================================================================

/// An [`ActivationIr`] plus its handler table, presented as an [`Activation`].
///
/// ```
/// use plexus_core::ir::{ActivationIr, AuthRequirementIr, MethodIr};
/// use plexus_core::runtime::{ErasedHandler, HandlerTable, IrActivation, TurnOutcome};
/// use plexus_core::Activation;
///
/// # tokio_test::block_on(async {
/// let ir = ActivationIr::new("greet", "1.0.0").with_method(
///     MethodIr::new("hello", "greet.hello").with_auth(AuthRequirementIr::Public),
/// );
/// let handlers = HandlerTable::new([(
///     "hello",
///     ErasedHandler::new(|_| async { TurnOutcome::serialize("hi") }),
/// )]);
///
/// let activation = IrActivation::new(ir, handlers);
/// assert_eq!(activation.namespace(), "greet");
/// assert_eq!(activation.methods(), vec!["hello"]);
/// # });
/// ```
#[derive(Clone)]
pub struct IrActivation {
    ir: Arc<ActivationIr>,
    handlers: Arc<HandlerTable>,
    peer: PeerCapabilities,
    /// Live turns, so a legacy `respond`-style method can reach a turn's
    /// control surface by id. Entries are removed when the turn resolves.
    live: Arc<Mutex<HashMap<TurnId, TurnControl>>>,
}

impl std::fmt::Debug for IrActivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrActivation")
            .field("namespace", &self.ir.namespace)
            .field("methods", &self.handlers.len())
            .field("peer", &self.peer)
            .finish()
    }
}

impl IrActivation {
    /// Wrap an IR and its handler table.
    pub fn new(ir: ActivationIr, handlers: impl Into<HandlerTable>) -> Self {
        Self {
            ir: Arc::new(ir),
            handlers: Arc::new(handlers.into()),
            peer: PeerCapabilities::all(),
            live: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Declare what the peer on the other end can serve, enabling the
    /// pre-flight capability check. See [`PeerCapabilities`].
    pub fn with_peer_capabilities(mut self, peer: PeerCapabilities) -> Self {
        self.peer = peer;
        self
    }

    /// The wrapped IR.
    pub fn ir(&self) -> &ActivationIr {
        &self.ir
    }

    /// The wrapped handler table.
    pub fn handlers(&self) -> &HandlerTable {
        &self.handlers
    }

    /// Open a turn directly, keeping the full turn surface.
    ///
    /// This is the seam build F and M2 use; [`Activation::call`] is the
    /// projection of it onto the legacy stream.
    pub fn open_turn(&self, mut request: TurnRequest) -> Result<TurnHandle, EntryError> {
        if request.peer.is_unrestricted() {
            request.peer = self.peer.clone();
        }
        let handle = entry(&self.ir, &self.handlers, request)?;
        self.live
            .lock()
            .expect("live turn registry poisoned")
            .insert(handle.turn_id(), handle.control());
        Ok(handle)
    }

    /// Answer a callback on one of this activation's live turns.
    ///
    /// The entry point a legacy `respond` method calls: the peer quotes the
    /// [`CallbackId`] it saw on the wire, and the turn it names is the turn it
    /// reaches — or [`RespondError::WrongTurn`] if the id has been tampered
    /// with.
    pub fn respond(&self, id: CallbackId, response: Value) -> Result<(), RespondError> {
        self.control_for(id.turn)?.respond(id, response)
    }

    /// Report that the peer could not serve a callback on a live turn.
    pub fn fail_callback(
        &self,
        id: CallbackId,
        message: impl Into<String>,
    ) -> Result<(), RespondError> {
        self.control_for(id.turn)?.fail_callback(id, message)
    }

    /// Cancel a live turn by id.
    pub fn cancel_turn(&self, turn: TurnId) -> Result<(), RespondError> {
        self.control_for(turn)?.cancel();
        Ok(())
    }

    /// How many turns are currently live.
    pub fn live_turns(&self) -> usize {
        self.live.lock().expect("live turn registry poisoned").len()
    }

    fn control_for(&self, turn: TurnId) -> Result<TurnControl, RespondError> {
        self.live
            .lock()
            .expect("live turn registry poisoned")
            .get(&turn)
            .cloned()
            .ok_or(RespondError::TurnEnded(turn))
    }
}

#[async_trait]
impl Activation for IrActivation {
    type Methods = IrMethods;

    fn namespace(&self) -> &str {
        &self.ir.namespace
    }

    fn version(&self) -> &str {
        &self.ir.version
    }

    fn description(&self) -> &str {
        &self.ir.description
    }

    fn long_description(&self) -> Option<&str> {
        self.ir.long_description.as_deref()
    }

    fn methods(&self) -> Vec<&str> {
        self.ir.methods.iter().map(|m| m.name.as_str()).collect()
    }

    fn method_help(&self, method: &str) -> Option<String> {
        self.ir
            .method(method)
            .map(|m| m.description.clone())
            .filter(|d| !d.is_empty())
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&plexus_auth_core::AuthContext>,
        raw_ctx: Option<&RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        let dotted = self
            .ir
            .method(method)
            .map(|m| m.dotted_id.clone())
            .unwrap_or_else(|| format!("{}.{}", self.ir.namespace, method));

        let request = TurnRequest {
            method: method.to_string(),
            params,
            auth: auth.cloned(),
            raw_ctx: raw_ctx.cloned(),
            peer: self.peer.clone(),
        };

        let handle = self.open_turn(request)?;
        let provenance = vec![self.ir.namespace.clone()];
        Ok(turn_stream_to_plexus_stream(
            dotted,
            provenance,
            handle,
            Some(self.live.clone()),
        ))
    }

    fn plugin_id(&self) -> uuid::Uuid {
        // Same derivation the trait's default uses, but keyed on the IR's own
        // namespace and major version so handles survive a minor bump.
        let major = self.ir.version.split('.').next().unwrap_or("0");
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            format!("{}@{}", self.ir.namespace, major).as_bytes(),
        )
    }

    /// PLX-142 — an IR-backed activation *is* its document, so this is the one
    /// override that needs no bridge at all.
    fn connectome_subtree(&self) -> Option<ActivationIr> {
        Some((*self.ir).clone())
    }

    fn into_rpc_methods(self) -> jsonrpsee::server::Methods {
        // An IR-backed activation is routed through `DynamicHub`, which calls
        // `Activation::call` directly; it registers no jsonrpsee methods of its
        // own. This is the same posture `DynamicHub` itself takes for children.
        jsonrpsee::server::Methods::new()
    }
}

/// `DynamicHub::register` requires a [`ChildRouter`] alongside
/// [`Activation`]. An IR-backed activation's children are
/// [`ChildEdge`](crate::ir::ChildEdge)s inside its own document, not separately
/// registered routers, so this implementation forwards `router_call` to
/// [`Activation::call`] and reports no children — the same posture a leaf
/// activation takes today. Descending into `ChildEdge`s is M2's concern, not
/// this build's, and pretending otherwise here would be inventing a routing
/// contract PLX-80 has not specified.
#[async_trait]
impl crate::plexus::ChildRouter for IrActivation {
    fn router_namespace(&self) -> &str {
        &self.ir.namespace
    }

    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&plexus_auth_core::AuthContext>,
        raw_ctx: Option<&RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, _name: &str) -> Option<Box<dyn crate::plexus::ChildRouter>> {
        None
    }
}

// ===========================================================================
// The projection
// ===========================================================================

/// Project a turn's event stream onto the legacy [`PlexusStream`].
///
/// Public because build F and M2 need the projection without necessarily
/// wanting [`IrActivation`]'s registry. See the module docs for the mapping
/// table.
pub fn turn_stream_to_plexus_stream(
    dotted_id: String,
    provenance: Vec<String>,
    handle: TurnHandle,
    live: Option<Arc<Mutex<HashMap<TurnId, TurnControl>>>>,
) -> PlexusStream {
    let plexus_hash = crate::plexus::context::PlexusContext::hash();
    let update_type = format!("{dotted_id}.update");
    let terminal_type = format!("{dotted_id}.terminal");
    let turn_id = handle.turn_id();

    let stream = handle.flat_map(move |event| {
        let meta = || StreamMetadata::new(provenance.clone(), plexus_hash.clone());
        let items: Vec<PlexusStreamItem> = match event {
            TurnEvent::Update { content, .. } => vec![PlexusStreamItem::Data {
                metadata: meta(),
                content_type: update_type.clone(),
                content,
            }],
            TurnEvent::Callback { id, name, request } => vec![PlexusStreamItem::Request {
                request_id: id.to_string(),
                request_data: serde_json::json!({ "callback": name, "request": request }),
                timeout_ms: NO_ADVERTISED_TIMEOUT_MS,
            }],
            TurnEvent::Terminal { stop, value, .. } => {
                if let Some(live) = &live {
                    live.lock()
                        .expect("live turn registry poisoned")
                        .remove(&turn_id);
                }
                let content = serde_json::json!({
                    "stop": stop,
                    "value": value,
                });
                vec![
                    PlexusStreamItem::Data {
                        metadata: meta(),
                        content_type: terminal_type.clone(),
                        content,
                    },
                    PlexusStreamItem::Done { metadata: meta() },
                ]
            }
        };
        futures::stream::iter(items)
    });

    Box::pin(stream)
}
