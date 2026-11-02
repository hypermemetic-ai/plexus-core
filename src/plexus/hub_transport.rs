//! LOCAL-6 · a whole hub, called in memory.
//!
//! A [`plexus_client::Transport`] over an `Arc<DynamicHub>`: a program that
//! imports a Plexus server as a crate (tether imports substrate) calls it
//! with the server's own generated client and no socket. Every call ends in
//! [`DynamicHub::route_with_ctx`] — the call a WebSocket ends in — so the
//! hub's routing to children, its grant gate, its roles and provenance apply
//! exactly as they do over the wire.
//!
//! # A caller, never a skipped gate
//!
//! The transport carries an [`AuthContext`]: the embedding program's
//! identity, or the agent a call acts for ([`HubTransport::as_`]). Without
//! one ([`HubTransport::anonymous`]) a call is the anonymous one, which a
//! gated hub holds to its anonymous view — nothing more than a socket with
//! no credential reaches.
//!
//! # The error layers, as the wire has them
//!
//! | Failure | Layer | Why |
//! |---|---|---|
//! | `route_with_ctx` returns `Err(PlexusError)` — unknown activation or method, the gate's refusal | in-band: one `error` item ([`error_item`](super::plexus::error_item)), then the end | it is what `{hub}.call` sends over the WebSocket, so the same client code sees the same answer over either |
//! | the stream contains a [`PlexusStreamItem::Error`](super::types::PlexusStreamItem::Error) | in-band | the activation answered, and the answer is an error |
//!
//! [`InProcessTransport`](super::InProcessTransport) reports a dispatch
//! failure at the transport layer instead; it has no hub, and nothing on
//! the wire to agree with.
//!
//! # Streams
//!
//! The hub's stream is the client's: a long one streams through item by
//! item, and dropping the client's stream drops the hub's.

use std::sync::Arc;

use futures::StreamExt;
use plexus_client::{ItemStream, MethodRef, StreamItem, Transport, TransportError};
use serde_json::Value;

use super::auth::AuthContext;
use super::in_process::to_client_item;
use super::plexus::{error_item, DynamicHub, PlexusError};

/// A [`Transport`] into a whole [`DynamicHub`], as one caller.
///
/// ```ignore
/// let hub = plexus_substrate::build_plexus_rpc_with(opts).await;
/// let client = ClaudecodeClient::new(HubTransport::as_(hub, tether_identity));
/// let sessions = client.list().await?;
/// ```
#[derive(Clone)]
pub struct HubTransport {
    hub: Arc<DynamicHub>,
    auth: Option<AuthContext>,
}

impl std::fmt::Debug for HubTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubTransport")
            .field("hub", &self.hub.runtime_namespace())
            .field("caller", &self.auth.as_ref().map(|a| a.user_id.as_str()))
            .finish()
    }
}

impl HubTransport {
    /// Call `hub` as `caller` — every call carries it to the gate, as a
    /// signed-in socket carries its session.
    pub fn as_(hub: Arc<DynamicHub>, caller: AuthContext) -> Self {
        Self { hub, auth: Some(caller) }
    }

    /// Call `hub` with no identity: what a gated hub admits anonymously,
    /// and nothing else.
    pub fn anonymous(hub: Arc<DynamicHub>) -> Self {
        Self { hub, auth: None }
    }

    /// The hub this transport calls.
    pub fn hub(&self) -> &Arc<DynamicHub> {
        &self.hub
    }

    /// The caller every call carries, if any.
    pub fn caller(&self) -> Option<&AuthContext> {
        self.auth.as_ref()
    }
}

/// The `error` item `{hub}.call` sends for a dispatch that failed.
fn refused(ns: &str, e: &PlexusError) -> StreamItem {
    serde_json::from_value(error_item(ns, e)).unwrap_or_else(|_| StreamItem::Error {
        metadata: None,
        recoverable: false,
        message: Some(e.to_string()),
        code: None,
        error: plexus_client::RemoteError::from(e),
        fields: Default::default(),
    })
}

impl Transport for HubTransport {
    fn call(&self, method: MethodRef, params: Value) -> ItemStream<'_> {
        let hub = self.hub.clone();
        let auth = self.auth.clone();
        Box::pin(
            futures::stream::once(async move {
                // The hub's own `call` takes the dotted path; a child's
                // method is `tickets.inputs.answer` (MACRO-16).
                match hub.route_with_ctx(&method.qualified(), params, auth.as_ref(), None).await {
                    Ok(stream) => stream.map(|item| Ok::<_, TransportError>(to_client_item(item))).left_stream(),
                    Err(e) => {
                        let item = refused(hub.runtime_namespace(), &e);
                        futures::stream::once(async move { Ok(item) }).right_stream()
                    }
                }
            })
            .flatten(),
        )
    }
}
