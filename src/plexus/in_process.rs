//! MACRO-2.B3 · the in-process transport.
//!
//! A [`plexus_client::Transport`] that dispatches straight into an
//! [`Activation`] — no socket, no server process, no runtime setup. It is
//! the test double for a generated client, and the transport an activation
//! author reaches for first.
//!
//! # Why it lives here and not in `plexus-client`
//!
//! `plexus-client` must build for `wasm32-unknown-unknown`, so it cannot
//! depend on `plexus-core`. The dependency only runs one way — `plexus-core
//! → plexus-client` — so the adapter that needs both lives on this side of
//! the seam. The other transports follow the same rule: each lives where its
//! dependencies do.
//!
//! # The error layers, preserved
//!
//! The three transports are meant to be interchangeable, which means they
//! must agree on *which layer* a failure belongs to:
//!
//! | Failure | Layer | Why |
//! |---|---|---|
//! | [`Activation::call`] returns `Err(PlexusError)` | transport | the request never produced a stream — unknown method, dispatch refused, scope gate denied. Same class as "the connection failed". |
//! | the stream contains a [`PlexusStreamItem::Error`] | in-band | the activation answered, and the answer is an error. |
//! | the [`MethodRef`]'s namespace is not this activation's | transport | nothing was dispatched. |
//!
//! Collapsing the first two would make this transport report a different
//! error layer than the wire ones for the same failure.
//!
//! # Not a way to skip the hub
//!
//! `DynamicHub` applies the scope gate, provenance and credential-envelope
//! assembly. This transport applies none of them: it is `Activation::call`
//! and nothing else. Reaching for it outside a test is a smell.

use futures::StreamExt;
use plexus_client::{ItemStream, MethodRef, StreamItem, StreamMetadata, Transport, TransportError};
use serde_json::Value;

use super::auth::AuthContext;
use super::plexus::Activation;
use super::types::PlexusStreamItem;

/// A [`Transport`] backed directly by one [`Activation`].
///
/// ```ignore
/// let client = TicketsClient::new(InProcessTransport::new(Tickets::new(store)));
/// let tickets = client.list_all(None, None).await?;
/// ```
#[derive(Debug, Clone)]
pub struct InProcessTransport<A> {
    activation: A,
    auth: Option<AuthContext>,
}

impl<A: Activation> InProcessTransport<A> {
    /// Dispatch anonymously.
    pub fn new(activation: A) -> Self {
        Self {
            activation,
            auth: None,
        }
    }

    /// Dispatch with an auth context attached to every call — the
    /// equivalent of a transport carrying a session cookie.
    pub fn with_auth(activation: A, auth: AuthContext) -> Self {
        Self {
            activation,
            auth: Some(auth),
        }
    }

    /// Borrow the activation, e.g. to assert on server-side state after a
    /// call.
    pub fn activation(&self) -> &A {
        &self.activation
    }
}

/// Translate the server envelope into the client one.
///
/// The client type is looser by design (see `plexus-client`'s
/// `envelope` module): every field the REST bridge drops is optional there.
/// In-process nothing is dropped, so every field is carried.
fn to_client_item(item: PlexusStreamItem) -> StreamItem {
    fn meta(m: super::types::StreamMetadata) -> Option<StreamMetadata> {
        Some(StreamMetadata {
            provenance: m.provenance,
            plexus_hash: m.plexus_hash,
            timestamp: m.timestamp,
        })
    }

    match item {
        PlexusStreamItem::Data {
            metadata,
            content_type,
            content,
        } => StreamItem::Data {
            metadata: meta(metadata),
            content_type: Some(content_type),
            content,
        },
        PlexusStreamItem::Progress {
            metadata,
            content_type,
            content,
        } => StreamItem::Progress {
            metadata: meta(metadata),
            content_type: Some(content_type),
            content,
        },
        PlexusStreamItem::Error {
            metadata,
            recoverable,
            error,
        } => StreamItem::Error {
            metadata: meta(metadata),
            recoverable,
            error,
        },
        PlexusStreamItem::Request {
            request_id,
            request_data,
            timeout_ms,
        } => StreamItem::Request {
            request_id,
            request_data,
            timeout_ms,
        },
        PlexusStreamItem::Done { metadata } => StreamItem::Done {
            metadata: meta(metadata),
        },
    }
}

impl<A: Activation> Transport for InProcessTransport<A> {
    fn call(&self, method: MethodRef, params: Value) -> ItemStream<'_> {
        // A `MethodRef` names an activation as well as a method. Dispatching
        // a `tickets.*` call into a `health` activation because the caller
        // wired the wrong client to the wrong transport must not silently
        // "work" for whichever method names happen to collide.
        if method.namespace() != self.activation.namespace() {
            let msg = format!(
                "InProcessTransport is bound to activation `{}`, but the call is for `{}`",
                self.activation.namespace(),
                method,
            );
            return Box::pin(futures::stream::once(async move {
                Err(TransportError::protocol(msg))
            }));
        }

        Box::pin(
            futures::stream::once(async move {
                match self
                    .activation
                    .call(method.method(), params, self.auth.as_ref(), None)
                    .await
                {
                    // `call` succeeded: the activation owns the outcome from
                    // here, including any in-band `error` item.
                    Ok(stream) => stream.map(|item| Ok(to_client_item(item))).left_stream(),
                    // `call` failed: nothing was answered.
                    Err(e) => futures::stream::once(async move {
                        Err(TransportError::other(e.to_string()))
                    })
                    .right_stream(),
                }
            })
            .flatten(),
        )
    }
}
