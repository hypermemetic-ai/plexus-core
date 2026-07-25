//! `Client<C>` — the typed capability handle.

use std::marker::PhantomData;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::ir::CallbackIr;

use super::markers::{
    Capability, FsRead, FsReadRequest, FsReadResponse, FsWrite, FsWriteRequest, FsWriteResponse,
    Permission, PermissionOutcome, PermissionRequest, Terminal, TerminalCreateRequest,
    TerminalCreateResponse,
};
use super::set::{has_duplicate_names, CapabilitySet, Has};

/// Why a callback could not be completed.
///
/// Deliberately small: PLX-77 defines the *typing* of callbacks, not their
/// transport. Build C replaces [`CallbackError::NotWired`] with real
/// correlation and delivery.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallbackError {
    /// The handle has no transport installed.
    ///
    /// This is the state every `Client` built by this crate is in today —
    /// PLX-77 ships the type system, build C ships the wire. It is an ordinary
    /// `Err`, never a panic: an unwired handle must not be able to take a
    /// process down.
    #[error("callback `{0}` was invoked on a handle with no transport installed (PLX-77 ships the typing; transport lands in build C)")]
    NotWired(&'static str),

    /// The request could not be encoded, or the response could not be decoded.
    #[error("callback `{callback}` payload could not be converted: {message}")]
    Payload {
        /// Wire name of the callback.
        callback: &'static str,
        /// What went wrong.
        message: String,
    },

    /// The transport reported a failure.
    #[error("callback `{callback}` failed in transport: {message}")]
    Transport {
        /// Wire name of the callback.
        callback: &'static str,
        /// What the transport said.
        message: String,
    },
}

/// The seam a later build fills in with real server-to-client correlation.
///
/// Intentionally JSON-in/JSON-out and intentionally *not* async: PLX-77 must
/// not decide the async shape of callback delivery, which belongs to build C
/// along with the turn's cancellation token. Nothing in this crate implements
/// it — `Client` works, and gates correctly, with no transport at all.
pub trait CallbackTransport: Send + Sync + 'static {
    /// Issue one server-to-client request and return its response.
    fn call(
        &self,
        callback: &CallbackIr,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// The injected handle through which a method issues server-to-client requests.
///
/// # The handle's type IS the declaration
///
/// ```text
/// async fn prompt(&self, req: PromptRequest, client: Client<(Permission, FsRead)>) -> ...
/// ```
///
/// `C` is a tuple of capability markers. Two things follow *by construction*,
/// not by discipline:
///
/// 1. **Only declared capabilities are callable.** `client.fs_write(..)` on
///    that signature does not compile — [`FsWrite`] is not in `C`. See
///    [`Has`](super::set::Has) for the encoding.
/// 2. **The declaration is derived from the same `C`.**
///    [`Client::callbacks`] returns exactly `C`'s
///    [`CallbackIr`]s, which is what a later build writes into
///    [`crate::ir::MethodIr::callbacks`]. There is no second, hand-maintained
///    attribute list to drift out of sync with what the body actually calls.
///
/// The union of those declarations across the IR is what a service advertises,
/// which is what turns "peer cannot serve `fs/write_text_file`" into a
/// pre-flight rejection instead of a mid-turn surprise.
///
/// # What is real here and what is not
///
/// The **typing** is real: which accessors exist for which `C`, and the
/// `C -> Vec<CallbackIr>` derivation. The **transport** is not: without a
/// [`CallbackTransport`] every accessor returns
/// [`CallbackError::NotWired`]. Build C supplies the wire.
pub struct Client<C> {
    transport: Option<Arc<dyn CallbackTransport>>,
    /// `fn() -> C` rather than `C`: the handle is covariant in `C` and imposes
    /// no `Send`/`Sync`/drop obligations from the marker tuple.
    _set: PhantomData<fn() -> C>,
}

impl<C> Clone for Client<C> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            _set: PhantomData,
        }
    }
}

impl<C> std::fmt::Debug for Client<C>
where
    C: CapabilitySet,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("capabilities", &C::names())
            .field("wired", &self.transport.is_some())
            .finish()
    }
}

impl<C: CapabilitySet> Default for Client<C> {
    fn default() -> Self {
        Self::unwired()
    }
}

impl<C: CapabilitySet> Client<C> {
    /// A capability set is a **set**: each capability at most once.
    ///
    /// This const is `()` for every well-formed `C` and *fails to evaluate*
    /// for a `C` that lists the same marker twice. Every path that uses a set
    /// — [`unwired`](Self::unwired), [`new`](Self::new),
    /// [`callbacks`](Self::callbacks), [`capability_names`](Self::capability_names),
    /// and every gated accessor — forces it with `let () = Self::NO_DUPLICATES;`,
    /// so `Client<(FsRead, FsRead)>` is rejected at the first place an author
    /// touches it, with a message that names the actual mistake.
    ///
    /// Without it, `Client<(FsRead, FsRead)>` still failed — two [`Has`] impls
    /// match, so the position index is ambiguous — but it failed talking about
    /// type inference (PLX-77 residual #3).
    ///
    /// It is `pub` so it can be forced deliberately (`let () =
    /// Client::<C>::NO_DUPLICATES;`) at a site of one's choosing; its value
    /// carries no information.
    pub const NO_DUPLICATES: () = assert!(
        !has_duplicate_names(C::NAMES),
        "duplicate capability: this Client's capability set lists the same capability more than once. A capability set is a set — each capability may appear at most once in the tuple (e.g. write Client<(FsRead,)>, not Client<(FsRead, FsRead)>)."
    );

    /// A handle with no transport. Every accessor returns
    /// [`CallbackError::NotWired`]; the *typing* is unaffected, which is the
    /// only thing PLX-77 claims.
    pub fn unwired() -> Self {
        let () = Self::NO_DUPLICATES;
        Self {
            transport: None,
            _set: PhantomData,
        }
    }

    /// A handle backed by a transport.
    pub fn new(transport: Arc<dyn CallbackTransport>) -> Self {
        let () = Self::NO_DUPLICATES;
        Self {
            transport: Some(transport),
            _set: PhantomData,
        }
    }

    /// Whether a transport is installed.
    pub fn is_wired(&self) -> bool {
        self.transport.is_some()
    }

    /// Issue one callback. Private: the only way in is a typed accessor, and
    /// each accessor carries the `Has` bound that gates it.
    fn issue<M, Req, Resp>(&self, request: Req) -> Result<Resp, CallbackError>
    where
        M: Capability,
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let transport = self
            .transport
            .as_ref()
            .ok_or(CallbackError::NotWired(M::NAME))?;

        let payload = serde_json::to_value(request).map_err(|e| CallbackError::Payload {
            callback: M::NAME,
            message: e.to_string(),
        })?;

        let raw = transport
            .call(&M::descriptor(), payload)
            .map_err(|message| CallbackError::Transport {
                callback: M::NAME,
                message,
            })?;

        serde_json::from_value(raw).map_err(|e| CallbackError::Payload {
            callback: M::NAME,
            message: e.to_string(),
        })
    }
}

impl<C: CapabilitySet> Client<C> {
    /// The [`CallbackIr`] set this handle declares — the bridge a later build
    /// uses to populate [`crate::ir::MethodIr::callbacks`] from a signature.
    ///
    /// Same names and schemas the markers declare, in `C`'s declaration order.
    /// `Client<()>::callbacks()` is empty.
    pub fn callbacks() -> Vec<CallbackIr> {
        let () = Self::NO_DUPLICATES;
        C::callbacks()
    }

    /// The wire names this handle declares, in declaration order.
    pub fn capability_names() -> Vec<&'static str> {
        let () = Self::NO_DUPLICATES;
        C::names()
    }
}

// ===========================================================================
// The gated accessors
// ===========================================================================
//
// Each is generic over the position index `I`, which rustc infers. The bound
// `C: Has<M, I>` is the entire membership gate: no impl, no method.

impl<C> Client<C> {
    /// Ask the client to approve an operation.
    ///
    /// Requires [`Permission`] in `C`.
    pub fn request_permission<I>(
        &self,
        request: PermissionRequest,
    ) -> Result<PermissionOutcome, CallbackError>
    where
        C: Has<Permission, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue::<Permission, _, _>(request)
    }

    /// Read a text file through the client.
    ///
    /// Requires [`FsRead`] in `C`.
    pub fn fs_read<I>(&self, request: FsReadRequest) -> Result<FsReadResponse, CallbackError>
    where
        C: Has<FsRead, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue::<FsRead, _, _>(request)
    }

    /// Write a text file through the client.
    ///
    /// Requires [`FsWrite`] in `C`.
    pub fn fs_write<I>(&self, request: FsWriteRequest) -> Result<FsWriteResponse, CallbackError>
    where
        C: Has<FsWrite, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue::<FsWrite, _, _>(request)
    }

    /// Create a terminal on the client.
    ///
    /// Requires [`Terminal`] in `C`.
    pub fn terminal_create<I>(
        &self,
        request: TerminalCreateRequest,
    ) -> Result<TerminalCreateResponse, CallbackError>
    where
        C: Has<Terminal, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue::<Terminal, _, _>(request)
    }
}
