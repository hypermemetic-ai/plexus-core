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

/// The seam PLX-77 left open and PLX-80 filled: JSON-in/JSON-out delivery of
/// one server-to-client request.
///
/// # The two halves, and why there are two
///
/// [`call`](Self::call) is PLX-77's original synchronous seam. It is unchanged:
/// every existing implementation, every `Client<C>` accessor built on it, and
/// the trybuild fixtures that pin the compile-time capability gating keep
/// working byte for byte.
///
/// [`call_async`](Self::call_async) is PLX-80's addition, and it is the shape
/// real turn-scoped delivery needs — a callback *awaits* a correlated response
/// that arrives on the turn's event stream, and there is no way to serve that
/// from a `fn -> Result<..>` except by blocking a runtime worker. It has a
/// default implementation that delegates to `call`, so a transport that really
/// is synchronous (an in-memory test double, a stub) implements one method and
/// gets both. `plexus_core::runtime::TurnTransport` overrides it.
///
/// The alternative — making the whole trait and every `Client<C>` accessor
/// async — was rejected because it would have changed a compile-time surface
/// that PLX-77/78 deliberately pinned with `.stderr` fixtures, for no gain
/// beyond a nicer method name.
pub trait CallbackTransport: Send + Sync + 'static {
    /// Issue one server-to-client request and return its response.
    fn call(
        &self,
        callback: &CallbackIr,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, String>;

    /// Issue one server-to-client request and **await** its response.
    ///
    /// The default delegates to [`call`](Self::call), which is correct for any
    /// transport that can answer without waiting.
    fn call_async<'a>(
        &'a self,
        callback: &'a CallbackIr,
        request: serde_json::Value,
    ) -> futures::future::BoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(async move { self.call(callback, request) })
    }
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

    /// The awaiting twin of [`issue`](Self::issue) — identical encode/decode,
    /// identical error mapping, delivery through
    /// [`CallbackTransport::call_async`].
    async fn issue_async<M, Req, Resp>(&self, request: Req) -> Result<Resp, CallbackError>
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

        let descriptor = M::descriptor();
        let raw = transport
            .call_async(&descriptor, payload)
            .await
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

// ===========================================================================
// The awaiting accessors (PLX-80)
// ===========================================================================
//
// One per capability, carrying **exactly** the `Has<M, I>` bound its
// synchronous twin carries. The capability typing is therefore identical: an
// undeclared capability has no accessor in either flavour, and PLX-78's
// duplicate-set assertion is forced on both.
//
// The `_async` suffix is a wart, and a deliberate one: the synchronous names
// are load-bearing for PLX-77/78's compile-fail fixtures, so renaming or
// re-signaturing them would have meant editing tests this build is required to
// leave unmodified. See `CallbackTransport` for the full reasoning.

impl<C> Client<C> {
    /// Ask the client to approve an operation, awaiting its answer.
    ///
    /// Requires [`Permission`] in `C`. This is the accessor a turn-scoped
    /// handler uses; see [`crate::runtime`].
    pub async fn request_permission_async<I>(
        &self,
        request: PermissionRequest,
    ) -> Result<PermissionOutcome, CallbackError>
    where
        C: Has<Permission, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue_async::<Permission, _, _>(request).await
    }

    /// Read a text file through the client, awaiting the content.
    ///
    /// Requires [`FsRead`] in `C`.
    pub async fn fs_read_async<I>(
        &self,
        request: FsReadRequest,
    ) -> Result<FsReadResponse, CallbackError>
    where
        C: Has<FsRead, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue_async::<FsRead, _, _>(request).await
    }

    /// Write a text file through the client, awaiting acknowledgement.
    ///
    /// Requires [`FsWrite`] in `C`.
    pub async fn fs_write_async<I>(
        &self,
        request: FsWriteRequest,
    ) -> Result<FsWriteResponse, CallbackError>
    where
        C: Has<FsWrite, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue_async::<FsWrite, _, _>(request).await
    }

    /// Create a terminal on the client, awaiting its handle.
    ///
    /// Requires [`Terminal`] in `C`.
    pub async fn terminal_create_async<I>(
        &self,
        request: TerminalCreateRequest,
    ) -> Result<TerminalCreateResponse, CallbackError>
    where
        C: Has<Terminal, I>,
    {
        let () = Self::NO_DUPLICATES;
        self.issue_async::<Terminal, _, _>(request).await
    }
}

// ===========================================================================
// The protocol-typed accessor (PLX-137)
// ===========================================================================

impl<C> Client<C> {
    /// Issue the callback that capability `M` names, carrying a **protocol's
    /// own** request and response types instead of `M`'s built-in payloads.
    ///
    /// # Why this exists
    ///
    /// A capability marker's identity is its **wire name** — that is stated in
    /// [`Capability::NAME`]'s own docs, and it is what the duplicate check and
    /// the peer pre-flight both key on. Its payload structs
    /// ([`PermissionRequest`], [`FsReadRequest`], …) are this crate's minimum
    /// shape for that wire name; they were written before any protocol
    /// vocabulary existed and they are deliberately small.
    ///
    /// A protocol crate that owns the *real* vocabulary for the same wire name
    /// needs to send it. `plexus-acp` is the motivating case: ACP's
    /// `session/request_permission` carries a tool call and a list of
    /// selectable options, and its response is an option **id**, none of which
    /// fits [`PermissionOutcome`]'s `Allow`/`Deny`. Projecting ACP onto that
    /// shape would lose the option id, and inventing a second permission model
    /// in `plexus-acp` is the failure PLX-135 records as already deleted three
    /// times.
    ///
    /// # What this does NOT relax
    ///
    /// The gate. `C: Has<M, I>` is character-for-character the bound the
    /// built-in accessors carry, [`Capability`] is sealed so `M` can only be
    /// one of this crate's markers, and `NO_DUPLICATES` is forced here as
    /// everywhere else. A handler still cannot reach a capability its method
    /// did not declare, and the wire name still comes from `M::descriptor()`
    /// rather than from the caller.
    ///
    /// # The residual, stated rather than hidden
    ///
    /// [`CallbackIr`]'s *schemas* still come from `M::descriptor()`, so a
    /// method using this accessor advertises `M`'s built-in schema in the IR
    /// while putting the protocol's shape on the wire. The **name** cannot
    /// disagree; the **schema** can. Closing that needs per-declaration schema
    /// override on `CallbackIr`, which is a change to what an activation
    /// advertises and is not in PLX-137's scope. `plexus-acp` pins the
    /// disagreement with a test so it is recorded, not discovered.
    ///
    /// ```
    /// use plexus_core::capability::{Client, Permission};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize)]
    /// struct AcpShapedRequest { session_id: String, options: Vec<String> }
    /// #[derive(Deserialize, Debug)]
    /// struct AcpShapedResponse { outcome: String }
    ///
    /// # tokio_test::block_on(async {
    /// let client = Client::<(Permission,)>::unwired();
    /// let out: Result<AcpShapedResponse, _> = client
    ///     .issue_as_async::<Permission, _, _, _>(AcpShapedRequest {
    ///         session_id: "s1".into(),
    ///         options: vec!["allow".into()],
    ///     })
    ///     .await;
    /// // Unwired, so it reports rather than panics — and it reports under the
    /// // marker's wire name, which is the identity this accessor preserves.
    /// assert!(format!("{}", out.unwrap_err()).contains("session/request_permission"));
    /// # });
    /// ```
    pub async fn issue_as_async<M, I, Req, Resp>(
        &self,
        request: Req,
    ) -> Result<Resp, CallbackError>
    where
        C: Has<M, I>,
        M: Capability,
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let () = Self::NO_DUPLICATES;
        self.issue_async::<M, _, _>(request).await
    }
}
