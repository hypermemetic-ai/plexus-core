//! The declared capability set, carried in the type (PLX-102).
//!
//! # The seam this closes
//!
//! PLX-77 and PLX-78 made *declaration equals use* true by construction: a
//! capability that is not in `C` has no accessor on `Client<C>`
//! ([`Has<M, I>`](crate::capability::Has)), a marker cannot be invented outside
//! the crate (the sealed trait), and a malformed set fails to compile with a
//! message that names the mistake (the `NO_DUPLICATES` const assertion).
//!
//! One place was left true by *comment*. `TurnContext` used to expose
//!
//! ```text
//! pub fn client<C: CapabilitySet>(&self) -> Client<C>
//! ```
//!
//! with `C` entirely free, and a doc comment arguing that the guarantee
//! survived because "the handler asks for exactly the capability set its method
//! signature declares". That is a description of intended usage, not a
//! constraint: a handler serving a method that declared `(FsRead,)` could write
//! `turn.client::<(FsWrite,)>()` and receive a working `FsWrite` accessor. The
//! callback then failed at the transport — the runtime pre-flight had checked
//! the peer against [`MethodIr::callbacks`], which never listed
//! `fs/write_text_file` — so this was a guarantee gap rather than a hole in the
//! permission model. But it failed at *runtime*, which is precisely what the
//! surrounding design exists to prevent.
//!
//! # The fix: one `C`, two artifacts
//!
//! A handler and the method IR it serves are now built from a single type
//! parameter, at a single site:
//!
//! ```
//! use plexus_core::capability::{Permission, PermissionRequest};
//! use plexus_core::ir::MethodIr;
//! use plexus_core::runtime::{DeclaredHandler, HandlerTable, TurnOutcome};
//!
//! // ONE `C`. It becomes the method's declaration *and* the handler's client.
//! let ask = DeclaredHandler::new::<(Permission,), _, _>(|input| async move {
//!     let client = input.turn.client(); // `Client<(Permission,)>`, inferred
//!     let outcome = client
//!         .request_permission_async(PermissionRequest {
//!             operation: "fs/write_text_file".into(),
//!             rationale: None,
//!         })
//!         .await;
//!     let _ = outcome;
//!     Ok(TurnOutcome::complete())
//! });
//!
//! // The IR declaration is derived from the same `C`, not written again.
//! let method = ask.declare(MethodIr::new("ask", "fixture.ask"));
//! assert_eq!(method.callbacks.len(), 1);
//! assert_eq!(method.callbacks[0].name, "session/request_permission");
//!
//! let handlers = HandlerTable::new([("ask", ask.into_handler())]);
//! # let _ = handlers;
//! ```
//!
//! Inside the closure, `input.turn` is a [`Turn<C>`] rather than a bare
//! [`TurnContext`], and [`Turn::client`] is bound by
//! [`Declares`](crate::capability::Declares) — an identity relation with
//! exactly one blanket impl. Two consequences, both by construction:
//!
//! 1. **`C` is inferred.** `turn.client()` needs no turbofish; the declared set
//!    is the only set that satisfies the bound.
//! 2. **Widening does not compile.** `turn.client::<(FsWrite,)>()` on a handler
//!    declared `(FsRead,)` fails with a message naming both sets. Pinned by
//!    `tests/ui/widened_capability_set.rs`, in the same style as PLX-77's and
//!    PLX-78's goldens.
//!
//! [`TurnContext`] itself no longer mints clients at all. That is the load-
//! bearing half: had the free accessor been left in place beside this one, a
//! handler could simply have kept using it, and the guarantee would have gone
//! back to being a matter of which constructor an author happened to pick. A
//! handler that declares nothing can now call nothing.
//!
//! # What is still convention, stated plainly
//!
//! [`DeclaredHandler::declare`] is what stamps the derived
//! [`CallbackIr`]s onto the method IR, and nothing in the type system *forces*
//! a registration to call it — an author may still build a `MethodIr` by hand
//! and register the handler beside it. What changed is the size of the
//! discipline: it went from "keep two independently written capability sets in
//! agreement, forever, in every handler body" to "pass the method IR through
//! `declare` once at registration". Closing the remainder means having the
//! registration surface (`ActivationIr` / `HandlerTable`) take a
//! `DeclaredHandler` and stamp the IR itself, which is a change to how every
//! activation is assembled and is deliberately out of this build's scope.

use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use serde_json::Value;

use crate::capability::{CapabilitySet, Client, Declares};
use crate::ir::{CallbackIr, MethodIr};

use super::error::TurnError;
use super::handler::{ErasedHandler, HandlerInput, TurnContext, TurnOutcome};

// ===========================================================================
// Turn<C>
// ===========================================================================

/// A [`TurnContext`] that knows, in its type, which capability set its method
/// declared.
///
/// Everything a [`TurnContext`] offers is available through [`Deref`] — turn
/// id, method IR, auth, cancellation, `emit`. The one thing that is *added* is
/// [`client`](Self::client), and the one thing that is *not* available anywhere
/// else is minting a capability handle.
///
/// Only [`DeclaredHandler`] constructs one, and it does so with the same `C`
/// that produced the method's declared callbacks.
pub struct Turn<C: CapabilitySet> {
    ctx: TurnContext,
    /// `fn() -> C` for the same reason [`Client`] uses it: covariance, and no
    /// `Send`/`Sync`/drop obligations inherited from the marker tuple.
    _declared: PhantomData<fn() -> C>,
}

impl<C: CapabilitySet> Clone for Turn<C> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            _declared: PhantomData,
        }
    }
}

impl<C: CapabilitySet> std::fmt::Debug for Turn<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Turn")
            .field("declares", &C::NAMES)
            .field("turn", &self.ctx)
            .finish()
    }
}

impl<C: CapabilitySet> Turn<C> {
    pub(crate) fn new(ctx: TurnContext) -> Self {
        Self {
            ctx,
            _declared: PhantomData,
        }
    }

    /// PLX-146 — the generated-dispatch seam. **Not public API; call
    /// [`DeclaredHandler`] instead.**
    ///
    /// This is deliberately *not* the free `TurnContext::client::<C>()` that
    /// the module header (see "Why the free minter went away") records as
    /// removed. There, `C` was chosen by the caller with nothing tying it to
    /// what the method declared, so a handler could mint a capability its IR
    /// never advertised. Here `C` is not free either: a
    /// `#[plexus_macros::activation]` reads it out of the method's
    /// `client: Client<C>` parameter, and **the same `C` tokens** are what
    /// `ir_parse` turns into `MethodIr::callbacks` — one signature, one source,
    /// so the minted handle and the declared callbacks cannot disagree.
    ///
    /// The invariant is therefore held by the macro rather than by this
    /// function, which is why it is `#[doc(hidden)]` and why hand-written
    /// handlers must keep going through [`DeclaredHandler`].
    #[doc(hidden)]
    pub fn __declared_by_macro(ctx: TurnContext) -> Self {
        Self::new(ctx)
    }

    /// A capability handle wired to this turn's callback transport.
    ///
    /// `D` is not free: [`Declares`] has exactly one impl — the identity — so
    /// `D` is *inferred* to be the declared set `C`, and naming any other set
    /// is a compile error rather than a runtime transport failure. This is the
    /// whole of PLX-102. (See [`Declares`] for why the bound is written
    /// `C: Declares<D>` and not `D: DeclaredAs<C>`: only this direction
    /// infers.)
    ///
    /// ```compile_fail
    /// # use plexus_core::capability::{FsRead, FsWrite};
    /// # use plexus_core::runtime::{DeclaredHandler, TurnOutcome};
    /// let h = DeclaredHandler::new::<(FsRead,), _, _>(|input| async move {
    ///     // The method declared `(FsRead,)`; this asks for something else.
    ///     let _widened = input.turn.client::<(FsWrite,)>();
    ///     Ok(TurnOutcome::complete())
    /// });
    /// ```
    ///
    /// Use the `*_async` accessors — see
    /// [`CallbackTransport`](crate::capability::CallbackTransport) for why the
    /// synchronous ones cannot serve a correlated response.
    pub fn client<D>(&self) -> Client<D>
    where
        D: CapabilitySet,
        C: Declares<D>,
    {
        Client::new(self.ctx.transport())
    }

    /// The wire names this turn's method declared, in declaration order.
    pub fn declared_capabilities(&self) -> &'static [&'static str] {
        C::NAMES
    }

    /// The untyped turn, for code that does not mint capability handles.
    pub fn context(&self) -> &TurnContext {
        &self.ctx
    }

    /// Consume the typed view, keeping the turn.
    pub fn into_context(self) -> TurnContext {
        self.ctx
    }
}

impl<C: CapabilitySet> Deref for Turn<C> {
    type Target = TurnContext;

    fn deref(&self) -> &TurnContext {
        &self.ctx
    }
}

// ===========================================================================
// CapabilityInput<C>
// ===========================================================================

/// What a capability-declaring handler is handed: [`HandlerInput`] with the
/// declared set carried in the turn's type.
#[derive(Debug)]
pub struct CapabilityInput<C: CapabilitySet> {
    /// The raw params, still undecoded — identical to
    /// [`HandlerInput::params`].
    pub params: Value,
    /// The turn, typed by the capability set the method declared.
    pub turn: Turn<C>,
}

impl<C: CapabilitySet> CapabilityInput<C> {
    fn from_erased(input: HandlerInput) -> Self {
        Self {
            params: input.params,
            turn: Turn::new(input.turn),
        }
    }
}

// ===========================================================================
// DeclaredHandler
// ===========================================================================

/// A handler plus the capability declaration of the method it serves — both
/// derived from one `C`.
///
/// See the [module docs](self) for why the pairing exists. `S` is the
/// activation state, exactly as on [`ErasedHandler`], and defaults to `()`.
pub struct DeclaredHandler<S = ()> {
    handler: ErasedHandler<S>,
    callbacks: Vec<CallbackIr>,
    names: Vec<&'static str>,
}

impl<S> Clone for DeclaredHandler<S> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            callbacks: self.callbacks.clone(),
            names: self.names.clone(),
        }
    }
}

impl<S> std::fmt::Debug for DeclaredHandler<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclaredHandler")
            .field("declares", &self.names)
            .finish()
    }
}

impl DeclaredHandler<()> {
    /// Declare a capability set and write the handler that uses it.
    ///
    /// ```
    /// use plexus_core::capability::{FsRead, FsReadRequest};
    /// use plexus_core::runtime::{DeclaredHandler, TurnOutcome};
    ///
    /// let read = DeclaredHandler::new::<(FsRead,), _, _>(|input| async move {
    ///     let client = input.turn.client();
    ///     let _ = client.fs_read_async(FsReadRequest { path: "/etc/hosts".into() }).await;
    ///     Ok(TurnOutcome::complete())
    /// });
    /// assert_eq!(read.capability_names(), ["fs/read_text_file"]);
    /// ```
    pub fn new<C, F, Fut>(f: F) -> Self
    where
        C: CapabilitySet,
        F: Fn(CapabilityInput<C>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TurnOutcome, TurnError>> + Send + 'static,
    {
        Self {
            handler: ErasedHandler::new(move |input: HandlerInput| {
                f(CapabilityInput::<C>::from_erased(input))
            }),
            callbacks: C::callbacks(),
            names: C::names(),
        }
    }
}

impl<S: Send + Sync + 'static> DeclaredHandler<S> {
    /// The [`ErasedHandler::stateful`] twin: the closure is handed the
    /// activation's state as a parameter, so it captures nothing and can be
    /// built inside `&self` methods (PLX-97).
    pub fn stateful<C, F, Fut>(f: F) -> Self
    where
        C: CapabilitySet,
        F: Fn(Arc<S>, CapabilityInput<C>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TurnOutcome, TurnError>> + Send + 'static,
    {
        Self {
            handler: ErasedHandler::<S>::stateful(move |state, input: HandlerInput| {
                f(state, CapabilityInput::<C>::from_erased(input))
            }),
            callbacks: C::callbacks(),
            names: C::names(),
        }
    }
}

impl<S> DeclaredHandler<S> {
    /// The [`CallbackIr`]s the declared set derives — what
    /// [`MethodIr::callbacks`] must contain for this handler's callbacks to
    /// survive the runtime's pre-flight check against the peer.
    pub fn callbacks(&self) -> &[CallbackIr] {
        &self.callbacks
    }

    /// The declared wire names, in declaration order.
    pub fn capability_names(&self) -> &[&'static str] {
        &self.names
    }

    /// Stamp the declaration onto a method IR.
    ///
    /// The point of the pairing: the IR's callbacks are *derived from the same
    /// `C`* as the handler's `Client<C>`, rather than written a second time
    /// beside it.
    pub fn declare(&self, method: MethodIr) -> MethodIr {
        method.with_callbacks(self.callbacks.iter().cloned())
    }

    /// The erased handler, for a [`HandlerTable`](super::HandlerTable).
    pub fn into_handler(self) -> ErasedHandler<S> {
        self.handler
    }

    /// Borrow the erased handler.
    pub fn handler(&self) -> &ErasedHandler<S> {
        &self.handler
    }
}

impl<S> From<DeclaredHandler<S>> for ErasedHandler<S> {
    fn from(d: DeclaredHandler<S>) -> Self {
        d.handler
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        FsRead, FsReadRequest, FsWrite, FsWriteRequest, Permission, PermissionRequest,
    };
    use crate::ir::MethodIr;

    #[test]
    fn the_declaration_and_the_handle_come_from_one_type() {
        let h = DeclaredHandler::new::<(Permission, FsRead), _, _>(|_input| async move {
            Ok(TurnOutcome::complete())
        });

        // Derived, not restated.
        assert_eq!(
            h.capability_names(),
            ["session/request_permission", "fs/read_text_file"]
        );
        let method = h.declare(MethodIr::new("m", "a.m"));
        assert_eq!(
            method
                .callbacks
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["session/request_permission", "fs/read_text_file"],
        );
        // …and it is exactly what the same set derives on its own.
        assert_eq!(method.callbacks, Client::<(Permission, FsRead)>::callbacks());
    }

    #[test]
    fn an_empty_declaration_declares_nothing() {
        let h = DeclaredHandler::new::<(), _, _>(|_| async { Ok(TurnOutcome::complete()) });
        assert!(h.callbacks().is_empty());
        assert!(h.declare(MethodIr::new("m", "a.m")).callbacks.is_empty());
    }

    /// Both accessor families (PLX-80) are reachable on the inferred handle,
    /// with no turbofish anywhere — the legitimate path is untouched.
    #[test]
    fn the_declared_set_is_inferred_for_both_accessor_families() {
        let h = DeclaredHandler::new::<(Permission, FsRead, FsWrite), _, _>(|input| async move {
            let client = input.turn.client();

            // Synchronous family.
            let _ = client.request_permission(PermissionRequest {
                operation: "x".into(),
                rationale: None,
            });
            let _ = client.fs_read(FsReadRequest { path: "p".into() });

            // Awaiting family.
            let _ = client
                .fs_write_async(FsWriteRequest {
                    path: "p".into(),
                    content: "c".into(),
                })
                .await;
            Ok(TurnOutcome::complete())
        });
        assert_eq!(h.callbacks().len(), 3);
    }

    /// End to end through [`entry`](super::entry): a handler that mints exactly
    /// its declared set dispatches, its `_async` callback correlates, and its
    /// synchronous twin is reachable on the same inferred handle (returning
    /// PLX-80's directed error, which is what a turn-scoped sync callback is
    /// *supposed* to do).
    #[tokio::test]
    async fn the_declared_handle_dispatches_on_both_accessor_families() {
        use crate::ir::{ActivationIr, AuthRequirementIr};
        use crate::runtime::{entry, TurnEvent, TurnRequest};
        use futures::StreamExt;
        use serde_json::json;

        let ask = DeclaredHandler::new::<(Permission,), _, _>(|input| async move {
            let client = input.turn.client();

            // Synchronous family: typed, callable, and honest about the wire.
            let sync = client.request_permission(PermissionRequest {
                operation: "sync".into(),
                rationale: None,
            });
            assert!(
                format!("{}", sync.unwrap_err()).contains("_async"),
                "the sync accessor points at its awaiting twin"
            );

            // Awaiting family: the real path.
            let outcome = client
                .request_permission_async(PermissionRequest {
                    operation: "async".into(),
                    rationale: None,
                })
                .await
                .map_err(|e| TurnError::callback_failed(e.to_string()))?;
            TurnOutcome::serialize(&outcome)
        });

        let ir = ActivationIr::new("declared", "1.0.0").with_method(
            ask.declare(MethodIr::new("ask", "declared.ask").with_auth(AuthRequirementIr::Public)),
        );
        let handlers = super::super::HandlerTable::new([("ask", ask.into_handler())]);

        let mut turn = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
        let control = turn.control();

        let (id, name) = match turn.next().await.unwrap() {
            TurnEvent::Callback { id, name, .. } => (id, name),
            other => panic!("expected a callback, got {other:?}"),
        };
        assert_eq!(name, "session/request_permission");
        control.respond(id, json!({"outcome": "allow"})).unwrap();

        let terminal = turn.next().await.unwrap();
        match terminal {
            TurnEvent::Terminal { value, .. } => {
                assert_eq!(value.unwrap(), json!({"outcome": "allow"}))
            }
            other => panic!("expected a terminal, got {other:?}"),
        }
    }

    #[test]
    fn a_stateful_declaring_handler_captures_nothing() {
        struct Service;
        let h = DeclaredHandler::<Service>::stateful::<(Permission,), _, _>(
            |_state, input| async move {
                let _client = input.turn.client();
                Ok(TurnOutcome::complete())
            },
        );
        assert_eq!(h.capability_names(), ["session/request_permission"]);
    }
}
