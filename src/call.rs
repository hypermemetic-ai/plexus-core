//! RETURNS-47 · the call's context: who is calling, as the gate admitted
//! them, how far the call reaches, and the hop it came through.
//!
//! A method reaches its caller through the call it runs in, never through
//! its signature, so a method of a hand-written trait (whose signature is
//! the same for every implementation) reaches it the same way an inherent
//! method does:
//!
//! ```ignore
//! #[plexus_macros::activation]
//! impl forge::Forge for GitHub {
//!     async fn repos(&self) -> Vec<Repo> {
//!         let Ok(caller) = plexus_core::call::caller() else { return vec![] };   // fail closed
//!         self.repos_within(caller.reach()).await
//!     }
//! }
//! ```
//!
//! - **Typed and verified.** [`caller()`] answers the [`AuthContext`] the
//!   service's gate admitted (after AUTH-11's liveness: a sign-in that ended
//!   is anonymous here, as at the gate) and the [`Reach`] it answered for the
//!   call. A service's own verifier turns it into its own verified user, as
//!   `#[from_auth]` does (`VerifiedUser::current(&self.access).await?`).
//!   Nothing outside this crate builds one: a [`DynamicHub`] sets it as it
//!   dispatches.
//! - **Fail closed.** Outside a call there is no caller: [`caller()`],
//!   [`hop()`] and [`crate::plexus::current_reach`] are errors, never a
//!   default. A service without a gate dispatches every call with
//!   [`Reach::everywhere`] — what no gate has always meant — said by the
//!   dispatch, not assumed by the reader.
//! - **Through a hop.** In a child service reached through the seam
//!   ([`crate::plexus::remote_child::serve_child`]), the call's context is
//!   the hop's (spec/12: the acting service, the caller it acts for, the
//!   gate's verdict as a ceiling, the call id): [`hop()`] answers it, and
//!   [`Hop::allows`] bounds a read by it. [`caller()`] there is an error:
//!   no gate of this process admitted anyone, and the hop is not a
//!   credential.
//! - **With the call's stream.** The context goes with the stream the call
//!   answers: each poll of it runs inside the context ([`InCall`]), so a
//!   method's stream body reads [`caller()`] as its first line does.
//! - **Across spawned work, only when handed.** A task the method spawns
//!   does not inherit the context: it carries it only when handed it
//!   explicitly, [`scope`]`(`[`context()`]`?, fut)`. Nothing inherits a
//!   caller by accident.
//!
//! `#[plexus_macros::from_auth]` stays for inherent methods: the dispatch
//! hands it the same identity it puts here.
//!
//! [`DynamicHub`]: crate::plexus::DynamicHub

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::any::Any;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use futures::Stream;
use plexus_auth_core::grants::{Gate, Grant, Reach, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::plexus::{AuthContext, PlexusError};

tokio::task_local! {
    static CALL: CallContext;
}

/// The context of one call: the caller as the gate admitted them and the
/// reach it answered — or, in a child, the hop the call came through.
/// Cheap to clone. Built only by the dispatch (and the child seam), never by
/// hand; a method gets it with [`context()`], to hand to work it spawns.
#[derive(Clone)]
pub struct CallContext(Arc<Inner>);

struct Inner {
    auth: Option<AuthContext>,
    reach: OnceLock<Reach>,
    /// An introspection call's reach, asked of the gate only if something
    /// reads it (PERF-15: an introspection answer looks no role up).
    deferred: Option<(Arc<Gate>, Grant)>,
    hop: Option<Hop>,
    /// What a trait-impl method's verifier answered for this call
    /// (`#[plexus_macros::from_auth(…)]` on the method): [`verified`]. Shared
    /// by a context narrowed from this one (`with_reach`: the same call);
    /// another caller's context (`with_auth`, `ungated`) starts its own.
    verified: Verified,
}

type Verified = Arc<Mutex<Option<Arc<dyn Any + Send + Sync>>>>;

impl Inner {
    fn with(auth: Option<AuthContext>, reach: Option<Reach>, deferred: Option<(Arc<Gate>, Grant)>, hop: Option<Hop>) -> Self {
        let cell = OnceLock::new();
        if let Some(r) = reach {
            let _ = cell.set(r);
        }
        Inner { auth, reach: cell, deferred, hop, verified: Verified::default() }
    }
}

impl fmt::Debug for CallContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallContext")
            .field("principal", &self.0.auth.as_ref().and_then(|a| a.principal()).map(|p| p.to_string()))
            .field("reach", &self.0.reach.get())
            .field("hop", &self.0.hop)
            .finish()
    }
}

impl CallContext {
    /// A call a service's dispatch admitted: `auth` the identity that
    /// stands (none: anonymous), `reach` what the gate answered — or
    /// [`Reach::everywhere`] on a service without a gate.
    pub(crate) fn admitted(auth: Option<&AuthContext>, reach: Reach) -> Self {
        Self(Arc::new(Inner::with(auth.cloned(), Some(reach), None, None)))
    }

    /// An introspection call a gated service let through (AUTH-4): its
    /// reach is the caller's for the path, as the gate answers a public
    /// method's — asked only when read.
    pub(crate) fn introspection(auth: Option<&AuthContext>, gate: Arc<Gate>, grant: Grant) -> Self {
        Self(Arc::new(Inner::with(auth.cloned(), None, Some((gate, grant)), None)))
    }

    /// A call that came through the child seam (owner, 2026-11-04: children
    /// receive auth): its caller is the one the hop names — `for`'s far end,
    /// as an `AuthContext` whose session is the hop's call id; anonymous when
    /// `for` is empty — and its reach the hop's ceiling (`limit.held_on` for
    /// `limit.grant`, as a gate of the hop alone answers it), never wider;
    /// nowhere when no gate decided (`limit: null`) or `for` cannot be read. The hop is
    /// believed as the transport delivered it (`remote_child::serve_child_on`
    /// takes it only from a sender it trusts).
    pub(crate) fn through_hop(hop: Hop) -> Self {
        // `for` names someone this cannot read: anonymous, and no ceiling —
        // the verdict was for a caller this child cannot name.
        let unreadable = hop.caller().is_some_and(|p| p.parse::<plexus_auth_core::identity::Principal>().is_err());
        let auth = hop.caller().and_then(|p| p.parse::<plexus_auth_core::identity::Principal>().ok()).map(|p| {
            AuthContext::for_principal(&p, format!("hop:{}", hop.call), Vec::new(), serde_json::json!({ "hop_principal": hop.principal }))
        });
        let reach = match &hop.limit {
            Some(l) if !unreadable => ceiling_reach(auth.as_ref(), &l.grant, &hop.held_on()),
            _ => Reach::nowhere(),
        };
        Self(Arc::new(Inner::with(auth, Some(reach), None, Some(hop))))
    }

    /// The context of a call routed into an in-process child, under its
    /// forward policy: `callee` the context the policy derived (none, or
    /// one no longer signed in, is anonymous); the call's reach kept when
    /// the policy keeps the caller's identity, nowhere when it does not; the
    /// hop kept as the caller is (none under `anonymous`); the verified
    /// value the child's own (another caller).
    pub(crate) fn for_child(&self, callee: Option<&AuthContext>, keeps_identity: bool) -> Self {
        let auth = callee.filter(|a| a.is_authenticated()).cloned();
        // The reach and the hop follow the caller: kept with its identity
        // (`same_service`, `identity_only`, `pass_through`), none under
        // `anonymous` — `hop()` there errors, as outside a hop.
        let (reach, hop) = if keeps_identity {
            (self.reach().cloned().unwrap_or_else(Reach::nowhere), self.0.hop.clone())
        } else {
            (Reach::nowhere(), None)
        };
        Self(Arc::new(Inner::with(auth, Some(reach), None, hop)))
    }

    /// This context with its identity replaced: a call routed from inside
    /// another, through a service with no gate of its own.
    pub(crate) fn with_auth(&self, auth: Option<&AuthContext>) -> Self {
        Self(Arc::new(Inner::with(auth.cloned(), self.0.reach.get().cloned(), self.0.deferred.clone(), self.0.hop.clone())))
    }

    /// This context with its reach replaced: the same call, so the same
    /// verified value (the same slot, set once for both).
    pub(crate) fn with_reach(&self, reach: Reach) -> Self {
        let mut inner = Inner::with(self.0.auth.clone(), Some(reach), None, self.0.hop.clone());
        inner.verified = Arc::clone(&self.0.verified);
        Self(Arc::new(inner))
    }

    /// The identity the gate admitted (in a child, the one the hop names, or
    /// the one its forward policy derived); `None` for an anonymous call.
    pub fn auth(&self) -> Option<&AuthContext> {
        self.0.auth.as_ref()
    }

    /// The reach the gate answered (in a child through the seam, the hop's
    /// ceiling).
    pub fn reach(&self) -> Option<&Reach> {
        if let Some(reach) = self.0.reach.get() {
            return Some(reach);
        }
        let (gate, grant) = self.0.deferred.as_ref()?;
        Some(self.0.reach.get_or_init(|| gate.reach_of_public(self.0.auth.as_ref(), grant)))
    }

    /// The hop the call came through, in a child.
    pub fn hop(&self) -> Option<&Hop> {
        self.0.hop.as_ref()
    }

    /// The caller this context names: an error for a call that came
    /// through a hop (no gate of this process admitted anyone).
    pub fn caller(&self) -> Result<Caller, CallError> {
        match self.reach() {
            Some(_) => Ok(Caller(self.clone())),
            None => Err(CallError::ThroughHop),
        }
    }
}

/// The caller of the call being run, as the service's gate admitted them:
/// [`caller()`].
#[derive(Clone, Debug)]
pub struct Caller(CallContext);

impl Caller {
    /// The identity the gate admitted; `None` for an anonymous caller (a
    /// `public` method, or a sign-in that has ended).
    pub fn auth(&self) -> Option<&AuthContext> {
        self.0.auth()
    }

    /// The identity, signed in — `Unauthenticated` for an anonymous caller,
    /// as `#[from_auth]` refuses one.
    pub fn signed_in(&self) -> Result<&AuthContext, PlexusError> {
        self.0
            .auth()
            .ok_or_else(|| PlexusError::Unauthenticated("This method requires authentication".to_string()))
    }

    /// What the gate answered for the call: where its grant is held.
    pub fn reach(&self) -> &Reach {
        self.0.reach().expect("a caller is made only from a context with a reach")
    }

    /// The whole context, to hand to work the method spawns ([`scope`]).
    pub fn context(&self) -> &CallContext {
        &self.0
    }
}

/// Why there is no caller (or no hop) to answer. Fail closed: each is an
/// error, never a default; as a [`PlexusError`] it is `Unauthenticated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// Not inside a call: no dispatch set a context here — a task spawned
    /// without one handed to it ([`scope`]), or code run outside any call.
    OutsideCall,
    /// Inside a call that came through a hop: no gate of this process
    /// admitted a caller; read [`hop()`].
    ThroughHop,
    /// Inside a call that did not come through a hop: there is none to read.
    NoHop,
    /// Inside a call whose method declared no verifier, or one that answered
    /// another type than the one asked for.
    NotVerified,
    /// The call's verified value is already set: it is set once, by the
    /// method's verifier, and never replaced.
    AlreadyVerified,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CallError::OutsideCall => {
                "no caller: this runs outside a call (a spawned task carries one only when handed it, plexus_core::call::scope)"
            }
            CallError::ThroughHop => "no caller admitted here: this call came through a hop (read plexus_core::call::hop)",
            CallError::NoHop => "no hop: this call did not come through the child seam",
            CallError::AlreadyVerified => "the call's verified value is set once, by its verifier, and is set",
            CallError::NotVerified => {
                "nothing verified: the method declares no `#[plexus_macros::from_auth(…)]` answering this type"
            }
        })
    }
}

impl std::error::Error for CallError {}

impl From<CallError> for PlexusError {
    fn from(e: CallError) -> Self {
        PlexusError::Unauthenticated(e.to_string())
    }
}

/// The caller of the call this runs in, as the gate admitted them, with the
/// reach it answered. An error outside a call, and in a child (read
/// [`hop()`] there).
pub fn caller() -> Result<Caller, CallError> {
    CALL.try_with(CallContext::caller).unwrap_or(Err(CallError::OutsideCall))
}

/// The hop the call this runs in came through (spec/12), in a child reached
/// through the seam. An error outside a call, and in a call that did not
/// come through a hop.
pub fn hop() -> Result<Hop, CallError> {
    CALL.try_with(|c| c.hop().cloned().ok_or(CallError::NoHop)).unwrap_or(Err(CallError::OutsideCall))
}

/// The whole context of the call this runs in — to hand to a task it
/// spawns, [`scope`]`(context()?, fut)`. An error outside a call.
pub fn context() -> Result<CallContext, CallError> {
    CALL.try_with(CallContext::clone).map_err(|_| CallError::OutsideCall)
}

/// What the method's verifier answered for this call: on `impl Trait for
/// Type`, `#[plexus_macros::from_auth(self.access.verify)]` on the method
/// runs the verifier before the body — its error the call's refusal, out of
/// band and typed, as a `#[from_auth]` parameter's is — and keeps its value
/// here for the body. An error outside a call, and when the method declared
/// no verifier of type `T`.
pub fn verified<T: Clone + Send + Sync + 'static>() -> Result<T, CallError> {
    let ctx = context()?;
    let held = ctx.0.verified.lock().unwrap_or_else(|p| p.into_inner()).clone();
    held.and_then(|v| v.downcast_ref::<T>().cloned()).ok_or(CallError::NotVerified)
}

/// The macro's half of [`verified`]: keep a verifier's answer on the call.
/// Set once per call: the dispatch sets it before the body runs, so a second
/// set — by any code inside the call — is refused (`AlreadyVerified`) and
/// the verifier's value stands.
#[doc(hidden)]
pub fn __keep_verified<T: Send + Sync + 'static>(value: T) -> Result<(), CallError> {
    let ctx = context()?;
    let mut held = ctx.0.verified.lock().unwrap_or_else(|p| p.into_inner());
    if held.is_some() {
        return Err(CallError::AlreadyVerified);
    }
    *held = Some(Arc::new(value));
    Ok(())
}

/// Dispatch a call to one activation as a service with no gate dispatches
/// it: in a context admitting `auth` everywhere — said here, by the caller of
/// this function, never assumed by the method. The leaf path of a bridge that
/// serves a single activation (plexus-transport's REST and MCP bridges call
/// `Activation::call` straight, outside any context, where a method that
/// needs its caller is refused). Inside a call already, that call's reach
/// and hop are kept, with this call's identity.
pub async fn ungated<A: crate::plexus::Activation + ?Sized>(
    activation: &A,
    method: &str,
    params: serde_json::Value,
    auth: Option<&AuthContext>,
    raw_ctx: Option<&crate::request::RawRequestContext>,
) -> Result<crate::plexus::PlexusStream, PlexusError> {
    let ctx = match context() {
        Ok(outer) => outer.with_auth(auth),
        Err(_) => CallContext::admitted(auth, Reach::everywhere()),
    };
    let stream = scope(ctx.clone(), activation.call(method, params, auth, raw_ctx)).await?;
    Ok(Box::pin(InCall::new(ctx, stream)))
}

/// A test's way into a call (feature `test-util`, never default): a
/// verifier that reads [`caller()`] or `current_reach()`, tested without a
/// service. Nothing but a test builds a caller by hand.
#[cfg(feature = "test-util")]
pub mod test {
    use super::{scope, CallContext};
    use crate::plexus::AuthContext;
    use plexus_auth_core::grants::Reach;
    use std::future::Future;

    /// Run `fut` inside a call admitted for `auth` (none: anonymous) with
    /// `reach`, as a service's dispatch would run it.
    pub async fn in_call<F: Future>(auth: Option<&AuthContext>, reach: Reach, fut: F) -> F::Output {
        scope(CallContext::admitted(auth, reach), fut).await
    }
}

/// Run `fut` inside `ctx`: how a task a method spawns carries its caller.
pub fn scope<F: Future>(ctx: CallContext, fut: F) -> impl Future<Output = F::Output> {
    CALL.scope(ctx, fut)
}

pin_project_lite::pin_project! {
    /// A stream polled inside a call's context: what the dispatch hands its
    /// caller, so a method's stream reads [`caller()`] as its first line
    /// does.
    pub struct InCall<S> {
        ctx: CallContext,
        #[pin]
        inner: S,
    }
}

impl<S> InCall<S> {
    /// `inner`, each poll of it inside `ctx`.
    pub fn new(ctx: CallContext, inner: S) -> Self {
        Self { ctx, inner }
    }
}

impl<S: Stream> Stream for InCall<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let this = self.project();
        let inner = this.inner;
        CALL.sync_scope(this.ctx.clone(), || inner.poll_next(cx))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// spec/12's hop, as a child reads it: who acts, for whom, within what.
/// `for` grants nothing; `limit` is a ceiling, never a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    /// Who acts: the service that forwarded the call.
    pub principal: String,
    /// On whose behalf, nearest first; `[]` when the service calls for
    /// itself or its caller is anonymous.
    #[serde(rename = "for", default)]
    pub for_: Vec<String>,
    /// The service gate's verdict, in this child's terms; `None` when no
    /// gate decided.
    #[serde(default)]
    pub limit: Option<HopLimit>,
    /// The hop's id for this call, to join the two logs.
    #[serde(default)]
    pub call: String,
}

/// The near side's decision, as a ceiling (spec/12 `limit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopLimit {
    /// The grant the service's gate checked (`{ns}.<method>`).
    pub grant: String,
    /// The scopes it admitted the caller on for it (`["*"]`, `["MENGER"]`).
    #[serde(default)]
    pub held_on: Vec<String>,
}

impl Hop {
    /// The caller the hop acts for — the far end of `for` — or `None`
    /// when it acts for itself or for an anonymous caller.
    pub fn caller(&self) -> Option<&str> {
        self.for_.last().map(String::as_str)
    }

    /// The grant the near side checked, if a gate decided.
    pub fn grant(&self) -> Option<&str> {
        self.limit.as_ref().map(|l| l.grant.as_str())
    }

    /// The ceiling: the scopes the near side admitted the caller on. Empty
    /// when no gate decided — and then nothing is within it (fail closed).
    pub fn held_on(&self) -> Vec<ScopeRef> {
        self.limit.as_ref().map(|l| l.held_on.iter().map(|s| ScopeRef::parse(s)).collect()).unwrap_or_default()
    }

    /// Whether a target whose scope chain is `chain` is within the ceiling:
    /// held on `*`, or on a scope of the chain. `false` when no gate decided.
    pub fn allows(&self, chain: &[ScopeRef]) -> bool {
        self.held_on().iter().any(|s| s.is_everywhere() || chain.contains(s))
    }

    /// [`Hop::allows`] for one named scope.
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.allows(&[ScopeRef::parse(scope)])
    }
}

/// The reach a hop's ceiling gives its caller: what a gate of the hop alone
/// answers — the caller holds one role, listing `grant` alone, on each scope
/// of `held_on`, and a target resolves to itself and `*` (the child cannot
/// resolve the service's scopes) — so it names `grant`, covers exactly
/// `held_on`, and allows a target by name only on `*`. An anonymous caller
/// holds nothing. RETURNS-47: no public constructor makes a reach from a
/// list of scopes; this one is the seam's, built from a hop it took.
fn ceiling_reach(caller: Option<&AuthContext>, grant: &str, held_on: &[ScopeRef]) -> Reach {
    use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable};
    struct Held(Vec<Membership>);
    impl Memberships for Held {
        fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
            self.0.iter().filter(|m| &m.principal == who).cloned().collect()
        }
    }
    struct Itself;
    impl Resolve for Itself {
        fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
            Some(vec![ScopeRef::named(target), ScopeRef::Everywhere])
        }
    }
    const ROLE: &str = "hop";
    let grant = Grant::new(grant.to_string());
    let held: Vec<Membership> = match caller.and_then(|a| a.principal()) {
        Some(p) => held_on
            .iter()
            .map(|s| Membership { principal: p.clone(), role: plexus_auth_core::RoleName::new(ROLE), scope: s.clone() })
            .collect(),
        None => Vec::new(),
    };
    let roles = RoleTable::from_lists([(ROLE, [grant.as_str()])]);
    let gate = Gate::new(std::sync::Arc::new(Held(held)), std::sync::Arc::new(roles), std::sync::Arc::new(Itself));
    gate.reach_of_public(caller, &grant)
}
