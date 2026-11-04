//! BIDIR-8 (BIDIR-5's rule, made a library) — the gate over a duplex call.
//!
//! A duplex call is params, then an input half and an output half
//! (BIDIR-1). [`DuplexGate::open`] decides it as the grant gate decides any
//! call — once, the method's grant on its target, within the ceiling — and
//! takes the call's place on its connection ([`CallCounter`]: in a server,
//! plexus-transport's `ConnectionCalls`, one per connection, a duplex call
//! counted as one call). The [`DuplexCall`] it answers holds the caller and
//! admits each input frame **without asking the gate**:
//!
//! | when | the gate does | refusal (`error_kind`) | ends the call? |
//! |---|---|---|---|
//! | open | [`Gate::check`] once | `forbidden {grant, scope, roles, held_on}` / `unauthenticated` | never opens |
//! | open, past the connection's calls | count it as any call | `too_many_calls {max}` | never opens |
//! | an input frame from another connection | compare connection ids | `not_this_call` (to the sender) | no |
//! | an input frame past credit | compare `seq` with the credit granted | `past_credit {seq, credit}` | yes |
//! | an input frame past a ceiling its method opted into, or past what one call may hold | count items and bytes | `too_much_input {limit, max}` | yes |
//! | an input frame out of sequence | the transport compares `seq` with the next expected | `out_of_sequence {seq, expected}` | yes |
//! | the gate's grants generation moves (grant, revoke, role edit, team, sign-out) | [`Gate::check`] once per call | `forbidden` / `unauthenticated` | yes, items after it dropped |
//! | the sign-in's expiry | the call's own timer: the caller proves no one | `unauthenticated` | yes |
//! | a question answered | [`Answerer`]: own connection; a person; or a grant on the target ([`Gate::check`] once per answer) | `not_this_call` / `person_required` / `forbidden` | no |
//!
//! A frame's admission is: the half is open, the frame is the call's own
//! connection's, the gate's generation is the one last verified (one atomic
//! load), the frame is within credit and the ceiling. So a revoke reaches
//! every open call at the generation's move — [`DuplexCall::input`] selects
//! on it, so a quiet call ends then too — and no item ever costs a gate
//! check. The generation is the gate's own ([`Gate::generation`],
//! plexus-auth-core): every service that keeps a gate keeps one, and moves
//! it with [`Gate::moved`] wherever it writes a grant.
//!
//! Every typed refusal is one audit record
//! ([`AuditRecordKind::DuplexRefused`](plexus_auth_core::audit::AuditRecordKind::DuplexRefused)),
//! built only when it happens and offered to a bounded [`AuditQueue`] that
//! never waits ([`DuplexGate::with_audit`]): an admitted frame allocates
//! nothing.
//!
//! BIDIR-6's call slot ([`super::input`]), keyed by `(connection,
//! subscription)`, feeds [`DuplexCall::input`] one [`InputFrame`] for each
//! `{ns}.input {subscription, seq, items}`. `seq` counts frames; credit counts
//! items, so a frame carries how many it holds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::stream::{Stream, StreamExt};
use plexus_auth_core::audit::{AuditQueue, AuditRecord};
use plexus_auth_core::duplex::is_person;
/// The gate's terms for a duplex call (plexus-auth-core), re-exported so a
/// caller of this module needs no second import.
pub use plexus_auth_core::duplex::{Answerer, CallCeiling, CallRef, DuplexRefusalCode};
pub use plexus_auth_core::grants::{GrantsGeneration, GrantsMove};
use plexus_auth_core::grants::{Gate, Grant, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use super::auth::AuthContext;
use super::context::PlexusContext;
use super::plexus::{error_item, PlexusError};
use super::types::{spec_code, spec_fields, PlexusStreamItem, StreamMetadata};
use super::RemoteError;

/// A connection, as the transport numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

impl From<ConnId> for CallRef {
    /// A call on `conn` with no subscription named (0) — a test's, or a
    /// caller that keys calls by connection alone.
    fn from(conn: ConnId) -> Self {
        CallRef { conn: conn.0, subscription: 0 }
    }
}

/// A call's place on its connection, held for as long as the call is open
/// and given back when dropped — whatever the counter keeps behind it.
pub struct CallPlace(#[allow(dead_code)] Box<dyn Send + Sync>);

impl CallPlace {
    /// A place that gives itself back when `held` is dropped.
    pub fn new(held: impl Send + Sync + 'static) -> Self {
        Self(Box::new(held))
    }
}

/// The calls open on one connection, as whoever counts them keeps them —
/// plexus-transport's `ConnectionCalls` in a server (BIDIR-8: the count is
/// the transport's, so no service writes it). A duplex call is one call.
pub trait CallCounter: Send + Sync {
    /// A place for one more call, or the most there may be (`too_many_calls
    /// {max}`).
    fn take_place(&self) -> Result<CallPlace, usize>;
}

/// The wall clock, in unix seconds: when a sign-in expires.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn wall_clock() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Why the gate refused a duplex call, a frame or an answer — each typed on
/// the wire as an error item with its `error_kind`.
#[derive(Debug, Clone)]
pub enum DuplexRefusal {
    /// The grant gate's own refusal (`forbidden`, `unauthenticated`).
    Gate(PlexusError),
    TooManyCalls { max: usize },
    NotThisCall,
    PastCredit { seq: u64, credit: u64 },
    TooMuchInput { limit: &'static str, max: u64 },
    PersonRequired,
    /// The input half is already closed (a frame after the end).
    InputClosed,
    /// A frame out of sequence, on a socket that delivers in order.
    OutOfSequence { seq: u64, expected: u64 },
    /// An item of frame `seq` that does not decode as the method's type.
    InvalidInput { seq: u64, message: String },
}

impl DuplexRefusal {
    /// The `error_kind` it goes on the wire as.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Gate(PlexusError::Forbidden { .. }) => "forbidden",
            Self::Gate(PlexusError::Unauthenticated(_)) => "unauthenticated",
            Self::Gate(PlexusError::InvalidParams { .. }) => "invalid_params",
            Self::Gate(_) => "error",
            other => other.code().as_str(),
        }
    }

    /// The refusal's code: its audit `reason` (a gate refusal other than
    /// `unauthenticated` is `forbidden`).
    pub fn code(&self) -> DuplexRefusalCode {
        match self {
            Self::Gate(PlexusError::Unauthenticated(_)) => DuplexRefusalCode::Unauthenticated,
            Self::Gate(_) => DuplexRefusalCode::Forbidden,
            Self::TooManyCalls { .. } => DuplexRefusalCode::TooManyCalls,
            Self::NotThisCall => DuplexRefusalCode::NotThisCall,
            Self::PastCredit { .. } => DuplexRefusalCode::PastCredit,
            Self::TooMuchInput { .. } => DuplexRefusalCode::TooMuchInput,
            Self::PersonRequired => DuplexRefusalCode::PersonRequired,
            Self::InputClosed => DuplexRefusalCode::InputClosed,
            Self::OutOfSequence { .. } => DuplexRefusalCode::OutOfSequence,
            Self::InvalidInput { .. } => DuplexRefusalCode::InvalidInput,
        }
    }

    /// Whether it ends the call's input half (else it refuses one frame or
    /// one answer to its sender, and the call runs on).
    pub fn ends_input(&self) -> bool {
        !matches!(self, Self::NotThisCall | Self::PersonRequired)
    }

    /// The gate's own refusal, when it is one.
    pub fn into_plexus(self) -> Option<PlexusError> {
        match self {
            Self::Gate(e) => Some(e),
            _ => None,
        }
    }

    /// The error item: a gate refusal exactly as `{ns}.call` sends one; the
    /// rest a typed error item (spec/05), `error_kind` and its facts beside
    /// `message`.
    pub fn to_item(&self, ns: &str) -> Value {
        let (message, facts) = match self {
            Self::Gate(e) => return error_item(ns, e),
            Self::TooManyCalls { max } => (format!("too many calls open on this connection (at most {max})"), json!({ "max": max })),
            Self::NotThisCall => ("this call is not yours: input and answers come from the connection that opened it".into(), json!({})),
            Self::PastCredit { seq, credit } => (format!("item {seq} is past the credit granted ({credit})"), json!({ "seq": seq, "credit": credit })),
            Self::TooMuchInput { limit, max } => (format!("this call takes at most {max} {limit} of input"), json!({ "limit": limit, "max": max })),
            Self::PersonRequired => ("this question needs a person's answer".into(), json!({})),
            Self::InputClosed => ("the input half is closed".into(), json!({})),
            Self::OutOfSequence { seq, expected } => (format!("input frame {seq} is out of sequence: {expected} comes next"), json!({ "seq": seq, "expected": expected })),
            Self::InvalidInput { seq, message } => (format!("an item of input frame {seq} is not this method's input: {message}"), json!({ "seq": seq })),
        };
        let Value::Object(facts) = facts else { unreachable!("facts are an object") };
        let metadata = StreamMetadata::new(vec![ns.into()], PlexusContext::hash());
        // RETURNS-36: an error item carries its typed `RemoteError`; a kind
        // the vocabulary does not know is `Other`, its facts its fields.
        let error = match self {
            Self::TooManyCalls { max } => RemoteError::TooManyCalls { max: *max as u64, child: None },
            _ => RemoteError::Other(plexus_client::OtherError { kind: self.kind().to_string(), fields: facts }),
        };
        let item = PlexusStreamItem::Error {
            metadata,
            message,
            code: Some(spec_code(&error)),
            recoverable: false,
            fields: spec_fields(&error),
            error,
        };
        serde_json::to_value(&item).unwrap_or(Value::Null)
    }
}

/// What the transport found wrong with a frame when it arrived. It holds
/// nothing past the first one, so the frame says so and goes through the
/// same admission as any other, whenever that comes: [`DuplexCall::admit`]
/// refuses it, whatever the credit has become since.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overrun {
    /// More items than the window holds were outstanding: past credit.
    Credit,
    /// Out of sequence.
    Sequence { expected: u64 },
    /// A frame of no items: a broken client (`invalid_input`).
    Empty,
}

/// One input frame as the transport hands it over: which connection sent
/// it, its `seq`, what it holds, how many items that is, and their size on
/// the wire.
#[derive(Debug, Clone)]
pub struct InputFrame<I = Value> {
    pub from: ConnId,
    pub seq: u64,
    pub item: I,
    /// Items in the frame: what credit counts.
    pub items: u64,
    pub bytes: u64,
    /// `Some`: the transport refused it on arrival.
    pub overrun: Option<Overrun>,
}

impl InputFrame {
    /// A frame of one item, its size its JSON (a transport has the raw
    /// length already).
    pub fn new(from: ConnId, seq: u64, item: Value) -> Self {
        let bytes = serde_json::to_vec(&item).map(|v| v.len() as u64).unwrap_or(0);
        Self { from, seq, item, items: 1, bytes, overrun: None }
    }
}

/// The credit a call has granted, shared with whoever grants it: the
/// transport's pipe grants as the handler consumes, on a call that
/// [`DuplexCall::input`] has taken.
#[derive(Debug, Clone)]
pub struct CreditLine(Arc<AtomicU64>);

impl CreditLine {
    /// `n` more items.
    pub fn grant(&self, n: u64) {
        let _ = self.0.fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| Some(c.saturating_add(n)));
    }

    /// Every item granted so far.
    pub fn granted(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// The gate of a service that has none: nobody holds anything, and its
/// generation is nobody's to move, so a call is never asked again.
struct Nobody;

impl Memberships for Nobody {
    fn held(&self, _who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        Vec::new()
    }
}

impl Resolve for Nobody {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        None
    }
}

/// The gate over duplex calls: a [`Gate`] (and its grants generation, which
/// says when to ask it again), the audit, and the clock expiry is read by.
#[derive(Clone)]
pub struct DuplexGate {
    gate: Gate,
    checks: Arc<AtomicU64>,
    audit: Option<AuditQueue>,
    clock: Clock,
}

impl DuplexGate {
    /// The gate over duplex calls in front of `gate`; re-verifies when
    /// `gate`'s generation ([`Gate::generation`]) moves.
    pub fn new(gate: Gate) -> Self {
        Self { gate, checks: Arc::new(AtomicU64::new(0)), audit: None, clock: Arc::new(wall_clock) }
    }

    /// The duplex gate of a service with no [`Gate`]: as a call on it
    /// dispatches ungated, a duplex call opens with [`admitted`](Self::admitted)
    /// and is never asked again; credit, the ceilings and the sign-in's expiry
    /// hold as on any other.
    pub fn ungated() -> Self {
        Self::new(Gate::new(Arc::new(Nobody), Arc::new(RoleTable::new()), Arc::new(Nobody)))
    }

    /// Every typed refusal to `audit` (one record each, never waiting).
    pub fn with_audit(mut self, audit: AuditQueue) -> Self {
        self.audit = Some(audit);
        self
    }

    /// When a sign-in expires is read by `clock` (unix seconds; a test's).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The grant gate it asks (its [`Gate::generation`], [`Gate::moved`]).
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// How many times the gate has been asked through this one.
    pub fn gate_checks(&self) -> u64 {
        self.checks.load(Ordering::Relaxed)
    }

    fn check(&self, caller: Option<&AuthContext>, grant: &Grant, target: Option<&str>) -> Result<(), DuplexRefusal> {
        self.checks.fetch_add(1, Ordering::Relaxed);
        self.gate.check(caller, grant, target).map(drop).map_err(|r| DuplexRefusal::Gate(r.into()))
    }

    /// The refusal, audited: one record, built here and only here.
    fn audited(&self, call: CallRef, who: Option<&AuthContext>, grant: &Grant, why: DuplexRefusal) -> DuplexRefusal {
        if let Some(q) = &self.audit {
            q.offer(AuditRecord::duplex_refused(call, why.code(), who, grant.as_str()));
        }
        why
    }

    /// Open a duplex call: the gate first (a refusal takes no place), then
    /// the call's place on its connection. `at` is the call — its
    /// connection and subscription (a [`ConnId`] alone is subscription 0).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        at: impl Into<CallRef>,
        calls: &dyn CallCounter,
        caller: Option<Arc<AuthContext>>,
        grant: &str,
        target: Option<&str>,
        ceiling: CallCeiling,
        answer_by: Answerer,
    ) -> Result<DuplexCall, DuplexRefusal> {
        let at = at.into();
        // Subscribe before deciding: a move after the check is a wake.
        let mut moves = self.gate.generation().subscribe();
        let seen = *moves.borrow_and_update();
        let grant = Grant::new(grant);
        if let Err(e) = self.check(caller.as_deref(), &grant, target) {
            return Err(self.audited(at, caller.as_deref(), &grant, e));
        }
        let targets = target.map(str::to_string).into_iter().collect();
        self.opened(at, calls, caller, grant, targets, seen, moves, true, ceiling, answer_by)
    }

    /// BIDIR-6: open a call the service's dispatch has already decided, so
    /// the decision is still made once. `seen` is the generation read before
    /// that decision: a move since is found at the first frame (or at once,
    /// by [`DuplexCall::input`]). `recheck` false: the method is one the gate
    /// admits whoever calls (`public`, a signed-in grant), so a move asks
    /// nothing; the sign-in's expiry still holds. `targets`: every value the
    /// dispatch checked, asked again together.
    #[allow(clippy::too_many_arguments)]
    pub fn admitted(
        &self,
        at: impl Into<CallRef>,
        calls: &dyn CallCounter,
        caller: Option<Arc<AuthContext>>,
        grant: &str,
        targets: Vec<String>,
        seen: u64,
        recheck: bool,
        ceiling: CallCeiling,
        answer_by: Answerer,
    ) -> Result<DuplexCall, DuplexRefusal> {
        let mut moves = self.gate.generation().subscribe();
        moves.mark_changed();
        self.opened(at.into(), calls, caller, Grant::new(grant), targets, seen, moves, recheck, ceiling, answer_by)
    }

    #[allow(clippy::too_many_arguments)]
    fn opened(
        &self,
        at: CallRef,
        calls: &dyn CallCounter,
        caller: Option<Arc<AuthContext>>,
        grant: Grant,
        targets: Vec<String>,
        seen: u64,
        moves: watch::Receiver<u64>,
        recheck: bool,
        ceiling: CallCeiling,
        answer_by: Answerer,
    ) -> Result<DuplexCall, DuplexRefusal> {
        let place = match calls.take_place() {
            Ok(p) => p,
            Err(max) => return Err(self.audited(at, caller.as_deref(), &grant, DuplexRefusal::TooManyCalls { max })),
        };
        Ok(DuplexCall {
            dg: self.clone(),
            conn: ConnId(at.conn),
            at,
            caller,
            grant,
            targets,
            recheck,
            seen,
            moves,
            ceiling,
            credit: CreditLine(Arc::new(AtomicU64::new(ceiling.credit))),
            items: 0,
            bytes: 0,
            closed: None,
            answer_by,
            _place: place,
        })
    }
}

/// One open duplex call, holding its caller (the module docs).
pub struct DuplexCall {
    dg: DuplexGate,
    conn: ConnId,
    at: CallRef,
    caller: Option<Arc<AuthContext>>,
    grant: Grant,
    targets: Vec<String>,
    recheck: bool,
    seen: u64,
    moves: watch::Receiver<u64>,
    ceiling: CallCeiling,
    credit: CreditLine,
    items: u64,
    bytes: u64,
    closed: Option<DuplexRefusal>,
    answer_by: Answerer,
    _place: CallPlace,
}

impl DuplexCall {
    /// Which call this is: its connection and subscription.
    pub fn call(&self) -> CallRef {
        self.at
    }

    /// Who may answer its questions.
    pub fn answer_by(&self) -> &Answerer {
        &self.answer_by
    }

    /// Why its input half closed, once it has.
    pub fn closed(&self) -> Option<&DuplexRefusal> {
        self.closed.as_ref()
    }

    /// The callee grants `n` more items (the `credit { n }` output item).
    pub fn grant_credit(&mut self, n: u64) {
        self.credit.grant(n);
    }

    /// The handle to go on granting by, once [`input`](Self::input) has the
    /// call.
    pub fn credit_line(&self) -> CreditLine {
        self.credit.clone()
    }

    fn refuse(&self, why: DuplexRefusal) -> DuplexRefusal {
        self.dg.audited(self.at, self.caller.as_deref(), &self.grant, why)
    }

    fn close(&mut self, why: DuplexRefusal) -> DuplexRefusal {
        let why = self.refuse(why);
        self.closed = Some(why.clone());
        why
    }

    /// The caller, verified again (the generation moved): one gate check.
    pub fn reverify(&mut self) -> Result<(), DuplexRefusal> {
        let now = self.dg.gate.generation().current();
        let asked = if !self.recheck {
            Ok(())
        } else if self.targets.is_empty() {
            self.dg.check(self.caller.as_deref(), &self.grant, None)
        } else {
            self.targets.iter().try_for_each(|t| self.dg.check(self.caller.as_deref(), &self.grant, Some(t)))
        };
        match asked {
            Ok(()) => {
                self.seen = now;
                Ok(())
            }
            Err(e) => Err(self.close(e)),
        }
    }

    /// The sign-in's expiry came: the caller proves no one now (the gate
    /// would say the same — [`Gate::alive`] refuses a context past its
    /// `expires_at`), so no check is asked. The input half closes.
    pub fn expire(&mut self) -> DuplexRefusal {
        self.close(DuplexRefusal::Gate(PlexusError::Unauthenticated("your sign-in has expired: sign in again".into())))
    }

    /// Admit one input frame — no gate check unless the generation moved.
    pub fn admit<I>(&mut self, f: &InputFrame<I>) -> Result<(), DuplexRefusal> {
        if self.closed.is_some() {
            return Err(self.refuse(DuplexRefusal::InputClosed));
        }
        if f.from != self.conn {
            return Err(self.refuse(DuplexRefusal::NotThisCall));
        }
        if self.dg.gate.generation().current() != self.seen {
            self.reverify()?;
        }
        let credit = self.credit.granted();
        match f.overrun {
            None => {}
            Some(Overrun::Credit) => return Err(self.close(DuplexRefusal::PastCredit { seq: f.seq, credit })),
            Some(Overrun::Sequence { expected }) => return Err(self.close(DuplexRefusal::OutOfSequence { seq: f.seq, expected })),
            Some(Overrun::Empty) => return Err(self.close(DuplexRefusal::InvalidInput { seq: f.seq, message: "an input frame with no items".into() })),
        }
        if f.items == 0 {
            return Err(self.close(DuplexRefusal::InvalidInput { seq: f.seq, message: "an input frame with no items".into() }));
        }
        if self.items.saturating_add(f.items) > credit {
            return Err(self.close(DuplexRefusal::PastCredit { seq: f.seq, credit }));
        }
        if self.items.saturating_add(f.items) > self.ceiling.max_items {
            return Err(self.close(DuplexRefusal::TooMuchInput { limit: "items", max: self.ceiling.max_items }));
        }
        if self.bytes.saturating_add(f.bytes) > self.ceiling.max_bytes {
            return Err(self.close(DuplexRefusal::TooMuchInput { limit: "bytes", max: self.ceiling.max_bytes }));
        }
        self.items = self.items.saturating_add(f.items);
        self.bytes = self.bytes.saturating_add(f.bytes);
        Ok(())
    }

    /// May `who`, on connection `from`, answer a question this call asked?
    /// By the method's [`Answerer`]; a refusal is audited as `who`'s.
    pub fn answer(&self, from: ConnId, who: Option<&AuthContext>) -> Result<(), DuplexRefusal> {
        let refused = |why| Err(self.dg.audited(self.at, who, &self.grant, why));
        if self.closed.is_some() {
            return refused(DuplexRefusal::InputClosed);
        }
        match &self.answer_by {
            Answerer::Caller if from == self.conn => Ok(()),
            Answerer::Person if from == self.conn => match who {
                Some(w) if is_person(w) => Ok(()),
                _ => refused(DuplexRefusal::PersonRequired),
            },
            Answerer::Caller | Answerer::Person => refused(DuplexRefusal::NotThisCall),
            Answerer::Grant(g) => match self.dg.check(who, &Grant::new(g.clone()), self.targets.first().map(String::as_str)) {
                Ok(()) => Ok(()),
                Err(e) => refused(e),
            },
        }
    }

    /// The handler's input: the frames as they come, each admitted; the
    /// generation and the sign-in's expiry selected beside them, so a quiet
    /// call ends at a revoke. A frame from another connection is refused to
    /// its sender on `refused` and the call runs on; any other refusal is
    /// the stream's last item, and what follows is never read (dropped).
    pub fn input<S, I>(mut self, frames: S, refused: mpsc::UnboundedSender<(ConnId, Value)>) -> impl Stream<Item = Result<I, DuplexRefusal>> + Send + 'static
    where
        S: Stream<Item = InputFrame<I>> + Send + 'static,
        I: Send + 'static,
    {
        let ns = self.grant.as_str().split('.').next().unwrap_or("").to_string();
        let expires = self
            .caller
            .as_ref()
            .and_then(|c| c.metadata.get(plexus_auth_core::auth::EXPIRES_AT_KEY))
            .and_then(Value::as_i64);
        let now = (self.dg.clock)();
        async_stream::stream! {
            let frames = frames;
            futures::pin_mut!(frames);
            let expiry = async move {
                match expires {
                    Some(at) => {
                        let secs = at.saturating_sub(now).max(0) as u64;
                        tokio::time::sleep(std::time::Duration::from_secs(secs)).await
                    }
                    None => std::future::pending().await,
                }
            };
            futures::pin_mut!(expiry);
            loop {
                tokio::select! {
                    biased;
                    moved = self.moves.changed() => {
                        // Already verified at this generation (a frame
                        // found the move first): nothing to ask again.
                        if moved.is_err() || self.dg.gate.generation().current() == self.seen { continue; }
                        if let Err(e) = self.reverify() { yield Err(e); break; }
                    }
                    () = &mut expiry => {
                        yield Err(self.expire());
                        break;
                    }
                    f = frames.next() => match f {
                        None => break,
                        Some(f) => match self.admit(&f) {
                            Ok(()) => yield Ok(f.item),
                            Err(e) if !e.ends_input() => { let _ = refused.send((f.from, e.to_item(&ns))); }
                            Err(e) => { yield Err(e); break; }
                        },
                    },
                }
            }
        }
    }
}
