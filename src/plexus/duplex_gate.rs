//! BIDIR-5 — the gate over a duplex call (spike; the rule, not the product).
//!
//! A duplex call is params, then an input half and an output half
//! (BIDIR-1). [`DuplexGate::open`] decides it as the grant gate decides any
//! call — once, the method's grant on its target, within the ceiling — and
//! takes the call's place on its connection. The [`DuplexCall`] it answers
//! holds the caller and admits each input frame **without asking the gate**:
//!
//! | when | the gate does | refusal (`error_kind`) | ends the call? |
//! |---|---|---|---|
//! | open | [`Gate::check`] once | `forbidden {grant, scope, roles, held_on}` / `unauthenticated` | never opens |
//! | open, past the connection's calls | count it as any call | `too_many_calls {max}` | never opens |
//! | an input frame from another connection | compare connection ids | `not_this_call` (to the sender) | no |
//! | an input frame past credit | compare `seq` with the credit granted | `past_credit {seq, credit}` | yes |
//! | an input frame past the call's ceiling | count items and bytes | `too_much_input {limit, max}` | yes |
//! | the grants generation moves, or the sign-in's expiry comes | [`Gate::check`] once per call | `forbidden` / `unauthenticated` | yes, items after it dropped |
//! | a question answered | [`Answerer`]: own connection; a person; or a grant on the target ([`Gate::check`] once per answer) | `not_this_call` / `person_required` / `forbidden` | no |
//!
//! A frame's admission is: the half is open, the frame is the call's own
//! connection's, the generation is the one last verified (one atomic load),
//! the frame is within credit and the ceiling. So a revoke reaches every
//! open call at the generation's move — the stream selects on it, so a
//! quiet call ends then too — and no item ever costs a gate check.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use futures::stream::{Stream, StreamExt};
use plexus_auth_core::duplex::{is_person, Answerer, CallCeiling};
use plexus_auth_core::grants::{Gate, Grant, Reach};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use super::auth::AuthContext;
use super::plexus::{error_item, PlexusError};

/// A connection, as the transport numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// The service's grants generation: moved by every grant, revoke, role edit
/// and sign-out (menger's `Store::grants_generation`, ACCESS-9). Cheap to
/// clone; a load is one atomic read.
#[derive(Clone)]
pub struct GrantsGeneration {
    now: Arc<AtomicU64>,
    tx: Arc<watch::Sender<u64>>,
}

impl Default for GrantsGeneration {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantsGeneration {
    pub fn new() -> Self {
        Self { now: Arc::new(AtomicU64::new(0)), tx: Arc::new(watch::channel(0).0) }
    }
    /// Something that could change an answer moved.
    pub fn bump(&self) {
        let n = self.now.fetch_add(1, Ordering::AcqRel) + 1;
        self.tx.send_replace(n);
    }
    pub fn current(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
    fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }
}

/// The calls open on one connection, a duplex call counted as one call
/// (menger's ACCESS-29 `--max-calls-per-connection`, which belongs in the
/// transport).
#[derive(Clone)]
pub struct ConnectionCalls {
    open: Arc<AtomicUsize>,
    max: usize,
}

/// A call's place on its connection, given back when dropped.
pub struct CallPlace(Arc<AtomicUsize>);

impl Drop for CallPlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ConnectionCalls {
    pub fn new(max: usize) -> Self {
        Self { open: Arc::new(AtomicUsize::new(0)), max }
    }
    /// A place for one more call, or `too_many_calls`.
    pub fn try_open(&self) -> Result<CallPlace, DuplexRefusal> {
        let mut now = self.open.load(Ordering::Acquire);
        loop {
            if now >= self.max {
                return Err(DuplexRefusal::TooManyCalls { max: self.max });
            }
            match self.open.compare_exchange(now, now + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(CallPlace(self.open.clone())),
                Err(seen) => now = seen,
            }
        }
    }
    pub fn open_count(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }
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
}

impl DuplexRefusal {
    /// The `error_kind` it goes on the wire as.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Gate(PlexusError::Forbidden { .. }) => "forbidden",
            Self::Gate(PlexusError::Unauthenticated(_)) => "unauthenticated",
            Self::Gate(PlexusError::InvalidParams(_)) => "invalid_params",
            Self::Gate(_) => "error",
            Self::TooManyCalls { .. } => "too_many_calls",
            Self::NotThisCall => "not_this_call",
            Self::PastCredit { .. } => "past_credit",
            Self::TooMuchInput { .. } => "too_much_input",
            Self::PersonRequired => "person_required",
            Self::InputClosed => "input_closed",
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

    /// The error item: a gate refusal exactly as `{ns}.call` sends one;
    /// the rest `{"type":"error","error_kind":…, <facts>, "message"}`.
    pub fn to_item(&self, ns: &str) -> Value {
        let (message, facts) = match self {
            Self::Gate(e) => return error_item(ns, e),
            Self::TooManyCalls { max } => (format!("too many calls open on this connection (at most {max})"), json!({ "max": max })),
            Self::NotThisCall => ("this call is not yours: input and answers come from the connection that opened it".into(), json!({})),
            Self::PastCredit { seq, credit } => (format!("item {seq} is past the credit granted ({credit})"), json!({ "seq": seq, "credit": credit })),
            Self::TooMuchInput { limit, max } => (format!("this call takes at most {max} {limit} of input"), json!({ "limit": limit, "max": max })),
            Self::PersonRequired => ("this question needs a person's answer".into(), json!({})),
            Self::InputClosed => ("the input half is closed".into(), json!({})),
        };
        let mut item = json!({ "type": "error", "error_kind": self.kind(), "message": message, "recoverable": false });
        if let (Some(o), Value::Object(f)) = (item.as_object_mut(), facts) {
            o.extend(f);
        }
        item
    }
}

/// One input frame as the transport hands it over: which connection sent
/// it, its `seq`, the item, and its size on the wire.
#[derive(Debug, Clone)]
pub struct InputFrame {
    pub from: ConnId,
    pub seq: u64,
    pub item: Value,
    pub bytes: u64,
}

impl InputFrame {
    /// A frame whose size is its item's JSON (a transport has the raw
    /// length already).
    pub fn new(from: ConnId, seq: u64, item: Value) -> Self {
        let bytes = serde_json::to_vec(&item).map(|v| v.len() as u64).unwrap_or(0);
        Self { from, seq, item, bytes }
    }
}

/// The gate over duplex calls: a [`Gate`] and the generation that says when
/// to ask it again.
#[derive(Clone)]
pub struct DuplexGate {
    gate: Gate,
    generation: GrantsGeneration,
    checks: Arc<AtomicU64>,
}

impl DuplexGate {
    pub fn new(gate: Gate, generation: GrantsGeneration) -> Self {
        Self { gate, generation, checks: Arc::new(AtomicU64::new(0)) }
    }

    /// How many times the gate has been asked (the spike's counter).
    pub fn gate_checks(&self) -> u64 {
        self.checks.load(Ordering::Relaxed)
    }

    fn check(&self, caller: Option<&AuthContext>, grant: &Grant, target: Option<&str>) -> Result<Reach, DuplexRefusal> {
        self.checks.fetch_add(1, Ordering::Relaxed);
        self.gate.check(caller, grant, target).map_err(|r| DuplexRefusal::Gate(r.into()))
    }

    /// Open a duplex call: the gate first (a refusal takes no place), then
    /// the call's place on its connection.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        conn: ConnId,
        calls: &ConnectionCalls,
        caller: Option<&AuthContext>,
        grant: &str,
        target: Option<&str>,
        ceiling: CallCeiling,
        answer_by: Answerer,
    ) -> Result<DuplexCall, DuplexRefusal> {
        // Subscribe before deciding: a move after the check is a wake.
        let mut moves = self.generation.subscribe();
        let seen = *moves.borrow_and_update();
        let grant = Grant::new(grant);
        let reach = self.check(caller, &grant, target)?;
        let place = calls.try_open()?;
        Ok(DuplexCall {
            dg: self.clone(),
            conn,
            caller: caller.cloned(),
            grant,
            target: target.map(str::to_string),
            reach,
            seen,
            moves,
            ceiling,
            credit: ceiling.credit,
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
    caller: Option<AuthContext>,
    grant: Grant,
    target: Option<String>,
    reach: Reach,
    seen: u64,
    moves: watch::Receiver<u64>,
    ceiling: CallCeiling,
    credit: u64,
    items: u64,
    bytes: u64,
    closed: Option<DuplexRefusal>,
    answer_by: Answerer,
    _place: CallPlace,
}

impl DuplexCall {
    /// The reach the call was last verified with.
    pub fn reach(&self) -> &Reach {
        &self.reach
    }

    /// The callee grants `n` more items (the `credit { n }` output item).
    pub fn grant_credit(&mut self, n: u64) {
        self.credit = self.credit.saturating_add(n);
    }

    fn close(&mut self, why: DuplexRefusal) -> DuplexRefusal {
        self.closed = Some(why.clone());
        why
    }

    /// The caller, verified again (a generation move, the expiry).
    pub fn reverify(&mut self) -> Result<(), DuplexRefusal> {
        let now = self.dg.generation.current();
        match self.dg.check(self.caller.as_ref(), &self.grant, self.target.as_deref()) {
            Ok(reach) => {
                self.reach = reach;
                self.seen = now;
                Ok(())
            }
            Err(e) => Err(self.close(e)),
        }
    }

    /// Admit one input frame — no gate check unless the generation moved.
    pub fn admit(&mut self, f: &InputFrame) -> Result<(), DuplexRefusal> {
        if self.closed.is_some() {
            return Err(DuplexRefusal::InputClosed);
        }
        if f.from != self.conn {
            return Err(DuplexRefusal::NotThisCall);
        }
        if self.dg.generation.current() != self.seen {
            self.reverify()?;
        }
        if f.seq >= self.credit {
            return Err(self.close(DuplexRefusal::PastCredit { seq: f.seq, credit: self.credit }));
        }
        if self.items + 1 > self.ceiling.max_items {
            return Err(self.close(DuplexRefusal::TooMuchInput { limit: "items", max: self.ceiling.max_items }));
        }
        if self.bytes + f.bytes > self.ceiling.max_bytes {
            return Err(self.close(DuplexRefusal::TooMuchInput { limit: "bytes", max: self.ceiling.max_bytes }));
        }
        self.items += 1;
        self.bytes += f.bytes;
        Ok(())
    }

    /// May `who`, on connection `from`, answer a question this call asked?
    pub fn answer(&self, from: ConnId, who: Option<&AuthContext>) -> Result<(), DuplexRefusal> {
        if self.closed.is_some() {
            return Err(DuplexRefusal::InputClosed);
        }
        match &self.answer_by {
            Answerer::Caller if from == self.conn => Ok(()),
            Answerer::Person if from == self.conn => match who {
                Some(w) if is_person(w) => Ok(()),
                _ => Err(DuplexRefusal::PersonRequired),
            },
            Answerer::Caller | Answerer::Person => Err(DuplexRefusal::NotThisCall),
            Answerer::Grant(g) => self.dg.check(who, &Grant::new(g.clone()), self.target.as_deref()).map(|_| ()),
        }
    }

    /// The handler's input: the frames as they come, each admitted; the
    /// generation and the sign-in's expiry selected beside them, so a quiet
    /// call ends at a revoke. A frame from another connection is refused to
    /// its sender on `refused` and the call runs on; any other refusal is
    /// the stream's last item, and what follows is never read (dropped).
    pub fn input<S>(mut self, frames: S, refused: mpsc::UnboundedSender<(ConnId, Value)>) -> impl Stream<Item = Result<Value, DuplexRefusal>> + Send + 'static
    where
        S: Stream<Item = InputFrame> + Send + 'static,
    {
        let ns = self.grant.as_str().split('.').next().unwrap_or("").to_string();
        let expires = self
            .caller
            .as_ref()
            .and_then(|c| c.metadata.get(plexus_auth_core::auth::EXPIRES_AT_KEY))
            .and_then(Value::as_i64);
        async_stream::stream! {
            let frames = frames;
            futures::pin_mut!(frames);
            let expiry = async move {
                match expires {
                    Some(at) => {
                        let secs = at.saturating_sub(chrono::Utc::now().timestamp()).max(0) as u64;
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
                        if moved.is_err() { continue; }
                        if let Err(e) = self.reverify() { yield Err(e); break; }
                    }
                    () = &mut expiry => {
                        if let Err(e) = self.reverify() { yield Err(e); break; }
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
