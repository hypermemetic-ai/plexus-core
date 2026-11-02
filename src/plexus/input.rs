//! BIDIR-6: the input half of a call. A method declares one parameter
//! [`Input<T>`] and reads what its caller streams into the live call.
//!
//! ```text
//! → {ns}.call {method, params}        ← the subscription id, then credit {n: window}
//! → {ns}.input {subscription, seq, items: [T…]}   (seq counts frames from 0)
//!                                     ← ack {seq}, credit {n}, as the handler consumes
//! → {ns}.end {subscription, seq}      (seq: the number of frames sent)
//!                                     ← the method's items, done
//! ```
//!
//! | when | then |
//! | -- | -- |
//! | a socket opens | the transport puts an [`InputTable`] in its calls' extensions (a connection's, so a frame of another socket reaches nothing) and hands it each input frame on its reader, inline, in arrival order, zero-copy: no task and no decode per frame |
//! | `{ns}.call` dispatches | [`serve_call`](super::plexus)'s seam (`CALL`, a task-local) holds the unaccepted subscription; a method with no `Input` never looks at it, so its call is what it was |
//! | a method with `Input` dispatches | [`open`], after its params and its gate, before its body: the [`DuplexCall`] taken with the gate's decision standing, the slot in the table **before** the subscription is accepted (so a frame sent on reading the id finds it), the subscription accepted, the `Input` handed to the method |
//! | anywhere with no seam or no table (stdio, HTTP, MCP, in process) | [`open`] refuses, naming the method: the call fails, it does not hang |
//! | a frame arrives | [`InputTable`] checks its `seq` (a resend below the next one is dropped; past it is `out_of_sequence`) and what the call holds, then queues it; a frame past either bound is marked ([`Overrun`]) and is the last it takes |
//! | the pipe runs | one task, as any call: it polls [`DuplexCall::input`] (each frame admitted, the generation and the sign-in's expiry selected beside it, so a call whose handler is not reading ends at a revoke all the same), the handler's stream, and the ledger |
//! | the handler polls for the next item | everything before it counts as consumed: a handler that forwards before it polls reports what was forwarded. Half a window consumed, the pipe writes `ack` and `credit` |
//! | the handler ends with the half open | `input_closed {reason: "method_ended", ack}`, then `done`; a later frame reaches nothing |
//! | a refusal | `input_closed {reason, ack}` and the typed error, the handler's stream dropped |
//!
//! `credit` is what the handler consumes, not a number anyone chose
//! (BIDIR-6's first decision): a client that obeys it meets no refusal.
//! Order is arrival: the socket's reader takes frames in order, so `seq` is
//! for `ack` and `end`, not for reassembly.

use std::cell::RefCell;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::stream::Stream;
use http::Extensions;
use jsonrpsee::types::{Params, SubscriptionId};
use jsonrpsee::{PendingSubscriptionSink, SubscriptionSink};
use plexus_auth_core::duplex::{Answerer, CallCeiling, CallRef};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::UnboundedReceiverStream;

use super::auth::AuthContext;
use super::duplex_gate::{CallCounter, ConnId, CreditLine, DuplexCall, DuplexRefusal, InputFrame, Overrun};
use super::plexus::{DynamicHub, PlexusError};
use super::wire::FrameSink;

/// What a frame's items are while they wait: each item's JSON, sharing the
/// frame's bytes.
#[derive(Debug)]
pub(crate) struct Batch {
    seq: u64,
    items: Vec<Bytes>,
    bytes: u64,
}

// ---------------------------------------------------------------------------
// The ledger: what the handler has consumed, for the pipe to report
// ---------------------------------------------------------------------------

/// One call's input, as its reader, its handler and its pipe share it.
pub(crate) struct Ledger {
    window: u64,
    /// What the call holds: received and not consumed.
    held_items: AtomicU64,
    held_bytes: AtomicU64,
    /// One past the last frame consumed whole: 0, none yet.
    done: AtomicU64,
    /// Items consumed.
    consumed: AtomicU64,
    /// `consumed` at the last grant, the pipe's.
    returned: AtomicU64,
    /// The client sent `end`.
    ended: AtomicBool,
    /// The handler saw the end of its input.
    finished: AtomicBool,
    /// The handler let go of its input before the end.
    abandoned: AtomicBool,
    refused: AtomicBool,
    refusal: Mutex<Option<DuplexRefusal>>,
    wake: Notify,
}

impl Ledger {
    fn new(window: u64) -> Self {
        Self {
            window,
            held_items: AtomicU64::new(0),
            held_bytes: AtomicU64::new(0),
            done: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            returned: AtomicU64::new(0),
            ended: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            refusal: Mutex::new(None),
            wake: Notify::new(),
        }
    }

    fn half(&self) -> u64 {
        (self.window / 2).max(1)
    }

    /// Frame `seq` is consumed: the handler has polled past its last item.
    fn frame_done(&self, seq: u64, items: u64, bytes: u64) {
        self.held_items.fetch_sub(items, Ordering::AcqRel);
        self.held_bytes.fetch_sub(bytes, Ordering::AcqRel);
        self.done.store(seq + 1, Ordering::Release);
        let consumed = self.consumed.fetch_add(items, Ordering::AcqRel) + items;
        if consumed - self.returned.load(Ordering::Acquire) >= self.half() {
            self.wake.notify_one();
        }
    }

    fn input_finished(&self) {
        self.finished.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    fn refuse(&self, why: DuplexRefusal) {
        *lock(&self.refusal) = Some(why);
        self.refused.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    pub(crate) async fn woken(&self) {
        self.wake.notified().await
    }

    /// A refusal the handler's side made (an item that does not decode).
    pub(crate) fn take_refusal(&self) -> Option<DuplexRefusal> {
        if !self.refused.load(Ordering::Acquire) {
            return None;
        }
        lock(&self.refusal).take()
    }

    /// What the pipe owes the client now: `Some` when there is something to
    /// say. The last frame consumed, when it is news, and the items to grant.
    /// Half a window at a time, and all that is left when the input is done.
    pub(crate) fn owed(&self, acked: u64) -> Option<Owed> {
        let finished = self.finished.load(Ordering::Acquire);
        let ended = self.ended.load(Ordering::Acquire);
        let done = self.done.load(Ordering::Acquire);
        let consumed = self.consumed.load(Ordering::Acquire);
        let due = consumed - self.returned.load(Ordering::Acquire);
        if due < self.half() && !(finished && done > acked) {
            return None;
        }
        self.returned.store(consumed, Ordering::Release);
        Some(Owed { ack: (done > acked).then(|| done - 1), done, credit: if finished || ended { 0 } else { due } })
    }

    /// The last frame consumed whole, for `input_closed`.
    pub(crate) fn last_done(&self) -> Option<u64> {
        self.done.load(Ordering::Acquire).checked_sub(1)
    }

    pub(crate) fn client_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    pub(crate) fn abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }
}

/// [`Ledger::owed`]'s answer.
pub(crate) struct Owed {
    pub(crate) ack: Option<u64>,
    pub(crate) done: u64,
    pub(crate) credit: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Input<T>: what the handler reads
// ---------------------------------------------------------------------------

/// The input half of a call: the items its caller streams in, as `T`, in
/// order, ending at the caller's `end`.
///
/// A method takes at most one, as a parameter, and reads it as any `Stream`:
///
/// ```ignore
/// #[plexus_macros::method]
/// pub async fn tokens(&self, run: RunId, tokens: Input<Token>) -> impl Stream<Item = IngestEvent> + Send + 'static {
///     ingest_stream(self.store.clone(), run, tokens.into_stream())
/// }
/// ```
///
/// An item counts as consumed when the handler polls for the next one, so
/// the credit the caller is given is what the handler has taken: a handler
/// that forwards an item before it polls reports what was forwarded.
///
/// The stream also ends at a refusal: an item that does not decode, a
/// revoked grant, a client past its credit. The call then ends with that
/// error, whatever the handler does next.
pub struct Input<T> {
    source: Source<T>,
}

enum Source<T> {
    /// A live call's: what the pipe admitted.
    Wire(WireInput),
    /// Any stream: an activation's trait called in process, a test.
    Stream(Pin<Box<dyn Stream<Item = T> + Send + 'static>>),
}

struct WireInput {
    rx: mpsc::UnboundedReceiver<Batch>,
    cur: Option<Reading>,
    ledger: Arc<Ledger>,
    over: bool,
}

struct Reading {
    seq: u64,
    items: std::vec::IntoIter<Bytes>,
    count: u64,
    bytes: u64,
}

impl<T> Input<T> {
    /// The items as a `Stream`: `Input` is one, so this only says so.
    pub fn into_stream(self) -> Self {
        self
    }

    /// An input that reads `stream`: a method called with no wire under it.
    pub fn from_stream(stream: impl Stream<Item = T> + Send + 'static) -> Self {
        Self { source: Source::Stream(Box::pin(stream)) }
    }
}

impl<T: DeserializeOwned + Send + 'static> Input<T> {
    /// The input as a boxed stream (what an activation's trait method takes).
    pub fn into_boxed(self) -> Pin<Box<dyn Stream<Item = T> + Send + 'static>> {
        match self.source {
            Source::Stream(s) => s,
            wire => Box::pin(Input { source: wire }),
        }
    }
}

/// An activation's trait hands its input over boxed.
impl<T> From<Pin<Box<dyn Stream<Item = T> + Send + 'static>>> for Input<T> {
    fn from(stream: Pin<Box<dyn Stream<Item = T> + Send + 'static>>) -> Self {
        Self { source: Source::Stream(stream) }
    }
}

impl<T> std::fmt::Debug for Input<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Input");
        match &self.source {
            Source::Wire(w) => d.field("window", &w.ledger.window).field("over", &w.over),
            Source::Stream(_) => d.field("window", &"none: a stream"),
        };
        d.finish()
    }
}

impl<T: DeserializeOwned> Stream for Input<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match &mut self.get_mut().source {
            Source::Wire(wire) => wire.poll_item(cx),
            Source::Stream(stream) => stream.as_mut().poll_next(cx),
        }
    }
}

impl WireInput {
    fn poll_item<T: DeserializeOwned>(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        loop {
            if self.over {
                return Poll::Ready(None);
            }
            if let Some(r) = &mut self.cur {
                if let Some(raw) = r.items.next() {
                    match serde_json::from_slice::<T>(&raw) {
                        Ok(item) => return Poll::Ready(Some(item)),
                        Err(e) => {
                            self.over = true;
                            self.ledger.refuse(DuplexRefusal::InvalidInput { seq: r.seq, message: e.to_string() });
                            return Poll::Ready(None);
                        }
                    }
                }
                self.ledger.frame_done(r.seq, r.count, r.bytes);
                self.cur = None;
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => {
                    self.cur = Some(Reading { seq: b.seq, count: b.items.len() as u64, bytes: b.bytes, items: b.items.into_iter() });
                }
                Poll::Ready(None) => {
                    self.over = true;
                    self.ledger.input_finished();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for WireInput {
    fn drop(&mut self) {
        if !self.over {
            self.ledger.abandon();
        }
    }
}

// ---------------------------------------------------------------------------
// The table: a connection's open input halves
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct InputParams<'a> {
    subscription: u64,
    seq: u64,
    #[serde(borrow)]
    items: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
struct EndParams {
    subscription: u64,
    seq: u64,
}

struct Slot {
    ns: Arc<str>,
    next_seq: u64,
    /// `None`: the half is closed to frames (ended, or refused on arrival).
    tx: Option<mpsc::UnboundedSender<InputFrame<Batch>>>,
    ledger: Arc<Ledger>,
    max_buffered: u64,
}

/// What became of an input frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// It reached the call.
    Taken,
    /// A resend, or a frame after the half closed: dropped, safely.
    Dropped,
    /// It names no call of this connection (`not_this_call`).
    NotThisCall,
    /// It is not an input frame's shape.
    Malformed,
}

/// A connection's open input halves, keyed by subscription, the slot of
/// BIDIR-5's rule: (connection, subscription). The transport makes one a
/// connection, puts it in its calls' extensions and hands it frames.
pub struct InputTable {
    conn: ConnId,
    calls: Arc<dyn CallCounter>,
    slots: Mutex<HashMap<u64, Slot>>,
    open: AtomicUsize,
    strays: AtomicU64,
}

impl std::fmt::Debug for InputTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputTable").field("conn", &self.conn).field("open", &self.open.load(Ordering::Relaxed)).finish()
    }
}

impl InputTable {
    /// The table of connection `conn`, its calls counted by `calls`.
    pub fn new(conn: u64, calls: Arc<dyn CallCounter>) -> Arc<Self> {
        Arc::new(Self { conn: ConnId(conn), calls, slots: Mutex::new(HashMap::new()), open: AtomicUsize::new(0), strays: AtomicU64::new(0) })
    }

    /// Whether no input half is open: one load, so a connection with none
    /// reads its frames as it always did.
    pub fn idle(&self) -> bool {
        self.open.load(Ordering::Acquire) == 0
    }

    /// Input frames that named no call of this connection and could not be
    /// told so (a notification has no answer): counted, dropped.
    pub fn strays(&self) -> u64 {
        self.strays.load(Ordering::Relaxed)
    }

    /// A whole inbound message, if it is an input notification: `true`, it
    /// is taken. Run on the socket's reader, in arrival order. A frame with
    /// an `id` goes through the method table, which answers it.
    pub fn take_frame(&self, data: &Bytes) -> bool {
        #[derive(Deserialize)]
        struct Shape<'a> {
            #[serde(borrow)]
            method: &'a str,
            #[serde(borrow, default)]
            id: Option<&'a RawValue>,
            #[serde(borrow, default)]
            params: Option<&'a RawValue>,
        }
        let Ok(shape) = serde_json::from_slice::<Shape>(data) else { return false };
        if shape.id.is_some() {
            return false;
        }
        let Some((ns, name)) = shape.method.rsplit_once('.') else { return false };
        let params = shape.params.map_or(&b"null"[..], |p| p.get().as_bytes());
        let delivered = match name {
            "input" => self.input(ns, params, data),
            "end" => self.end(ns, params),
            _ => return false,
        };
        if matches!(delivered, Delivered::NotThisCall | Delivered::Malformed) {
            self.strays.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// `{ns}.input`: `params` a slice of `frame`, or `frame` itself.
    pub fn input(&self, ns: &str, params: &[u8], frame: &Bytes) -> Delivered {
        let Ok(p) = serde_json::from_slice::<InputParams>(params) else { return Delivered::Malformed };
        let mut slots = lock(&self.slots);
        let Some(slot) = slots.get_mut(&p.subscription).filter(|s| &*s.ns == ns) else { return Delivered::NotThisCall };
        let Some(tx) = &slot.tx else { return Delivered::Dropped };
        if p.seq < slot.next_seq {
            return Delivered::Dropped;
        }
        if p.seq > slot.next_seq {
            let last = InputFrame { from: self.conn, seq: p.seq, item: empty(p.seq), items: 0, bytes: 0, overrun: Some(Overrun::Sequence { expected: slot.next_seq }) };
            let _ = tx.send(last);
            slot.tx = None;
            return Delivered::Taken;
        }
        slot.next_seq += 1;
        let count = p.items.len() as u64;
        let bytes: u64 = p.items.iter().map(|i| i.get().len() as u64).sum();
        let held_items = slot.ledger.held_items.load(Ordering::Acquire);
        let held_bytes = slot.ledger.held_bytes.load(Ordering::Acquire);
        let overrun = if held_items + count > slot.ledger.window {
            Some(Overrun::Credit)
        } else if held_bytes + bytes > slot.max_buffered {
            Some(Overrun::Buffered { max: slot.max_buffered })
        } else {
            None
        };
        if overrun.is_some() {
            let last = InputFrame { from: self.conn, seq: p.seq, item: empty(p.seq), items: 0, bytes: 0, overrun };
            let _ = tx.send(last);
            slot.tx = None;
            return Delivered::Taken;
        }
        slot.ledger.held_items.fetch_add(count, Ordering::AcqRel);
        slot.ledger.held_bytes.fetch_add(bytes, Ordering::AcqRel);
        let items = p.items.iter().map(|i| shared(frame, i.get().as_bytes())).collect();
        let _ = tx.send(InputFrame { from: self.conn, seq: p.seq, item: Batch { seq: p.seq, items, bytes }, items: count, bytes, overrun: None });
        Delivered::Taken
    }

    /// `{ns}.end`: its `seq` is the number of frames sent. Since frames come
    /// in order, one that says otherwise has lost count.
    pub fn end(&self, ns: &str, params: &[u8]) -> Delivered {
        let Ok(p) = serde_json::from_slice::<EndParams>(params) else { return Delivered::Malformed };
        let mut slots = lock(&self.slots);
        let Some(slot) = slots.get_mut(&p.subscription).filter(|s| &*s.ns == ns) else { return Delivered::NotThisCall };
        let Some(tx) = slot.tx.take() else { return Delivered::Dropped };
        if p.seq == slot.next_seq {
            slot.ledger.ended.store(true, Ordering::Release);
        } else {
            let last = InputFrame { from: self.conn, seq: p.seq, item: empty(p.seq), items: 0, bytes: 0, overrun: Some(Overrun::Sequence { expected: slot.next_seq }) };
            let _ = tx.send(last);
        }
        Delivered::Taken
    }

    fn attach(self: &Arc<Self>, subscription: u64, slot: Slot) -> SlotGuard {
        lock(&self.slots).insert(subscription, slot);
        self.open.fetch_add(1, Ordering::AcqRel);
        SlotGuard { table: self.clone(), subscription }
    }
}

fn empty(seq: u64) -> Batch {
    Batch { seq, items: Vec::new(), bytes: 0 }
}

/// `part` of `frame`, as `Bytes` sharing it; a copy when it is not a part of
/// it (a request form's params reach here from the method table).
fn shared(frame: &Bytes, part: &[u8]) -> Bytes {
    let (start, end) = (frame.as_ptr() as usize, frame.as_ptr() as usize + frame.len());
    let p = part.as_ptr() as usize;
    if p >= start && p + part.len() <= end {
        frame.slice_ref(part)
    } else {
        Bytes::copy_from_slice(part)
    }
}

/// A call's place in the table: gone when the pipe ends, or when the half
/// closes before it does.
pub(crate) struct SlotGuard {
    table: Arc<InputTable>,
    subscription: u64,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        lock(&self.table.slots).remove(&self.subscription);
        self.table.open.fetch_sub(1, Ordering::AcqRel);
    }
}

// ---------------------------------------------------------------------------
// The seam between `{ns}.call` and the method's dispatch
// ---------------------------------------------------------------------------

/// What `{ns}.call` hands the dispatch, for a method that turns out to have
/// an input half: nothing is built here, so a method without one costs a
/// move. Everything of it comes back when the dispatch is over.
pub(crate) struct Seam {
    pub(crate) service: DynamicHub,
    /// The call's params as they came (read again only by [`open`]).
    pub(crate) params: Params<'static>,
    pub(crate) pending: Option<PendingSubscriptionSink>,
    pub(crate) ext: Extensions,
    /// The grants generation before the dispatch's decision.
    pub(crate) seen: u64,
    pub(crate) opened: Option<Opened>,
    /// A refusal at open, as its item (`too_many_calls {max}`).
    pub(crate) refused: Option<Value>,
}

/// A call its [`open`] accepted.
pub(crate) struct Opened {
    pub(crate) sink: SubscriptionSink,
    pub(crate) duplex: Duplex,
}

/// What the pipe drives.
pub(crate) struct Duplex {
    pub(crate) ledger: Arc<Ledger>,
    pub(crate) gate: Pin<Box<dyn Stream<Item = Result<Batch, DuplexRefusal>> + Send>>,
    pub(crate) inbox: mpsc::UnboundedSender<Batch>,
    pub(crate) credit: CreditLine,
    pub(crate) ns: Arc<str>,
    pub(crate) to: FrameSink,
    pub(crate) slot: SlotGuard,
}

tokio::task_local! {
    pub(crate) static CALL: RefCell<Seam>;
}

/// The refusal for everywhere that carries no input half.
fn unserved(method: &str) -> PlexusError {
    PlexusError::ExecutionError(format!(
        "`{method}` takes an input stream, and this transport carries none: call it over a WebSocket"
    ))
}

impl Seam {
    /// Everything of an open but the acceptance: the gate's decision taken
    /// up, the call's place taken, the slot in the table.
    fn open<T>(&mut self, method: &str, ceiling: CallCeiling) -> Result<(Input<T>, PendingSubscriptionSink, Duplex), PlexusError> {
        let (Some(table), Some(to)) = (self.ext.get::<Arc<InputTable>>().cloned(), self.ext.get::<FrameSink>().cloned()) else {
            return Err(unserved(method));
        };
        let Some(pending) = self.pending.as_ref() else {
            return Err(unserved(method));
        };
        let SubscriptionId::Num(subscription) = pending.subscription_id() else {
            return Err(PlexusError::ExecutionError(format!("`{method}`: an input half needs integer subscription ids")));
        };
        let call: super::plexus::CallParams = self.params.parse().map_err(|e| PlexusError::InvalidParams(e.to_string()))?;
        // A method's own body routing to another: the subscription is the
        // call's, and that one has no caller to stream to it.
        if !call.method.ends_with(method) {
            return Err(unserved(method));
        }
        let terms = self.service.input_terms(&call.method, call.params.as_ref().unwrap_or(&Value::Null))?;
        let ns: Arc<str> = Arc::from(self.service.runtime_namespace());
        let caller = self.ext.get::<Arc<AuthContext>>().cloned();
        let at = CallRef { conn: table.conn.0, subscription };
        let opened = self.service.duplex_gate().admitted(at, &*table.calls, caller, &terms.grant, terms.targets, self.seen, terms.recheck, ceiling, Answerer::Caller);
        let call: DuplexCall = match opened {
            Ok(c) => c,
            Err(why) => {
                let item = why.to_item(&ns);
                let message = item.get("message").and_then(Value::as_str).unwrap_or("refused").to_string();
                self.refused = Some(item);
                return Err(PlexusError::ExecutionError(message));
            }
        };
        let credit = call.credit_line();
        let ledger = Arc::new(Ledger::new(ceiling.credit));
        let (tx, rx) = mpsc::unbounded_channel();
        let (inbox, handler) = mpsc::unbounded_channel();
        let slot = table.attach(
            subscription,
            Slot { ns: ns.clone(), next_seq: 0, tx: Some(tx), ledger: ledger.clone(), max_buffered: ceiling.max_buffered },
        );
        // `refused` is for a frame of another connection, and the table is
        // this connection's: nothing reads it.
        let (not_ours, _) = mpsc::unbounded_channel();
        let gate = Box::pin(call.input(UnboundedReceiverStream::new(rx), not_ours));
        let pending = self.pending.take().expect("checked above");
        let input = Input { source: Source::Wire(WireInput { rx: handler, cur: None, ledger: ledger.clone(), over: false }) };
        Ok((input, pending, Duplex { ledger, gate, inbox, credit, ns, to, slot }))
    }
}

/// Open the input half of the call being dispatched (the macro's dispatch of
/// a method with an [`Input`] parameter). `method` names it to a refusal.
pub async fn open<T>(method: &'static str, ceiling: CallCeiling) -> Result<Input<T>, PlexusError> {
    let (input, pending, duplex) = CALL
        .try_with(|seam| seam.borrow_mut().open::<T>(method, ceiling))
        .unwrap_or_else(|_| Err(unserved(method)))?;
    // The slot is in the table: a frame the client sends on reading this
    // answer finds it.
    let sink = pending.accept().await.map_err(|_| PlexusError::ExecutionError("the connection closed".into()))?;
    let _ = CALL.try_with(|seam| seam.borrow_mut().opened = Some(Opened { sink, duplex }));
    Ok(input)
}
