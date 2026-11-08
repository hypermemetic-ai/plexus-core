//! PERF-7: the item path — an item encoded once, by its method's own event
//! type, straight into a buffer its socket writes from.
//!
//! | when | then |
//! | -- | -- |
//! | a method yields an event under the WebSocket pipe ([`pipe`]) | [`wrap_stream`](super::streaming::wrap_stream) serializes it once, by its own `Serialize`, into the pipe's buffer (a block from its connection's pool); the `Data` item carries it as [`Content`] — JSON bytes, no `Value` |
//! | the pipe's buffer takes an event's JSON (`json`, PERF-34) | written by a real scan, not a byte at a time, the bytes `serde_json` writes |
//! | the same event anywhere else (in process, a nested route, a test) | it becomes a `Value` as before: in-process items stay what they cost |
//! | a transformer reads a `Data` item's content | [`Content`] decodes its bytes once, on demand (`Deref` to `Value`); one that rewrites it replaces the whole [`Content`] — an encoded item is a `Data` item, so no rewrite can miss one (PERF-17's finding: the gated view's rewrite did) |
//! | the pipe writes an item | the notification's prefix (once a call), the metadata (once a stream), the content type and the content's bytes, and the suffix, into the same buffer: one frame, split off as `Bytes` (no allocation while the block has room) |
//! | the transport offers a [`FrameSink`] (plexus-transport's socket loop) | the frame goes to the socket's writer as it is; the call's first frame is fenced, so it follows the subscription's answer that jsonrpsee queued |
//! | it does not (jsonrpsee's own sink: stdio, an in-memory module) | the item's bytes go to the sink as one raw value, as before |
//! | one change fans out to N watchers ([`Shared`]) | the first socket that sends it encodes it, once; every other writes those bytes |
//! | a call has an input half ([`super::input`]) | [`pipe_duplex`] takes it instead: the same frames and buffer, and beside the method's items the frames of the input half (`credit`, `ack`, `input_closed`), made here since they are this transport's and no method's. [`pipe`] is unchanged by them |
//! | the client offered `batch` at its upgrade ([`FrameSink::batching`], PERF-8) | the items a stream has ready together, up to the batch and about [`BATCH_BYTES`], go in one notification whose `results` are their array, the metadata said once; a lone item goes at once, in today's form |
//!
//! PERF-8 batches frames here (`results: […]`), PERF-9 adds an encoding
//! ([`WireEncoding`]), PERF-13 relays a child's content as bytes.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::Value;

use super::types::{PlexusStreamItem, StreamMetadata};

mod json;

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// A `data` item's content: the method's event, encoded once (JSON bytes),
/// or a `Value` — whichever the item was made with. Reads as a `Value`
/// either way ([`Content::value`], `Deref`), the bytes decoded once on
/// demand; serializes as its JSON. Equal as JSON is equal.
#[derive(Clone, Default)]
pub struct Content(Repr);

#[derive(Clone)]
enum Repr {
    Value(Value),
    /// JSON text the pipe's writer wrote (valid by construction: the bytes
    /// serde_json writes), and its `Value` once someone asked for it.
    Json { text: Bytes, value: OnceLock<Value> },
}

impl Default for Repr {
    fn default() -> Self {
        Repr::Value(Value::Null)
    }
}

impl Content {
    /// Content that is a `Value`.
    pub fn from_value(value: Value) -> Self {
        Content(Repr::Value(value))
    }

    /// Content that is JSON text, checked (a parse, no `Value` built).
    pub fn from_json(text: Bytes) -> Result<Self, serde_json::Error> {
        serde_json::from_slice::<serde::de::IgnoredAny>(&text)?;
        Ok(Self::json(text))
    }

    /// JSON text the pipe's writer wrote, taken as it is.
    pub(crate) fn json(text: Bytes) -> Self {
        Content(Repr::Json { text, value: OnceLock::new() })
    }

    /// The content as a `Value` (encoded bytes decoded once, kept).
    pub fn value(&self) -> &Value {
        match &self.0 {
            Repr::Value(v) => v,
            Repr::Json { text, value } => value.get_or_init(|| serde_json::from_slice(text).unwrap_or(Value::Null)),
        }
    }

    /// The content as an owned `Value`.
    pub fn into_value(self) -> Value {
        match self.0 {
            Repr::Value(v) => v,
            Repr::Json { text, value } => value.into_inner().unwrap_or_else(|| serde_json::from_slice(&text).unwrap_or(Value::Null)),
        }
    }

    /// A copy of the content as a `Value`.
    pub fn to_value(&self) -> Value {
        match &self.0 {
            Repr::Value(v) => v.clone(),
            Repr::Json { text, value } => value.get().cloned().unwrap_or_else(|| serde_json::from_slice(text).unwrap_or(Value::Null)),
        }
    }

    /// The content as `T`, decoded straight from its bytes when it is
    /// encoded (no `Value` in between).
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match &self.0 {
            Repr::Value(v) => T::deserialize(v),
            Repr::Json { text, value } => match value.get() {
                Some(v) => T::deserialize(v),
                None => serde_json::from_slice(text),
            },
        }
    }

    /// The JSON text the content was encoded as, when it was.
    pub fn json_bytes(&self) -> Option<&Bytes> {
        match &self.0 {
            Repr::Json { text, .. } => Some(text),
            Repr::Value(_) => None,
        }
    }

    /// Whether the content was encoded once from its event (PERF-7).
    pub fn is_encoded(&self) -> bool {
        matches!(self.0, Repr::Json { .. })
    }

    /// Its JSON text, appended to `out`: the bytes, or the `Value` written.
    fn write_json(&self, out: &mut BytesMut) {
        match &self.0 {
            Repr::Json { text, .. } => out.put_slice(text),
            Repr::Value(v) => {
                let _ = serde_json::to_writer((&mut *out).writer(), v);
            }
        }
    }
}

impl std::ops::Deref for Content {
    type Target = Value;
    fn deref(&self) -> &Value {
        self.value()
    }
}

impl From<Value> for Content {
    fn from(value: Value) -> Self {
        Content::from_value(value)
    }
}

impl From<Content> for Value {
    fn from(content: Content) -> Self {
        content.into_value()
    }
}

/// Whatever a `Value` compares with — another content, a `Value`, a string,
/// a number, a bool — a content compares with as its `Value`.
impl<T: ?Sized> PartialEq<T> for Content
where
    Value: PartialEq<T>,
{
    fn eq(&self, other: &T) -> bool {
        self.value() == other
    }
}

impl PartialEq<Content> for Value {
    fn eq(&self, other: &Content) -> bool {
        self == other.value()
    }
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Value(v) => v.fmt(f),
            Repr::Json { text, .. } => write!(f, "{}", String::from_utf8_lossy(text)),
        }
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Value(v) => v.fmt(f),
            Repr::Json { text, .. } => f.write_str(&String::from_utf8_lossy(text)),
        }
    }
}

impl Serialize for Content {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if let Repr::Json { text, value } = &self.0 {
            // serde_json writes a raw value as it is; any other serializer
            // gets the `Value`.
            if writing_json() {
                if let Ok(raw) = serde_json::from_slice::<&RawValue>(text) {
                    return raw.serialize(s);
                }
            }
            if let Some(v) = value.get() {
                return v.serialize(s);
            }
        }
        self.value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Content {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Value::deserialize(d).map(Content::from_value)
    }
}

impl schemars::JsonSchema for Content {
    fn inline_schema() -> bool {
        <Value as schemars::JsonSchema>::inline_schema()
    }
    fn schema_name() -> Cow<'static, str> {
        <Value as schemars::JsonSchema>::schema_name()
    }
    fn schema_id() -> Cow<'static, str> {
        <Value as schemars::JsonSchema>::schema_id()
    }
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Value as schemars::JsonSchema>::json_schema(generator)
    }
}

// ---------------------------------------------------------------------------
// The connection's encoding and its frames
// ---------------------------------------------------------------------------

/// The encoding of every frame on a connection, fixed when it opens. JSON
/// text until PERF-9 adds msgpack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WireEncoding {
    /// JSON-RPC 2.0 objects, one text message each.
    #[default]
    Json,
}

/// A frame ready for a socket, in its connection's encoding.
#[derive(Debug, Clone)]
pub struct WireFrame {
    bytes: Bytes,
    fence: bool,
}

impl WireFrame {
    /// The frame's bytes (JSON text under [`WireEncoding::Json`]).
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The frame's bytes, owned.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// A call's first frame: written only after every frame the connection's
    /// method table queued before it (its subscription's answer among them,
    /// which jsonrpsee queues when the call is accepted).
    pub fn fenced(&self) -> bool {
        self.fence
    }
}

/// The frames a transport takes from a connection's calls (plexus-transport's
/// socket loop puts one in each call's extensions): each item a frame, in
/// order, written as it is. Cheap to clone.
#[derive(Clone)]
pub struct FrameSink {
    tx: tokio::sync::mpsc::Sender<WireFrame>,
    encoding: WireEncoding,
    /// The connection's pool: one spare block a call starts in, so a short
    /// call allocates none.
    spare: Arc<Mutex<Option<BytesMut>>>,
    /// The most items one notification carries (PERF-8): 0 or 1, one an item.
    batch: usize,
    /// BIDIR-6: the connection's input halves. Carried here, not as an entry
    /// of its own in the extensions, which every call clones: an entry is an
    /// allocation a call (call.one_item's +2 allocations, +192 bytes).
    inputs: Option<Arc<super::input::InputTable>>,
}

/// The most items one notification carries when the client offered `batch`
/// at its upgrade (PERF-8, spec/02): a client may ask for fewer.
pub const MAX_BATCH: usize = 64;

/// Where a batch stops taking items: once what it holds reaches this many
/// bytes, so a batch of large items stays small. A queue's 1,024 frames are
/// bounded by frames, not bytes (PERF.115-37), and each item takes its size
/// twice from a block: 64 items of 4 KB to a frame held 280 KB a frame and
/// allocated a 512 KiB block every few frames, 16 KiB still 4,096 B an item
/// in one run of two, and a ticket body's batch would hold a megabyte. At
/// 8 KiB a full queue of 4 KB items holds about 18 MB, which the call's 80
/// spare blocks keep. PERF-17 found a count alone cost a 4 KB stream 27 %, and
/// said a batch should stop at bytes.
pub const BATCH_BYTES: usize = 8 * 1024;

/// What the transport's writer reads a [`FrameSink`]'s frames from.
pub type FrameReceiver = tokio::sync::mpsc::Receiver<WireFrame>;

impl FrameSink {
    /// A connection's frame queue, bounded at `capacity` frames.
    pub fn channel(capacity: usize, encoding: WireEncoding) -> (FrameSink, FrameReceiver) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
        (FrameSink { tx, encoding, spare: Arc::new(Mutex::new(None)), batch: 0, inputs: None }, rx)
    }

    /// The same sink for a client that takes batches (it offered `batch` at
    /// its upgrade): up to `max` items a stream has ready go in one
    /// notification. 0 or 1: one an item, as before.
    pub fn batching(mut self, max: usize) -> Self {
        self.batch = max;
        self
    }

    /// BIDIR-6: the same sink carrying the connection's input halves, where a
    /// method with an `Input` finds its table.
    pub fn with_inputs(mut self, table: Arc<super::input::InputTable>) -> Self {
        self.inputs = Some(table);
        self
    }

    /// BIDIR-6: the connection's input halves, when its transport carries
    /// them.
    pub fn inputs(&self) -> Option<&Arc<super::input::InputTable>> {
        self.inputs.as_ref()
    }

    /// The most items one notification carries: 0 or 1, one an item.
    pub fn batch(&self) -> usize {
        self.batch
    }

    /// The connection's encoding.
    pub fn encoding(&self) -> WireEncoding {
        self.encoding
    }

    /// Whether the connection is gone.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    fn take_block(&self) -> Option<BytesMut> {
        self.spare.lock().ok().and_then(|mut s| s.take())
    }

    fn give_block(&self, block: BytesMut) {
        if block.capacity() <= Buffer::POOLED {
            if let Ok(mut s) = self.spare.lock() {
                if s.is_none() {
                    *s = Some(block);
                }
            }
        }
    }
}

impl std::fmt::Debug for FrameSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameSink").field("encoding", &self.encoding).field("batch", &self.batch).field("closed", &self.tx.is_closed()).finish()
    }
}

// ---------------------------------------------------------------------------
// The buffer: blocks a call's items and frames are written into
// ---------------------------------------------------------------------------

/// A call's buffer. Each item and each frame is written at the end of the
/// current block and split off as `Bytes` sharing it; a block is reused once
/// every frame cut from it has been written and dropped, and a new one is
/// allocated only when none is free.
struct Buffer {
    cur: BytesMut,
    /// Blocks still holding frames in flight, kept to be reused once free.
    spare: Vec<BytesMut>,
    /// The size a new block is made at: grown with the frames it holds.
    block: usize,
    /// Whether a block has been made (or taken from the pool) yet.
    started: bool,
    /// Blocks made, for the tests.
    #[cfg(test)]
    made: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer {
            cur: BytesMut::new(),
            spare: Vec::new(),
            block: Self::FIRST,
            started: false,
            #[cfg(test)]
            made: 0,
        }
    }
}

impl Buffer {
    /// A first block: a short call's frames fit.
    const FIRST: usize = 8 * 1024;
    /// The largest block made for a stream's frames (one larger item gets a
    /// block of its own size).
    const MOST: usize = 512 * 1024;
    /// The largest block a connection keeps for its next call.
    const POOLED: usize = 64 * 1024;
    /// Blocks kept to be reused. A stream that outruns its socket has the
    /// connection's whole queue in flight (1,024 frames), and each item has
    /// taken its size twice from a block, content and frame: 8.8 MB at 4 KB an
    /// item, 36 MB at a ticket body. Blocks that hold fewer than that are
    /// dropped before they come free, and every block filled is a new one, so
    /// a faster encode allocates more: three held 8 KB an item at 4 KB and 37 KB
    /// at a body (PERF-34; PERF-9 found it with msgpack, at b80cb2e). They are
    /// bytes those frames hold anyway.
    const SPARE: usize = 80;
    /// Blocks kept once the queue has drained: what a long watch holds.
    const DRAINED: usize = 3;

    fn from_block(block: Option<BytesMut>) -> Self {
        match block {
            Some(cur) => Buffer { block: cur.capacity().max(Self::FIRST), cur, started: true, ..Buffer::default() },
            None => Buffer::default(),
        }
    }

    /// Room for `n` more bytes in the current block: it, or a free block, or
    /// a new one.
    fn room(&mut self, n: usize) {
        if self.cur.capacity() - self.cur.len() >= n {
            return;
        }
        if self.cur.try_reclaim(n) {
            // None of this block's frames is left, and older ones went first.
            self.spare.truncate(Self::DRAINED);
            return;
        }
        // The current block holds unsent frames, or is too small: keep it
        // for later and take a free one, if any is free.
        let free = self.spare.iter_mut().position(|b| b.try_reclaim(n));
        let next = match free {
            Some(i) => self.spare.swap_remove(i),
            None => {
                // Every block is busy: the frames outrun the socket, so the
                // next block holds more of them.
                if self.started {
                    self.block = (self.block * 2).clamp(Self::FIRST, Self::MOST);
                }
                self.started = true;
                #[cfg(test)]
                {
                    self.made += 1;
                }
                BytesMut::with_capacity(self.block.max(n))
            }
        };
        let old = std::mem::replace(&mut self.cur, next);
        if old.capacity() > 0 {
            if self.spare.len() >= Self::SPARE {
                self.spare.remove(0);
            }
            self.spare.push(old);
        }
    }

    /// What was written since the last split, as `Bytes`.
    fn split(&mut self) -> Bytes {
        self.cur.split().freeze()
    }

    /// The block a call with no connection leaves for its thread's next one:
    /// all of it, with no frame of a call in flight, and not one a stream grew.
    fn into_idle(mut self) -> Option<BytesMut> {
        let _ = self.cur.try_reclaim(Self::FIRST);
        (Self::FIRST..=Self::POOLED).contains(&self.cur.capacity()).then_some(self.cur)
    }

    /// The block to give back to the connection's pool: the current one,
    /// whatever is left of it (frames still in flight keep what they hold).
    fn into_block(self) -> Option<BytesMut> {
        (self.cur.capacity() >= 1024).then_some(self.cur)
    }
}

// ---------------------------------------------------------------------------
// The pipe's encoder: the events of the stream the pipe polls
// ---------------------------------------------------------------------------

/// The pipe's encoder, for the task that polls a call's stream.
struct Encoder {
    /// The connection's encoding: JSON until PERF-9 reads it here.
    #[allow(dead_code)]
    encoding: WireEncoding,
    buffer: RefCell<Buffer>,
    /// How deep the poll is in streams [`wrap_stream`] wrapped: only the
    /// outermost encodes — a stream polled inside a method's own (a call
    /// it routes and reads in process) keeps its items as `Value`s.
    ///
    /// [`wrap_stream`]: super::streaming::wrap_stream
    depth: Cell<u32>,
    /// The last content's size, to make room for the next.
    last: Cell<usize>,
}

tokio::task_local! {
    static WIRE: Encoder;
}

thread_local! {
    /// The pipe's serde_json writer is serializing an event on this thread.
    static WRITING_JSON: Cell<u32> = const { Cell::new(0) };
}

/// Whether the serializer at work on this thread is the pipe's JSON writer
/// (so a [`Shared`] event or an encoded [`Content`] may write its bytes as
/// they are).
fn writing_json() -> bool {
    WRITING_JSON.with(|w| w.get() > 0)
}

struct WritingJson;

impl WritingJson {
    fn on() -> Self {
        WRITING_JSON.with(|w| w.set(w.get() + 1));
        WritingJson
    }
}

impl Drop for WritingJson {
    fn drop(&mut self) {
        WRITING_JSON.with(|w| w.set(w.get().saturating_sub(1)));
    }
}

/// Run `poll` (a wrapped stream's poll of its method's stream) one stream
/// deeper: what it yields is not the pipe's to encode.
pub(crate) fn nested<R>(poll: impl FnOnce() -> R) -> R {
    if WIRE.try_with(|e| e.depth.set(e.depth.get() + 1)).is_err() {
        return poll();
    }
    // Put back after the poll, a panic included.
    struct Back;
    impl Drop for Back {
        fn drop(&mut self) {
            let _ = WIRE.try_with(|e| e.depth.set(e.depth.get().saturating_sub(1)));
        }
    }
    let _back = Back;
    poll()
}

/// `event` encoded once into the pipe's buffer — when the pipe is polling
/// this stream directly, the event is not a credential's (whose envelope is
/// assembled as before) and it serializes. `None`: make a `Value` as before.
pub(crate) fn encode<T: Serialize + ?Sized>(event: &T) -> Option<Content> {
    WIRE.try_with(|e| {
        if e.depth.get() > 0 {
            return None;
        }
        let mut buffer = e.buffer.borrow_mut();
        buffer.room(e.last.get().saturating_mul(2).max(256));
        debug_assert!(buffer.cur.is_empty());
        let (written, captured) = plexus_auth_core::credential::run_with_credential_capture(|| {
            let _json = WritingJson::on();
            json::write(&mut buffer.cur, event).is_ok()
        });
        if !written || !captured.is_empty() {
            buffer.cur.clear();
            return None;
        }
        e.last.set(buffer.cur.len());
        Some(Content::json(buffer.split()))
    })
    .ok()
    .flatten()
}

thread_local! {
    /// The block of a call with no frame sink, for this thread's next one.
    /// Such a call has no connection to keep a block, and it was half of what
    /// a one-item call allocated (PERF-27).
    static IDLE: Cell<Option<BytesMut>> = const { Cell::new(None) };
}

/// One call's frames: the notification around each item. With no frame sink
/// there is none to write, so no prefix: jsonrpsee's sink writes its own.
#[derive(Default)]
struct Frames {
    /// `{"jsonrpc":"2.0","method":M,"params":{"subscription":S,"result":`
    prefix: Vec<u8>,
    /// A `data` item's opening, `{"type":"data","metadata":…,"content_type":…,"content":`,
    /// for the stream's metadata (shared by its items) and content type.
    head: Option<(Arc<StreamMetadata>, Cow<'static, str>, Vec<u8>)>,
    /// A batch's (PERF-8): `,"metadata":…,"results":[` for the stream's
    /// metadata, and a `data` item's opening without it,
    /// `{"type":"data","content_type":…,"content":`, for its content type.
    batch: Option<(Arc<StreamMetadata>, Vec<u8>)>,
    bare: Option<(Cow<'static, str>, Vec<u8>)>,
}

/// Where a notification's `params` stop and its `result` begins, in [`Frames::prefix`].
const RESULT: &[u8] = br#","result":"#;

impl Frames {
    fn new(method: &str, subscription: &jsonrpsee::types::SubscriptionId<'_>) -> Self {
        // Sized once: each grew from its first literal, and three reallocations a call.
        let mut prefix = Vec::with_capacity(64);
        prefix.extend_from_slice(br#"{"jsonrpc":"2.0","method":"#);
        let _ = serde_json::to_writer(&mut prefix, method);
        prefix.extend_from_slice(br#","params":{"subscription":"#);
        let _ = serde_json::to_writer(&mut prefix, subscription);
        prefix.extend_from_slice(RESULT);
        Frames { prefix, head: None, batch: None, bare: None }
    }

    /// `item`'s JSON, written at the end of `out`.
    fn item(&mut self, out: &mut BytesMut, item: &PlexusStreamItem) {
        match item {
            PlexusStreamItem::Data { metadata, content_type, content } => {
                let fresh = match &self.head {
                    Some((m, ct, _)) => !Arc::ptr_eq(m, metadata) || ct != content_type,
                    None => true,
                };
                if fresh {
                    let mut head = Vec::with_capacity(128);
                    head.extend_from_slice(br#"{"type":"data","metadata":"#);
                    let _ = serde_json::to_writer(&mut head, &**metadata);
                    head.extend_from_slice(br#","content_type":"#);
                    let _ = serde_json::to_writer(&mut head, content_type.as_ref());
                    head.extend_from_slice(br#","content":"#);
                    self.head = Some((metadata.clone(), content_type.clone(), head));
                }
                let head = &self.head.as_ref().expect("made above").2;
                out.reserve(head.len() + content.json_bytes().map_or(64, Bytes::len) + 1);
                out.put_slice(head);
                content.write_json(out);
                out.put_u8(b'}');
            }
            other => {
                let _ = serde_json::to_writer((&mut *out).writer(), other);
            }
        }
    }

    /// `items`, ready together, in one notification (PERF-8, spec/02):
    /// `{"jsonrpc":"2.0","method":M,"params":{"subscription":S,"metadata":…,"results":[…]}}`.
    /// The metadata is the first `data` item's, said once: a `data` item whose
    /// metadata writes the same leaves its own out; any other item is written
    /// whole, as alone.
    /// One item alone is today's frame.
    fn batch(&mut self, buffer: &mut Buffer, items: &[PlexusStreamItem]) -> Bytes {
        if let [item] = items {
            return self.frame(buffer, item);
        }
        let shared = items.iter().find_map(|item| match item {
            PlexusStreamItem::Data { metadata, .. } => Some(metadata),
            _ => None,
        });
        let open = match shared {
            Some(m) => {
                if !matches!(&self.batch, Some((had, _)) if Arc::ptr_eq(had, m)) {
                    let mut open = Vec::with_capacity(128);
                    open.extend_from_slice(br#","metadata":"#);
                    let _ = serde_json::to_writer(&mut open, &**m);
                    open.extend_from_slice(br#","results":["#);
                    self.batch = Some((m.clone(), open));
                }
                &self.batch.as_ref().expect("made above").1[..]
            }
            None => br#","results":["#,
        };
        let content: usize = items
            .iter()
            .map(|item| match item {
                PlexusStreamItem::Data { content, .. } => content.json_bytes().map_or(64, Bytes::len) + 64,
                _ => 256,
            })
            .sum();
        let start = &self.prefix[..self.prefix.len() - RESULT.len()];
        buffer.room(start.len() + open.len() + content + 4);
        buffer.cur.put_slice(start);
        buffer.cur.put_slice(open);
        for (n, item) in items.iter().enumerate() {
            if n > 0 {
                buffer.cur.put_u8(b',');
            }
            match item {
                PlexusStreamItem::Data { metadata, content_type, content } if shared.is_some_and(|m| same_metadata(m, metadata)) => {
                    if !matches!(&self.bare, Some((ct, _)) if ct == content_type) {
                        let mut bare = Vec::with_capacity(64);
                        bare.extend_from_slice(br#"{"type":"data","content_type":"#);
                        let _ = serde_json::to_writer(&mut bare, content_type.as_ref());
                        bare.extend_from_slice(br#","content":"#);
                        self.bare = Some((content_type.clone(), bare));
                    }
                    let bare = &self.bare.as_ref().expect("made above").1;
                    buffer.cur.reserve(bare.len() + content.json_bytes().map_or(64, Bytes::len) + 1);
                    buffer.cur.put_slice(bare);
                    content.write_json(&mut buffer.cur);
                    buffer.cur.put_u8(b'}');
                }
                other => self.item(&mut buffer.cur, other),
            }
        }
        buffer.cur.put_slice(b"]}}");
        buffer.split()
    }

    /// The notification carrying `item`: the frame a socket writes.
    fn frame(&mut self, buffer: &mut Buffer, item: &PlexusStreamItem) -> Bytes {
        let content = match item {
            PlexusStreamItem::Data { content, .. } => content.json_bytes().map_or(256, Bytes::len),
            _ => 256,
        };
        buffer.room(self.prefix.len() + content + 256);
        buffer.cur.put_slice(&self.prefix);
        self.item(&mut buffer.cur, item);
        buffer.cur.put_slice(b"}}");
        buffer.split()
    }

    /// The notification carrying `body`, JSON text this side wrote.
    fn body(&mut self, buffer: &mut Buffer, body: &[u8]) -> Bytes {
        buffer.room(self.prefix.len() + body.len() + 2);
        buffer.cur.put_slice(&self.prefix);
        buffer.cur.put_slice(body);
        buffer.cur.put_slice(b"}}");
        buffer.split()
    }

    /// `item` alone, for jsonrpsee's sink, which wraps it in the notification:
    /// text of its own, its exact size, written once and not read again. The
    /// copy and the check this took were most of the 6,644 instructions PERF-27
    /// took off a one-item call's 50,842.
    fn raw_item(&mut self, item: &PlexusStreamItem) -> Result<Box<RawValue>, serde_json::Error> {
        if !matches!(item, PlexusStreamItem::Data { .. }) {
            return serde_json::value::to_raw_value(item);
        }
        let mut text = BytesMut::new();
        self.item(&mut text, item);
        // This one stays: `Content::from_json` holds text to JSON's grammar, not to UTF-8.
        let text = String::from_utf8(Vec::from(text)).map_err(serde::ser::Error::custom)?;
        // SAFETY: one JSON value with nothing around it. `Frames::item` writes
        // a `data` item's opening, then its content, then `}`. The opening is
        // literal keys around values serde_json wrote into a `Vec`, which
        // cannot fail. The content is one value: `encode`'s text, whole (a
        // failed write leaves a `Value` instead); text `Content::from_json`
        // parsed, by the same parse `RawValue::from_string` would run here; or
        // a `Value`, which serde_json cannot fail to write.
        // A debug build parses it here all the same (tests/no_frame_sink.rs).
        Ok(unsafe { RawValue::from_string_unchecked(text) })
    }
}

/// Pipe a call's stream to its accepted subscription: each item encoded
/// once and written as one frame.
///
/// With a [`FrameSink`] in the call's extensions (plexus-transport's socket
/// loop) each frame goes to the socket's writer as it is, the first fenced
/// behind the subscription's answer; without one, each item goes to
/// jsonrpsee's sink as one raw value. The pipe ends
/// when the stream does, or when the caller lets go (an unsubscribe, a lost
/// socket), dropping the stream at once.
pub async fn pipe(sink: jsonrpsee::SubscriptionSink, stream: super::streaming::PlexusStream, ext: &http::Extensions) -> jsonrpsee::core::SubscriptionResult {
    let frames = ext.get::<FrameSink>().cloned();
    let encoding = frames.as_ref().map(FrameSink::encoding).unwrap_or_default();
    let block = match &frames {
        Some(to) => to.take_block(),
        None => IDLE.try_with(Cell::take).ok().flatten(),
    };
    let buffer = Buffer::from_block(block);
    let encoder = Encoder { encoding, buffer: RefCell::new(buffer), depth: Cell::new(0), last: Cell::new(0) };
    WIRE.scope(encoder, run(sink, stream, frames)).await
}

async fn run(sink: jsonrpsee::SubscriptionSink, mut stream: super::streaming::PlexusStream, frames: Option<FrameSink>) -> jsonrpsee::core::SubscriptionResult {
    use futures::StreamExt;
    let mut notification = match &frames {
        Some(_) => Frames::new(sink.method_name(), &sink.subscription_id()),
        None => Frames::default(),
    };
    let mut first = true;
    // A batch's items, kept for the call: no allocation until two are ready together.
    let mut ready: Vec<PlexusStreamItem> = Vec::new();
    let out: jsonrpsee::core::SubscriptionResult = async {
        loop {
            let item = tokio::select! {
                biased;
                _ = sink.closed() => return Ok(()),
                item = stream.next() => item,
            };
            let Some(item) = item else { return Ok(()) };
            match &frames {
                Some(to) => {
                    // PERF-8: what else the stream has ready now goes with it,
                    // for a client that takes batches. Never what is not ready
                    // yet: a lone item goes at once, in today's form.
                    let mut ended = false;
                    let mut held = if to.batch > 1 { size(&item) } else { BATCH_BYTES };
                    let more = held < BATCH_BYTES;
                    let bytes = match more.then(|| ready_now(&mut stream, &mut ended)).flatten() {
                        None => WIRE.with(|e| notification.frame(&mut e.buffer.borrow_mut(), &item)),
                        Some(next) => {
                            held += size(&next);
                            ready.push(item);
                            ready.push(next);
                            while ready.len() < to.batch && held < BATCH_BYTES && !ended {
                                match ready_now(&mut stream, &mut ended) {
                                    Some(more) => {
                                        held += size(&more);
                                        ready.push(more);
                                    }
                                    None => break,
                                }
                            }
                            let bytes = WIRE.with(|e| notification.batch(&mut e.buffer.borrow_mut(), &ready));
                            ready.clear();
                            bytes
                        }
                    };
                    if to.tx.send(WireFrame { bytes, fence: first }).await.is_err() || ended {
                        return Ok(());
                    }
                }
                None => {
                    // jsonrpsee's sink takes a raw value, which it wraps in
                    // the notification: a copy, the price of a transport
                    // without frames of its own (stdio, a module called in memory).
                    let raw = notification.raw_item(&item)?;
                    drop(item);
                    sink.send(raw).await?;
                }
            }
            first = false;
        }
    }
    .await;
    drop(stream);
    let buffer = WIRE.with(|e| std::mem::take(&mut *e.buffer.borrow_mut()));
    match &frames {
        Some(to) => {
            if let Some(block) = buffer.into_block() {
                to.give_block(block);
            }
        }
        None => {
            let _ = IDLE.try_with(|idle| idle.set(buffer.into_idle()));
        }
    }
    out
}

/// About what an item writes into a batch: its encoded content, or a guess.
fn size(item: &PlexusStreamItem) -> usize {
    match item {
        PlexusStreamItem::Data { content, .. } => content.json_bytes().map_or(256, Bytes::len),
        _ => 128,
    }
}

/// Whether two items' metadata write the same JSON: the same one, or equal
/// (a child's items, relayed, each bring their own copy).
fn same_metadata(a: &Arc<StreamMetadata>, b: &Arc<StreamMetadata>) -> bool {
    Arc::ptr_eq(a, b) || (a.timestamp == b.timestamp && a.plexus_hash == b.plexus_hash && a.provenance == b.provenance)
}

/// The stream's next item if it is ready now: no waiting, so a batch never
/// holds an item back for one that has not come. `ended` once the stream is.
fn ready_now(stream: &mut super::streaming::PlexusStream, ended: &mut bool) -> Option<PlexusStreamItem> {
    use futures::StreamExt;
    match futures::FutureExt::now_or_never(stream.next()) {
        Some(Some(item)) => Some(item),
        Some(None) => {
            *ended = true;
            None
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// The pipe of a call with an input half
// ---------------------------------------------------------------------------

/// What a call with an input half answers: its stream, or (BIDIR-17's
/// review) the route that will make it, still resolving because its handler
/// reads its input first. An error is the item to send.
pub(crate) enum Output<'a> {
    Ready(super::streaming::PlexusStream),
    Routing(std::pin::Pin<&'a mut (dyn std::future::Future<Output = Result<super::streaming::PlexusStream, Value>> + Send + 'a)>),
}

impl Output<'_> {
    /// The next turn of the output half: an item, or the route's refusal.
    async fn next(&mut self) -> Turn {
        std::future::poll_fn(|cx| loop {
            match self {
                Output::Ready(stream) => return stream.as_mut().poll_next(cx).map(Turn::Item),
                Output::Routing(route) => match route.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok(stream)) => *self = Output::Ready(stream),
                    std::task::Poll::Ready(Err(item)) => return std::task::Poll::Ready(Turn::Failed(item)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                },
            }
        })
        .await
    }
}

/// [`pipe`] for a call with an input half ([`super::input`]): the subscription
/// is already accepted, and its first frame is the first `credit`.
pub(crate) async fn pipe_duplex(sink: jsonrpsee::SubscriptionSink, out: Output<'_>, duplex: super::input::Duplex) -> jsonrpsee::core::SubscriptionResult {
    let encoding = duplex.to.encoding();
    let buffer = Buffer::from_block(duplex.to.take_block());
    let encoder = Encoder { encoding, buffer: RefCell::new(buffer), depth: Cell::new(0), last: Cell::new(0) };
    WIRE.scope(encoder, run_duplex(sink, out, duplex)).await
}

/// One frame of the input half, as `body` says.
async fn control(to: &FrameSink, notification: &mut Frames, body: &str, fence: bool) -> Result<(), ()> {
    let bytes = WIRE.with(|e| notification.body(&mut e.buffer.borrow_mut(), body.as_bytes()));
    to.tx.send(WireFrame { bytes, fence }).await.map_err(drop)
}

/// `input_closed`: the half is over, said once, before anything final.
fn input_closed(reason: &str, ack: Option<u64>) -> String {
    match ack {
        Some(seq) => format!(r#"{{"type":"input_closed","reason":{},"ack":{seq}}}"#, Value::from(reason)),
        None => format!(r#"{{"type":"input_closed","reason":{}}}"#, Value::from(reason)),
    }
}

/// What the loop below learned this turn.
enum Turn {
    /// The method's next item.
    Item(Option<PlexusStreamItem>),
    /// Nothing to write but what the ledger owes.
    Moved,
    /// The call is refused.
    Refused(super::duplex_gate::DuplexRefusal),
    /// The route answered an error: this item.
    Failed(Value),
}

async fn run_duplex(sink: jsonrpsee::SubscriptionSink, mut output: Output<'_>, duplex: super::input::Duplex) -> jsonrpsee::core::SubscriptionResult {
    use futures::StreamExt;
    let super::input::Duplex { ledger, mut gate, inbox, credit, ns, to, slot } = duplex;
    let mut inbox = Some(inbox);
    let mut slot = Some(slot);
    let mut notification = Frames::new(sink.method_name(), &sink.subscription_id());
    let mut acked = 0u64;
    let out: Result<(), ()> = async {
        // Fenced behind the subscription's answer (the client holds nothing
        // yet: it may read this before it has the id).
        control(&to, &mut notification, &format!(r#"{{"type":"credit","n":{}}}"#, ledger.window()), true).await?;
        loop {
            let turn = tokio::select! {
                biased;
                _ = sink.closed() => return Ok(()),
                frame = gate.next(), if inbox.is_some() => match frame {
                    Some(Ok(batch)) => {
                        // The handler let go of its input: the next turn says so.
                        let _ = inbox.as_ref().expect("guarded").send(batch);
                        Turn::Moved
                    }
                    Some(Err(why)) => Turn::Refused(why),
                    None => {
                        inbox = None;
                        Turn::Moved
                    }
                },
                _ = ledger.woken() => Turn::Moved,
                turn = output.next() => turn,
            };
            if let Turn::Failed(item) = turn {
                if slot.take().is_some() && !ledger.client_ended() {
                    control(&to, &mut notification, &input_closed("method_ended", ledger.last_done()), false).await?;
                }
                return control(&to, &mut notification, &serde_json::to_string(&item).unwrap_or_default(), false).await;
            }
            let (item, refused) = match turn {
                Turn::Failed(_) => unreachable!("answered above"),
                Turn::Refused(why) => (None, Some(why)),
                Turn::Item(item) => (Some(item), ledger.take_refusal()),
                Turn::Moved => (None, ledger.take_refusal()),
            };
            if let Some(owed) = ledger.owed(acked) {
                if let Some(seq) = owed.ack {
                    control(&to, &mut notification, &format!(r#"{{"type":"ack","seq":{seq}}}"#), false).await?;
                }
                acked = owed.done;
                if owed.credit > 0 {
                    credit.grant(owed.credit);
                    control(&to, &mut notification, &format!(r#"{{"type":"credit","n":{}}}"#, owed.credit), false).await?;
                }
            }
            if let Some(why) = refused {
                // The handler's input ends with the refusal, and the call
                // with it: nothing the handler says after it goes out.
                if slot.take().is_some() && !ledger.client_ended() {
                    control(&to, &mut notification, &input_closed(why.kind(), ledger.last_done()), false).await?;
                }
                let item = serde_json::to_string(&why.to_item(&ns)).unwrap_or_default();
                return control(&to, &mut notification, &item, false).await;
            }
            if ledger.abandoned() && slot.is_some() && !ledger.client_ended() {
                slot = None;
                inbox = None;
                control(&to, &mut notification, &input_closed("method_ended", ledger.last_done()), false).await?;
            }
            let Some(item) = item else { continue };
            let Some(item) = item else { return Ok(()) };
            match &item {
                // After `done` there is no channel to tell anything on.
                PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. } => {
                    inbox = None;
                    if slot.take().is_some() && !ledger.client_ended() {
                        control(&to, &mut notification, &input_closed("method_ended", ledger.last_done()), false).await?;
                    }
                }
                _ => {}
            }
            let bytes = WIRE.with(|e| notification.frame(&mut e.buffer.borrow_mut(), &item));
            drop(item);
            to.tx.send(WireFrame { bytes, fence: false }).await.map_err(drop)?;
        }
    }
    .await;
    drop(output);
    let _ = out; // Err: the socket is gone, as the call's end says.
    if let Some(block) = WIRE.with(|e| std::mem::take(&mut *e.buffer.borrow_mut())).into_block() {
        to.give_block(block);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared: one event, many streams
// ---------------------------------------------------------------------------

/// An event many streams send — one change fanned out to every watcher.
/// The first socket that sends it encodes it, once; every other writes
/// those bytes as they are (PERF-7's fan-out). Anywhere else (in process, a
/// `Value`, another encoding) it serializes as `T` does. Reads as `T`.
///
/// An event that carries a credential is not kept encoded: each stream
/// encodes it, so each assembles its own `_credentials` envelope.
pub struct Shared<T>(Arc<SharedInner<T>>);

struct SharedInner<T> {
    value: T,
    /// The JSON the first socket wrote (`None`: never kept — a credential).
    json: OnceLock<Option<Box<RawValue>>>,
}

impl<T> Shared<T> {
    /// `value`, to be sent by many streams.
    pub fn new(value: T) -> Self {
        Shared(Arc::new(SharedInner { value, json: OnceLock::new() }))
    }

    /// Whether this event has been encoded (a socket has sent it).
    pub fn is_encoded(&self) -> bool {
        matches!(self.0.json.get(), Some(Some(_)))
    }
}

impl<T: Serialize> Shared<T> {
    fn encoded(&self) -> Option<&RawValue> {
        self.0
            .json
            .get_or_init(|| {
                let (text, captured) = plexus_auth_core::credential::run_with_credential_capture(|| serde_json::to_string(&self.0.value));
                match text {
                    Ok(text) if captured.is_empty() => RawValue::from_string(text).ok(),
                    _ => None,
                }
            })
            .as_deref()
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Shared(self.0.clone())
    }
}

impl<T> std::ops::Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0.value
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.value.fmt(f)
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Shared::new(T::default())
    }
}

impl<T: Serialize> Serialize for Shared<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if writing_json() {
            if let Some(raw) = self.encoded() {
                return raw.serialize(s);
            }
        }
        self.0.value.serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Shared<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Shared::new)
    }
}

impl<T: schemars::JsonSchema> schemars::JsonSchema for Shared<T> {
    fn inline_schema() -> bool {
        T::inline_schema()
    }
    fn schema_name() -> Cow<'static, str> {
        T::schema_name()
    }
    fn schema_id() -> Cow<'static, str> {
        T::schema_id()
    }
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        T::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use super::*;

    #[test]
    fn content_reads_as_its_value_either_way() {
        let v = serde_json::json!({"b": [1, 2], "a": "x"});
        let encoded = Content::from_json(Bytes::from_static(br#"{"b":[1,2],"a":"x"}"#)).unwrap();
        let valued = Content::from(v.clone());
        assert!(encoded.is_encoded() && !valued.is_encoded());
        assert_eq!(encoded, v);
        assert_eq!(valued, v);
        assert_eq!(encoded, valued);
        assert_eq!(encoded["a"], "x");
        assert_eq!(encoded.decode::<serde_json::Map<String, Value>>().unwrap().len(), 2);
        assert_eq!(serde_json::to_value(&encoded).unwrap(), v);
        assert_eq!(serde_json::to_string(&encoded).unwrap(), serde_json::to_string(&v).unwrap(), "outside the pipe it writes its Value");
        assert_eq!(encoded.into_value(), v);
        assert!(Content::from_json(Bytes::from_static(b"{nope")).is_err());
    }

    /// PERF-27: a block a call was half of what a one-item call allocated on
    /// a transport with no frame sink, which has no connection to keep one.
    #[test]
    fn a_call_with_no_connection_leaves_its_block_whole_for_the_next() {
        let mut b = Buffer::default();
        b.room(300);
        b.cur.put_slice(&[1u8; 300]);
        drop(b.split());
        let block = b.into_idle().expect("a block this size is kept");
        assert!(block.capacity() >= Buffer::FIRST, "all of it again, not what was left: {}", block.capacity());
        let mut next = Buffer::from_block(Some(block));
        let kept = next.cur.as_ptr();
        next.room(300);
        assert_eq!(next.cur.as_ptr(), kept, "the next call makes none");
    }

    /// One a stream grew is not kept, or a thread holds it for good.
    #[test]
    fn a_block_too_large_to_keep_goes() {
        let mut b = Buffer::default();
        b.room(Buffer::POOLED + 1);
        assert!(b.into_idle().is_none());
    }

    /// A stream that outruns its socket holds the queue's 1,024 frames in
    /// flight. The blocks in rotation must hold them, or every block filled is
    /// a new one: at 4 KB an item (8.6 KB of block each, content and frame) a
    /// fresh block every 60 items, at a ticket body one every 15, for the
    /// stream's life. Red with 3 spares.
    #[test]
    fn a_queue_full_of_frames_comes_back_to_blocks_already_made() {
        for size in [8_600, 35_500] {
            let mut b = Buffer::default();
            let mut in_flight = std::collections::VecDeque::new();
            let item = vec![7u8; size];
            let mut ramp = 0;
            for n in 0..40_000 {
                b.room(item.len());
                b.cur.put_slice(&item);
                in_flight.push_back(b.split());
                if in_flight.len() > 1024 {
                    in_flight.pop_front();
                }
                if n == 20_000 {
                    ramp = b.made;
                }
            }
            assert_eq!(b.made, ramp, "at {size} B: past the ramp ({ramp} blocks), every block is one already made");
        }
    }

    /// Those blocks are for the burst: a watch that lives on after one holds
    /// what it held before it.
    #[test]
    fn a_drained_queue_lets_its_blocks_go() {
        let mut b = Buffer::default();
        let mut in_flight = Vec::new();
        for _ in 0..4_000 {
            b.room(35_500);
            b.cur.put_slice(&[7u8; 35_500]);
            in_flight.push(b.split());
        }
        assert_eq!(b.spare.len(), Buffer::SPARE, "the burst keeps them");
        drop(in_flight);
        for _ in 0..200 {
            b.room(35_500);
            b.cur.put_slice(&[7u8; 35_500]);
            drop(b.split());
        }
        assert!(b.spare.len() <= Buffer::DRAINED, "drained, it keeps {}", b.spare.len());
    }

    #[test]
    fn a_buffer_reuses_a_block_once_its_frames_are_gone() {
        let mut b = Buffer::default();
        b.room(100);
        b.cur.put_slice(&[1u8; 100]);
        let first = b.split();
        let block = b.cur.capacity() + 100;
        for _ in 0..1000 {
            b.room(100);
            b.cur.put_slice(&[2u8; 100]);
            drop(b.split());
        }
        assert_eq!(first.len(), 100, "a frame in flight stays whole");
        assert!(b.block <= Buffer::FIRST * 2, "blocks are reused, not grown, when frames are written: {} (first {block})", b.block);
    }

    // -----------------------------------------------------------------------
    // PERF-34: the writer, held to serde_json
    // -----------------------------------------------------------------------

    /// What the pipe's writer writes for `value` against `serde_json::to_vec`:
    /// the same bytes, or a refusal where it refuses.
    #[track_caller]
    fn same_as_serde_json<T: Serialize + ?Sized>(value: &T) {
        let _raw = WritingJson::on();
        let want = serde_json::to_vec(value);
        let mut got = BytesMut::new();
        let wrote = json::write(&mut got, value);
        match want {
            Ok(want) => {
                assert!(wrote.is_ok(), "serde_json wrote {}, the writer refused: {:?}", String::from_utf8_lossy(&want), wrote.err());
                assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&want));
                assert_eq!(&got[..], &want[..]);
            }
            Err(e) => assert!(wrote.is_err(), "serde_json refused ({e}), the writer wrote {}", String::from_utf8_lossy(&got)),
        }
    }

    /// A seeded xorshift: a property test with no dependency, the same cases
    /// every run, and a failure that names what it failed on.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Everything a string can be, weighted to what breaks a scan: runs of
    /// plain text around each block size, every control character, quotes and
    /// backslashes alone and together, text that looks escaped and is not, and
    /// everything past ASCII, each width.
    fn a_string(r: &mut Rng) -> String {
        const PIECES: &[&str] = &[
            "\"", "\\", "\\\\", "\\\"", "\"\"", "\n", "\r", "\t", "\u{8}", "\u{c}", "\u{0}", "\u{1}", "\u{1f}", "\u{7f}", "\u{80}", "\u{ff}", "/", "é", "→", "—", "\u{2028}", "\u{2029}", "\u{feff}", "𝄞", "😀", "\u{10ffff}",
            "\\n", "\\u00e9", "\\ud83d", "\\x41", "\\", "\\u", "\\u12", "u0041", "<m-field label=\"x\">", "`code`", "{\"json\":\"in a string\"}", "null", " ",
        ];
        let mut s = String::new();
        for _ in 0..r.below(12) {
            match r.below(4) {
                0 => s.push_str(PIECES[r.below(PIECES.len())]),
                1 => s.extend(std::iter::repeat_n('x', r.below(70))),
                2 => s.push(char::from(r.below(128) as u8)),
                _ => s.push(char::from_u32(r.next() as u32 % 0x11_0000).unwrap_or('\u{fffd}')),
            }
        }
        s
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum External {
        Unit,
        Newtype(String),
        Tuple(u8, String),
        Struct { a: u8, b: String },
    }

    #[derive(Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Internal {
        Unit,
        Newtype(Inner),
        Struct { n: u64, text: String, maybe: Option<String>, list: Vec<String> },
    }

    #[derive(Serialize)]
    #[serde(tag = "t", content = "c")]
    enum Adjacent {
        Unit,
        Newtype(String),
        Tuple(u8, u8),
        Struct { s: String },
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum Untagged {
        Number(u8),
        Text(String),
        Fields { s: String },
    }

    #[derive(Serialize, Clone)]
    struct Inner {
        s: String,
        #[serde(rename = "a key with a \"quote\" and a \n")]
        renamed: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        skipped: Option<u8>,
    }

    /// A field's name that wants a look: the first, the next, and one past a block.
    #[derive(Serialize)]
    struct Names {
        #[serde(rename = "a \"first\" name\t")]
        first: u8,
        #[serde(rename = "a \\next\\ name")]
        next: u8,
        a_name_that_is_longer_than_a_block_of_sixteen: u8,
        #[serde(rename = "")]
        empty: u8,
        #[serde(rename = "é")]
        past_ascii: u8,
    }

    #[derive(Serialize)]
    struct Flat {
        a: u8,
        #[serde(flatten)]
        inner: Inner,
        #[serde(flatten)]
        rest: BTreeMap<String, Value>,
    }

    #[derive(Serialize)]
    struct Nothing;

    #[derive(Serialize)]
    struct Wrapped(String);

    #[derive(Serialize)]
    struct Pair(u8, String);

    #[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "snake_case")]
    enum KeyName {
        First,
    }

    #[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
    struct WrappedKey(String);

    /// `serialize_bytes`, as `serde_bytes` calls it.
    struct Blob(&'static [u8]);

    impl Serialize for Blob {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.0)
        }
    }

    /// `collect_str`, in pieces.
    struct Pieces(String);

    impl std::fmt::Display for Pieces {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for (i, piece) in self.0.split('x').enumerate() {
                if i > 0 {
                    f.write_str("x\"")?;
                }
                f.write_str(piece)?;
            }
            Ok(())
        }
    }

    impl Serialize for Pieces {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(self)
        }
    }

    /// A length that lies: serde_json writes what it is told, so the writer does.
    struct Lies(Option<usize>, u8);

    impl Serialize for Lies {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::{SerializeMap, SerializeSeq};
            if self.1 == 0 {
                let mut seq = s.serialize_seq(self.0)?;
                seq.serialize_element(&1)?;
                seq.serialize_element(&2)?;
                seq.end()
            } else {
                let mut map = s.serialize_map(self.0)?;
                map.serialize_entry("a", &1)?;
                map.serialize_entry("b", &2)?;
                map.end()
            }
        }
    }

    /// A `Serialize` that fails partway, as a credential's or a user's can.
    struct Fails;

    impl Serialize for Fails {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::{Error, SerializeStruct};
            let mut st = s.serialize_struct("Fails", 2)?;
            st.serialize_field("written", "so far")?;
            st.end()?;
            Err(S::Error::custom("no"))
        }
    }

    #[test]
    fn same_bytes_as_serde_json_on_every_shape() {
        same_as_serde_json(&());
        same_as_serde_json(&Nothing);
        same_as_serde_json(&Wrapped("x\"".into()));
        same_as_serde_json(&Pair(1, "a\n".into()));
        same_as_serde_json(&(1, "two", 3.5, true, None::<u8>, Some('c')));
        same_as_serde_json(&Vec::<u8>::new());
        same_as_serde_json(&Vec::<Vec<u8>>::from([vec![], vec![1], vec![]]));
        same_as_serde_json(&[(); 2]);
        same_as_serde_json(&BTreeMap::<String, u8>::new());
        same_as_serde_json(&BTreeMap::from([("a\"b".to_string(), BTreeMap::from([(1, 2)]))]));
        same_as_serde_json(&Blob(b""));
        same_as_serde_json(&Blob(b"\x00\xffabc"));
        same_as_serde_json(&'x');
        same_as_serde_json(&'"');
        same_as_serde_json(&'\u{1}');
        same_as_serde_json(&'𝄞');
        same_as_serde_json(&std::net::IpAddr::from([127, 0, 0, 1]));
        same_as_serde_json(&std::time::Duration::from_millis(1500));
        same_as_serde_json(&std::marker::PhantomData::<u8>);
        same_as_serde_json(&Ok::<u8, String>(1));
        same_as_serde_json(&Err::<u8, String>("no".into()));
        same_as_serde_json(&std::borrow::Cow::Borrowed("a\tb"));
        same_as_serde_json(&Arc::<str>::from("shared\n"));
        for lie in [None, Some(0), Some(1), Some(5)] {
            same_as_serde_json(&Lies(lie, 0));
            same_as_serde_json(&Lies(lie, 1));
        }
        same_as_serde_json(&Fails);
        same_as_serde_json(&vec![Some(Fails)]);
        same_as_serde_json(&External::Unit);
        same_as_serde_json(&External::Newtype("n\"".into()));
        same_as_serde_json(&External::Tuple(1, "t".into()));
        same_as_serde_json(&External::Struct { a: 1, b: "b".into() });
        same_as_serde_json(&Internal::Unit);
        same_as_serde_json(&Adjacent::Unit);
        same_as_serde_json(&Adjacent::Newtype("n".into()));
        same_as_serde_json(&Adjacent::Tuple(1, 2));
        same_as_serde_json(&Adjacent::Struct { s: "s".into() });
        same_as_serde_json(&Untagged::Number(1));
        same_as_serde_json(&Untagged::Text("t".into()));
        same_as_serde_json(&Untagged::Fields { s: "s".into() });
        same_as_serde_json(&Names { first: 1, next: 2, a_name_that_is_longer_than_a_block_of_sixteen: 3, empty: 4, past_ascii: 5 });
    }

    #[test]
    fn same_bytes_as_serde_json_on_every_number() {
        same_as_serde_json(&[u8::MIN, u8::MAX]);
        same_as_serde_json(&[u16::MAX]);
        same_as_serde_json(&[u32::MAX]);
        same_as_serde_json(&[u64::MIN, 1, 9, 10, 99, 100, u64::MAX]);
        same_as_serde_json(&[u128::MAX]);
        same_as_serde_json(&[i8::MIN, i8::MAX]);
        same_as_serde_json(&[i16::MIN]);
        same_as_serde_json(&[i32::MIN]);
        same_as_serde_json(&[i64::MIN, -1, 0, i64::MAX]);
        same_as_serde_json(&[i128::MIN, i128::MAX]);
        for f in [0.0, -0.0, 0.1, 1.0, 1.5, -1.5, 1e7, 1e15, 1e16, 1e20, 1e21, 1e22, 1e100, 1e-5, 1e-7, 1e-100, 5e-324, 2.2250738585072014e-308, f64::MAX, f64::MIN, f64::EPSILON, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            same_as_serde_json(&f);
            same_as_serde_json(&(f as f32));
        }
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..20_000 {
            let bits = r.next();
            same_as_serde_json(&f64::from_bits(bits));
            same_as_serde_json(&f32::from_bits(bits as u32));
            same_as_serde_json(&(bits as i64));
        }
    }

    /// serde_json's map keys: a string, or what reads as one; anything else
    /// refused by both.
    #[test]
    fn same_bytes_as_serde_json_on_every_key() {
        same_as_serde_json(&BTreeMap::from([(1u8, 0)]));
        same_as_serde_json(&BTreeMap::from([(-1i64, 0)]));
        same_as_serde_json(&BTreeMap::from([(u128::MAX, 0)]));
        same_as_serde_json(&BTreeMap::from([(i128::MIN, 0)]));
        same_as_serde_json(&BTreeMap::from([(true, 0)]));
        same_as_serde_json(&BTreeMap::from([('"', 0)]));
        same_as_serde_json(&BTreeMap::from([("a key\n", 0)]));
        same_as_serde_json(&BTreeMap::from([(KeyName::First, 0)]));
        same_as_serde_json(&BTreeMap::from([(WrappedKey("a\"".into()), 0)]));
        same_as_serde_json(&BTreeMap::from([(Some(1), 0)]));
        same_as_serde_json(&BTreeMap::from([(None::<u8>, 0)]));
        same_as_serde_json(&BTreeMap::from([(vec![1], 0)]));
        same_as_serde_json(&BTreeMap::from([((), 0)]));
        same_as_serde_json(&BTreeMap::from([((1, 2), 0)]));
        same_as_serde_json(&HashMap::from([(1.5f64.to_string(), 0)]));
        for key in [1.5f64, -0.0, 1e21, f64::NAN, f64::INFINITY] {
            same_as_serde_json(&FloatKey(key));
            same_as_serde_json(&FloatKey32(key as f32));
        }
        same_as_serde_json(&PiecesKey("axb\n".into()));
        same_as_serde_json(&BlobKey);
    }

    struct FloatKey(f64);

    impl Serialize for FloatKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(Some(1))?;
            map.serialize_entry(&self.0, &0)?;
            map.end()
        }
    }

    struct FloatKey32(f32);

    impl Serialize for FloatKey32 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(Some(1))?;
            map.serialize_entry(&self.0, &0)?;
            map.end()
        }
    }

    struct PiecesKey(String);

    impl Serialize for PiecesKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(Some(1))?;
            map.serialize_entry(&Pieces(self.0.clone()), &0)?;
            map.end()
        }
    }

    struct BlobKey;

    impl Serialize for BlobKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(None)?;
            map.serialize_entry(&Blob(b"no"), &0)?;
            map.end()
        }
    }

    /// A raw value's text goes as it is, whatever is in it; a `Content` and a
    /// `Shared`, encoded, are raw values to the writer.
    #[test]
    fn same_bytes_as_serde_json_on_raw_values() {
        #[derive(Serialize)]
        struct Holds {
            raw: Box<RawValue>,
            content: Content,
            shared: Shared<Inner>,
        }
        let raw = |text: &str| RawValue::from_string(text.to_string()).unwrap();
        same_as_serde_json(&raw(r#"{ "spaced" : [1, 2.50, "é"] }"#));
        same_as_serde_json(&raw("null"));
        same_as_serde_json(&Some(raw("[]")));
        same_as_serde_json(&vec![raw("1"), raw("\"two\"")]);
        same_as_serde_json(&BTreeMap::from([("k", raw("{}"))]));
        same_as_serde_json(&BTreeMap::from([(raw("\"a raw key\""), 0)].map(|(k, v)| (k.get().to_string(), v))));
        let inner = Inner { s: "s\"".into(), renamed: 1, skipped: None };
        let held = Holds {
            raw: raw("[ 1 ]"),
            content: Content::from_json(Bytes::from_static(br#"{"b":[1,2], "a":"x"}"#)).unwrap(),
            shared: Shared::new(inner.clone()),
        };
        same_as_serde_json(&held);
        same_as_serde_json(&Content::from(serde_json::json!({"a": 1})));
        same_as_serde_json(&Shared::new(inner));
        // a tag around a raw value, which serde_json refuses
        #[derive(Serialize)]
        #[serde(tag = "type")]
        enum Tagged {
            Raw(Box<RawValue>),
        }
        same_as_serde_json(&Tagged::Raw(raw("{}")));
    }

    #[test]
    fn same_bytes_as_serde_json_on_every_string() {
        let mut r = Rng(0x2545_F491_4F6C_DD1D);
        for _ in 0..200_000 {
            let s = a_string(&mut r);
            same_as_serde_json(&s);
            same_as_serde_json(&Pieces(s));
        }
        for len in 0..300 {
            same_as_serde_json(&"x".repeat(len));
            same_as_serde_json(&"é".repeat(len));
            same_as_serde_json(&"\"".repeat(len));
            same_as_serde_json(&"\u{1}".repeat(len));
        }
        // a string that grows sixfold, past any room made for its length
        same_as_serde_json(&"\u{1f}".repeat(1 << 20));
    }

    /// Every shape with the strings of [`a_string`] in it: keys included.
    #[test]
    fn same_bytes_as_serde_json_on_random_events() {
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..20_000 {
            let (a, b, c) = (a_string(&mut r), a_string(&mut r), a_string(&mut r));
            same_as_serde_json(&Internal::Struct { n: r.next(), text: a.clone(), maybe: (r.below(2) == 0).then(|| b.clone()), list: vec![c.clone(), a.clone()] });
            same_as_serde_json(&Internal::Newtype(Inner { s: b.clone(), renamed: r.next() as u8, skipped: (r.below(2) == 0).then_some(1) }));
            same_as_serde_json(&Flat { a: 1, inner: Inner { s: c.clone(), renamed: 2, skipped: None }, rest: BTreeMap::from([(a.clone(), Value::String(b.clone()))]) });
            let value = serde_json::json!({ (a.clone()): [b.clone(), null, 1, -1, 1.5, true, { (c.clone()): {} }, []] });
            same_as_serde_json(&value);
            same_as_serde_json(&Content::from(value));
            same_as_serde_json(&BTreeMap::from([(a, b), (c, String::new())]));
        }
    }

    /// PERF-34: a hit at every position, around each block size, by each scan.
    #[test]
    fn scan_at_every_offset() {
        const ESCAPED: &[u8] = &[b'"', b'\\', 0x00, 0x01, 0x08, b'\t', b'\n', 0x0c, b'\r', 0x1f];
        const PLAIN: &[u8] = &[b'x', b' ', b'!', b'#', b'/', b'[', b']', b'^', 0x7f, 0x80, 0xc3, 0xff];
        let mut scans: Vec<(&str, unsafe fn(&[u8], *mut u8) -> usize)> = vec![("a byte at a time", json::scan::one_at_a_time), ("the best this CPU has", json::scan::copy_clean)];
        #[cfg(target_arch = "x86_64")]
        scans.push(("a CPU without AVX2", json::scan::x86::sse2));
        for (name, scan) in scans {
            for len in 0..=130usize {
                for fill in PLAIN {
                    let mut text = vec![*fill; len];
                    let mut copy = vec![0u8; len];
                    // SAFETY: `copy` is as long as `text`.
                    assert_eq!(unsafe { scan(&text, copy.as_mut_ptr()) }, len, "{name}: {len} of {fill:#x}");
                    assert_eq!(copy, text, "{name}: {len} of {fill:#x}, copied");
                    for at in 0..len {
                        for escaped in ESCAPED {
                            text[at] = *escaped;
                            // SAFETY: as above.
                            assert_eq!(unsafe { scan(&text, copy.as_mut_ptr()) }, at, "{name}: {escaped:#x} at {at} of {len}");
                            assert_eq!(&copy[..at], &text[..at], "{name}: the run before {escaped:#x} at {at} of {len}");
                            // the first of two
                            if at + 1 < len {
                                text[at + 1] = b'"';
                                // SAFETY: as above.
                                assert_eq!(unsafe { scan(&text, copy.as_mut_ptr()) }, at, "{name}: the first of two at {at} of {len}");
                                text[at + 1] = *fill;
                            }
                            text[at] = *fill;
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // PERF-8: batches, for a client that offered them
    // -----------------------------------------------------------------------

    /// A content type every test item carries.
    const CT: &str = "test.count";

    fn meta(stamp: i64) -> Arc<StreamMetadata> {
        Arc::new(StreamMetadata { provenance: vec!["test".into()], plexus_hash: "ab".into(), timestamp: stamp })
    }

    /// A data item as the pipe's encode makes one: its content already JSON.
    fn data(m: &Arc<StreamMetadata>, n: u64) -> PlexusStreamItem {
        let content = Content::json(Bytes::from(serde_json::to_vec(&serde_json::json!({"type": "item", "n": n})).unwrap()));
        PlexusStreamItem::Data { metadata: m.clone(), content_type: Cow::Borrowed(CT), content }
    }

    fn done(stamp: i64) -> PlexusStreamItem {
        PlexusStreamItem::Done { metadata: StreamMetadata { provenance: vec!["test".into()], plexus_hash: "ab".into(), timestamp: stamp } }
    }

    /// Every frame `stream` makes down the pipe, to a sink batching `batch`,
    /// as JSON, until its terminal item; `wait` once the stream stops for good.
    fn frames_of(stream: super::super::streaming::PlexusStream, batch: usize) -> Vec<Value> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let (to, mut frames) = FrameSink::channel(1024, WireEncoding::Json);
            let to = to.batching(batch);
            let stream = Arc::new(Mutex::new(Some(stream)));
            let mut module = jsonrpsee::RpcModule::new(());
            module
                .register_subscription("open", "note", "close", move |_, pending, _, mut ext| {
                    let (to, stream) = (to.clone(), stream.lock().unwrap().take());
                    async move {
                        let sink = pending.accept().await?;
                        ext.insert(to);
                        pipe(sink, stream.expect("one call"), &ext).await
                    }
                })
                .unwrap();
            let (_answer, _notes) = module.raw_json_request(r#"{"jsonrpc":"2.0","id":1,"method":"open","params":[]}"#, 1).await.unwrap();
            let mut out = Vec::new();
            loop {
                let frame = tokio::time::timeout(std::time::Duration::from_secs(5), frames.recv()).await.expect("a frame in time").expect("the pipe runs");
                let v: Value = serde_json::from_slice(frame.bytes()).expect("a frame is one JSON value");
                let last = items_of(&v).last().map(|i| i["type"] == "done" || i["type"] == "error").unwrap_or(false);
                out.push(v);
                if last {
                    return out;
                }
            }
        })
    }

    /// A notification's items, as a client that offered `batch` reads them: a
    /// `result` alone, or each of `results`, a `data` item without `metadata`
    /// taking the batch's.
    fn items_of(note: &Value) -> Vec<Value> {
        let params = &note["params"];
        if let Some(one) = params.get("result") {
            return vec![one.clone()];
        }
        let shared = params.get("metadata").cloned();
        params["results"]
            .as_array()
            .expect("`result` or `results`")
            .iter()
            .map(|item| {
                let mut item = item.clone();
                if item["type"] == "data" && item.get("metadata").is_none() {
                    item["metadata"] = shared.clone().expect("a data item without metadata takes the batch's");
                }
                item
            })
            .collect()
    }

    fn ready(items: Vec<PlexusStreamItem>) -> super::super::streaming::PlexusStream {
        Box::pin(futures::stream::iter(items))
    }

    /// 200 items ready at once, then `done`: batches of 64, in order, each item
    /// equal as JSON to the one a client that offered nothing is sent.
    #[test]
    fn a_batch_is_the_items_ready_together_in_one_notification() {
        let m = meta(7);
        let make = || ready((0..200).map(|n| data(&m, n)).chain([done(7)]).collect());
        let one_each = frames_of(make(), 0);
        assert_eq!(one_each.len(), 201, "one an item");
        assert!(one_each.iter().all(|f| f["params"].get("result").is_some() && f["params"].get("results").is_none()), "today's frames");
        let batched = frames_of(make(), 64);
        let sizes: Vec<usize> = batched.iter().map(|f| items_of(f).len()).collect();
        assert_eq!(sizes, vec![64, 64, 64, 9], "what was ready, up to 64, the last with `done`");
        assert!(batched.iter().all(|f| f["params"]["results"].is_array()), "a batch is `results`");
        let unbatched: Vec<Value> = one_each.iter().flat_map(items_of).collect();
        assert_eq!(batched.iter().flat_map(items_of).collect::<Vec<_>>(), unbatched, "the same items, in order, equal as JSON");
        assert!(batched.iter().all(|f| f["params"]["subscription"] == batched[0]["params"]["subscription"] && f["method"] == "note"), "one call's, on its own method");
    }

    /// The metadata goes once a batch where it is the same: a `data` item of
    /// the batch's leaves its own out; any other keeps it.
    #[test]
    fn metadata_goes_once_a_batch_where_it_is_the_same() {
        // a child's items, relayed, each bring their own copy of the same
        let (a, b, copy) = (meta(7), meta(8), meta(7));
        let frames = frames_of(ready(vec![data(&a, 0), data(&a, 1), data(&b, 2), data(&copy, 3), done(9)]), 64);
        assert_eq!(frames.len(), 1);
        let p = &frames[0]["params"];
        assert_eq!(p["metadata"], serde_json::to_value(&*a).unwrap(), "the batch's, its first data item's");
        let raw = p["results"].as_array().unwrap();
        assert!(raw[0].get("metadata").is_none() && raw[1].get("metadata").is_none() && raw[3].get("metadata").is_none(), "the same, or an equal copy: {raw:?}");
        assert_eq!(raw[2]["metadata"], serde_json::to_value(&*b).unwrap(), "another stream's metadata stays with its item");
        assert_eq!(raw[4]["metadata"]["timestamp"], 9, "`done` keeps its own");
    }

    /// A stream that yields one item and then waits: that item goes at once,
    /// alone, in today's form. A batch is what is ready, never what a timer
    /// waits for.
    #[test]
    fn a_lone_item_goes_at_once_alone() {
        let m = meta(7);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (to, mut frames) = FrameSink::channel(16, WireEncoding::Json);
            let to = to.batching(64);
            let stream: super::super::streaming::PlexusStream = Box::pin(futures::StreamExt::chain(futures::stream::iter([data(&m, 0)]), futures::stream::pending()));
            let stream = Arc::new(Mutex::new(Some(stream)));
            let mut module = jsonrpsee::RpcModule::new(());
            module
                .register_subscription("open", "note", "close", move |_, pending, _, mut ext| {
                    let (to, stream) = (to.clone(), stream.lock().unwrap().take());
                    async move {
                        let sink = pending.accept().await?;
                        ext.insert(to);
                        pipe(sink, stream.expect("one call"), &ext).await
                    }
                })
                .unwrap();
            let (_answer, _notes) = module.raw_json_request(r#"{"jsonrpc":"2.0","id":1,"method":"open","params":[]}"#, 1).await.unwrap();
            let frame = tokio::time::timeout(std::time::Duration::from_millis(500), frames.recv()).await.expect("at once, not when more come").unwrap();
            let v: Value = serde_json::from_slice(frame.bytes()).unwrap();
            assert_eq!(v["params"]["result"]["content"]["n"], 0, "alone, in today's form: {v}");
        });
    }

    /// A batch of large items stops at its bytes: 4 KB items go two to a
    /// notification, not 64, and a ticket body goes alone.
    #[test]
    fn a_batch_stops_at_its_bytes() {
        let m = meta(7);
        let big = |n: u64, size: usize| PlexusStreamItem::Data { metadata: m.clone(), content_type: Cow::Borrowed(CT), content: Content::json(Bytes::from(format!(r#"{{"type":"item","n":{n},"pad":"{}"}}"#, "x".repeat(size)))) };
        let frames = frames_of(ready((0..20).map(|n| big(n, 4096)).chain([done(7)]).collect()), 64);
        let sizes: Vec<usize> = frames.iter().map(|f| items_of(f).len()).collect();
        assert!(sizes.iter().all(|&n| n <= 2), "about 8 KiB a batch: {sizes:?}");
        assert_eq!(sizes.iter().sum::<usize>(), 21);
        let frames = frames_of(ready((0..3).map(|n| big(n, 17_000)).chain([done(7)]).collect()), 64);
        assert!(frames.iter().take(2).all(|f| f["params"].get("result").is_some()), "a body alone, as today: {:?}", frames.iter().map(|f| items_of(f).len()).collect::<Vec<_>>());
    }

    /// A client may ask for fewer than 64: no notification carries more.
    #[test]
    fn a_batch_holds_no_more_than_asked() {
        let m = meta(7);
        let frames = frames_of(ready((0..10).map(|n| data(&m, n)).chain([done(7)]).collect()), 4);
        assert_eq!(frames.iter().map(|f| items_of(f).len()).collect::<Vec<_>>(), vec![4, 4, 3]);
    }
}
