//! PERF-7: the item path — an item encoded once, by its method's own event
//! type, straight into a buffer its socket writes from.
//!
//! | when | then |
//! | -- | -- |
//! | a method yields an event under the WebSocket pipe ([`pipe`]) | [`wrap_stream`](super::streaming::wrap_stream) serializes it once, by its own `Serialize`, into the pipe's buffer (a block from its connection's pool); the `Data` item carries it as [`Content`] — JSON bytes, no `Value` |
//! | the same event anywhere else (in process, a nested route, a test) | it becomes a `Value` as before: in-process items stay what they cost |
//! | a transformer reads a `Data` item's content | [`Content`] decodes its bytes once, on demand (`Deref` to `Value`); one that rewrites it replaces the whole [`Content`] — an encoded item is a `Data` item, so no rewrite can miss one (PERF-17's finding: the gated view's rewrite did) |
//! | the pipe writes an item | the notification's prefix (once a call), the metadata (once a stream), the content type and the content's bytes, and the suffix, into the same buffer: one frame, split off as `Bytes` (no allocation while the block has room) |
//! | the transport offers a [`FrameSink`] (plexus-transport's socket loop) | the frame goes to the socket's writer as it is; the call's first frame is fenced, so it follows the subscription's answer that jsonrpsee queued |
//! | it does not (jsonrpsee's own sink: stdio, an in-memory module) | the item's bytes go to the sink as one raw value, as before |
//! | one change fans out to N watchers ([`Shared`]) | the first socket that sends it encodes it, once; every other writes those bytes |
//!
//! | the connection speaks msgpack (PERF-9, spec/13) | the event is encoded once as a msgpack map with its field names ([`super::msgpack`]), the frame is the notification's map around it, and the socket sends it as one binary message — no JSON on the path |
//!
//! PERF-8 batches frames from here (`results: […]`), PERF-13 relays a
//! child's content as bytes.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::Value;

use super::types::{PlexusStreamItem, StreamMetadata};

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// A `data` item's content: the method's event, encoded once (JSON bytes,
/// or msgpack bytes on a msgpack connection), or a `Value` — whichever the
/// item was made with. Reads as a `Value` either way ([`Content::value`],
/// `Deref`), the bytes decoded once on demand; serializes as its JSON (or,
/// to the msgpack writer, as its msgpack). Equal as JSON is equal.
#[derive(Clone, Default)]
pub struct Content(Repr);

#[derive(Clone)]
enum Repr {
    Value(Value),
    /// JSON text serde_json wrote (valid by construction), and its `Value`
    /// once someone asked for it.
    Json { text: Bytes, value: OnceLock<Value> },
    /// PERF-9: one msgpack value (this crate's writer's, or checked), and
    /// its `Value` once someone asked for it.
    Msgpack { bytes: Bytes, value: OnceLock<Value> },
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

    /// JSON text serde_json wrote, taken as it is.
    pub(crate) fn json(text: Bytes) -> Self {
        Content(Repr::Json { text, value: OnceLock::new() })
    }

    /// Content that is one msgpack value, checked (decoded once, kept as its
    /// `Value`): a child's content read off a msgpack link (PERF-13).
    pub fn from_msgpack(bytes: Bytes) -> Result<Self, super::msgpack::Error> {
        let v = super::msgpack::to_value(&bytes)?;
        let value = OnceLock::new();
        let _ = value.set(v);
        Ok(Content(Repr::Msgpack { bytes, value }))
    }

    /// msgpack this crate's writer wrote, taken as it is.
    pub(crate) fn msgpack(bytes: Bytes) -> Self {
        Content(Repr::Msgpack { bytes, value: OnceLock::new() })
    }

    fn decode_msgpack(bytes: &[u8]) -> Value {
        super::msgpack::to_value(bytes).unwrap_or(Value::Null)
    }

    /// The content as a `Value` (encoded bytes decoded once, kept).
    pub fn value(&self) -> &Value {
        match &self.0 {
            Repr::Value(v) => v,
            Repr::Json { text, value } => value.get_or_init(|| serde_json::from_slice(text).unwrap_or(Value::Null)),
            Repr::Msgpack { bytes, value } => value.get_or_init(|| Self::decode_msgpack(bytes)),
        }
    }

    /// The content as an owned `Value`.
    pub fn into_value(self) -> Value {
        match self.0 {
            Repr::Value(v) => v,
            Repr::Json { text, value } => value.into_inner().unwrap_or_else(|| serde_json::from_slice(&text).unwrap_or(Value::Null)),
            Repr::Msgpack { bytes, value } => value.into_inner().unwrap_or_else(|| Self::decode_msgpack(&bytes)),
        }
    }

    /// A copy of the content as a `Value`.
    pub fn to_value(&self) -> Value {
        match &self.0 {
            Repr::Value(v) => v.clone(),
            Repr::Json { text, value } => value.get().cloned().unwrap_or_else(|| serde_json::from_slice(text).unwrap_or(Value::Null)),
            Repr::Msgpack { bytes, value } => value.get().cloned().unwrap_or_else(|| Self::decode_msgpack(bytes)),
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
            // As a JSON reader reads it: through its `Value`.
            Repr::Msgpack { .. } => T::deserialize(self.value()),
        }
    }

    /// The JSON text the content was encoded as, when it was.
    pub fn json_bytes(&self) -> Option<&Bytes> {
        match &self.0 {
            Repr::Json { text, .. } => Some(text),
            Repr::Value(_) | Repr::Msgpack { .. } => None,
        }
    }

    /// The msgpack the content was encoded as, when it was (PERF-9).
    pub fn msgpack_bytes(&self) -> Option<&Bytes> {
        match &self.0 {
            Repr::Msgpack { bytes, .. } => Some(bytes),
            Repr::Value(_) | Repr::Json { .. } => None,
        }
    }

    /// Whether the content was encoded once from its event (PERF-7), in
    /// either encoding.
    pub fn is_encoded(&self) -> bool {
        matches!(self.0, Repr::Json { .. } | Repr::Msgpack { .. })
    }

    /// The size of its encoded bytes (a guess for one that is a `Value`).
    fn encoded_len(&self) -> usize {
        match &self.0 {
            Repr::Json { text, .. } => text.len(),
            Repr::Msgpack { bytes, .. } => bytes.len(),
            Repr::Value(_) => 256,
        }
    }

    /// Its JSON text, appended to `out`: the bytes, or the `Value` written.
    fn write_json(&self, out: &mut BytesMut) {
        match &self.0 {
            Repr::Json { text, .. } => out.put_slice(text),
            Repr::Value(_) | Repr::Msgpack { .. } => {
                let _ = serde_json::to_writer((&mut *out).writer(), self.value());
            }
        }
    }

    /// Its msgpack, appended to `out`: the bytes, or the `Value` written.
    fn write_msgpack(&self, out: &mut BytesMut) {
        match &self.0 {
            Repr::Msgpack { bytes, .. } => out.put_slice(bytes),
            Repr::Value(_) | Repr::Json { .. } => {
                if super::msgpack::write(out, self.value()).is_err() {
                    super::msgpack::put_nil(out);
                }
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
            Repr::Msgpack { .. } => self.value().fmt(f),
        }
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Value(v) => v.fmt(f),
            Repr::Json { text, .. } => f.write_str(&String::from_utf8_lossy(text)),
            Repr::Msgpack { .. } => self.value().fmt(f),
        }
    }
}

impl Serialize for Content {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            // serde_json writes a raw value as it is, and the msgpack writer
            // its own bytes as they are; any other serializer gets the `Value`.
            Repr::Json { text, value } => {
                if writing_json() {
                    if let Ok(raw) = serde_json::from_slice::<&RawValue>(text) {
                        return raw.serialize(s);
                    }
                }
                if let Some(v) = value.get() {
                    return v.serialize(s);
                }
            }
            Repr::Msgpack { bytes, .. } if super::msgpack::writing() => {
                return super::msgpack::Raw(bytes).serialize(s);
            }
            _ => {}
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

/// The encoding of every frame on a connection, fixed when it opens
/// (spec/13; [`super::encoding`] negotiates it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum WireEncoding {
    /// JSON-RPC 2.0 objects, one text message each (`plexus.json`).
    #[default]
    Json,
    /// PERF-9: the same objects as msgpack maps, their field names kept and
    /// `jsonrpc` left out, one binary message each (`plexus.msgpack`).
    Msgpack,
}

/// A frame ready for a socket, in its connection's encoding.
#[derive(Debug, Clone)]
pub struct WireFrame {
    bytes: Bytes,
    fence: bool,
}

impl WireFrame {
    /// The frame's bytes (JSON text under [`WireEncoding::Json`], one
    /// msgpack map under [`WireEncoding::Msgpack`]).
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
}

/// What the transport's writer reads a [`FrameSink`]'s frames from.
pub type FrameReceiver = tokio::sync::mpsc::Receiver<WireFrame>;

impl FrameSink {
    /// A connection's frame queue, bounded at `capacity` frames.
    pub fn channel(capacity: usize, encoding: WireEncoding) -> (FrameSink, FrameReceiver) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
        (FrameSink { tx, encoding, spare: Arc::new(Mutex::new(None)) }, rx)
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
        f.debug_struct("FrameSink").field("encoding", &self.encoding).field("closed", &self.tx.is_closed()).finish()
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
    /// taken its size twice from a block, content and frame: 8.8 MB at 4 KB
    /// an item. Blocks that hold fewer than that are dropped before they
    /// come free, and every block filled is a new one (PERF-9: msgpack
    /// outruns the socket where JSON's escaping did not, 8 KB allocated an
    /// item at 4 KB). They hold bytes those frames hold anyway, for the
    /// call's life alone.
    const SPARE: usize = 32;

    fn from_block(block: Option<BytesMut>) -> Self {
        match block {
            Some(cur) => Buffer { block: cur.capacity().max(Self::FIRST), cur, started: true, ..Buffer::default() },
            None => Buffer::default(),
        }
    }

    /// Room for `n` more bytes in the current block: it, or a free block, or
    /// a new one.
    fn room(&mut self, n: usize) {
        if self.cur.capacity() - self.cur.len() >= n || self.cur.try_reclaim(n) {
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
    /// The connection's encoding: what the events are encoded as.
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
        let encoding = e.encoding;
        let (written, captured) = plexus_auth_core::credential::run_with_credential_capture(|| match encoding {
            WireEncoding::Json => {
                let _json = WritingJson::on();
                serde_json::to_writer((&mut buffer.cur).writer(), event).is_ok()
            }
            // PERF-9: a map with its field names, as JSON has them.
            WireEncoding::Msgpack => super::msgpack::write(&mut buffer.cur, event).is_ok(),
        });
        if !written || !captured.is_empty() {
            buffer.cur.clear();
            return None;
        }
        e.last.set(buffer.cur.len());
        let bytes = buffer.split();
        Some(match encoding {
            WireEncoding::Json => Content::json(bytes),
            WireEncoding::Msgpack => Content::msgpack(bytes),
        })
    })
    .ok()
    .flatten()
}

/// One call's frames: the notification around each item, in the
/// connection's encoding.
struct Frames {
    encoding: WireEncoding,
    /// JSON: `{"jsonrpc":"2.0","method":M,"params":{"subscription":S,"result":`;
    /// msgpack: the map `{method: M, params: {subscription: S, result:` —
    /// its counts written ahead, so nothing closes it.
    prefix: Vec<u8>,
    /// A `data` item's opening, `{"type":"data","metadata":…,"content_type":…,"content":`
    /// (in msgpack the same map, its 4 members counted ahead), for the
    /// stream's metadata (shared by its items) and content type.
    head: Option<(Arc<StreamMetadata>, Cow<'static, str>, Vec<u8>)>,
}

impl Frames {
    fn new(method: &str, subscription: &jsonrpsee::types::SubscriptionId<'_>, encoding: WireEncoding) -> Self {
        let mut prefix = Vec::with_capacity(64);
        match encoding {
            WireEncoding::Json => {
                prefix.extend_from_slice(br#"{"jsonrpc":"2.0","method":"#);
                let _ = serde_json::to_writer(&mut prefix, method);
                prefix.extend_from_slice(br#","params":{"subscription":"#);
                let _ = serde_json::to_writer(&mut prefix, subscription);
                prefix.extend_from_slice(br#","result":"#);
            }
            WireEncoding::Msgpack => {
                use super::msgpack::{put_map_len, put_str};
                let _ = put_map_len(&mut prefix, 2);
                put_str(&mut prefix, "method");
                put_str(&mut prefix, method);
                put_str(&mut prefix, "params");
                let _ = put_map_len(&mut prefix, 2);
                put_str(&mut prefix, "subscription");
                if super::msgpack::write(&mut prefix, subscription).is_err() {
                    super::msgpack::put_nil(&mut prefix);
                }
                put_str(&mut prefix, "result");
            }
        }
        Frames { encoding, prefix, head: None }
    }

    /// The opening of a `data` item, through `"content":`, for `metadata`
    /// and `content_type`.
    fn data_head(&self, metadata: &StreamMetadata, content_type: &str) -> Vec<u8> {
        let mut head = Vec::with_capacity(128);
        match self.encoding {
            WireEncoding::Json => {
                head.extend_from_slice(br#"{"type":"data","metadata":"#);
                let _ = serde_json::to_writer(&mut head, metadata);
                head.extend_from_slice(br#","content_type":"#);
                let _ = serde_json::to_writer(&mut head, content_type);
                head.extend_from_slice(br#","content":"#);
            }
            WireEncoding::Msgpack => {
                use super::msgpack::{put_map_len, put_str};
                let _ = put_map_len(&mut head, 4);
                put_str(&mut head, "type");
                put_str(&mut head, "data");
                put_str(&mut head, "metadata");
                let _ = super::msgpack::write(&mut head, metadata);
                put_str(&mut head, "content_type");
                put_str(&mut head, content_type);
                put_str(&mut head, "content");
            }
        }
        head
    }

    /// `item`, written at the end of `out` in the connection's encoding.
    fn item(&mut self, out: &mut BytesMut, item: &PlexusStreamItem) {
        match item {
            PlexusStreamItem::Data { metadata, content_type, content } => {
                let fresh = match &self.head {
                    Some((m, ct, _)) => !Arc::ptr_eq(m, metadata) || ct != content_type,
                    None => true,
                };
                if fresh {
                    let head = self.data_head(metadata, content_type);
                    self.head = Some((metadata.clone(), content_type.clone(), head));
                }
                let head = &self.head.as_ref().expect("made above").2;
                out.reserve(head.len() + content.encoded_len() + 1);
                out.put_slice(head);
                match self.encoding {
                    WireEncoding::Json => {
                        content.write_json(out);
                        out.put_u8(b'}');
                    }
                    WireEncoding::Msgpack => content.write_msgpack(out),
                }
            }
            other => match self.encoding {
                WireEncoding::Json => {
                    let _ = serde_json::to_writer((&mut *out).writer(), other);
                }
                WireEncoding::Msgpack => {
                    let start = out.len();
                    if super::msgpack::write(out, other).is_err() {
                        // Not one value: no item at all is better than half of one.
                        out.truncate(start);
                        super::msgpack::put_nil(out);
                    }
                }
            },
        }
    }

    /// The notification carrying `item`: the frame a socket writes.
    fn frame(&mut self, buffer: &mut Buffer, item: &PlexusStreamItem) -> Bytes {
        let content = match item {
            PlexusStreamItem::Data { content, .. } => content.encoded_len(),
            _ => 256,
        };
        buffer.room(self.prefix.len() + content + 256);
        buffer.cur.put_slice(&self.prefix);
        self.item(&mut buffer.cur, item);
        if self.encoding == WireEncoding::Json {
            buffer.cur.put_slice(b"}}");
        }
        buffer.split()
    }

    /// `item` alone, for jsonrpsee's sink, which wraps it in the notification.
    fn raw_item(&mut self, buffer: &mut Buffer, item: &PlexusStreamItem) -> Bytes {
        buffer.room(512);
        self.item(&mut buffer.cur, item);
        buffer.split()
    }
}

/// Pipe a call's stream to its accepted subscription: each item encoded
/// once and written as one frame.
///
/// With a [`FrameSink`] in the call's extensions (plexus-transport's socket
/// loop) each frame goes to the socket's writer as it is, the first fenced
/// behind the subscription's answer; without one, each item goes to
/// jsonrpsee's sink as one raw value. A `Request` item (an in-call
/// question) is bound to this connection first (BIDIR-13). The pipe ends
/// when the stream does, or when the caller lets go (an unsubscribe, a lost
/// socket), dropping the stream at once.
pub async fn pipe(sink: jsonrpsee::SubscriptionSink, stream: super::streaming::PlexusStream, ext: &http::Extensions) -> jsonrpsee::core::SubscriptionResult {
    let frames = ext.get::<FrameSink>().cloned();
    let encoding = frames.as_ref().map(FrameSink::encoding).unwrap_or_default();
    let buffer = Buffer::from_block(frames.as_ref().and_then(FrameSink::take_block));
    let encoder = Encoder { encoding, buffer: RefCell::new(buffer), depth: Cell::new(0), last: Cell::new(0) };
    WIRE.scope(encoder, run(sink, stream, frames)).await
}

async fn run(sink: jsonrpsee::SubscriptionSink, mut stream: super::streaming::PlexusStream, frames: Option<FrameSink>) -> jsonrpsee::core::SubscriptionResult {
    use futures::StreamExt;
    let connection = sink.connection_id().0;
    let encoding = frames.as_ref().map(FrameSink::encoding).unwrap_or_default();
    let mut notification = Frames::new(sink.method_name(), &sink.subscription_id(), encoding);
    let mut first = true;
    let out: jsonrpsee::core::SubscriptionResult = async {
        loop {
            let item = tokio::select! {
                biased;
                _ = sink.closed() => return Ok(()),
                item = stream.next() => item,
            };
            let Some(item) = item else { return Ok(()) };
            if let PlexusStreamItem::Request { request_id, .. } = &item {
                super::bidirectional::bind_asker(request_id, connection);
            }
            match &frames {
                Some(to) => {
                    let bytes = WIRE.with(|e| notification.frame(&mut e.buffer.borrow_mut(), &item));
                    drop(item);
                    if to.tx.send(WireFrame { bytes, fence: first }).await.is_err() {
                        return Ok(());
                    }
                }
                None => {
                    let bytes = WIRE.with(|e| notification.raw_item(&mut e.buffer.borrow_mut(), &item));
                    drop(item);
                    // jsonrpsee's sink takes a raw value, which it wraps in
                    // the notification: a copy and a check — the price of a
                    // transport without frames of its own (stdio, a module
                    // called in memory).
                    let raw = RawValue::from_string(String::from_utf8(bytes.to_vec()).unwrap_or_default())?;
                    sink.send(raw).await?;
                }
            }
            first = false;
        }
    }
    .await;
    drop(stream);
    if let Some(to) = &frames {
        if let Some(block) = WIRE.with(|e| std::mem::take(&mut *e.buffer.borrow_mut())).into_block() {
            to.give_block(block);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Shared: one event, many streams
// ---------------------------------------------------------------------------

/// An event many streams send — one change fanned out to every watcher.
/// The first socket that sends it encodes it, once; every other writes
/// those bytes as they are (PERF-7's fan-out) — once per encoding: the JSON
/// and the msgpack sockets each share theirs (PERF-9). Anywhere else (in
/// process, a `Value`) it serializes as `T` does. Reads as `T`.
///
/// An event that carries a credential is not kept encoded: each stream
/// encodes it, so each assembles its own `_credentials` envelope.
pub struct Shared<T>(Arc<SharedInner<T>>);

struct SharedInner<T> {
    value: T,
    /// The JSON the first socket wrote (`None`: never kept — a credential).
    json: OnceLock<Option<Box<RawValue>>>,
    /// The msgpack the first msgpack socket wrote (`None`: a credential).
    msgpack: OnceLock<Option<Vec<u8>>>,
}

impl<T> Shared<T> {
    /// `value`, to be sent by many streams.
    pub fn new(value: T) -> Self {
        Shared(Arc::new(SharedInner { value, json: OnceLock::new(), msgpack: OnceLock::new() }))
    }

    /// Whether this event has been encoded (a socket has sent it), in
    /// either encoding.
    pub fn is_encoded(&self) -> bool {
        matches!(self.0.json.get(), Some(Some(_))) || matches!(self.0.msgpack.get(), Some(Some(_)))
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

    fn encoded_msgpack(&self) -> Option<&[u8]> {
        self.0
            .msgpack
            .get_or_init(|| {
                let (bytes, captured) = plexus_auth_core::credential::run_with_credential_capture(|| super::msgpack::to_vec(&self.0.value));
                match bytes {
                    Ok(bytes) if captured.is_empty() => Some(bytes),
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
        } else if super::msgpack::writing() {
            if let Some(bytes) = self.encoded_msgpack() {
                return super::msgpack::Raw(bytes).serialize(s);
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

    /// PERF-9: a stream that outruns its socket holds the queue's 1,024 frames
    /// in flight. The blocks in rotation must hold them, or every block filled
    /// is a new one: at 4 KB an item (8.6 KB of block each, content and frame)
    /// a fresh block every 60 items, for the stream's life.
    #[test]
    fn a_queue_full_of_frames_comes_back_to_blocks_already_made() {
        let mut b = Buffer::default();
        let mut in_flight = std::collections::VecDeque::new();
        let item = [7u8; 8600];
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
        assert_eq!(b.made, ramp, "past the ramp ({ramp} blocks), every block is one already made");
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
}
