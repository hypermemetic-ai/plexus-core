//! PERF-17 (spike, never merged): the floor's switches in plexus-core, each an
//! env var read once, at first use; all off by default, so with every switch
//! off a build behaves byte for byte as `archive/PERF-5`.
//!
//! - `PERF17_LINT_ONCE=1` (E7, PERF-15): the credentials lint
//!   (`warn_on_credentials_field_collisions`) runs once per namespace, at the
//!   first `PluginSchema` built for it — registration — not inside every
//!   constructor on every `_info` / `hash` / `schema` call.
//! - `PERF17_DESCRIBE_CACHE=1` (E7, PERF-15): `_info` and a gated service's
//!   introspection answers (`<ns>.schema`, `hash`, `hashes`, `<ns>.<m>.schema`)
//!   cached per (service, method, params, caller) and the gate's grants
//!   generation; a move of the generation misses. Assumes the activations'
//!   schemas are fixed once registered (true of every macro activation).
//! - `PERF17_ONE_ENCODE=1` (E1, PERF-7's first half): each item serialized
//!   once, straight into its notification (`SubscriptionMessage::new`, which
//!   jsonrpsee passes through whole), instead of `to_raw_value` and then
//!   jsonrpsee's envelope copying it.
//! - `PERF17_ENCODED=1` (E1, PERF-7's second half): `wrap_stream` writes
//!   each item's whole JSON once, straight from the typed event (the
//!   metadata and content type written once per stream), into an
//!   `Encoded` item the pipe sends as its bytes — no `Value`, no per-item
//!   metadata clone. An item that captures a credential takes today's path.
//!   The content's keys come in the type's order, not sorted as a `Value`
//!   writes them: the same JSON, not the same bytes. Only a stream the
//!   WebSocket pipe polls is encoded (the pipe sets `PIPE_ENCODES` for its
//!   task): whoever reads `route()`'s items in process still gets `Data`.
//! - `PERF17_GATE_CACHE=1` (E3, PERF-10): the gate's verdict for a call
//!   that names no target, kept per worker thread by (caller, grant) and the
//!   gate's grants generation; a refusal is never kept, and a sign-in that
//!   ended is caught before (`standing`). The caller is its address plus a
//!   hash of its user and session, so a reused address is a miss.
//! - `PERF17_BATCH=N` (E2b, PERF-8's second half): the items a stream has
//!   ready when one is taken (polled until `Pending`, never a timer), up to N,
//!   go as one notification whose `result` is the array of them (PERF-8 names
//!   it `results`; jsonrpsee's public API writes `result`); a lone item goes
//!   alone, as today. Every client is sent batches (no negotiation here).

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

fn flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1").unwrap_or(false)
}

/// E7: the credentials lint once per namespace.
pub fn lint_once() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| flag("PERF17_LINT_ONCE"))
}

/// E7: true the first time `namespace` is linted in this process.
pub fn first_lint(namespace: &str) -> bool {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(Default::default).lock().unwrap().insert(namespace.to_string())
}

/// E7: the describe answers cached per caller and grants generation.
pub fn describe_cache() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| flag("PERF17_DESCRIBE_CACHE"))
}

/// A cache of answers, each kept with the generation it was computed at.
pub struct GenCache<V: Clone> {
    map: Mutex<HashMap<String, (u64, V)>>,
}

impl<V: Clone> Default for GenCache<V> {
    fn default() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
}

impl<V: Clone> GenCache<V> {
    pub fn get(&self, key: &str, generation: u64) -> Option<V> {
        let map = self.map.lock().unwrap();
        map.get(key).filter(|(g, _)| *g == generation).map(|(_, v)| v.clone())
    }
    pub fn put(&self, key: String, generation: u64, v: V) {
        let mut map = self.map.lock().unwrap();
        if map.len() >= 4096 {
            map.clear();
        }
        map.insert(key, (generation, v));
    }
}

/// The part of a caller that decides its view: who, its roles and its
/// session's metadata (a ceiling lives there); anonymous is "-".
pub fn caller_key(caller: Option<&super::auth::AuthContext>) -> String {
    match caller {
        None => "-".to_string(),
        Some(a) => format!("{}|{:?}|{}", a.user_id, a.roles, a.metadata),
    }
}

pub fn info_cache() -> &'static GenCache<serde_json::Value> {
    static C: OnceLock<GenCache<serde_json::Value>> = OnceLock::new();
    C.get_or_init(Default::default)
}

pub fn introspect_cache() -> &'static GenCache<std::sync::Arc<Vec<super::types::PlexusStreamItem>>> {
    static C: OnceLock<GenCache<std::sync::Arc<Vec<super::types::PlexusStreamItem>>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// E1: the item serialized once, into its notification.
pub fn one_encode() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| flag("PERF17_ONE_ENCODE"))
}

pub fn view_cache() -> &'static GenCache<std::sync::Arc<super::view::View>> {
    static C: OnceLock<GenCache<std::sync::Arc<super::view::View>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// E2b: at most this many ready items in one notification (0 or 1: off).
pub fn batch() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| std::env::var("PERF17_BATCH").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

pub fn encoded_cache() -> &'static GenCache<std::sync::Arc<Vec<Box<serde_json::value::RawValue>>>> {
    static C: OnceLock<GenCache<std::sync::Arc<Vec<Box<serde_json::value::RawValue>>>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// E3: the gate's verdict cached per (caller, grant) and grants generation.
pub fn gate_cache() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| flag("PERF17_GATE_CACHE"))
}

thread_local! {
    static VERDICTS: std::cell::RefCell<HashMap<(usize, u64), (u64, plexus_auth_core::grants::Reach)>> = std::cell::RefCell::new(HashMap::new());
}

/// E3: `gate.check(auth, grant, None)`, answered from this thread's cache
/// when the generation has not moved.
pub fn cached_check(
    gate: &plexus_auth_core::grants::Gate,
    auth: Option<&super::auth::AuthContext>,
    grant: &plexus_auth_core::grants::Grant,
) -> Result<plexus_auth_core::grants::Reach, plexus_auth_core::grants::Refusal> {
    use std::hash::{Hash, Hasher};
    let generation = gate.generation().current();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    grant.as_str().hash(&mut h);
    if let Some(a) = auth {
        a.user_id.hash(&mut h);
        a.session_id.hash(&mut h);
    }
    let key = (auth.map(|a| a as *const _ as usize).unwrap_or(0), h.finish());
    if let Some(r) = VERDICTS.with(|m| m.borrow().get(&key).filter(|(g, _)| *g == generation).map(|(_, r)| r.clone())) {
        return Ok(r);
    }
    let r = gate.check(auth, grant, None)?;
    VERDICTS.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() >= 4096 {
            m.clear();
        }
        m.insert(key, (generation, r.clone()));
    });
    Ok(r)
}

/// E1: items encoded once in `wrap_stream`.
pub fn encoded() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| flag("PERF17_ENCODED"))
}

/// E1: one `data` item's whole JSON in one typed pass — the metadata already
/// encoded (written verbatim), the event straight from its type — under the
/// credential capture; `None` when it captured a credential (today's path
/// assembles the envelope) or could not be written.
pub fn encode_item<T: serde::Serialize>(
    meta: &serde_json::value::RawValue,
    content_type: &str,
    item: &T,
) -> Option<Box<serde_json::value::RawValue>> {
    use serde::ser::SerializeStruct;
    struct Enc<'a, T> {
        meta: &'a serde_json::value::RawValue,
        content_type: &'a str,
        content: &'a T,
    }
    impl<T: serde::Serialize> serde::Serialize for Enc<'_, T> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut st = s.serialize_struct("PlexusStreamItem", 4)?;
            st.serialize_field("type", "data")?;
            st.serialize_field("metadata", self.meta)?;
            st.serialize_field("content_type", self.content_type)?;
            st.serialize_field("content", self.content)?;
            st.end()
        }
    }
    let mut buf: Vec<u8> = Vec::with_capacity(meta.get().len() + content_type.len() + 192);
    let (written, captured) = plexus_auth_core::credential::run_with_credential_capture(|| {
        serde_json::to_writer(&mut buf, &Enc { meta, content_type, content: item }).is_ok()
    });
    if !written || !captured.is_empty() {
        return None;
    }
    // serde_json wrote this text: it is valid JSON and UTF-8.
    let text: Box<str> = String::from_utf8(buf).ok()?.into_boxed_str();
    // SAFETY: RawValue is #[repr(transparent)] over str (serde_json's own
    // `RawValue::from_owned` does this); the text is the JSON serde_json just
    // wrote, so skipping `from_string`'s re-parse keeps its invariant.
    Some(unsafe { std::mem::transmute::<Box<str>, Box<serde_json::value::RawValue>>(text) })
}

/// E1: an item as the wire writes it — an `Encoded` one as its bytes.
pub struct Wire<'a>(pub &'a super::types::PlexusStreamItem);

impl serde::Serialize for Wire<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            super::types::PlexusStreamItem::Encoded(raw) => raw.serialize(s),
            item => item.serialize(s),
        }
    }
}

/// E1 with E2b: a batch as the wire writes it.
pub struct WireBatch<'a>(pub &'a [super::types::PlexusStreamItem]);

impl serde::Serialize for WireBatch<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            seq.serialize_element(&Wire(item))?;
        }
        seq.end()
    }
}

tokio::task_local! {
    /// E1: set by the WebSocket pipe for the task that polls a call's stream.
    pub static PIPE_ENCODES: bool;
}

/// E1: true while the WebSocket pipe is the one polling this stream.
pub fn pipe_encodes() -> bool {
    PIPE_ENCODES.try_with(|v| *v).unwrap_or(false)
}
