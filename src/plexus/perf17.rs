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
