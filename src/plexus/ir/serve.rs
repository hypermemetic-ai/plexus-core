//! What a service's `ir` method answers ([`DynamicHub::service_ir`]): the
//! IR of the walks from the namespaces asked for, or why not — and what the
//! service keeps of it.
//!
//! [`DynamicHub::service_ir`]: crate::plexus::DynamicHub::service_ir

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::OnceCell;

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;

use super::build::{build, IrBuildError};

/// A service's IR, as `<service>.ir` answers it: IR 3.1 — the document
/// synapse's `buildIRFromSchemas` builds from the same schemas (its
/// `irBackend` the service's namespace, its `irMetadata` `null`). Kept as
/// its JSON, written once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceIr(pub Arc<RawValue>);

impl ServiceIr {
    /// The IR as a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::from_str(self.0.get()).unwrap_or(Value::Null)
    }
}

impl PartialEq for ServiceIr {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}

impl JsonSchema for ServiceIr {
    fn schema_name() -> Cow<'static, str> {
        "ServiceIr".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "The service's IR 3.1: every type once (irTypes), each method referring to them (irMethods) — as synapse's buildIRFromSchemas builds it from the same schemas"
        })
    }
}

/// Why a service writes no IR for what was asked. (A title collision is no
/// reason: the walk refuses that activation into the IR's `irRefusals`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IrError {
    /// A namespace asked for is not one the caller's view of the service shows.
    NotFound { namespace: String, message: String },
    /// A schema the service answered is one synapse could not read.
    Unreadable { namespace: String, message: String },
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrError::NotFound { message, .. } | IrError::Unreadable { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for IrError {}

/// The walks' roots for `namespaces` (dotted paths; none, `""` or the
/// service's own namespace: the root): sorted, each once, and none under
/// another named one — its walk reads it already. Sorted, an ancestor comes
/// before everything under it, and only names under it come between: one
/// pass against the last root kept (RETURNS-40 review #1: linear, not a
/// comparison of every pair).
pub fn roots(service: &str, namespaces: &[String]) -> Vec<Vec<String>> {
    let mut paths: Vec<Vec<String>> = namespaces
        .iter()
        .map(|n| if n.is_empty() || n == service { vec![] } else { n.split('.').map(str::to_string).collect() })
        .collect();
    if paths.is_empty() {
        return vec![vec![]];
    }
    paths.sort();
    paths.dedup();
    let mut kept: Vec<Vec<String>> = Vec::with_capacity(paths.len());
    for p in paths {
        if kept.last().is_some_and(|q| p.starts_with(q)) {
            continue;
        }
        kept.push(p);
    }
    kept
}

fn dotted(path: &[String]) -> String {
    path.join(".")
}

/// The answer for `roots` over `schemas` (every `<path>.schema` the walks
/// read, by path): the IR, or why not.
pub fn answer(service: &str, roots: &[Vec<String>], schemas: &BTreeMap<Vec<String>, Value>) -> Result<ServiceIr, IrError> {
    match build(service, roots, schemas) {
        Ok(ir) => {
            let text = serde_json::to_string(&ir.to_json()).expect("an IR serializes");
            Ok(ServiceIr(Arc::from(RawValue::from_string(text).expect("JSON"))))
        }
        Err(e) => {
            let message = e.to_string();
            Err(match e {
                // the walk refuses a title collision into the IR (synapse's
                // pluginIRRefusing): build() never fails so
                IrBuildError::TitleCollision { namespace, .. } => IrError::Unreadable { namespace, message },
                IrBuildError::MissingSchema { path } => IrError::NotFound {
                    message: format!("no namespace {} in this service", if path.is_empty() { service.to_string() } else { dotted(&path) }),
                    namespace: dotted(&path),
                },
                IrBuildError::Unreadable { path, .. } => IrError::Unreadable { namespace: dotted(&path), message },
            })
        }
    }
}

/// What one kept answer is kept by: the hash of the view it was built from
/// (the service's, or the caller's view's under the grant gate), the roots
/// asked, and — under the R-5 scope gate — the namespaces whose schema the
/// caller's own calls are answered, so a caller is never answered what was
/// built for another (RETURNS-40 review #2, #3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IrKey {
    pub view: String,
    pub roots: Vec<Vec<String>>,
    pub permitted: Option<Vec<String>>,
}

/// At most this many answers are kept.
pub const IR_CACHE_ENTRIES: usize = 128;
/// At most this many bytes of answers are kept (64 MiB: a hundred of
/// menger's whole-service IR, 565 KB).
pub const IR_CACHE_BYTES: usize = 64 << 20;

/// What a service keeps of its `ir` answers (RETURNS-40 review #4, re-review
/// #1, #2): one build per key at a time — a later asker of a key waits for
/// the build under way, and when the asker building it goes the next waiter
/// takes the build over; bounded at the ask — a slot being built counts
/// toward the entries, and an ask with no room (every slot building) builds
/// without keeping; a slot whose every asker has gone before it was built
/// is removed (a blocking build under way then finishes and its answer is
/// dropped); built answers kept least recently used out, by entries and by
/// bytes, an answer past the byte bound never kept, a slot being built
/// never evicted; a refusal never kept. The lock is held for O(log n) work
/// alone.
pub struct IrCache {
    state: Mutex<CacheState>,
    builds: AtomicUsize,
    max_entries: usize,
    max_bytes: usize,
}

#[derive(Default)]
struct CacheState {
    slots: HashMap<IrKey, Slot>,
    /// The built slots, by when each was last used: the least recently
    /// used first. A slot being built is not here, so never evicted.
    lru: BTreeMap<u64, IrKey>,
    tick: u64,
    bytes: usize,
    next_id: u64,
}

struct Slot {
    /// Which slot this is: a key removed and asked again is another.
    id: u64,
    cell: Arc<OnceCell<ServiceIr>>,
    /// The asks waiting on it.
    waiters: usize,
    /// Once built and kept: when it was last used, and its bytes.
    built: Option<(u64, usize)>,
}

impl Default for IrCache {
    fn default() -> Self {
        IrCache::with_limits(IR_CACHE_ENTRIES, IR_CACHE_BYTES)
    }
}

/// One ask waiting on a slot; gone (finished or cancelled), it says so.
struct Waiter<'a> {
    cache: &'a IrCache,
    key: &'a IrKey,
    id: u64,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut st = self.cache.state();
        let gone = match st.slots.get_mut(self.key) {
            Some(slot) if slot.id == self.id => {
                slot.waiters -= 1;
                slot.waiters == 0 && slot.built.is_none()
            }
            _ => false,
        };
        if gone {
            st.slots.remove(self.key);
        }
    }
}

impl IrCache {
    pub fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        IrCache { state: Mutex::new(CacheState::default()), builds: AtomicUsize::new(0), max_entries: max_entries.max(1), max_bytes }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The answer kept for `key`, or `build`'s — run once for every asker
    /// of `key` while it runs. An `Err` is answered and not kept.
    pub async fn get_or_build<F, Fut>(&self, key: IrKey, build: F) -> Result<ServiceIr, IrError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<ServiceIr, IrError>>,
    {
        let joined = self.join(&key);
        let Some((id, cell)) = joined else {
            // no room beside the slots being built: built, not kept
            self.builds.fetch_add(1, Ordering::SeqCst);
            return build().await;
        };
        let _waiting = Waiter { cache: self, key: &key, id };
        let answer = cell
            .get_or_try_init(|| {
                self.builds.fetch_add(1, Ordering::SeqCst);
                build()
            })
            .await
            .cloned();
        if let Ok(ir) = &answer {
            self.settle(&key, id, ir.0.get().len());
        }
        answer
    }

    /// Wait on `key`'s slot — made when there is room — counted as one of
    /// its askers; `None` when every slot is being built.
    fn join(&self, key: &IrKey) -> Option<(u64, Arc<OnceCell<ServiceIr>>)> {
        let mut st = self.state();
        st.tick += 1;
        let tick = st.tick;
        if let Some(slot) = st.slots.get_mut(key) {
            slot.waiters += 1;
            let used = slot.built.map(|(used, _)| used);
            if let Some((_, bytes)) = slot.built {
                slot.built = Some((tick, bytes));
            }
            let joined = (slot.id, slot.cell.clone());
            if let Some(used) = used {
                st.lru.remove(&used);
                st.lru.insert(tick, key.clone());
            }
            return Some(joined);
        }
        while st.slots.len() >= self.max_entries {
            let Some((_, oldest)) = st.lru.pop_first() else { return None };
            if let Some(gone) = st.slots.remove(&oldest) {
                st.bytes -= gone.built.map_or(0, |(_, b)| b);
            }
        }
        st.next_id += 1;
        let id = st.next_id;
        let cell = Arc::new(OnceCell::new());
        st.slots.insert(key.clone(), Slot { id, cell: cell.clone(), waiters: 1, built: None });
        Some((id, cell))
    }

    /// Keep a built answer — unless it is past the byte bound — then drop
    /// the least recently used others while past it.
    fn settle(&self, key: &IrKey, id: u64, bytes: usize) {
        let mut st = self.state();
        let fresh = matches!(st.slots.get(key), Some(slot) if slot.id == id && slot.built.is_none());
        if !fresh {
            return;
        }
        if bytes > self.max_bytes {
            st.slots.remove(key);
            return;
        }
        st.tick += 1;
        let tick = st.tick;
        if let Some(slot) = st.slots.get_mut(key) {
            slot.built = Some((tick, bytes));
        }
        st.lru.insert(tick, key.clone());
        st.bytes += bytes;
        while st.bytes > self.max_bytes {
            let Some((_, oldest)) = st.lru.pop_first() else { break };
            if let Some(gone) = st.slots.remove(&oldest) {
                st.bytes -= gone.built.map_or(0, |(_, b)| b);
            }
        }
    }

    /// How many slots there are: answers kept, and answers being built.
    pub fn len(&self) -> usize {
        self.state().slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of the answers kept.
    pub fn bytes(&self) -> usize {
        self.state().bytes
    }

    /// How many builds have run.
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn key(n: usize) -> IrKey {
        IrKey { view: format!("h{n}"), roots: vec![vec![]], permitted: None }
    }

    fn ir_of(bytes: usize) -> ServiceIr {
        ServiceIr(Arc::from(RawValue::from_string(format!("\"{}\"", "x".repeat(bytes - 2))).unwrap()))
    }

    #[tokio::test]
    async fn the_cache_keeps_the_most_recently_used_within_both_bounds() {
        let cache = IrCache::with_limits(3, 250);
        for n in 0..3 {
            cache.get_or_build(key(n), || async { Ok(ir_of(50)) }).await.unwrap();
        }
        assert_eq!((cache.len(), cache.bytes(), cache.builds()), (3, 150, 3));
        // 0 is used again; 3 comes in: 1, the least recently used, goes
        cache.get_or_build(key(0), || async { Ok(ir_of(50)) }).await.unwrap();
        cache.get_or_build(key(3), || async { Ok(ir_of(50)) }).await.unwrap();
        assert_eq!((cache.len(), cache.builds()), (3, 4));
        cache.get_or_build(key(1), || async { Ok(ir_of(50)) }).await.unwrap();
        assert_eq!(cache.builds(), 5, "1 was dropped, so built again");
        // a large answer: the others go one by one, oldest first, until it fits — never all at once
        cache.get_or_build(key(9), || async { Ok(ir_of(150)) }).await.unwrap();
        assert!(cache.bytes() <= 250, "{}", cache.bytes());
        assert_eq!(cache.len(), 3, "9 and the two most recently used");
        cache.get_or_build(key(1), || async { Ok(ir_of(50)) }).await.unwrap();
        assert_eq!(cache.builds(), 6, "1 was kept");
    }

    #[tokio::test]
    async fn a_refusal_is_not_kept() {
        let cache = IrCache::default();
        let refused = || async { Err(IrError::NotFound { namespace: "x".into(), message: "no".into() }) };
        assert!(cache.get_or_build(key(0), refused).await.is_err());
        assert!(cache.get_or_build(key(0), refused).await.is_err());
        assert_eq!((cache.builds(), cache.len()), (2, 0));
    }

    #[test]
    fn roots_of_what_is_asked() {
        assert_eq!(roots("svc", &[]), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["svc"])), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["beta", "alpha", "beta"])), vec![p(&["alpha"]), p(&["beta"])]);
        assert_eq!(roots("svc", &p(&["alpha.gamma", "alpha"])), vec![p(&["alpha"])]);
        assert_eq!(roots("svc", &p(&["alpha", ""])), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["alphabet", "alpha"])), vec![p(&["alpha"]), p(&["alphabet"])]);
        assert_eq!(roots("svc", &p(&["a.b.c", "a.x", "a.b", "b"])), vec![p(&["a", "b"]), p(&["a", "x"]), p(&["b"])]);
    }
}
