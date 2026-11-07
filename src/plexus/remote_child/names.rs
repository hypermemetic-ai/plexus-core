//! NEST-6 · one dynamic instance's schema, kept by the mount.
//!
//! A dynamic child's *names* exist only inside the child, so the schema of
//! one instance (`<mount>.<path>.<name>.schema`) is the one schema that may
//! cross the hop (spec/12 rule 7's exception): the first time per name, it
//! is asked of the child with the caller's hop and kept here, under the
//! instance's path below the mount and the `plexus_hash` its answer carried;
//! every later ask is answered from here. At most `max` names are kept
//! (`--child-schema-cache`, default 1024), the least recently used out
//! first; `max = 0` keeps none, so every ask crosses.
//!
//! An entry goes when a call through its name carries another `plexus_hash`
//! (the child changed under it), and every entry goes when the child is
//! started again ([`Names::get`]/[`Names::put`] take the restart count as
//! the epoch they are valid in).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::plexus::schema::PluginSchema;

#[derive(Debug)]
struct Entry {
    schema: PluginSchema,
    /// The `plexus_hash` the child's answer carried.
    seen: String,
    used: u64,
}

#[derive(Debug, Default)]
struct State {
    epoch: u64,
    tick: u64,
    map: HashMap<String, Entry>,
}

impl State {
    /// A restart drops every name.
    fn at(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.map.clear();
            self.epoch = epoch;
        }
    }
}

/// The per-name schema cache of one mount (see the module docs).
#[derive(Debug)]
pub(super) struct Names {
    max: usize,
    state: Mutex<State>,
    /// Schemas asked across the hop.
    pub hops: AtomicU64,
    /// Asks answered from here.
    pub hits: AtomicU64,
}

impl Names {
    pub fn new(max: usize) -> Self {
        Self { max, state: Mutex::new(State::default()), hops: AtomicU64::new(0), hits: AtomicU64::new(0) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The schema kept for `path` in `epoch`, counted a hit; `None` counts
    /// nothing (the caller crosses and [`Names::crossed`]).
    pub fn get(&self, path: &str, epoch: u64) -> Option<PluginSchema> {
        let mut s = self.state();
        s.at(epoch);
        s.tick += 1;
        let tick = s.tick;
        let e = s.map.get_mut(path)?;
        e.used = tick;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(e.schema.clone())
    }

    /// One schema asked across the hop.
    pub fn crossed(&self) {
        self.hops.fetch_add(1, Ordering::Relaxed);
    }

    /// Keep `schema` for `path`, answered with `seen` as its `plexus_hash`,
    /// in `epoch`; past `max` the least recently used name goes.
    pub fn put(&self, path: &str, schema: PluginSchema, seen: String, epoch: u64) {
        if self.max == 0 {
            return;
        }
        let mut s = self.state();
        s.at(epoch);
        s.tick += 1;
        let used = s.tick;
        if !s.map.contains_key(path) && s.map.len() >= self.max {
            if let Some(old) = s.map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| k.clone()) {
                s.map.remove(&old);
            }
        }
        s.map.insert(path.to_string(), Entry { schema, seen, used });
    }

    /// An item of a call through `instance` (its path below the mount)
    /// carried `hash`: a name kept under another hash — the instance's, or
    /// one below it — is dropped.
    pub fn observe(&self, instance: &str, hash: &str) {
        let mut s = self.state();
        let below = format!("{instance}.");
        s.map.retain(|k, e| !((k == instance || k.starts_with(&below)) && e.seen != hash));
    }

    /// Names kept now, in `epoch` (a restart since drops them).
    pub fn len(&self, epoch: u64) -> usize {
        let mut s = self.state();
        s.at(epoch);
        s.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(ns: &str) -> PluginSchema {
        PluginSchema::leaf(ns, "1.0", "d", vec![])
    }

    #[test]
    fn a_name_is_kept_once_and_answered_after() {
        let n = Names::new(4);
        assert!(n.get("solar.earth", 0).is_none());
        n.crossed();
        n.put("solar.earth", schema("planet"), "h1".into(), 0);
        for _ in 0..9 {
            assert_eq!(n.get("solar.earth", 0).unwrap().namespace, "planet");
        }
        assert_eq!((n.hops.load(Ordering::Relaxed), n.hits.load(Ordering::Relaxed), n.len(0)), (1, 9, 1));
    }

    #[test]
    fn the_least_recently_used_name_goes_first() {
        let n = Names::new(2);
        n.put("a.x", schema("x"), "h".into(), 0);
        n.put("a.y", schema("y"), "h".into(), 0);
        assert!(n.get("a.x", 0).is_some()); // x used after y
        n.put("a.z", schema("z"), "h".into(), 0);
        assert!(n.get("a.y", 0).is_none(), "y was the least recently used");
        assert!(n.get("a.x", 0).is_some() && n.get("a.z", 0).is_some());
        assert_eq!(n.len(0), 2);
    }

    #[test]
    fn zero_keeps_nothing() {
        let n = Names::new(0);
        n.put("a.x", schema("x"), "h".into(), 0);
        assert!(n.get("a.x", 0).is_none());
    }

    #[test]
    fn another_hash_drops_the_name_and_those_below_it() {
        let n = Names::new(8);
        n.put("a.x", schema("x"), "h1".into(), 0);
        n.put("a.x.moon.luna", schema("moon"), "h1".into(), 0);
        n.put("a.y", schema("y"), "h1".into(), 0);
        n.observe("a.x", "h1");
        assert_eq!(n.len(0), 3, "the same hash keeps every name");
        n.observe("a.x", "h2");
        assert!(n.get("a.x", 0).is_none() && n.get("a.x.moon.luna", 0).is_none());
        assert!(n.get("a.y", 0).is_some(), "another name stays");
    }

    #[test]
    fn a_restart_drops_every_name() {
        let n = Names::new(8);
        n.put("a.x", schema("x"), "h".into(), 0);
        n.put("a.y", schema("y"), "h".into(), 0);
        assert!(n.get("a.x", 1).is_none());
        assert_eq!(n.len(0), 0);
    }
}
