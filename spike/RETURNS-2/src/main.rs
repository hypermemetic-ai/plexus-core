//! RETURNS-3 spike — can a method's hash cover the shape of its types?
//!
//! Builds the schemars `schema_for!` JSON of three shapes — a struct (`Ticket`,
//! T), a tagged enum (`TicketsEvent`) and the generic
//! `Result<Progress<Ticket, Note>, TicketError>` — and of two 0.7-style
//! methods built from them (`watch`: returns T, error E, progress P,
//! cardinality many; `get`: returns the tagged enum, cardinality one), in a
//! base version and in variants that change one thing. Canonicalises the
//! JSON (sorted keys, no whitespace) and hashes it with SHA-256 truncated to
//! 16 hex. Prints one JSON line per fact on stdout:
//!
//!   {"kind":"hash",…}    per probe — run.sh compares these across runs/builds
//!   {"kind":"check",…}   this build's own expectations, pass or fail
//!   {"kind":"defs",…}    the `$defs` names schemars chose
//!   {"kind":"timing",…}  cost; never compared
//!
//! `returns3-hash-spike [DUMP_DIR]` also writes each probe's canonical and
//! raw (`serde_json::to_string`) JSON to DUMP_DIR, for byte-for-byte diffs.

#![allow(dead_code)]

use returns3_hash_spike::{
    canonical, hash16, method_hash, method_hash_required_sorted, rollup_default_hasher,
    rollup_sha256, token_hash_today,
};
use serde_json::{json, Value};
use std::hint::black_box;
use std::time::Instant;

mod prelude {
    pub use schemars::{schema_for, JsonSchema};
    pub use serde::{Deserialize, Serialize};
}

/// One probe's schemas, as JSON values.
pub struct Shapes {
    pub t: Value,
    pub e: Value,
    pub p: Value,
    pub tagged: Value,
    pub generic: Value,
    pub params: Value,
}

pub fn to_value(s: schemars::Schema) -> Value {
    serde_json::to_value(s).expect("a schema serializes")
}

/// The types that *contain* T, E, P — redefined in every variant module so
/// they pick up that module's T, E, P.
macro_rules! dependents {
    () => {
        /// What `get` yields — a tagged enum over this module's T and E.
        #[derive(Serialize, Deserialize, JsonSchema)]
        #[serde(tag = "type", rename_all = "snake_case")]
        pub enum TicketsEvent {
            Created { ticket: Ticket },
            StatusChanged { id: String, from: Status, to: Status },
            Failed { error: TicketError },
        }

        /// RETURNS-4's `Progress<T, P = Note>`: `Update(P) | Item(T)`.
        #[derive(Serialize, Deserialize, JsonSchema)]
        pub enum Progress<T, P> {
            Update(P),
            Item(T),
        }

        pub fn shapes() -> crate::Shapes {
            crate::Shapes {
                t: crate::to_value(schema_for!(Ticket)),
                e: crate::to_value(schema_for!(TicketError)),
                p: crate::to_value(schema_for!(Note)),
                tagged: crate::to_value(schema_for!(TicketsEvent)),
                generic: crate::to_value(schema_for!(Result<Progress<Ticket, Note>, TicketError>)),
                params: crate::to_value(schema_for!(super::base::WatchParams)),
            }
        }
    };
}

mod base {
    use crate::prelude::*;

    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }

    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    pub enum Status {
        Pending,
        Ready,
        Coding,
        Done,
    }

    /// Why a call failed — E.
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum TicketError {
        NotFound { id: String },
        Invalid { field: String, reason: String },
        Conflict { id: String, held_by: u32 },
    }

    /// RETURNS-4's `Note { message, percentage }` — P.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Note {
        pub message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub percentage: Option<f32>,
    }

    /// Two instances of one generic in one schema: how schemars names them.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct TwoProgresses {
        pub noted: Progress<Ticket, Note>,
        pub stepped: Progress<Ticket, Status>,
    }

    /// `watch`'s params.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct WatchParams {
        /// Only this epic.
        pub epic: Option<String>,
        /// Only changes after this unix time.
        pub since: Option<u64>,
    }

    dependents!();
}

// ---- T (Ticket) ---------------------------------------------------------

mod t_added {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
        pub assignee: Option<String>,
    }
    dependents!();
}

mod t_renamed {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub name: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    dependents!();
}

mod t_retyped {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    dependents!();
}

mod t_reordered {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// Short description.
        pub title: String,
        /// `EPIC-N`.
        pub id: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    dependents!();
}

/// A change two levels down: a variant added to `Status`, which `Ticket` holds.
mod t_nested_variant {
    use crate::prelude::*;
    pub use super::base::{Note, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    pub enum Status {
        Pending,
        Ready,
        Coding,
        Blocked,
        Done,
    }
    dependents!();
}

/// The Rust field is renamed, the wire name is not (`#[serde(rename)]`):
/// the client cannot tell, so the hash should not either.
mod t_rust_rename_wire_same {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        #[serde(rename = "title")]
        pub headline: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    dependents!();
}

/// Only a doc comment changes — it reaches the schema as `description`.
mod t_doc_edited {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Ticket {
        /// `EPIC-N`.
        pub id: String,
        /// One-line summary.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    dependents!();
}

/// The type is renamed, its shape is not: `title` and the `$defs` key move.
mod t_type_renamed {
    use crate::prelude::*;
    pub use super::base::{Note, Status, TicketError};
    /// A unit of planned work.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Issue {
        /// `EPIC-N`.
        pub id: String,
        /// Short description.
        pub title: String,
        pub status: Status,
        pub blocked_by: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub body: Option<String>,
    }
    pub type Ticket = Issue;
    dependents!();
}

// ---- E (TicketError) ----------------------------------------------------

mod e_added {
    use crate::prelude::*;
    pub use super::base::{Note, Status, Ticket};
    /// Why a call failed — E.
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum TicketError {
        NotFound { id: String },
        Invalid { field: String, reason: String, hint: Option<String> },
        Conflict { id: String, held_by: u32 },
    }
    dependents!();
}

mod e_renamed {
    use crate::prelude::*;
    pub use super::base::{Note, Status, Ticket};
    /// Why a call failed — E.
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum TicketError {
        NotFound { id: String },
        Invalid { field: String, reason: String },
        Conflict { id: String, holder: u32 },
    }
    dependents!();
}

mod e_retyped {
    use crate::prelude::*;
    pub use super::base::{Note, Status, Ticket};
    /// Why a call failed — E.
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum TicketError {
        NotFound { id: String },
        Invalid { field: String, reason: String },
        Conflict { id: String, held_by: String },
    }
    dependents!();
}

// ---- P (Note) -----------------------------------------------------------

mod p_added {
    use crate::prelude::*;
    pub use super::base::{Status, Ticket, TicketError};
    /// RETURNS-4's `Note { message, percentage }` — P.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Note {
        pub message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub percentage: Option<f32>,
        pub step: u32,
    }
    dependents!();
}

mod p_renamed {
    use crate::prelude::*;
    pub use super::base::{Status, Ticket, TicketError};
    /// RETURNS-4's `Note { message, percentage }` — P.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Note {
        pub text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub percentage: Option<f32>,
    }
    dependents!();
}

mod p_retyped {
    use crate::prelude::*;
    pub use super::base::{Status, Ticket, TicketError};
    /// RETURNS-4's `Note { message, percentage }` — P.
    #[derive(Serialize, Deserialize, JsonSchema)]
    pub struct Note {
        pub message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub percentage: Option<u8>,
    }
    dependents!();
}

// ---- methods built from a probe's shapes --------------------------------

const WATCH_DESC: &str = "Stream ticket changes";
const GET_DESC: &str = "Get one ticket";

/// A method schema in RETURNS-5's 0.7 shape (`returns`, `error`,
/// `progress`, `cardinality`), with the fields the hash must cover.
fn method(
    name: &str,
    description: &str,
    params: Option<&Value>,
    returns: &Value,
    error: Option<&Value>,
    progress: Option<&Value>,
    cardinality: &str,
) -> Value {
    let mut m = json!({
        "name": name,
        "description": description,
        "hash": "(computed)",
        "returns": returns,
        "cardinality": cardinality,
    });
    let o = m.as_object_mut().unwrap();
    if let Some(p) = params {
        o.insert("params".into(), p.clone());
    }
    if let Some(e) = error {
        o.insert("error".into(), e.clone());
    }
    if let Some(p) = progress {
        o.insert("progress".into(), p.clone());
    }
    m
}

/// `watch(epic, since) -> impl Stream<Item = Result<Progress<Ticket, Note>, TicketError>>`
fn watch(s: &Shapes) -> Value {
    method("watch", WATCH_DESC, Some(&s.params), &s.t, Some(&s.e), Some(&s.p), "many")
}

/// `get(id) -> TicketsEvent`
fn get(s: &Shapes) -> Value {
    method("get", GET_DESC, None, &s.tagged, None, None, "one")
}

/// Today's macro hash of `watch`: the signature's tokens, which no variant
/// in this file changes.
fn today_watch(desc: &str) -> String {
    token_hash_today(
        "watch",
        desc,
        &[
            ("epic", "Option < String >", Some("Only this epic")),
            ("since", "Option < u64 >", Some("Only changes after this unix time")),
        ],
        Some("Result < Progress < Ticket , Note > , TicketError >"),
    )
}

fn today_get() -> String {
    token_hash_today("get", GET_DESC, &[("id", "String", None)], Some("TicketsEvent"))
}

struct Row {
    probe: &'static str,
    watch: Value,
    get: Value,
    shapes: Shapes,
    today_watch: String,
}

fn h(v: &Value) -> String {
    hash16(canonical(v).as_bytes())
}

fn raw(v: &Value) -> String {
    hash16(serde_json::to_string(v).unwrap().as_bytes())
}

fn row(probe: &'static str, shapes: Shapes) -> Row {
    Row {
        probe,
        watch: watch(&shapes),
        get: get(&shapes),
        today_watch: today_watch(WATCH_DESC),
        shapes,
    }
}

fn main() {
    let dump = std::env::args().nth(1).map(std::path::PathBuf::from);

    // Every probe: (name, a fresh schema build). Built twice to check
    // in-process determinism.
    let builders: Vec<(&'static str, fn() -> Shapes)> = vec![
        ("base", base::shapes),
        ("t_added", t_added::shapes),
        ("t_renamed", t_renamed::shapes),
        ("t_retyped", t_retyped::shapes),
        ("t_reordered", t_reordered::shapes),
        ("t_nested_variant", t_nested_variant::shapes),
        ("t_rust_rename_wire_same", t_rust_rename_wire_same::shapes),
        ("t_doc_edited", t_doc_edited::shapes),
        ("t_type_renamed", t_type_renamed::shapes),
        ("e_added", e_added::shapes),
        ("e_renamed", e_renamed::shapes),
        ("e_retyped", e_retyped::shapes),
        ("p_added", p_added::shapes),
        ("p_renamed", p_renamed::shapes),
        ("p_retyped", p_retyped::shapes),
    ];

    let mut rows: Vec<Row> = Vec::new();
    let mut checks: Vec<(String, bool, String)> = Vec::new();

    for (name, build) in &builders {
        let a = build();
        let b = build();
        let same = [
            (&a.t, &b.t),
            (&a.e, &b.e),
            (&a.p, &b.p),
            (&a.tagged, &b.tagged),
            (&a.generic, &b.generic),
        ]
        .iter()
        .all(|(x, y)| canonical(x) == canonical(y) && serde_json::to_string(x).unwrap() == serde_json::to_string(y).unwrap());
        checks.push((
            format!("in_process_deterministic:{name}"),
            same,
            "two schema_for! builds in one process: canonical and raw JSON byte-identical".into(),
        ));
        rows.push(row(name, a));
    }

    // Method-level rows the pass condition's table needs beyond T/E/P fields.
    let base = base::shapes();
    let extra: Vec<(&'static str, Value)> = vec![
        ("m_cardinality_one", method("watch", WATCH_DESC, Some(&base.params), &base.t, Some(&base.e), Some(&base.p), "one")),
        ("m_no_progress", method("watch", WATCH_DESC, Some(&base.params), &base.t, Some(&base.e), None, "many")),
        ("m_infallible", method("watch", WATCH_DESC, Some(&base.params), &base.t, None, Some(&base.p), "many")),
        ("m_description_edited", method("watch", "Stream every ticket change", Some(&base.params), &base.t, Some(&base.e), Some(&base.p), "many")),
        ("m_returns_replaced", method("watch", WATCH_DESC, Some(&base.params), &base.p, Some(&base.e), Some(&base.p), "many")),
    ];

    let base_row = &rows[0];
    let base_watch = method_hash(&base_row.watch);
    let base_get = method_hash(&base_row.get);
    let base_watch_sorted = method_hash_required_sorted(&base_row.watch);

    // ---- hash lines ----
    for r in &rows {
        let watch_h = method_hash(&r.watch);
        let get_h = method_hash(&r.get);
        let today = vec![r.today_watch.clone(), today_get()];
        let new = vec![watch_h.clone(), get_h.clone()];
        let (self_today, _, plugin_today) = rollup_default_hasher(&today, None);
        let (self_new_sha, _, plugin_new_sha) = rollup_sha256(&new, None);
        let (_, _, plugin_new_dh) = rollup_default_hasher(&new, None);
        println!(
            "{}",
            json!({
                "kind": "hash",
                "probe": r.probe,
                "t": h(&r.shapes.t),
                "e": h(&r.shapes.e),
                "p": h(&r.shapes.p),
                "tagged": h(&r.shapes.tagged),
                "generic": h(&r.shapes.generic),
                "method_watch": watch_h,
                "method_get": get_h,
                "method_watch_required_sorted": method_hash_required_sorted(&r.watch),
                "today_method_watch": r.today_watch,
                "today_self_hash": self_today,
                "today_plugin_hash": plugin_today,
                "new_self_hash": self_new_sha,
                "new_plugin_hash": plugin_new_sha,
                "new_methods_old_rollup_plugin_hash": plugin_new_dh,
                "raw_generic": raw(&r.shapes.generic),
                "raw_tagged": raw(&r.shapes.tagged),
            })
        );
    }
    for (probe, m) in &extra {
        println!(
            "{}",
            json!({"kind": "hash", "probe": probe, "method_watch": method_hash(m), "method_watch_required_sorted": method_hash_required_sorted(m)})
        );
    }

    // ---- checks: field changes inside T, E, P change the method hash ----
    let expect_change = [
        "t_added", "t_renamed", "t_retyped", "t_nested_variant", "e_added", "e_renamed",
        "e_retyped", "p_added", "p_renamed", "p_retyped",
    ];
    for r in &rows[1..] {
        let wh = method_hash(&r.watch);
        let changed = wh != base_watch;
        let today_changed = r.today_watch != base_row.today_watch;
        let note;
        let pass = if expect_change.contains(&r.probe) {
            note = "a field added/renamed/retyped inside T, E or P must change watch's hash";
            changed
        } else if r.probe == "t_rust_rename_wire_same" {
            note = "Rust name changed, wire name kept by #[serde(rename)]: hash should NOT change";
            !changed
        } else {
            note = "recorded, not part of the pass condition";
            true
        };
        checks.push((
            format!("changes:{}", r.probe),
            pass,
            format!(
                "{note}; new watch hash changed={changed}, get hash changed={}, required-sorted changed={}, today's token hash changed={today_changed}",
                method_hash(&r.get) != base_get,
                method_hash_required_sorted(&r.watch) != base_watch_sorted,
            ),
        ));
    }
    for (probe, m) in &extra {
        let changed = method_hash(m) != base_watch;
        checks.push((format!("changes:{probe}"), changed, format!("method-level change must change the hash; changed={changed}")));
    }
    let all16 = rows.iter().all(|r| {
        [method_hash(&r.watch), method_hash(&r.get)]
            .iter()
            .all(|x| x.len() == 16 && x.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
    });
    checks.push(("width:16_lowercase_hex".into(), all16, "every new hash is 16 lowercase hex (plexus_hash validator)".into()));

    for (name, pass, detail) in &checks {
        println!("{}", json!({"kind": "check", "name": name, "pass": pass, "detail": detail}));
    }

    // ---- $defs names ----
    for r in rows.iter().filter(|r| ["base", "t_type_renamed"].contains(&r.probe)) {
        for (shape, v) in [("tagged", &r.shapes.tagged), ("generic", &r.shapes.generic)] {
            let defs: Vec<String> = v
                .get("$defs")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let title = v.get("title").cloned().unwrap_or(Value::Null);
            let has_module_path = canonical(v).contains("::");
            println!(
                "{}",
                json!({"kind": "defs", "probe": r.probe, "shape": shape, "title": title, "defs": defs, "contains_rust_path": has_module_path})
            );
        }
    }

    {
        let v = to_value(schemars::schema_for!(base::TwoProgresses));
        let defs: Vec<String> = v["$defs"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
        let refs = |k: &str| v["properties"][k]["$ref"].clone();
        println!(
            "{}",
            json!({"kind": "defs", "probe": "base", "shape": "TwoProgresses", "defs": defs, "noted_ref": refs("noted"), "stepped_ref": refs("stepped"), "hash": h(&v)})
        );
    }

    // ---- dumps ----
    if let Some(dir) = &dump {
        std::fs::create_dir_all(dir).expect("dump dir");
        for r in &rows {
            for (shape, v) in [
                ("t", &r.shapes.t),
                ("e", &r.shapes.e),
                ("p", &r.shapes.p),
                ("tagged", &r.shapes.tagged),
                ("generic", &r.shapes.generic),
                ("method_watch", &r.watch),
            ] {
                std::fs::write(dir.join(format!("{}.{shape}.canonical.json", r.probe)), canonical(v)).unwrap();
                std::fs::write(dir.join(format!("{}.{shape}.raw.json", r.probe)), serde_json::to_string(v).unwrap()).unwrap();
            }
        }
    }

    // ---- timing (base types) ----
    const N: u32 = 2000;
    let time = |label: &str, f: &dyn Fn() -> usize| {
        let mut bytes = 0;
        for _ in 0..50 {
            black_box(f());
        }
        let t0 = Instant::now();
        for _ in 0..N {
            bytes = black_box(f());
        }
        let us = t0.elapsed().as_secs_f64() * 1e6 / N as f64;
        println!("{}", json!({"kind": "timing", "what": label, "us_per_op": (us * 100.0).round() / 100.0, "bytes": bytes}));
    };
    use base::*;
    use schemars::schema_for;
    time("schema_for!(Ticket) + to_value + canonical", &|| canonical(&to_value(schema_for!(Ticket))).len());
    time("schema_for!(TicketError) + to_value + canonical", &|| canonical(&to_value(schema_for!(TicketError))).len());
    time("schema_for!(Note) + to_value + canonical", &|| canonical(&to_value(schema_for!(Note))).len());
    time("schema_for!(TicketsEvent) + to_value + canonical", &|| canonical(&to_value(schema_for!(TicketsEvent))).len());
    time(
        "schema_for!(Result<Progress<Ticket,Note>,TicketError>) + to_value + canonical",
        &|| canonical(&to_value(schema_for!(Result<Progress<Ticket, Note>, TicketError>))).len(),
    );
    let w = watch(&base);
    time("canonical(watch) only", &|| canonical(&w).len());
    time("method_hash(watch) = clone + canonical + sha256", &|| method_hash(&w).len());
    time("whole method: 3 schema_for! + params + canonical + sha256", &|| {
        let s = Shapes {
            t: to_value(schema_for!(Ticket)),
            e: to_value(schema_for!(TicketError)),
            p: to_value(schema_for!(Note)),
            tagged: Value::Null,
            generic: Value::Null,
            params: to_value(schema_for!(WatchParams)),
        };
        method_hash(&watch(&s)).len()
    });

    let failed = checks.iter().filter(|c| !c.1).count();
    eprintln!("{} checks, {} failed", checks.len(), failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
