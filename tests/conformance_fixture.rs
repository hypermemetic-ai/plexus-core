//! RETURNS-7: the conformance fixture's expected JSON parses with the 0.7
//! types.
//!
//! The fixture is `../plexus-macros/fixtures/conformance/`, read by sibling
//! path (MFE-10): one activation with one method per signature form, and the
//! schema, frames and aggregate every generator must reproduce. RETURNS-8
//! serves it, and RETURNS-9, -12, -13, -17 and -18 decode it. This test
//! checks the half that needs no macro: every expected file is a value of the
//! 0.7 type it claims to be, and the files agree with each other and with
//! the fixture's own item types (`src/types.rs`, included below).
//!
//! Comparison rules (the fixture's README): a `"*"` hash is a wildcard,
//! `timestamp` is normalized to 0, and key order is not significant except in
//! `aggregate.jsonl`, which is byte-exact serde output.

use std::collections::BTreeSet;
use std::path::PathBuf;

use plexus_client::{wire_result, Note, StreamItem};
use plexus_core::plexus::schema::Cardinality;
use plexus_core::plexus::{PlexusStreamItem, PluginSchema};
use schemars::schema_for;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[path = "../../plexus-macros/fixtures/conformance/src/types.rs"]
mod types;
use types::*;

const NS: &str = "conformance";

fn expected_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-macros/fixtures/conformance/expected")
}

fn read(rel: &str) -> String {
    let path = expected_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (the fixture is read by sibling path, ../plexus-macros)",
            path.display()
        )
    })
}

/// The non-empty lines of a `.jsonl` file, 1-based.
fn lines(rel: &str) -> Vec<(usize, String)> {
    read(rel)
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

fn value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON: {e}: {text}"))
}

/// Decodes `v` as `T` and asserts it re-encodes to the same value, so a field
/// serde would silently ignore or default is a failure, not a pass.
fn exact<T: Serialize + DeserializeOwned>(v: &Value, what: &str) -> T {
    let t: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| {
        panic!(
            "{what}: does not decode as {}: {e}\n{v}",
            std::any::type_name::<T>()
        )
    });
    assert_eq!(
        &serde_json::to_value(&t).unwrap(),
        v,
        "{what}: does not round-trip"
    );
    t
}

/// [`exact`] for a Result item, through `plexus_client::wire_result`.
fn exact_result<T, E>(v: &Value, what: &str) -> Result<T, E>
where
    T: Serialize + DeserializeOwned,
    E: Serialize + DeserializeOwned,
{
    let r: Result<T, E> = wire_result::deserialize(v.clone())
        .unwrap_or_else(|e| panic!("{what}: not a wire_result item: {e}\n{v}"));
    assert_eq!(
        &wire_result::serialize(&r, serde_json::value::Serializer).unwrap(),
        v,
        "{what}: does not round-trip through wire_result"
    );
    r
}

/// One entry of `calls.json`: a call, and where its expected frames are.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    method: String,
    params: Value,
    /// Relative to `expected/`.
    frames: String,
    /// For `errors.jsonl`, the 1-based line holding this call's one frame.
    #[serde(default)]
    line: Option<usize>,
}

fn calls() -> Vec<Call> {
    serde_json::from_str(&read("calls.json")).expect("calls.json is a list of calls")
}

/// The aggregate rule (RETURNS-1 decisions 1, 5, 7), applied by hand: one
/// variant per method, keyed by its wire name, carrying the method's item. A
/// progress update is not an item, so `load` carries `Result<Loaded,
/// LoadError>` and `warm` carries `Warmed`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", content = "event", rename_all = "snake_case")]
enum ConformanceEvent {
    Ping(Pong),
    Lookup(#[serde(with = "plexus_client::wire_result")] Result<Thing, LookupError>),
    Count(Tick),
    Scan(#[serde(with = "plexus_client::wire_result")] Result<Row, ScanError>),
    Load(#[serde(with = "plexus_client::wire_result")] Result<Loaded, LoadError>),
    Warm(Warmed),
}

/// The method a frame belongs to, from its `content_type`.
fn method_of(content_type: &str) -> &str {
    content_type
        .strip_prefix("conformance.")
        .unwrap_or_else(|| panic!("content_type {content_type:?} is not conformance.<method>"))
}

/// Decodes a data frame's content as the method's item.
fn check_item(method: &str, content: &Value, what: &str) {
    match method {
        "ping" => {
            exact::<Pong>(content, what);
        }
        "lookup" => {
            let _ = exact_result::<Thing, LookupError>(content, what);
        }
        "count" => {
            exact::<Tick>(content, what);
        }
        "scan" => {
            let _ = exact_result::<Row, ScanError>(content, what);
        }
        "load" => {
            let _ = exact_result::<Loaded, LoadError>(content, what);
        }
        "warm" => {
            exact::<Warmed>(content, what);
        }
        other => panic!("{what}: no method {other:?} in the fixture"),
    }
}

/// Decodes a progress frame's content as the method's progress type.
fn check_progress(method: &str, content: &Value, what: &str) {
    match method {
        "load" => {
            exact::<LoadStep>(content, what);
        }
        "warm" => {
            exact::<Note>(content, what);
        }
        other => panic!("{what}: {other} declares no progress, yet has a progress frame"),
    }
}

/// Acceptance 1: every line of `wire/*.jsonl` and `errors.jsonl` is a
/// `PlexusStreamItem` 0.7 (and a client `StreamItem`), whole: it re-encodes to
/// the same value. Its metadata is the deterministic one. `calls.json` names
/// every file exactly once.
#[test]
fn every_frame_is_a_plexus_stream_item() {
    let calls = calls();

    let mut on_disk: BTreeSet<String> = std::fs::read_dir(expected_dir().join("wire"))
        .expect("expected/wire/")
        .map(|e| format!("wire/{}", e.unwrap().file_name().to_string_lossy()))
        .collect();
    on_disk.insert("errors.jsonl".into());
    let named: BTreeSet<String> = calls.iter().map(|c| c.frames.clone()).collect();
    assert_eq!(
        named, on_disk,
        "calls.json and expected/ disagree on the frame files"
    );

    let mut frames = 0;
    for file in &on_disk {
        for (n, line) in lines(file) {
            let what = format!("{file}:{n}");
            let v = value(&line);
            let item: PlexusStreamItem = exact(&v, &what);
            let _: StreamItem = exact(&v, &what);
            let metadata = match &item {
                PlexusStreamItem::Data { metadata, .. }
                | PlexusStreamItem::Progress { metadata, .. }
                | PlexusStreamItem::Error { metadata, .. }
                | PlexusStreamItem::Done { metadata } => metadata,
                PlexusStreamItem::Request { .. } => panic!("{what}: the fixture sends no requests"),
            };
            assert_eq!(
                metadata.provenance,
                vec![NS.to_string()],
                "{what}: provenance"
            );
            assert_eq!(
                metadata.plexus_hash, "*",
                "{what}: plexus_hash is the wildcard"
            );
            assert_eq!(
                metadata.timestamp, 0,
                "{what}: timestamp is normalized to 0"
            );
            frames += 1;
        }
    }
    assert_eq!(
        frames, 25,
        "frame count changed — a contract change: update the README"
    );
}

/// Acceptance 2 and 4: `schema.json` is a 0.7 `PluginSchema`, whole, with
/// every hash the `"*"` wildcard. Each method's `returns` / `error` /
/// `progress` is the schema of its T / E / P (RETURNS-5: `with_returns(
/// schema_for!(T))` …), and the six methods are the six signature forms.
#[test]
fn the_schema_is_a_plugin_schema() {
    let v = value(&read("schema.json"));
    let schema: PluginSchema = exact(&v, "schema.json");

    assert_eq!(schema.namespace, NS);
    assert_eq!(
        (schema.self_hash.as_str(), schema.hash.as_str()),
        ("*", "*")
    );
    assert_eq!(schema.children_hash, None, "a leaf");
    assert!(!schema.is_hub_by_role(), "a leaf");

    let s = |schema: schemars::Schema| serde_json::to_value(schema).unwrap();
    use Cardinality::{Many, One};
    let expected = [
        ("ping", One, s(schema_for!(Pong)), None, None),
        (
            "lookup",
            One,
            s(schema_for!(Thing)),
            Some(s(schema_for!(LookupError))),
            None,
        ),
        ("count", Many, s(schema_for!(Tick)), None, None),
        (
            "scan",
            Many,
            s(schema_for!(Row)),
            Some(s(schema_for!(ScanError))),
            None,
        ),
        (
            "load",
            Many,
            s(schema_for!(Loaded)),
            Some(s(schema_for!(LoadError))),
            Some(s(schema_for!(LoadStep))),
        ),
        (
            "warm",
            Many,
            s(schema_for!(Warmed)),
            None,
            Some(s(schema_for!(Note))),
        ),
    ];
    let names: Vec<&str> = schema.methods.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, expected.iter().map(|e| e.0).collect::<Vec<_>>());

    let mut forms = BTreeSet::new();
    for (m, (name, cardinality, returns, error, progress)) in schema.methods.iter().zip(expected) {
        assert_eq!(m.hash, "*", "{name}: hash is the wildcard");
        assert_eq!(m.cardinality, cardinality, "{name}: cardinality");
        assert_eq!(
            s(m.returns.clone()),
            returns,
            "{name}: returns is schema_for!(T)"
        );
        assert_eq!(
            m.error.clone().map(s),
            error,
            "{name}: error is schema_for!(E)"
        );
        assert_eq!(
            m.progress.clone().map(s),
            progress,
            "{name}: progress is schema_for!(P)"
        );
        forms.insert((cardinality == Many, m.error.is_some(), m.progress.is_some()));
    }
    assert_eq!(forms.len(), 6, "the six signature forms, one method each");
}

/// The frames of each call are its method's: data content decodes as the
/// item, progress content as P, and the stream ends in exactly one `done`.
/// `scan` has an err followed by more ok items (acceptance 4). Each
/// `errors.jsonl` line is the call failure its call provokes.
#[test]
fn every_frame_carries_its_methods_types() {
    let mut scan_err_then_ok = false;
    for call in calls() {
        let file = &call.frames;
        if let Some(line) = call.line {
            let (_, text) = lines(file)
                .into_iter()
                .find(|(n, _)| *n == line)
                .unwrap_or_else(|| panic!("{file} has no line {line}"));
            let PlexusStreamItem::Error {
                error, recoverable, ..
            } = serde_json::from_str(&text).unwrap()
            else {
                panic!("{file}:{line}: not an error frame");
            };
            assert!(!recoverable, "{file}:{line}: recoverable");
            let expected = match (call.method.as_str(), &call.params) {
                ("frob", _) => {
                    json!({"kind": "method_not_found", "activation": NS, "method": "frob"})
                }
                ("lookup", p) if p == &json!({}) => {
                    json!({"kind": "invalid_params", "param": "id", "problem": "missing"})
                }
                ("count", p) if p["to"].is_string() => json!({
                    "kind": "invalid_params", "param": "to", "problem": "malformed",
                    "detail": serde_json::from_value::<u32>(p["to"].clone()).unwrap_err().to_string(),
                }),
                other => panic!("{file}:{line}: unexpected error call {other:?}"),
            };
            assert_eq!(
                serde_json::to_value(&error).unwrap(),
                expected,
                "{file}:{line}"
            );
            continue;
        }

        let frames: Vec<(usize, PlexusStreamItem)> = lines(file)
            .into_iter()
            .map(|(n, l)| (n, serde_json::from_str(&l).unwrap()))
            .collect();
        let (last, body) = frames
            .split_last()
            .unwrap_or_else(|| panic!("{file} is empty"));
        assert!(
            matches!(last.1, PlexusStreamItem::Done { .. }),
            "{file}: ends in done"
        );
        let mut oks = Vec::new();
        for (n, frame) in body {
            let what = format!("{file}:{n}");
            match frame {
                PlexusStreamItem::Data {
                    content_type,
                    content,
                    ..
                } => {
                    assert_eq!(method_of(content_type), call.method, "{what}: content_type");
                    check_item(&call.method, content, &what);
                    if content.get("ok").is_some() || content.get("err").is_some() {
                        oks.push(content.get("ok").is_some());
                    }
                }
                PlexusStreamItem::Progress {
                    content_type,
                    content,
                    ..
                } => {
                    assert_eq!(method_of(content_type), call.method, "{what}: content_type");
                    check_progress(&call.method, content, &what);
                }
                other => panic!("{what}: only data and progress before done, got {other:?}"),
            }
        }
        if call.method == "scan" {
            let first_err = oks.iter().position(|ok| !ok).expect("scan yields an err");
            scan_err_then_ok = oks[first_err + 1..].iter().any(|ok| *ok);
        }
    }
    assert!(
        scan_err_then_ok,
        "scan carries on past its err with more ok items"
    );
}

/// Acceptance 3: every line of `aggregate.jsonl` is a `ConformanceEvent`,
/// byte for byte as serde writes it; every Result item in it decodes through
/// `plexus_client::wire_result`.
#[test]
fn aggregate_items_decode_through_wire_result() {
    let mut results = 0;
    for (n, line) in lines("aggregate.jsonl") {
        let what = format!("aggregate.jsonl:{n}");
        let event: ConformanceEvent =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            line,
            "{what}: byte for byte"
        );

        let v = value(&line);
        let item = &v["event"];
        match v["method"].as_str().unwrap() {
            "lookup" => {
                let _ = exact_result::<Thing, LookupError>(item, &what);
            }
            "scan" => {
                let _ = exact_result::<Row, ScanError>(item, &what);
            }
            "load" => {
                let _ = exact_result::<Loaded, LoadError>(item, &what);
            }
            _ => continue,
        }
        results += 1;
    }
    assert_eq!(results, 6, "two lookup, three scan, one load");
}

/// `aggregate.jsonl` is exactly the data frames of the calls, in call order,
/// each as `{"method": …, "event": <content>}`. Progress frames and call
/// failures are not items.
#[test]
fn the_aggregate_is_every_item_in_call_order() {
    let mut derived = Vec::new();
    for call in calls().into_iter().filter(|c| c.line.is_none()) {
        for (_, line) in lines(&call.frames) {
            if let PlexusStreamItem::Data {
                content_type,
                content,
                ..
            } = serde_json::from_str(&line).unwrap()
            {
                derived.push(json!({"method": method_of(&content_type), "event": content}));
            }
        }
    }
    let aggregate: Vec<Value> = lines("aggregate.jsonl")
        .iter()
        .map(|(_, l)| value(l))
        .collect();
    assert_eq!(aggregate, derived);
}
