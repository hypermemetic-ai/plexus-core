//! PERF-15's first line held fast: the self-description a caller gets —
//! `_info`, the service's `hash` and `schema`, every `<ns>.schema`, whole or
//! one method, on the module and routed — is the same answer whether it was
//! computed for this ask or kept from an earlier one, and the same, byte for
//! byte, as the answer before the cache existed.
//!
//! Every answer, its clocks set to 0, is held by `tests/golden/describe.json`
//! — the sha256 and length of its bytes (the 144 answers whole are 1.2 MB) —
//! written from main *before* PERF-15 (`GOLDEN_WRITE=1 cargo test -p
//! plexus-core --test describe_golden`, on the parent commit) and never by
//! the build it holds. Each is asked twice, and the second must equal the
//! first. A build that means to change what a caller sees writes the file
//! again deliberately; one that differs prints the answer it gave.
//!
//! PERF-21: AUTH-5's service is held too — the auth activation mounted beside
//! tickets — by `tests/golden/describe_auth.json`, with the hash it stamps as
//! every item's `plexus_hash` when it is a process's service. A service lists
//! its activations by namespace, so two activations answer the same at every
//! run. Before PERF-21 it listed them in its map's order, which differed from
//! one run to the next, and so did every hash over them; the file is main's
//! answer from a run whose map listed `auth` before `tickets`, the order a
//! service now always lists them in. `GOLDEN_WRITE=describe_auth.json` (or
//! `describe.json`) writes that file alone; `GOLDEN_WRITE=1` both.
//!
//! Its own test binary: the stream items' `plexus_hash` is a process-wide
//! value set by the first RPC module built, so nothing else may build one
//! here first. `world()`'s is built first, so both files' items carry its.

mod describe_support;

use describe_support::*;
use serde_json::{json, Value};

#[tokio::test]
async fn the_answers_are_todays() {
    let w = world();
    // The first module built names the process's plexus_hash: this world's.
    let _first = module_for(&w, None);
    hold("describe.json", answers(&w).await);
    // PERF-21: two activations, and what they hash to as a process's service.
    let a = auth_world();
    let mut got = answers(&a).await;
    got.push(("the service".into(), "plexus_hash: its compute_hash".into(), a.service.compute_hash()));
    hold("describe_auth.json", got);
}

/// Every ask in `asks()` for every caller in `callers()`, each asked twice
/// and the second equal to the first: (caller, ask, the answer's bytes).
async fn answers(w: &World) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (name, who) in callers() {
        let module = module_for(w, who.as_ref());
        for ask in asks() {
            let first = ask.answer(w, &module, who.as_ref()).await;
            let again = ask.answer(w, &module, who.as_ref()).await;
            assert_eq!(again, first, "{name}: {} asked again", ask.label());
            out.push((name.to_string(), ask.label(), serde_json::to_string(&first).unwrap()));
        }
    }
    out
}

/// `answers` against `tests/golden/<file>`, or written there when
/// `GOLDEN_WRITE` names it (or is `1`).
fn hold(file: &str, answers: Vec<(String, String, String)>) {
    let got: Vec<Value> = answers
        .iter()
        .map(|(caller, ask, bytes)| json!({"caller": caller, "ask": ask, "sha256": sha256(bytes), "bytes": bytes.len()}))
        .collect();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(file);
    if std::env::var("GOLDEN_WRITE").is_ok_and(|v| v == "1" || v == file) {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        eprintln!("wrote {} ({} answers)", path.display(), got.len());
        return;
    }
    let want: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("tests/golden/{file} (GOLDEN_WRITE={file} writes it)")),
    )
    .unwrap();
    assert_eq!(got.len(), want.len(), "{file}: the answers asked");
    for ((g, w), (_, _, bytes)) in got.iter().zip(&want).zip(&answers) {
        if g != w {
            eprintln!("--- {file}: {} — {}: the answer now ---\n{bytes}", w["caller"], w["ask"]);
        }
        assert_eq!(g, w, "{file}: {} — {}: not today's answer", w["caller"], w["ask"]);
    }
}

fn sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
