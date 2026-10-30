//! PERF-15's first line held fast: the self-description a caller gets —
//! `_info`, the service's `hash` and `schema`, every `<ns>.schema`, whole or
//! one method, on the module and routed — is the same answer whether it was
//! computed for this ask or kept from an earlier one, and the same, byte for
//! byte, as the answer before the cache existed.
//!
//! Every answer, its clocks set to 0, is held by `tests/golden/describe.json`
//! — the sha256 and length of its bytes (the 108 answers whole are 2.9 MB) —
//! written from main *before* PERF-15 (`GOLDEN_WRITE=1 cargo test -p
//! plexus-core --test describe_golden`, on the parent commit) and never by
//! the build it holds. Each is asked twice, and the second must equal the
//! first. A build that means to change what a caller sees writes the file
//! again deliberately; one that differs prints the answer it gave.
//!
//! Its own test binary: the stream items' `plexus_hash` is a process-wide
//! value set by the first RPC module built, so nothing else may build one
//! here first. And its service has one activation behind its gate: a
//! service lists its activations in its map's order, which differs from
//! one run to the next (`describe_support::service`).

mod describe_support;

use describe_support::*;
use serde_json::{json, Value};

#[tokio::test]
async fn the_answers_are_todays() {
    let w = world();
    // The first module built names the process's plexus_hash: this world's.
    let _first = module_for(&w, None);
    let callers: Vec<(&str, Option<plexus_core::plexus::AuthContext>)> = vec![
        ("anonymous", None),
        ("ada: editor on MENGER", Some(key(ADA, "worker-1"))),
        ("bob: editor on MENGER", Some(key(BOB, "worker-2"))),
        ("cat: editor on IDENTITY", Some(key(CAT, "worker-3"))),
        ("root: admin on *", Some(key(ROOT, "root"))),
        ("dan: holds nothing", Some(key(DAN, "dan"))),
        ("ada's session within editor@MENGER-12", Some(within(ADA, "worker-1", &["editor@MENGER-12"]))),
        ("root's session within tickets.get@*", Some(within(ROOT, "root", &["tickets.get@*"]))),
    ];
    let mut got = Vec::new();
    let mut answers = Vec::new();
    for (name, who) in &callers {
        let module = module_for(&w, who.as_ref());
        for ask in asks() {
            let first = ask.answer(&w, &module, who.as_ref()).await;
            let again = ask.answer(&w, &module, who.as_ref()).await;
            assert_eq!(again, first, "{name}: {} asked again", ask.label());
            let bytes = serde_json::to_string(&first).unwrap();
            got.push(json!({"caller": name, "ask": ask.label(), "sha256": sha256(&bytes), "bytes": bytes.len()}));
            answers.push(bytes);
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/describe.json");
    if std::env::var_os("GOLDEN_WRITE").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        eprintln!("wrote {} ({} answers)", path.display(), got.len());
        return;
    }
    let want: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("tests/golden/describe.json (GOLDEN_WRITE=1 on the parent commit writes it)"),
    )
    .unwrap();
    assert_eq!(got.len(), want.len(), "the answers asked");
    for ((g, w), bytes) in got.iter().zip(&want).zip(&answers) {
        if g != w {
            eprintln!("--- {} — {}: the answer now ---\n{bytes}", w["caller"], w["ask"]);
        }
        assert_eq!(g, w, "{} — {}: not today's answer", w["caller"], w["ask"]);
    }
}

fn sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
