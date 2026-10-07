//! RETURNS-3 spike — what the proposed method hash costs on a real
//! activation, and what it yields: menger's `tickets` (every method returns
//! the tagged `TicketsEvent`, which holds `Ticket`).
//!
//! One JSON line per method (today's macro hash beside the proposed one), a
//! roll-up line, and a timing line. A fresh process per run: the first
//! `method_schemas()` call is the uncached `compute_method_schemas()` a
//! server pays once at startup.

use menger_tickets_api::activation::TicketsMethod;
use returns3_hash_spike::{canonical, method_hash, rollup_default_hasher, rollup_sha256};
use serde_json::{json, Value};
use std::time::Instant;

fn us(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 1e6 * 100.0).round() / 100.0
}

fn main() {
    // Today's startup cost: schema_for! of every param struct and return
    // type, filtering, credential projection (macro-generated, OnceLock).
    let t0 = Instant::now();
    let schemas = TicketsMethod::method_schemas();
    let compute = t0.elapsed();

    let t1 = Instant::now();
    let cached = TicketsMethod::method_schemas();
    let cached_clone = t1.elapsed();
    assert_eq!(cached.len(), schemas.len());

    // The proposed addition: serialize each MethodSchema, canonicalise,
    // SHA-256 — once per method, at the same point.
    let t2 = Instant::now();
    let new_hashes: Vec<String> = schemas
        .iter()
        .map(|m| method_hash(&serde_json::to_value(m).expect("MethodSchema serializes")))
        .collect();
    let hashing = t2.elapsed();

    let values: Vec<Value> = schemas.iter().map(|m| serde_json::to_value(m).unwrap()).collect();
    let canonical_bytes: usize = values.iter().map(|v| canonical(v).len()).sum();

    for (m, new) in schemas.iter().zip(&new_hashes) {
        println!("{}", json!({"kind": "menger_method", "name": m.name, "today": m.hash, "new": new}));
    }
    let today: Vec<String> = schemas.iter().map(|m| m.hash.clone()).collect();
    let (today_self, _, today_hash) = rollup_default_hasher(&today, None);
    let (new_self, _, new_hash) = rollup_sha256(&new_hashes, None);
    println!(
        "{}",
        json!({"kind": "menger_rollup", "today_self_hash": today_self, "today_hash": today_hash, "new_self_hash": new_self, "new_hash": new_hash})
    );
    let rpc = schemas.iter().filter(|m| m.name != "schema").count();
    println!(
        "{}",
        json!({
            "kind": "menger_timing",
            "methods": schemas.len(),
            "rpc_methods": rpc,
            "compute_method_schemas_us": us(compute),
            "cached_clone_us": us(cached_clone),
            "hash_all_methods_us": us(hashing),
            "canonical_bytes_total": canonical_bytes,
        })
    );
}
