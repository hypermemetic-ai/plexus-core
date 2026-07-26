//! PLX-101 — a benchmark number is not quotable without its resolution.
//!
//! # Why this module exists
//!
//! Until PLX-101, `plexus-core/.gitignore` ignored `Cargo.lock`. That is the
//! conventional choice for a library and it was wrong here, because this
//! crate's benchmarks are **decision inputs**:
//!
//! - decision gate 2 (PLX-74 / PLX-80) resolved PASS on a measured dispatch
//!   delta of +10.4 ns against a ~819-847 ns bar;
//! - PLX-88's attribution table assigned 36.7% of a 2633 ns turn to
//!   `tokio::spawn` and produced the "leave it" verdict on those numbers;
//! - PLX-97 reported before/after turn cost against PLX-88's figures.
//!
//! Every one of those was measured on a resolution nobody wrote down. PLX-97
//! then discovered what that costs: a fresh worktree re-resolved tokio
//! 1.48.0 -> 1.53.1 and `ladder_current/full_turn` went 2.63 us -> 14.0 us,
//! reproducibly, with no source change. PLX-101 bisected it to **tokio 1.50.0**
//! (1.49.0: `block_on(yield_now())` on a current-thread runtime = 845 ns;
//! 1.50.0: 12,736 ns) — a real upstream behaviour change, not a plexus
//! regression and not measurement noise.
//!
//! So: the lock is committed, and every bench prints the resolution it ran
//! under. If two numbers carry different banners, they are not comparable, and
//! this module is what makes that visible instead of invisible.
//!
//! # How it works
//!
//! `Cargo.lock` is `include_str!`d at compile time, so the banner cannot drift
//! from the binary that produced the numbers, and a bench **cannot build at all**
//! without a lock file present. No `build.rs`, no new dependency.

use std::fmt::Write as _;

/// The lock file that resolved the dependencies of the binary printing this.
///
/// Compile-time inclusion is load-bearing: it makes the banner an attribute of
/// the built artifact rather than of the directory it happens to run in.
const LOCK: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"));

/// Dependencies whose version can plausibly move a benchmark result.
///
/// Kept explicit rather than dumping all ~273 packages: a banner nobody reads
/// is the same as no banner. `tokio` is first because it is the one that has
/// actually bitten us (5.3x, PLX-101). The rest are on the measured path —
/// the executor, the stream/select! envelope, `TurnId`'s uuid, params decoding,
/// and criterion itself, whose sampling changes across majors.
const PERF_RELEVANT: &[&str] = &[
    "tokio",
    "tokio-stream",
    "tokio-macros",
    "futures",
    "futures-core",
    "futures-util",
    "async-stream",
    "async-trait",
    "uuid",
    "getrandom",
    "serde_json",
    "criterion",
];

/// FNV-1a over the whole lock file: one short token that answers "is this the
/// same resolution?" for all 273 packages, including the ones not listed above.
///
/// Hand-rolled because a benchmark banner is not worth a dependency, and
/// because this needs no cryptographic property — only that two different
/// resolutions almost never collide.
fn lock_fingerprint() -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in LOCK.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Scan the lock for `[[package]]` blocks and pull out `name`/`version` pairs.
///
/// A five-line scanner instead of a TOML parser: the lock's format is
/// `name = "x"` / `version = "y"` on consecutive lines within a block, and if
/// cargo ever changes that, an empty banner is a louder failure than a subtly
/// wrong one.
fn resolved_versions() -> Vec<(&'static str, &'static str)> {
    fn quoted(line: &str) -> Option<&str> {
        let (_, rest) = line.split_once('"')?;
        let (val, _) = rest.rsplit_once('"')?;
        Some(val)
    }

    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut name: Option<&str> = None;
    for line in LOCK.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            name = None;
        } else if let Some(v) = line.strip_prefix("name = ").and_then(quoted) {
            name = Some(v);
        } else if let Some(v) = line.strip_prefix("version = ").and_then(quoted) {
            if let Some(n) = name.take() {
                if PERF_RELEVANT.contains(&n) {
                    out.push((n, v));
                }
            }
        }
    }
    out.sort_unstable();
    out
}

/// The banner, as a string, so callers can print it *and* persist it.
pub fn banner(bench: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "==== resolution (PLX-101) — bench: {bench} ====");
    let _ = writeln!(
        s,
        "lock-fingerprint : {:016x}  (FNV-1a over Cargo.lock, all packages)",
        lock_fingerprint()
    );
    let _ = writeln!(
        s,
        "toolchain        : {}",
        option_env!("RUSTUP_TOOLCHAIN").unwrap_or("<not set: not built under rustup>")
    );
    let _ = writeln!(
        s,
        "host             : {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(
        s,
        "profile          : {}",
        if cfg!(debug_assertions) {
            "debug_assertions ON — benchmark numbers from this build are NOT quotable"
        } else {
            "optimized (debug_assertions off)"
        }
    );
    let _ = writeln!(s, "perf-relevant resolved versions:");
    for (n, v) in resolved_versions() {
        let _ = writeln!(s, "    {n:<14} {v}");
    }
    let _ = writeln!(
        s,
        "Numbers from two runs with different lock-fingerprints are NOT comparable."
    );
    let _ = writeln!(
        s,
        "Known cliff: tokio >= 1.50.0 costs ~+11.5 us per current-thread park/unpark"
    );
    let _ = writeln!(
        s,
        "(block_on(yield_now): 1.49.0 = 845 ns, 1.50.0 = 12736 ns). See PLX-101."
    );
    let _ = writeln!(s, "{}", "=".repeat(60));
    s
}

/// Print the banner and, best-effort, drop it next to criterion's own output so
/// a saved result set carries its resolution with it.
///
/// The file write is deliberately best-effort: a benchmark must not fail
/// because a directory was read-only. The stdout copy is the one that matters,
/// because that is what ends up pasted into a ticket.
pub fn emit(bench: &str) {
    let banner = banner(bench);
    print!("{banner}");

    let dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dir = std::path::Path::new(&dir).join("criterion");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(dir.join(format!("resolution-{bench}.txt")), &banner);
    }
}
