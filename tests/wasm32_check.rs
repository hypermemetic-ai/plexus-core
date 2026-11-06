//! PLEXUS-45: plexus-core builds for `wasm32-unknown-unknown` — the library
//! with `--no-default-features`, as a browser crate depends on it. Part of the
//! native suite so a change that breaks the wasm build is red here, not in a
//! browser crate later; that it also *runs* is `tests/wasm_dispatch.rs`
//! (`scripts/wasm-test.sh`).
//!
//! Skipped, with a message, when the target is not installed.
#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;
use std::process::Command;

const TARGET: &str = "wasm32-unknown-unknown";

fn target_installed() -> bool {
    let sysroot = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
    sysroot.is_some_and(|s| s.join("lib/rustlib").join(TARGET).exists())
}

#[test]
fn the_library_checks_for_wasm32() {
    if !target_installed() {
        eprintln!("SKIPPED: {TARGET} is not installed (rustup target add {TARGET}); plexus-core's wasm32 build is unchecked");
        return;
    }
    // A target and build directory of its own: the suite's cargo holds its own.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wasm32-check");
    let out = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["check", "--lib", "--no-default-features", "--target", TARGET, "--message-format", "short"])
        .env("CARGO_TARGET_DIR", &dir)
        .env("CARGO_BUILD_BUILD_DIR", &dir)
        // the host's flags are not the target's; getrandom 0.3 takes its
        // randomness from JS only under this cfg
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS", r#"--cfg getrandom_backend="wasm_js""#)
        .output()
        .expect("cargo runs");
    assert!(
        out.status.success(),
        "cargo check --lib --no-default-features --target {TARGET} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
