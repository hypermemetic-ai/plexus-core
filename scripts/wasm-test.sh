#!/usr/bin/env bash
# PLEXUS-45: plexus-core runs in wasm32 — tests/wasm_dispatch.rs, a
# DynamicHub dispatched under Node by wasm-bindgen-test-runner.
#
# Node, not a browser: the test needs only JS's timers, clock and
# randomness, which Node has, and it runs headless with nothing installed
# but node (as plexus-client's wasm tests do). The runner must match the
# lock's wasm-bindgen exactly; it is found on PATH, in ~/.cache/plexus-tools
# or ~/.cache/menger-tools, else installed once into ~/.cache/plexus-tools.
#
# getrandom 0.3 needs `--cfg getrandom_backend="wasm_js"` for the target: in
# ~/.cargo/config.toml on this machine; set here too when it is not.
set -euo pipefail
cd "$(dirname "$0")/.."

rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown || {
  echo "wasm32-unknown-unknown is not installed: rustup target add wasm32-unknown-unknown" >&2
  exit 2
}
command -v node >/dev/null || { echo "node is not on PATH" >&2; exit 2; }

# The lock (not tracked) says which wasm-bindgen the test links against.
cargo metadata --format-version 1 >/dev/null
want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)
[ -n "$want" ] || { echo "no wasm-bindgen in Cargo.lock" >&2; exit 2; }

runner=""
if command -v wasm-bindgen-test-runner >/dev/null && wasm-bindgen-test-runner --version 2>/dev/null | grep -q " $want\$"; then
  runner=$(command -v wasm-bindgen-test-runner)
else
  for c in "$HOME/.cache/plexus-tools" "$HOME/.cache/menger-tools"; do
    if [ -x "$c/wasm-bindgen-$want/bin/wasm-bindgen-test-runner" ]; then runner="$c/wasm-bindgen-$want/bin/wasm-bindgen-test-runner"; break; fi
  done
fi
if [ -z "$runner" ]; then
  cargo install wasm-bindgen-cli --version "$want" --locked --root "$HOME/.cache/plexus-tools/wasm-bindgen-$want"
  runner="$HOME/.cache/plexus-tools/wasm-bindgen-$want/bin/wasm-bindgen-test-runner"
fi

case "${RUSTFLAGS:-}${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS:-}$(cat "$HOME/.cargo/config.toml" 2>/dev/null)" in
  *getrandom_backend*) ;;
  *) export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js"' ;;
esac

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$runner"
exec cargo test --target wasm32-unknown-unknown --no-default-features --test wasm_dispatch "$@"
