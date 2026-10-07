#!/usr/bin/env bash
# RETURNS-3 spike — the runner. Builds the probe four ways, runs each build
# twice, and compares what they print; then measures menger's tickets.
#
#   spike/RETURNS-2/run.sh            # everything
#   SKIP_CONTAINER=1 spike/RETURNS-2/run.sh
#
# Builds (each into its own target dir under $OUT, default target/run):
#   A  debug,   default features,          host rustc
#   B  release, --features preserve_order, host rustc  (serde_json Map = IndexMap)
#   C  release, default features, in a container: rust:1.85-slim-bookworm
#      (another OS, rustc, user, paths — the nearest thing to another machine)
#   D  release, schemars pinned to 1.1.0 instead of 1.2.2 (a lockfile bump)
#
# Compared: every `"kind":"hash"` line except the raw_* fields must be
# byte-identical across A1 A2 B1 B2 C1 C2 (D is reported, not required);
# canonical dumps must be byte-identical across A, B, C; raw dumps are
# reported (B is expected to differ: that is why canonicalisation exists).
# Each build's own checks (`"kind":"check"`) must all pass.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${OUT:-$here/target/run}
menger=${MENGER_DIR:-$here/../../../menger}
image=${RUST_IMAGE:-docker.io/library/rust:1.85-slim-bookworm}
rm -rf "$out/A"* "$out/B"* "$out/C"* "$out/D"* "$out/src-"*
mkdir -p "$out"
say() { printf '%s\n' "$*" >&2; }

run_twice() { # build-label binary
  "$2" "$out/${1}1.dump" >"$out/${1}1.jsonl"
  "$2" "$out/${1}2.dump" >"$out/${1}2.jsonl"
}

say "== A: debug, host $(rustc --version)"
CARGO_TARGET_DIR=$out/target-a cargo build --quiet --manifest-path "$here/Cargo.toml"
run_twice A "$out/target-a/debug/returns3-hash-spike"

say "== B: release --features preserve_order, host rustc"
CARGO_TARGET_DIR=$out/target-b cargo build --quiet --release --features preserve_order --manifest-path "$here/Cargo.toml"
run_twice B "$out/target-b/release/returns3-hash-spike"

if [ -z "${SKIP_CONTAINER:-}" ]; then
  say "== C: release in $image"
  mkdir -p "$out/src-c"
  cp -r "$here/Cargo.toml" "$here/src" "$out/src-c/"
  docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
    -e CARGO_HOME=/tmp/cargo-home -e CARGO_TARGET_DIR=/out/target-c \
    -v "$out:/out" -w /out/src-c "$image" sh -c '
      rustc --version >&2
      cargo build --quiet --release
      for i in 1 2; do /out/target-c/release/returns3-hash-spike /out/C$i.dump > /out/C$i.jsonl; done'
fi

say "== D: release, schemars =1.1.0"
mkdir -p "$out/src-d"
cp -r "$here/src" "$out/src-d/"
sed 's/schemars = { version = "=1.2.2"/schemars = { version = "=1.1.0"/' "$here/Cargo.toml" >"$out/src-d/Cargo.toml"
CARGO_TARGET_DIR=$out/target-d cargo build --quiet --release --manifest-path "$out/src-d/Cargo.toml"
run_twice D "$out/target-d/release/returns3-hash-spike"

# ---- compare ------------------------------------------------------------
proj() { jq -S -c 'select(.kind=="hash") | del(.raw_generic, .raw_tagged)' "$1"; }
raws() { jq -S -c 'select(.kind=="hash") | {probe, raw_generic, raw_tagged}' "$1"; }
runs=(A1 A2 B1 B2)
[ -z "${SKIP_CONTAINER:-}" ] && runs+=(C1 C2)
status=0
say ""
say "== results"
for r in "${runs[@]}" D1 D2; do
  failed=$(jq -c 'select(.kind=="check" and .pass==false) | .name' "$out/$r.jsonl" | wc -l)
  total=$(jq -c 'select(.kind=="check")' "$out/$r.jsonl" | wc -l)
  say "checks $r: $((total - failed))/$total pass"
  [ "$failed" = 0 ] || status=1
done
for r in "${runs[@]:1}"; do
  if diff <(proj "$out/A1.jsonl") <(proj "$out/$r.jsonl") >/dev/null; then
    say "hash lines A1 == $r: identical"
  else
    say "hash lines A1 == $r: DIFFER"; status=1
  fi
done
for r in A2 B1 C1 D1; do
  [ -f "$out/$r.jsonl" ] || continue
  if diff <(raws "$out/A1.jsonl") <(raws "$out/$r.jsonl") >/dev/null; then
    say "raw (uncanonicalised) JSON hashes A1 vs $r: identical"
  else
    say "raw (uncanonicalised) JSON hashes A1 vs $r: differ in $(diff <(raws "$out/A1.jsonl") <(raws "$out/$r.jsonl") | grep -c '^>') probes"
  fi
done
for r in B1 C1 D1; do
  [ -d "$out/$r.dump" ] || continue
  c=$(diff -rq "$out/A1.dump" "$out/$r.dump" | grep -c 'canonical.json' || true)
  w=$(diff -rq "$out/A1.dump" "$out/$r.dump" | grep -c 'raw.json' || true)
  say "dump files A1 vs $r: canonical differ: $c, raw differ: $w (of $(ls "$out/A1.dump" | grep -c canonical) each)"
done
if diff <(proj "$out/A1.jsonl") <(proj "$out/D1.jsonl") >/dev/null; then
  say "schemars 1.1.0 (D) vs 1.2.2 (A): hash lines identical"
else
  say "schemars 1.1.0 (D) vs 1.2.2 (A): hash lines differ in $(diff <(proj "$out/A1.jsonl") <(proj "$out/D1.jsonl") | grep -c '^>') probes"
fi
say "today's DefaultHasher token hash of watch across A B C D: $(for r in A1 B1 C1 D1; do [ -f "$out/$r.jsonl" ] && jq -r 'select(.kind=="hash" and .probe=="base") | .today_method_watch' "$out/$r.jsonl"; done | sort -u | tr '\n' ' ')"

# ---- menger's tickets: cost and the hashes it yields ---------------------
if [ -d "$menger/tickets-api" ] && [ -z "${SKIP_MENGER:-}" ]; then
  say ""
  say "== menger tickets (release; lock seeded from $menger/Cargo.lock)"
  [ -f "$here/menger-cost/Cargo.lock" ] || cp "$menger/Cargo.lock" "$here/menger-cost/Cargo.lock"
  CARGO_TARGET_DIR=$out/target-m cargo build --quiet --release --manifest-path "$here/menger-cost/Cargo.toml" 2>/dev/null
  : >"$out/menger.jsonl"
  for _ in $(seq 10); do "$out/target-m/release/returns3-menger-cost" >>"$out/menger.jsonl"; done
  jq -s -c '[.[] | select(.kind=="menger_timing")] as $t
    | {methods: $t[0].methods, rpc_methods: $t[0].rpc_methods, canonical_bytes_total: $t[0].canonical_bytes_total,
       compute_method_schemas_us_median: ($t | map(.compute_method_schemas_us) | sort | .[length/2|floor]),
       hash_all_methods_us_median: ($t | map(.hash_all_methods_us) | sort | .[length/2|floor]),
       cached_clone_us_median: ($t | map(.cached_clone_us) | sort | .[length/2|floor])}' "$out/menger.jsonl" >&2
  say "distinct menger roll-ups over 10 processes: $(jq -c 'select(.kind=="menger_rollup")' "$out/menger.jsonl" | sort -u | wc -l)"
fi
exit $status
