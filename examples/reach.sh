#!/usr/bin/env bash
# VISION-5 · the film's "Reach": two services with no listening port find each
# other through a relay — one outbound socket each, a key for a name; the
# relay's list of who is connected is discovery.
#
#   examples/reach.sh            # build, start, show, stop
#   RELAY_PORT=4741 KEEP=1 examples/reach.sh   # leave them running
#
# Needs synapse (and its `builder` key) on PATH. Ports: RELAY_PORT (4741).
# Each command it runs is printed before its output.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${RELAY_PORT:-4741}
URL="ws://127.0.0.1:$PORT/ws"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/reach.XXXXXX")
cargo build -q --manifest-path "${MANIFEST:-Cargo.toml}" --example relay --example peer
BIN="${CARGO_TARGET_DIR:-target}/debug/examples"

for n in relay alice bob; do
  head -c 32 /dev/urandom | base64 > "$WORK/$n.key"
  chmod 600 "$WORK/$n.key"
done
principal() { timeout 2 "$BIN/peer" --name "$1" --expose ws://127.0.0.1:1/ws --key "$WORK/$1.key" 2>/dev/null | head -1 | awk '{print $2}' || true; }
ALICE=$(principal alice)
BOB=$(principal bob)
ME=$(synapse _key show builder)

pids=()
stop() { [ -n "${KEEP:-}" ] || kill "${pids[@]}" 2>/dev/null || true; }
trap stop EXIT
run() { echo; echo "\$ $*"; "$@"; }

"$BIN/relay" --port "$PORT" --key "$WORK/relay.key" --member "$ME" --member "$ALICE" --member "$BOB" >"$WORK/relay.log" 2>&1 &
pids+=($!)
sleep 1
"$BIN/peer" --name alice --expose "$URL" --key "$WORK/alice.key" >"$WORK/alice.log" 2>&1 &
pids+=($!)
"$BIN/peer" --name bob --expose "$URL" --key "$WORK/bob.key" >"$WORK/bob.log" 2>&1 &
BOB_PID=$!
pids+=($BOB_PID)
sleep 1.5
sed 's/\x1b\[[0-9;]*m//g' "$WORK/alice.log" "$WORK/bob.log" | grep -v plexus::

echo; echo "# listening sockets held by alice and bob:"
ss -ltnp 2>/dev/null | grep -E "pid=(${pids[1]}|$BOB_PID)," || echo "(none — each holds one outbound socket to the relay)"

synapse --url "$URL" _login relay --key builder --as builder >/dev/null
run synapse --url "$URL" relay peers list
run synapse --url "$URL" relay peers alice hello --name you
run synapse --url "$URL" relay peers alice ask --peer bob --name carol
echo; echo "# bob's connection drops"
kill "$BOB_PID"
sleep 0.5
run synapse --url "$URL" relay peers list
run synapse --url "$URL" relay peers alice ask --peer bob --name carol
echo; echo "(logs in $WORK)"
