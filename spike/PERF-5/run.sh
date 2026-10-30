#!/usr/bin/env bash
# PERF-5: a Plexus call from syscall to socket — re-measure every row.
#
#   ./run.sh all              call, stream, raw, codec, inproc, flame, syscalls
#   ./run.sh call|stream|raw|codec|inproc|flame|syscalls|menger|describe
#   (menger and describe need the menger worktree built: CARGO_TARGET_DIR=~/.cache/cargo-target/menger-PERF-5
#    cargo build --release --bin menger --example perf5_describe, in ../../../menger)
#   PROFILE=perf ./run.sh call   the same under [profile.perf] (LTO fat, cgu 1)
#
# Server pinned to CPUs 2-5 (4 workers, physical cores 2-5), client to 8-9
# (physical cores 8-9): never SMT siblings of each other. Port 4478 (the
# service, or the raw echo in its place); menger throwaway on 4476/4477.
set -euo pipefail
cd "$(dirname "$0")"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/.cache/cargo-target/PERF-5}
PROFILE=${PROFILE:-release}
B=$CARGO_TARGET_DIR/$PROFILE
SRV_CPUS=${SRV_CPUS:-2-5}
CLI_CPUS=${CLI_CPUS:-8-9}
R=results
mkdir -p $R flame syscalls
cargo build -q --profile "$PROFILE" --bins 2>/dev/null
tag() { jq -c --arg p "$PROFILE" --arg l "$1" '. + {profile: $p, label: $l}'; }

server() { # args → starts p5-server pinned, sets SPID
  taskset -c "$SRV_CPUS" "$B/p5-server" --port 4478 "$@" > /tmp/perf5-server.log 2>&1 &
  SPID=$!
  until grep -q listening /tmp/perf5-server.log 2>/dev/null; do sleep 0.1; done
}
stop() { kill "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true; }
cli() { taskset -c "$CLI_CPUS" "$B/p5-client" "$@"; }

call() { # CALL_CFGS="multi off;current on" picks configurations; CALL_ALLOCS=0 skips the allocation rows
  local cfgs; IFS=';' read -ra cfgs <<< "${CALL_CFGS:-multi on;multi off;current on}"
  for cfg in "${cfgs[@]}"; do
    set -- $cfg
    server --rt "$1" --gate "$2"
    l="rt=$1 gate=$2"
    for i in 1 2 3; do cli seq --n 5000 | tag "$l" >> $R/call.jsonl; done
    for rate in 2000 5000 10000; do
      for i in 1 2 3; do cli open --rate $rate --n $((rate * 2)) | tag "$l" >> $R/call.jsonl; done
    done
    for c in "1 1" "1 16" "64 1" "64 4"; do
      set -- $c
      for i in 1 2 3; do cli max --conns "$1" --inflight "$2" --secs 2 --server-pid "$SPID" | tag "$l" >> $R/call.jsonl; done
    done
    stop
  done
  [ "${CALL_ALLOCS:-1}" = 0 ] && return 0
  server --count-allocs
  cli allocs --server-pid "$SPID" --n 2000 | tag "allocs" >> $R/call.jsonl
  stop
}

stream() {
  server
  for size in 64 1024 4096; do cli stream --to 10000 --size $size --server-pid "$SPID" | tag "rt=multi throughput" >> $R/stream.jsonl; done
  stop
  server --rt current
  for size in 64 4096; do cli stream --to 10000 --size $size --server-pid "$SPID" | tag "rt=current throughput" >> $R/stream.jsonl; done
  stop
  server --count-allocs
  for size in 64 1024 4096; do cli stream --to 10000 --size $size --server-pid "$SPID" | tag "allocs" >> $R/stream.jsonl; done
  stop
}

raw() { # the ceilings: the same bytes, no Plexus
  for stack in fastwebsockets tungstenite; do
    taskset -c "$SRV_CPUS" "$B/p5-rawecho" --port 4478 --stack $stack > /tmp/perf5-server.log 2>&1 &
    SPID=$!; sleep 0.5
    for i in 1 2 3; do cli seq --n 5000 | tag "raw $stack" >> $R/raw.jsonl; done
    for i in 1 2 3; do cli open --rate 10000 --n 20000 | tag "raw $stack" >> $R/raw.jsonl; done
    for c in "1 16" "64 4"; do set -- $c; for i in 1 2 3; do cli max --conns $1 --inflight $2 --secs 2 --server-pid $SPID | tag "raw $stack" >> $R/raw.jsonl; done; done
    for size in 64 1024 4096; do cli stream --to 10000 --size $size --server-pid $SPID | tag "raw $stack" >> $R/raw.jsonl; done
    stop
  done
}

codec() { cargo bench -q --profile "$PROFILE" --bench codec -- 2>/dev/null | tag codec > $R/codec.jsonl; }
inproc() { taskset -c "$SRV_CPUS" cargo bench -q --profile "$PROFILE" --bench inproc -- 2>/dev/null | tag inproc > $R/inproc.jsonl; }

flame() { # SIGPROF sampling of the server under each load
  for sc in call stream64 stream4096 call64conns; do
    server --flame-prefix "flame/$sc" --hz 1999
    kill -USR1 "$SPID"; sleep 0.2
    case $sc in
      call) cli max --conns 1 --inflight 1 --secs 4 >/dev/null ;;
      call64conns) cli max --conns 64 --inflight 4 --secs 4 >/dev/null ;;
      stream64) for i in 1 2 3 4 5 6; do cli stream --to 10000 --size 64 --warm 0 >/dev/null; done ;;
      stream4096) for i in 1 2 3; do cli stream --to 10000 --size 4096 --warm 0 >/dev/null; done ;;
    esac
    kill -USR2 "$SPID"; until [ -f "flame/$sc.shares.json" ]; do sleep 0.2; done; sleep 0.5
    stop
  done
}

syscalls() { # strace -c -f in an unprivileged fedora:44 container (MQ-11's image), the
  # server process alone. An idle server's counts are subtracted; syscalls/<sc>.units
  # says what was driven (calls or items), so report.py prints syscalls per unit.
  mkdir -p syscalls
  local BR CN; BR="$(readlink -f "$B")"
  st() { # name, server command line inside the container
    local name=$1; shift
    CN=perf5-strace-$name  # a name per scenario: --rm removes a stopped container asynchronously
    docker run -d --name "$CN" --rm --network host --security-opt label=disable \
      -v "$BR":/b:ro -v "$PWD/syscalls":/out mq-spike-prof:44 strace -f -c -o "/out/$name.txt" "$@" >/dev/null
    until ss -ltn | grep -q ':4478 '; do sleep 0.2; done; sleep 0.5
  }
  st_stop() { docker exec "$CN" pkill -TERM -f "$1" >/dev/null 2>&1 || true; while docker ps -aq -f name="^$CN\$" | grep -q .; do sleep 0.2; done; }
  st idle /b/p5-server --port 4478; sleep 2; st_stop p5-server; echo 0 > syscalls/idle.units
  st call /b/p5-server --port 4478
  cli seq --n 2000 --warm 0 | tag "under strace: call" >> $R/syscalls.jsonl; st_stop p5-server; echo 2000 > syscalls/call.units
  for size in 64 4096; do
    st stream$size /b/p5-server --port 4478
    cli stream --to 10000 --size $size --warm 0 | tag "under strace: stream$size" >> $R/syscalls.jsonl; st_stop p5-server; echo 30000 > syscalls/stream$size.units
  done
  for stack in tungstenite fastwebsockets; do # the floor: the same frames from a stack with no Plexus
    st raw-$stack-stream64 /b/p5-rawecho --port 4478 --stack $stack
    cli stream --to 10000 --size 64 --warm 0 | tag "under strace: raw $stack stream64" >> $R/syscalls.jsonl; st_stop p5-rawecho; echo 30000 > syscalls/raw-$stack-stream64.units
  done
}

menger() { # menger itself, a throwaway from the menger worktree's build (../../../menger at
  # spike/PERF-5) on 4476/4477, signed in as the builder key (the key's file, never argv):
  # the kit's client and the raw client on tickets.health, then the self-description calls.
  local M=${MENGER_BIN:-$HOME/.cache/cargo-target/menger-PERF-5/release/menger}
  local KIT=${KIT:-$HOME/dev/controlflow/hypermemetic/plexus-wire}
  local DATA=${MENGER_DATA:-/tmp/claude-$(id -u)/menger-PERF-5-data}
  mkdir -p "$DATA"
  PLEXUS_NO_REGISTRY=1 taskset -c "$SRV_CPUS" "$M" --port 4476 --shell-port 4477 --data-dir "$DATA" \
    --db-path /tmp/menger-PERF-5.db --auth-provider key --admin "$(synapse _key show builder)" > /tmp/menger-PERF-5.log 2>&1 &
  local MPID=$!
  until grep -q 'ws://127.0.0.1:4476' /tmp/menger-PERF-5.log 2>/dev/null; do sleep 0.2; done; sleep 1
  local U=ws://127.0.0.1:4476
  for i in 1 2 3; do
    (cd "$KIT" && taskset -c "$CLI_CPUS" python3 -I conformance/run.py $U --as builder --bench 1000 2>&1 | tail -1 | sed "s/\$/ load=$(cut -d' ' -f1 /proc/loadavg)/") >> $R/menger_kit.txt
  done
  for i in 1 2 3; do cli --url $U --bearer key:builder --call menger.call --method tickets.health --label "menger, rust raw client" seq --n 5000 >> $R/menger_call.jsonl; done
  for c in "_info x" "menger.hash x" "menger.call tickets.schema"; do
    set -- $c
    for i in 1 2 3; do cli --url $U --bearer key:builder --call $1 --method $2 --label "describe $1 $2" seq --n 5 --warm 1 >> $R/menger_describe.jsonl; done
  done
  kill $MPID; wait $MPID 2>/dev/null || true
}

describe() { # in process: where _info / hash / schema spend their time (menger's examples/perf5_describe.rs)
  local E=${DESCRIBE_BIN:-$HOME/.cache/cargo-target/menger-PERF-5/release/examples/perf5_describe}
  (cd ../../../menger && taskset -c "$SRV_CPUS" "$E" /tmp/menger-PERF-5-describe.db spike/PERF-5/describe 2>&1 | grep -v INFO \
    | jq -c --arg l "$(cut -d' ' -f1 /proc/loadavg)" '. + {loadavg: $l}' > spike/PERF-5/describe.jsonl)
}

case "${1:-all}" in
  all) call; stream; raw; codec; inproc; flame; syscalls ;;
  *) "$1" ;;
esac
