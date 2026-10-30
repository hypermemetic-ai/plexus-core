#!/usr/bin/env bash
# PERF-5: a Plexus call from syscall to socket — re-measure every row.
#
#   ./run.sh all              call, stream, raw, codec, inproc, flame, syscalls
#   ./run.sh call|stream|raw|codec|inproc|flame|syscalls|menger|describe|perf
#   PROFILE=perf ./run.sh call   the same under [profile.perf] (LTO fat, cgu 1)
#
# Server pinned to CPUs 2-5 (4 workers, physical cores 2-5), client to 8-9
# (physical cores 8-9): never SMT siblings of each other. Ports 4478 (the
# service) and 4479 (the raw echo); menger throwaway on 4476/4477.
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

call() {
  for cfg in "multi on" "multi off" "current on"; do
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

syscalls() { # strace -c -f in an unprivileged fedora:44 container (MQ-11's image)
  for sc in call stream64; do
    docker run -d --name perf5-strace --rm --network host --security-opt label=disable \
      -v "$B":/b:ro -v "$PWD/syscalls":/out mq-spike-prof:44 \
      strace -f -c -o /out/$sc.txt /b/p5-server --port 4478 >/dev/null
    sleep 2
    case $sc in
      call) cli seq --n 2000 --warm 0 | tag "under strace" >> $R/syscalls.jsonl ;;
      stream64) cli stream --to 10000 --size 64 --warm 0 | tag "under strace" >> $R/syscalls.jsonl ;;
    esac
    docker exec perf5-strace pkill -TERM p5-server; sleep 2
  done
}

case "${1:-all}" in
  all) call; stream; raw; codec; inproc; flame; syscalls ;;
  *) "$1" ;;
esac
