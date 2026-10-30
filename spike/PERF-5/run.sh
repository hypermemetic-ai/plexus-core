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
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}
# PERF-17 E6: [profile.perf] also gets -C target-cpu=native (NATIVE=0 leaves it out);
# RUSTFLAGS replaces .cargo/config.toml's flags, so they are repeated here.
if [ "$PROFILE" = perf ] && [ "${NATIVE:-1}" = 1 ]; then export RUSTFLAGS="-C force-frame-pointers=yes --cfg tokio_unstable -C target-cpu=native"; fi
case "${1:-all}" in snap|ab|e7|e5|vraw|vsyscalls) ;; *) cargo build -q --profile "$PROFILE" --bins 2>/dev/null ;; esac
tag() { jq -c --arg p "$PROFILE" --arg l "$1" '. + {profile: $p, label: $l}'; }

# PERF-17 (the floor): each experiment's server is a variant kept under $FB/<dir>/
# (`snap DIR` builds the bins under $PROFILE with $FEATURES and keeps them); every
# client is the one frozen at the start ($FB/client/p5-client), so only the server
# changes between rows. `ab EXP V...` runs the quick set over the variants in
# rotation, three rounds, each block started only once others' CPU has stayed
# under QUIET (% of a core; cpusampler.py running beside it) for 15 s. A variant
# is DIR[+KEY=VAL...][+--server-arg=VAL...]: env for the server, and its args.
FB=$CARGO_TARGET_DIR/floor
CPU=${CPU:-$R/floor/others-cpu.jsonl}
quiet() {
  local w0; w0=$(date +%s)
  until tail -3 "$CPU" | jq -s --argjson q "${QUIET:-800}" 'length == 3 and all(.others_pct < $q)' | grep -q true; do
    sleep 5
    if [ $(( $(date +%s) - w0 )) -gt "${WAITMAX:-1500}" ]; then echo "not quiet after ${WAITMAX:-1500}s; running anyway" >&2; break; fi
  done
}
snap() {
  local dir=$1
  cargo build -q --profile "$PROFILE" --bins ${FEATURES:+--features "$FEATURES"}
  mkdir -p "$FB/$dir"; cp "$B/p5-server" "$B/p5-client" "$B/p5-rawecho" "$FB/$dir/"
  echo "profile=$PROFILE features=${FEATURES:-} rustflags=${RUSTFLAGS:-config} $(date -u +%FT%TZ)" > "$FB/$dir/BUILD"
}
vserver() { # vserver VARIANT [extra server args] → SPID
  local v=$1; shift
  local dir=${v%%+*} envs=() args=() t
  if [[ $v == *+* ]]; then IFS='+' read -ra toks <<< "${v#*+}"; for t in "${toks[@]}"; do if [[ $t == --* ]]; then args+=("$t"); else envs+=("$t"); fi; done; fi
  env "${envs[@]}" taskset -c "$SRV_CPUS" "$FB/$dir/p5-server" --port 4478 "${args[@]}" "$@" > /tmp/perf5-server.log 2>&1 &
  SPID=$!
  until grep -q listening /tmp/perf5-server.log 2>/dev/null; do sleep 0.1; done
}
vsyscalls() { # vsyscalls VARIANT: syscalls() for a kept variant (its env passed into the container), rows to results/floor/syscalls-<label>
  local v=$1 dir=${1%%+*} envs=() t
  if [[ $v == *+* ]]; then IFS='+' read -ra toks <<< "${v#*+}"; for t in "${toks[@]}"; do [[ $t == --* ]] || envs+=(-e "$t"); done; fi
  local O; O="$PWD/syscalls/floor-${v//[^A-Za-z0-9=_-]/_}"; mkdir -p "$O"
  local C=${CLIENT_BIN:-$FB/client/p5-client}
  vst() { local name=$1; shift; CN=perf5-strace-$name-$$
    docker run -d --name "$CN" --rm --network host --security-opt label=disable "${envs[@]}" \
      -v "$(readlink -f "$FB/$dir")":/b:ro -v "$O":/out mq-spike-prof:44 strace -f -c -o "/out/$name.txt" "$@" >/dev/null
    until ss -ltn | grep -q ':4478 '; do sleep 0.2; done; sleep 0.5; }
  vst_stop() { docker exec "$CN" pkill -TERM -f p5-server >/dev/null 2>&1 || true; while docker ps -aq -f name="^$CN\$" | grep -q .; do sleep 0.2; done; }
  vst idle /b/p5-server --port 4478; sleep 2; vst_stop; echo 0 > "$O/idle.units"
  vst call /b/p5-server --port 4478; taskset -c "$CLI_CPUS" "$C" seq --n 2000 --warm 0 > /dev/null; vst_stop; echo 2000 > "$O/call.units"
  for size in 64 4096; do vst stream$size /b/p5-server --port 4478; taskset -c "$CLI_CPUS" "$C" stream --to 10000 --size $size --warm 0 > /dev/null; vst_stop; echo 30000 > "$O/stream$size.units"; done
  python3 -I - "$O" <<'PY'
import os, sys
O = sys.argv[1]
def counts(p):
    d = {}
    for line in open(p):
        x = line.split()
        if len(x) >= 5 and x[0][0].isdigit() and x[-1] != "total":
            try: d[x[-1]] = d.get(x[-1], 0) + int(x[3])
            except ValueError: pass
    return d
idle = counts(os.path.join(O, "idle.txt"))
for name in ("call", "stream64", "stream4096"):
    u = int(open(os.path.join(O, name + ".units")).read()); c = counts(os.path.join(O, name + ".txt"))
    per = {k: (v - idle.get(k, 0)) / u for k, v in c.items()}
    top = sorted(((k, v) for k, v in per.items() if v >= 0.005), key=lambda kv: -kv[1])
    print(f"{os.path.basename(O)} {name}: {sum(per.values()):.2f} a unit — " + ", ".join(f"{k} {v:.2f}" for k, v in top))
PY
}
e7() { # e7 VARIANT...: menger's self-description over the wire, a throwaway per variant (env KEY=VAL joined by +;
  # `base` = no switch), in rotation; _info / menger.hash / tickets.schema then tickets.health, signed in as builder.
  local M=${MENGER_BIN:-$HOME/.cache/cargo-target/menger-PERF-5/release/menger}
  local C=${CLIENT_BIN:-$FB/client/p5-client} out=$R/floor/e7.jsonl U=ws://127.0.0.1:4476
  mkdir -p $R/floor
  local vs=("$@") v c m1 m2
  for round in ${ROUNDS:-1 2 3}; do
    for v in "${vs[@]}"; do
      quiet
      local envs=(); [[ $v == base ]] || IFS='+' read -ra envs <<< "$v"
      local DATA=/tmp/claude-$(id -u)/menger-PERF-17-data; mkdir -p "$DATA"
      : > /tmp/menger-PERF-17.log
      env "${envs[@]}" PLEXUS_NO_REGISTRY=1 taskset -c "$SRV_CPUS" "$M" --port 4476 --shell-port 4477 --data-dir "$DATA" \
        --db-path /tmp/menger-PERF-17.db --auth-provider key --admin "$(synapse _key show builder)" > /tmp/menger-PERF-17.log 2>&1 &
      local MPID=$!
      until grep -q 'ws://127.0.0.1:4476' /tmp/menger-PERF-17.log 2>/dev/null; do sleep 0.2; done; sleep 1
      for c in "_info x" "menger.hash x" "menger.call tickets.schema" "menger.call tickets.health"; do
        read -r m1 m2 <<< "$c"
        local n=20; [ "$m2" = tickets.health ] && n=5000
        taskset -c "$CLI_CPUS" "$C" --url $U --bearer key:builder --call $m1 --method $m2 --label "describe $m1 $m2" seq --n $n --warm 1 \
          | jq -c --arg v "$v" --arg r "$round" '. + {exp: "e7", variant: $v, round: ($r | tonumber)}' >> $out
      done
      kill $MPID; wait $MPID 2>/dev/null || true
    done
  done
}
e5() { # e5 VARIANT...: a real Rust client (plexus-client's WsTransport, decode::<BenchEvent>) against each server
  # variant, its decode as today (PERF17_TYPED_DECODE=0) and through the borrowed envelope (=1), in rotation
  local out=$R/floor/e5.jsonl vs=("$@") v td size; mkdir -p $R/floor
  local C=${CLIENT_BIN:-$FB/e5/p5-client}
  for round in ${ROUNDS:-1 2 3}; do
    for v in "${vs[@]}"; do
      quiet
      vserver "$v"
      for td in 0 1; do
        [[ $td == 0 && $v == *PERF17_BATCH* ]] && continue  # today's decode cannot read a batch
        PERF17_TYPED_DECODE=$td taskset -c "$CLI_CPUS" "$C" pcseq --n 5000 | jq -c --arg v "$v" --arg t "$td" --arg r "$round" '. + {exp: "e5", variant: ($v + " | client td=" + $t), round: ($r | tonumber)}' >> $out
        for size in 64 4096; do
          PERF17_TYPED_DECODE=$td taskset -c "$CLI_CPUS" "$C" pcstream --to 10000 --size $size --server-pid "$SPID" | jq -c --arg v "$v" --arg t "$td" --arg r "$round" '. + {exp: "e5", variant: ($v + " | client td=" + $t), round: ($r | tonumber)}' >> $out
        done
      done
      stop
    done
  done
}
vraw() { # vraw EXP: the raw ceilings (PERF-5's p5-rawecho: the same frames, no Plexus) in the quick set's shape,
  # rows tagged raw-<stack>, three rounds, into results/floor/EXP.jsonl beside the Plexus variants
  local exp=$1 out=$R/floor/$1.jsonl stack
  local C=${CLIENT_BIN:-$FB/client/p5-client}
  for round in ${ROUNDS:-1 2 3}; do
    for stack in tungstenite fastwebsockets; do
      quiet
      taskset -c "$SRV_CPUS" "$FB/base/p5-rawecho" --port 4478 --stack $stack > /tmp/perf5-server.log 2>&1 &
      SPID=$!; sleep 0.5
      local tg=(jq -c --arg e "$exp" --arg v "raw-$stack" --arg r "$round" '. + {exp: $e, variant: $v, round: ($r | tonumber)}')
      taskset -c "$CLI_CPUS" "$C" seq --n 5000 | "${tg[@]}" >> $out
      taskset -c "$CLI_CPUS" "$C" max --conns 1 --inflight 1 --secs 2 --server-pid "$SPID" | "${tg[@]}" >> $out
      taskset -c "$CLI_CPUS" "$C" max --conns 64 --inflight 4 --secs 2 --server-pid "$SPID" | "${tg[@]}" >> $out
      for size in 64 1024 4096; do taskset -c "$CLI_CPUS" "$C" stream --to 10000 --size $size --server-pid "$SPID" | "${tg[@]}" >> $out; done
      stop
    done
  done
}
ab() {
  local exp=$1; shift
  local out=$R/floor/$exp.jsonl; mkdir -p $R/floor
  local C=${CLIENT_BIN:-$FB/client/p5-client}
  vcli() { taskset -c "$CLI_CPUS" "$C" "$@"; }
  vtag() { jq -c --arg e "$exp" --arg v "$1" --arg r "$2" '. + {exp: $e, variant: $v, round: ($r | tonumber)}'; }
  for round in ${ROUNDS:-1 2 3}; do
    for v in "$@"; do
      quiet
      vserver "$v"
      vcli seq --n 5000 | vtag "$v" "$round" >> $out
      vcli max --conns 1 --inflight 1 --secs 2 --server-pid "$SPID" | vtag "$v" "$round" >> $out
      vcli max --conns 64 --inflight 4 --secs 2 --server-pid "$SPID" | vtag "$v" "$round" >> $out
      for size in 64 1024 4096; do vcli stream --to 10000 --size $size --server-pid "$SPID" | vtag "$v" "$round" >> $out; done
      stop
    done
  done
  [ "${AB_ALLOCS:-1}" = 0 ] && return 0
  for v in "$@"; do # allocations are counts, not times: one pass a variant
    vserver "$v" --count-allocs
    vcli allocs --server-pid "$SPID" --n 2000 | vtag "$v" 0 >> $out
    for size in 64 4096; do vcli stream --to 10000 --size $size --server-pid "$SPID" | jq -c '. + {allocs_run: true}' | vtag "$v" 0 >> $out; done
    stop
  done
}

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
  *) "$@" ;;
esac
