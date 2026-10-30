#!/usr/bin/env bash
# runsteps.sh STEP... — each run.sh step in turn, each started only once other
# processes' CPU (cpusampler.py, running beside it: `python3 -I cpusampler.py
# results/others-cpu.jsonl &`) has stayed under QUIET% for 3 windows (15 s), up
# to WAITMAX s or past DEADLINE (epoch); the step's real exit code and the
# others' CPU during it go to the step log. PERF-5's close-out ran it so.
cd "$(dirname "$0")"
CPU=${CPU:-results/others-cpu.jsonl}; L=${STEPS_LOG:-results/quiet-steps.log}; QUIET=${QUIET:-150}; WAITMAX=${WAITMAX:-900}; DEADLINE=${DEADLINE:-0}  # epoch: no waiting past it
quiet3() { tail -3 "$CPU" | jq -s --argjson q "$QUIET" 'length == 3 and all(.others_pct < $q)' | grep -q true; }
for s in "$@"; do
  w0=$(date +%s)
  until quiet3; do sleep 5; now=$(date +%s); if [ $(( now - w0 )) -gt "$WAITMAX" ] || { [ "$DEADLINE" -gt 0 ] && [ "$now" -gt "$DEADLINE" ]; }; then echo "== $s: not quiet after $((now - w0))s (deadline or WAITMAX); running anyway" >> $L; break; fi; done
  t0=$(date +%s)
  echo "== $s start $(date -u +%T) waited $((t0 - w0))s load $(cut -d' ' -f1 /proc/loadavg) avail $(free -g | awk '/Mem/{print $7}')G" >> $L
  ./run.sh "$s" >> $L.out 2>&1; rc=$?
  t1=$(date +%s)
  o=$(jq -s --argjson a "$t0" --argjson b "$t1" '[.[] | select(.unix >= $a and .unix <= $b + 5) | .others_pct] | if length > 0 then "others CPU during: max \(max)% mean \((add / length) | floor)%" else "no samples" end' -r "$CPU")
  echo "== $s end   $(date -u +%T) exit=$rc $((t1 - t0))s load $(cut -d' ' -f1 /proc/loadavg) — $o" >> $L
done
