#!/usr/bin/env bash
# PERF-17: the final floor, with E1's second half — one window, a frozen copy of run.sh.
cd ~/dev/controlflow/hypermemetic/wt-PERF-5/plexus-core/spike/PERF-5
export CLIENT_BIN=$HOME/.cache/cargo-target/PERF-5/floor/e2/p5-client
ON=PERF17_WS_COALESCE=64+PERF17_WS_BUF=65536+PERF17_ENCODED=1+PERF17_GATE_CACHE=1
L=results/floor/floor.log
echo "== ab floor start $(date -u +%T)" >> $L
ROUNDS="1 2 3 4 5" ./.run-exec.sh ab floor base rel2+$ON+PERF17_BATCH=16 all2+$ON all2+$ON+PERF17_BATCH=16 all2+$ON+PERF17_BATCH=64 all2+$ON+PERF17_BATCH=16+--rt=percore >> $L 2>&1; echo "ab exit $?" >> $L
echo "== vraw start $(date -u +%T)" >> $L
ROUNDS="1 2 3 4 5" ./.run-exec.sh vraw floor >> $L 2>&1; echo "vraw exit $?" >> $L
echo "== e5 start $(date -u +%T)" >> $L
ROUNDS="1 2 3" CLIENT_BIN=$HOME/.cache/cargo-target/PERF-5/floor/e5/p5-client ./.run-exec.sh e5 all2+$ON+PERF17_BATCH=16 >> $L 2>&1; echo "e5 exit $?" >> $L
echo "== vsyscalls start $(date -u +%T)" >> $L
./.run-exec.sh vsyscalls all2+$ON+PERF17_BATCH=16 >> $L 2>&1; echo "vsyscalls exit $?" >> $L
echo "== vflame start $(date -u +%T)" >> $L
./.run-exec.sh vflame all2+$ON+PERF17_BATCH=16 floor-final >> $L 2>&1; echo "vflame exit $?" >> $L
./.run-exec.sh vflame all2+$ON+PERF17_BATCH=16+--rt=percore floor-final-percore >> $L 2>&1; echo "vflame2 exit $?" >> $L
echo "== done $(date -u +%T)" >> $L
