#!/usr/bin/env bash
# PERF-17: the combination, in one window. Runs from the harness dir with a frozen copy of run.sh.
cd ~/dev/controlflow/hypermemetic/wt-PERF-5/plexus-core/spike/PERF-5
export CLIENT_BIN=$HOME/.cache/cargo-target/PERF-5/floor/e2/p5-client
ON=PERF17_WS_COALESCE=64+PERF17_WS_BUF=65536+PERF17_ONE_ENCODE=1+PERF17_GATE_CACHE=1
L=results/floor/combo.log
echo "== ab combo start $(date -u +%T)" >> $L
ROUNDS="1 2 3 4 5" ./.run-exec.sh ab combo base all+$ON all+$ON+PERF17_BATCH=64 all+$ON+PERF17_BATCH=16 all+$ON+--rt=percore all+$ON+PERF17_BATCH=16+--rt=percore >> $L 2>&1; echo "ab exit $?" >> $L
echo "== vraw start $(date -u +%T)" >> $L
ROUNDS="1 2 3 4 5" ./.run-exec.sh vraw combo >> $L 2>&1; echo "vraw exit $?" >> $L
echo "== e7 start $(date -u +%T)" >> $L
ROUNDS="1 2 3" CLIENT_BIN=$HOME/.cache/cargo-target/PERF-5/floor/client/p5-client ./.run-exec.sh e7 base PERF17_LINT_ONCE=1+PERF17_DESCRIBE_CACHE=1 >> $L 2>&1; echo "e7 exit $?" >> $L
echo "== e5 start $(date -u +%T)" >> $L
ROUNDS="1 2 3" CLIENT_BIN=$HOME/.cache/cargo-target/PERF-5/floor/e5/p5-client ./.run-exec.sh e5 base all+$ON all+$ON+PERF17_BATCH=16 >> $L 2>&1; echo "e5 exit $?" >> $L
echo "== vsyscalls start $(date -u +%T)" >> $L
./.run-exec.sh vsyscalls all+$ON+PERF17_BATCH=16 >> $L 2>&1; echo "vsyscalls exit $?" >> $L
./.run-exec.sh vsyscalls all+$ON >> $L 2>&1; echo "vsyscalls2 exit $?" >> $L
echo "== vflame start $(date -u +%T)" >> $L
./.run-exec.sh vflame all+$ON+PERF17_BATCH=16 floor-all >> $L 2>&1; echo "vflame exit $?" >> $L
echo "== done $(date -u +%T)" >> $L
