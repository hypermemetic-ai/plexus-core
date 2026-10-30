#!/usr/bin/env python3
"""PERF-5: results/*.jsonl → results/report.md (medians of the three runs)."""
import json, statistics as st, sys, os, glob
from collections import defaultdict

R = sys.argv[1] if len(sys.argv) > 1 else "results"
QMAX = float(os.environ.get("QUIET_MAX", "800"))  # others' CPU % during a row (cpusampler.py); a row above it is busy
def rows(name, busy=False):
    p = os.path.join(R, name)
    rs = [json.loads(l) for l in open(p)] if os.path.exists(p) else []
    q = lambda r: r.get("others_cpu_pct") is None and "unix" not in r or (r.get("others_cpu_pct") is not None and r["others_cpu_pct"] <= QMAX)
    return [r for r in rs if (not q(r)) == busy]
def oth(v):
    xs = [x.get("others_cpu_pct") for x in v if x.get("others_cpu_pct") is not None]
    return f"{min(xs)}–{max(xs)}" if xs else "—"
med = lambda xs: st.median(xs) if xs else float("nan")
out = []
def table(head, body):
    out.append("| " + " | ".join(head) + " |")
    out.append("| " + " | ".join("--" for _ in head) + " |")
    for b in body:
        out.append("| " + " | ".join(str(x) for x in b) + " |")
    out.append("")

def calls(rs, src):
    g = defaultdict(list)
    for r in rs:
        if r["scenario"] == "call.one_item.allocs" or not r["scenario"].startswith("call"): continue
        k = (r.get("label",""), r["scenario"], r.get("rate",""), r.get("conns",""), r.get("inflight",""))
        g[k].append(r)
    body = []
    for k, v in g.items():
        s = [x["summary"] for x in v]
        thr = [x.get("calls_per_s") or x.get("achieved_per_s") for x in v]
        body.append([src, *k, f'{med([x["p50_us"] for x in s]):.0f}', f'{med([x["p99_us"] for x in s]):.0f}', f'{med([x["p999_us"] for x in s]):.0f}', f'{med(thr):,.0f}', len(v), v[0]["loadavg"].split()[0], oth(v)])
    return body

out.append(f"## Calls (µs; medians of runs at ≤ {QMAX:.0f} % other processes' CPU)\n")
H = ["src", "label", "scenario", "rate", "conns", "inflight", "p50", "p99", "p999", "calls/s", "runs", "load", "others %"]
table(H, calls(rows("call.jsonl"), "plexus") + calls(rows("raw.jsonl"), "raw"))
out.append(f"### Busy: the same, from rows above {QMAX:.0f} % (not in the medians above)\n")
table(H, calls(rows("call.jsonl", True), "plexus") + calls(rows("raw.jsonl", True), "raw"))
out.append("## Allocations and CPU per call\n")
table(["run", "allocs/call", "bytes/call", "spawned tasks/call", "server CPU µs/call", "vol cs/call"],
      [[r["run"], f'{r["allocs_per_call"]:.2f}', f'{r["alloc_bytes_per_call"]:.0f}', f'{r["spawned_tasks_per_call"]:.2f}', f'{r["server"]["cpu_us_per"]:.1f}', f'{r["server"]["vol_cs_per"]:.2f}'] for r in rows("call.jsonl") + rows("call.jsonl", True) if r["scenario"] == "call.one_item.allocs"])
out.append("## Streams (10,000 items)\n")
g = defaultdict(list)
for src, rs in (("plexus", rows("stream.jsonl")), ("raw", [r for r in rows("raw.jsonl") if r["scenario"].startswith("stream")]), ("raw, busy", [r for r in rows("raw.jsonl", True) if r["scenario"].startswith("stream")])):
    for r in rs: g[(src, r["label"], r["size"])].append(r)
table(["src", "label", "size", "items/s", "allocs/item", "alloc B/item", "wire B/item", "frames/item", "server CPU µs/item", "runs", "load", "others %"],
      [[*k, f'{med([x["items_per_s"] for x in v]):,.0f}', f'{med([x["allocs_per_item"] for x in v]):.2f}', f'{med([x["alloc_bytes_per_item"] for x in v]):.0f}',
        f'{med([x["wire_bytes_per_item"] for x in v]):.0f}', f'{med([x["frames_per_item"] for x in v]):.3f}', f'{med([x.get("server",{}).get("cpu_us_per",0) for x in v]):.2f}', len(v), v[0]["loadavg"].split()[0], oth(v)] for k, v in g.items()])
out.append("## Codecs (ns per item, median of 3 runs)\n")
table(["frame", "codec", "op", "bytes", "ns", "allocs", "runs", "load"], [[r["frame"], r["codec"], r["op"], r["bytes"], f'{r["ns_per_op"]:.0f}', f'{r["allocs_per_op"]:.0f}', "/".join(f"{x:.0f}" for x in r["runs_ns"]), r["loadavg"].split()[0]] for r in rows("codec.jsonl")])
out.append("## In process\n")
table(["group", "bench", "ns/op", "allocs/op", "bytes/op", "runs", "load"], [[r["group"], r["name"], f'{r["ns_per_op"]:.0f}', f'{r["allocs_per_op"]:.1f}', f'{r["alloc_bytes_per_op"]:.0f}', "/".join(f"{x:.0f}" for x in r["runs_ns"]), r["loadavg"].split()[0]] for r in rows("inproc.jsonl")])
# menger itself on a throwaway (run.sh menger): the wire baseline and the describe calls
mc = rows("menger_call.jsonl") + rows("menger_describe.jsonl") + rows("menger_call.jsonl", True) + rows("menger_describe.jsonl", True)
if mc:
    out.append("## menger on a throwaway (µs; medians of runs)\n")
    g = defaultdict(list)
    for r in mc: g[r.get("label", "")].append(r)
    table(["label", "p50", "p99", "p999", "max", "calls/s", "runs", "load", "others %"],
          [[k, f'{med([x["summary"]["p50_us"] for x in v]):,.0f}', f'{med([x["summary"]["p99_us"] for x in v]):,.0f}', f'{med([x["summary"]["p999_us"] for x in v]):,.0f}',
            f'{med([x["summary"]["max_us"] for x in v]):,.0f}', f'{med([x["calls_per_s"] for x in v]):,.1f}', len(v), "–".join(sorted({x["loadavg"].split()[0] for x in v})), oth(v)] for k, v in g.items()])

# syscalls (run.sh syscalls): strace -c -f of the server, an idle run subtracted, per unit driven
def strace_counts(path):
    d = {}
    for line in open(path):
        p = line.split()
        if len(p) >= 5 and p[0][0].isdigit() and p[-1] != "total":
            try: d[p[-1]] = d.get(p[-1], 0) + int(p[3])
            except ValueError: pass
    return d
S = "syscalls"
if os.path.exists(os.path.join(S, "idle.txt")):
    idle = strace_counts(os.path.join(S, "idle.txt"))
    out.append("## Syscalls per unit (strace -c -f in fedora:44, the server process, an idle run subtracted)\n")
    for f in sorted(glob.glob(os.path.join(S, "*.txt"))):
        name = os.path.basename(f)[:-4]
        if name == "idle": continue
        units = int(open(os.path.join(S, name + ".units")).read())
        c = strace_counts(f)
        per = {k: (v - idle.get(k, 0)) / units for k, v in c.items()}
        tot = sum(per.values())
        top = sorted(((k, v) for k, v in per.items() if v >= 0.005), key=lambda kv: -kv[1])
        out.append(f"**{name}** — {units:,} units · **{tot:.2f} syscalls a unit** · " + ", ".join(f"{k} {v:.2f}" for k, v in top) + "\n")
out.append("## CPU shares (SIGPROF samples, server process)\n")
for f in sorted(glob.glob("flame/*.shares.json")):
    s = json.load(open(f))
    out.append(f"**{os.path.basename(f)[:-12]}** — {s['samples']} samples · layers: " + ", ".join(f"{k} {v:.1f}%" for k, v in sorted(s["layer_pct"].items(), key=lambda kv: -kv[1])) + " · leaves: " + ", ".join(f"{k} {v:.1f}%" for k, v in sorted(s["leaf_pct"].items(), key=lambda kv: -kv[1])) + "\n")
open(os.path.join(R, "report.md"), "w").write("\n".join(out))
print("\n".join(out))
