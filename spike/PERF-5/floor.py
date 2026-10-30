#!/usr/bin/env python3
"""PERF-17 (the floor): results/floor/<exp>.jsonl → each row annotated with the
other processes' CPU during it (others-cpu.jsonl: the max of the 5 s windows
around the row), then per variant the medians over rounds, and the gain of each
variant against the first one named (its baseline). Prints markdown.

  python3 -I floor.py EXP [VARIANT ...]   (variants in order; default: as found)
"""
import json, os, statistics as st, sys
R = "results"
exp = sys.argv[1]
want = sys.argv[2:]
path = os.path.join(R, "floor", exp + ".jsonl")
cpu = [json.loads(l) for l in open(os.path.join(R, "floor", "others-cpu.jsonl")) if l.strip()]
rows = [json.loads(l) for l in open(path) if l.strip()]
def others(u):
    xs = [c["others_pct"] for c in cpu if u - 6 <= c["unix"] <= u + 6]
    return max(xs) if xs else None
for r in rows:
    if r.get("others_cpu_pct") is None:
        r["others_cpu_pct"] = others(r["unix"])
open(path, "w").write("".join(json.dumps(r) + "\n" for r in rows))
vs = want or list(dict.fromkeys(r["variant"] for r in rows))
QMAX = float(os.environ.get("QUIET_MAX", "800"))  # PERF-5's rule: medians over rows at most 8 cores elsewhere; the rest are busy
quiet = lambda r: r.get("allocs_run") or r["scenario"] == "call.one_item.allocs" or (r.get("others_cpu_pct") is not None and r["others_cpu_pct"] <= QMAX)
med = lambda xs: st.median(xs) if xs else float("nan")
def pick(v, pred):
    return [r for r in rows if r["variant"] == v and pred(r) and quiet(r)]
def m(v):
    o = {}
    seq = pick(v, lambda r: r["scenario"] == "call.one_item.seq")
    o["seq_p50"] = med([r["summary"]["p50_us"] for r in seq]); o["seq_p99"] = med([r["summary"]["p99_us"] for r in seq])
    o["seq_p999"] = med([r["summary"]["p999_us"] for r in seq]); o["seq_cps"] = med([r["calls_per_s"] for r in seq])
    one = pick(v, lambda r: r["scenario"] == "call.one_item.max" and r["conns"] == 1)
    o["c1_cps"] = med([r["calls_per_s"] for r in one]); o["c1_cpu"] = med([r["server"]["cpu_us_per"] for r in one]); o["c1_cs"] = med([r["server"]["vol_cs_per"] for r in one])
    big = pick(v, lambda r: r["scenario"] == "call.one_item.max" and r["conns"] == 64)
    o["c64_cps"] = med([r["calls_per_s"] for r in big]); o["c64_cpu"] = med([r["server"]["cpu_us_per"] for r in big]); o["c64_p50"] = med([r["summary"]["p50_us"] for r in big])
    for size in (64, 1024, 4096):
        s = pick(v, lambda r: r["scenario"] == f"stream.10k.{size}B" and not r.get("allocs_run"))
        o[f"s{size}"] = med([r["items_per_s"] for r in s]); o[f"s{size}_cpu"] = med([r["server"]["cpu_us_per"] for r in s if "server" in r])
        o[f"s{size}_fpi"] = med([r["frames_per_item"] for r in s])
        a = pick(v, lambda r: r["scenario"] == f"stream.10k.{size}B" and r.get("allocs_run"))
        o[f"s{size}_alloc"] = med([r["allocs_per_item"] for r in a])
    al = pick(v, lambda r: r["scenario"] == "call.one_item.allocs")
    o["call_alloc"] = med([r["allocs_per_call"] for r in al]); o["call_spawn"] = med([r["spawned_tasks_per_call"] for r in al])
    xs = [r["others_cpu_pct"] for r in rows if r["variant"] == v and r.get("others_cpu_pct") is not None and quiet(r) and r["round"] > 0]
    o["others"] = f"{min(xs)}–{max(xs)}" if xs else "—"
    o["rounds"] = len(seq)
    o["busy"] = len([r for r in rows if r["variant"] == v and r["round"] > 0 and not quiet(r)])
    return o
if exp == "e7":  # menger's self-description over the wire: per variant and method
    print(f"### e7 — menger over the wire, signed in; medians over rows at ≤ {QMAX:.0f} % others' CPU; gain against `{vs[0]}`\n")
    meths = list(dict.fromkeys(r["label"].replace("describe ", "") for r in rows))
    print("| call | " + " | ".join(f"`{v}` p50 · p99 ms" for v in vs) + " |")
    print("| -- | " + " | ".join("--" for _ in vs) + " |")
    for mt in meths:
        cells = []
        b = None
        for v in vs:
            rs = [r for r in rows if r["variant"] == v and r["label"] == "describe " + mt and quiet(r)]
            p50 = med([r["summary"]["p50_us"] / 1000 for r in rs]); p99 = med([r["summary"]["p99_us"] / 1000 for r in rs])
            b = p50 if b is None else b
            x = "" if v == vs[0] or p50 != p50 else f" ({b / p50:,.0f}× faster)" if p50 < b else f" ({(1 - p50 / b) * 100:+.1f} %)"
            cells.append(f"{p50:,.3f} · {p99:,.3f}{x} [{len(rs)}]")
        print(f"| `{mt}` | " + " | ".join(cells) + " |")
    xs = [r["others_cpu_pct"] for r in rows if r.get("others_cpu_pct") is not None]
    print(f"\nothers' CPU over the rows: {min(xs)}–{max(xs)} %; [n] = quiet runs in the median")
    sys.exit(0)
ms = {v: m(v) for v in vs}
base = ms[vs[0]]
cols = [("seq_p50", "call p50 µs", "lo"), ("seq_p99", "p99", "lo"), ("seq_p999", "p999", "lo"), ("seq_cps", "calls/s seq", "hi"),
        ("c1_cpu", "CPU-µs a call (1×1)", "lo"), ("c1_cs", "vol cs a call", "lo"), ("c64_cps", "calls/s 64×4", "hi"), ("c64_cpu", "CPU-µs a call 64×4", "lo"),
        ("s64", "items/s 64 B", "hi"), ("s1024", "items/s 1 KB", "hi"), ("s4096", "items/s 4 KB", "hi"), ("s64_cpu", "CPU-µs an item 64 B", "lo"), ("s4096_cpu", "CPU-µs an item 4 KB", "lo"),
        ("s64_fpi", "frames an item", "lo"), ("s64_alloc", "allocs an item 64 B", "lo"), ("s4096_alloc", "allocs an item 4 KB", "lo"), ("call_alloc", "allocs a call", "lo"), ("call_spawn", "spawns a call", "lo")]
def fmt(x):
    if x != x: return "—"
    return f"{x:,.0f}" if abs(x) >= 100 else f"{x:.2f}"
def gain(k, d, x):
    b = base[k]
    if b != b or x != x or b == 0: return ""
    g = (x / b - 1) * 100 if d == "hi" else (1 - x / b) * 100
    return f" ({g:+.1f} %)"
print(f"### {exp} — medians over the rows taken at ≤ {QMAX:.0f} % others' CPU; gain against `{vs[0]}`\n")
print("| metric | " + " | ".join(f"`{v}`" for v in vs) + " |")
print("| -- | " + " | ".join("--" for _ in vs) + " |")
for k, name, d in cols:
    print(f"| {name} | " + " | ".join(fmt(ms[v][k]) + ("" if v == vs[0] else gain(k, d, ms[v][k])) for v in vs) + " |")
print(f"| quiet seq rows · others' CPU % (rows ≤ {QMAX:.0f}) · busy rows left out | " + " | ".join(f"{ms[v]['rounds']} · {ms[v]['others']} · {ms[v]['busy']}" for v in vs) + " |")
