#!/usr/bin/env python3
"""Every 5 s: the whole machine's busy CPU (% of one core), the share of it
that is mine (the harness, my menger throwaway, my kit client, my strace
container's tracee), and the rest — others'. One JSON line per window."""
import os, time, json, sys
OUT = sys.argv[1]
MINE = ("p5-server", "p5-client", "p5-rawecho", "perf5_describe", "inproc-", "codec-")
def total():
    f = open("/proc/stat").readline().split()[1:]
    v = list(map(int, f)); idle = v[3] + v[4]
    return sum(v), idle
def mine():
    t = 0
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cmd = open(f"/proc/{p}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
            if not (any(m in cmd for m in MINE) or "--port 4476" in cmd or "127.0.0.1:4476" in cmd):
                continue
            st = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
            t += int(st[11]) + int(st[12])
        except Exception:
            pass
    return t
hz = os.sysconf("SC_CLK_TCK")
a_tot, a_idle = total(); a_mine = mine(); a_t = time.time()
while True:
    time.sleep(5)
    b_tot, b_idle = total(); b_mine = mine(); b_t = time.time()
    busy = ((b_tot - a_tot) - (b_idle - a_idle)) / hz / (b_t - a_t) * 100
    my = max(0, (b_mine - a_mine)) / hz / (b_t - a_t) * 100
    with open(OUT, "a") as f:
        f.write(json.dumps({"unix": round(b_t, 1), "busy_pct": round(busy), "mine_pct": round(my), "others_pct": round(max(0, busy - my)), "load1": float(open("/proc/loadavg").read().split()[0])}) + "\n")
    a_tot, a_idle, a_mine, a_t = b_tot, b_idle, b_mine, b_t
