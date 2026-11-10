"""KEEL-32 - a child that asks its service for schemas outside any call.

`py.probe {ask}` (forwarded to it) makes it send `_host.call {method: ask}`
with no `under`, and answer whatever came back: the first data item's
content, or the refusal. `py.later {ask, ms}` answers at once and asks
`ask` the same way `ms` later, on its own (as a revoked child still could).
Its schema declares one need, `vault.box1.wipe`.

Run as `schema_asker.py WHEN ASK OUT` it also asks on its own: once the
file WHEN exists (the test makes it once the mount is held, between its
handshake and any consent) it asks ASK and writes what came back to OUT,
as JSON.
"""
import json
import os
import sys
import threading
import time

NS = "py"
META = {"provenance": [NS], "plexus_hash": "", "timestamp": 0}
LOCK = threading.Lock()


def method(name):
    return {"name": name, "description": name, "hash": "h-" + name, "cardinality": "one", "returns": {}, "role": {"kind": "rpc"}}


SCHEMA = {"namespace": NS, "version": "0.1.0", "description": NS, "self_hash": "asker", "hash": "asker",
          "methods": [method("probe"), method("later")], "roles": {}, "needs": [{"method": "vault.box1.wipe"}]}


def send(v):
    with LOCK:
        sys.stdout.write(json.dumps(v) + "\n")
        sys.stdout.flush()


def item(sid, v):
    send({"jsonrpc": "2.0", "method": NS + ".call", "params": {"subscription": sid, "result": v}})


def done(sid):
    item(sid, {"type": "done", "metadata": META})


ask_id = 100000
asked = {}   # our request id -> probe sid (None: nobody waits)
hosted = {}  # the host's subscription id -> probe sid


def ask(target, probe_sid):
    global ask_id
    ask_id += 1
    asked[ask_id] = probe_sid
    send({"jsonrpc": "2.0", "id": ask_id, "method": "_host.call", "params": {"method": target, "params": {}}})


def answer(probe_sid, v):
    if probe_sid == "file":
        tmp = OUT + ".tmp"
        with open(tmp, "w") as f:
            json.dump(v, f)
        os.rename(tmp, OUT)
    elif probe_sid is not None:
        item(probe_sid, {"type": "data", "metadata": META, "content_type": "py.probe", "content": v})
        done(probe_sid)


def ask_when():
    while not os.path.exists(WHEN):
        time.sleep(0.01)
    ask(ASK, "file")


WHEN, ASK, OUT = (sys.argv[1:4] + [None, None, None])[:3]
if WHEN:
    threading.Thread(target=ask_when, daemon=True).start()

sid = 0
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    mid, m, p = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid in asked and m is None:
        probe = asked.pop(mid)
        if "error" in msg:
            answer(probe, {"refused": msg["error"]})
        else:
            hosted[msg.get("result")] = probe
        continue
    if m == "_host.call":
        hs, r = p.get("subscription"), p.get("result") or {}
        if hs in hosted:
            probe = hosted.pop(hs)
            if r.get("type") == "data":
                answer(probe, {"answered": r.get("content")})
            elif r.get("type") == "error":
                answer(probe, {"refused": r})
            else:
                hosted[hs] = probe
        continue
    if m == NS + ".call_unsub":
        send({"jsonrpc": "2.0", "id": mid, "result": False})
        continue
    if m not in ("_info", NS + ".call"):
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})
        continue
    sid += 1
    send({"jsonrpc": "2.0", "id": mid, "result": sid})
    if m == "_info":
        item(sid, {"type": "data", "metadata": META, "content_type": "_info", "content": {"backend": NS}})
        done(sid)
    elif p.get("method") == "py.schema":
        item(sid, {"type": "data", "metadata": META, "content_type": "py.schema", "content": SCHEMA})
        done(sid)
    elif p.get("method") == "py.probe":
        ask((p.get("params") or {}).get("ask"), sid)
    elif p.get("method") == "py.later":
        args = p.get("params") or {}
        item(sid, {"type": "data", "metadata": META, "content_type": "py.later", "content": "later"})
        done(sid)
        threading.Thread(target=lambda a=args: (time.sleep(a.get("ms", 100) / 1000), ask(a.get("ask"), None)), daemon=True).start()
    else:
        item(sid, {"type": "error", "metadata": META, "message": "Method not found", "code": "-32601", "recoverable": False})
        done(sid)
