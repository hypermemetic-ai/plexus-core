"""KEEL-31 - a far side built before `everywhere`: its schema marks `py.wipe`
`everywhere`, and it runs it for any hop the near side sends (it decides the
hop's grant, never where it is held). A host must not forward `wipe` to it
for a call not admitted on `*`.
"""
import json
import sys

NS = "py"
META = {"provenance": [NS], "plexus_hash": "", "timestamp": 0}


def method(name, **extra):
    m = {"name": name, "description": name, "hash": "h-" + name, "cardinality": "one", "returns": {}, "role": {"kind": "rpc"}}
    m.update(extra)
    return m


SCHEMA = {"namespace": NS, "version": "0.1.0", "description": NS, "self_hash": "old", "hash": "old",
          "methods": [method("ping"), method("wipe", everywhere=True)], "roles": {}}


def send(v):
    sys.stdout.write(json.dumps(v) + "\n")
    sys.stdout.flush()


def item(sid, v):
    send({"jsonrpc": "2.0", "method": NS + ".call", "params": {"subscription": sid, "result": v}})


sid = 0
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    mid, m, p = msg.get("id"), msg.get("method"), msg.get("params") or {}
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
    elif p.get("method") == "py.schema":
        item(sid, {"type": "data", "metadata": META, "content_type": "py.schema", "content": SCHEMA})
    elif p.get("method") in ("py.ping", "py.wipe"):
        item(sid, {"type": "data", "metadata": META, "content_type": p["method"], "content": p["method"] + " ran"})
    else:
        item(sid, {"type": "error", "metadata": META, "message": "Method not found", "code": "-32601", "recoverable": False})
        continue
    item(sid, {"type": "done", "metadata": META})
