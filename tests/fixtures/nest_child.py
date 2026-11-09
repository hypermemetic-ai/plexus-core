"""NEST-4 - a child with children, on stdio, in no language of plexus-core's.

The root `py` has a static child `a`, which has `b`; each level a method of
its own. It answers the wire as plexus-wire's spec/11-12 say, nothing more:
`_info`, `py.call {method, params, hop}` and `py.call_unsub`. A schema call
answers whatever its hop; any other call is refused unless the hop's
`limit.grant` names exactly the path called (spec/12 rule 2), and answers
the hop it was given. Its root's hash never moves (it is no Merkle tree), so
only the mount's own tree hash notices `b` change: `NEST_PY_VARIANT=2`
gives `b` a second method.
"""
import json
import os
import sys

NS = "py"


def method(name, role="rpc"):
    return {"name": name, "description": name, "hash": "h-" + name, "cardinality": "one", "returns": {}, "role": {"kind": role}}


def schema(ns, methods, roles, h):
    return {"namespace": ns, "version": "0.1.0", "description": ns, "self_hash": h, "hash": h, "methods": methods, "roles": roles}


B = [method("m")] + ([method("n")] if os.environ.get("NEST_PY_VARIANT") == "2" else [])
SCHEMAS = {
    "py.schema": schema(NS, [method("ping"), method("a", "static_child")], {"viewer": ["py.ping"]}, "root"),
    "py.a.schema": schema("a", [method("m"), method("b", "static_child")], {"viewer": ["a.m"]}, "a"),
    "py.a.b.schema": schema("b", B, {"editor": ["b.m"]}, "b-" + str(len(B))),
}
METHODS = {"py.ping", "py.a.m", "py.a.b.m", "py.a.b.n"}


def send(v):
    sys.stdout.write(json.dumps(v) + "\n")
    sys.stdout.flush()


def item(sid, v):
    send({"jsonrpc": "2.0", "method": NS + ".call", "params": {"subscription": sid, "result": v}})


META = {"provenance": [NS], "plexus_hash": "", "timestamp": 0}

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
    else:
        target, hop = p.get("method"), p.get("hop") or {}
        grant = (hop.get("limit") or {}).get("grant")
        if target in SCHEMAS:
            item(sid, {"type": "data", "metadata": META, "content_type": target, "content": SCHEMAS[target]})
        elif target not in METHODS:
            item(sid, {"type": "error", "metadata": META, "message": "Method not found: " + str(target), "code": "-32601", "recoverable": False})
            continue
        elif grant != target:
            item(sid, {"type": "error", "metadata": META, "message": "forbidden: needs `%s`" % target, "code": "-32003", "error_kind": "forbidden", "grant": target, "recoverable": False})
            continue
        else:
            item(sid, {"type": "data", "metadata": META, "content_type": target, "content": {"method": target, "hop": hop}})
    item(sid, {"type": "done", "metadata": META})
