"""NEST-6 - a child with dynamic slots, on stdio, in no language of plexus-core's.

The root `pys` has a typed dynamic slot `{planet}` (its type, `planet`, on
the role as `child`: `info` and `rename`), listed by `names`, and a static
child `belt` with an untyped slot `{rock}` (no `child`). It answers the wire
as plexus-wire's spec/11-12 say, nothing more: `_info`, `pys.call {method,
params, hop}` and `pys.call_unsub`. A schema call answers whatever its hop
(an instance's schema included: `pys.<name>.schema`); any other call is
refused unless the hop's `limit.grant` names the path called or the slot it
goes through (`pys.{planet}.<method>`, `pys.belt.{rock}`), and answers the
hop it was given. An unknown name is `activation_not_found`. Every item
carries `plexus_hash`, which `pys.bump` moves (the child changed under a
mount that keeps its names).
"""
import json
import sys

NS = "pys"
PLANETS = ["earth", "mars", "venus"]


def method(name, role=None):
    return {"name": name, "description": name, "hash": "h-" + name, "cardinality": "one", "returns": {}, "role": role or {"kind": "rpc"}}


def schema(ns, methods, roles, h):
    return {"namespace": ns, "version": "0.1.0", "description": ns, "self_hash": h, "hash": h, "methods": methods, "roles": roles}


PLANET = schema("planet", [method("info"), method("rename")], {}, "planet")
ROCK = schema("rock", [method("info")], {}, "rock")
ROOT = schema(
    NS,
    [
        method("ping"),
        method("bump"),
        method("names"),
        method("planet", {"kind": "dynamic_child", "list_method": "names", "child": PLANET}),
        method("belt", {"kind": "static_child"}),
    ],
    {"viewer": ["pys.ping", "pys.bump", "pys.names", "pys.{planet}.info", "pys.belt.{rock}"], "editor": ["pys.{planet}.rename"]},
    "root",
)
BELT = schema("belt", [method("count"), method("rock", {"kind": "dynamic_child"})], {"viewer": ["belt.count"]}, "belt")
SCHEMAS = {"pys.schema": ROOT, "pys.belt.schema": BELT}


def instance(target):
    """`pys.<planet>.<m>` -> (slot grant, schema, method) for a known name, or None."""
    parts = target.split(".")
    if len(parts) == 3 and parts[1] in PLANETS:
        return "pys.{planet}." + parts[2], PLANET, parts[2]
    if len(parts) == 4 and parts[1] == "belt" and not parts[2].startswith("dust"):
        return "pys.belt.{rock}", ROCK, parts[3]
    return None


def send(v):
    sys.stdout.write(json.dumps(v) + "\n")
    sys.stdout.flush()


hash_now = "v1"


def meta():
    return {"provenance": [NS], "plexus_hash": hash_now, "timestamp": 0}


def item(sid, v):
    send({"jsonrpc": "2.0", "method": NS + ".call", "params": {"subscription": sid, "result": v}})


def not_found(sid, target):
    item(sid, {"type": "error", "metadata": meta(), "message": "Activation not found: " + target, "code": "-32601",
               "error": {"kind": "activation_not_found", "activation": target}, "recoverable": False})


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
        item(sid, {"type": "data", "metadata": meta(), "content_type": "_info", "content": {"backend": NS}})
        item(sid, {"type": "done", "metadata": meta()})
        continue
    target, hop = p.get("method"), p.get("hop") or {}
    grant = (hop.get("limit") or {}).get("grant")
    if target in SCHEMAS:
        item(sid, {"type": "data", "metadata": meta(), "content_type": target, "content": SCHEMAS[target]})
    elif target.endswith(".schema"):
        found = instance(target[: -len(".schema")] + ".x")
        if found is None:
            not_found(sid, target)
            continue
        item(sid, {"type": "data", "metadata": meta(), "content_type": target, "content": found[1]})
    else:
        own = target in ("pys.ping", "pys.bump", "pys.names", "pys.belt.count")
        found = None if own else instance(target)
        if not own and found is None:
            not_found(sid, target)
            continue
        if grant != target and (found is None or grant != found[0]):
            item(sid, {"type": "error", "metadata": meta(), "message": "forbidden: needs `%s`" % target, "code": "-32003", "error_kind": "forbidden", "grant": target, "recoverable": False})
            continue
        if target == "pys.bump":
            hash_now = "v2"
        if target == "pys.names":
            for n in PLANETS:
                item(sid, {"type": "data", "metadata": meta(), "content_type": target, "content": n})
        else:
            item(sid, {"type": "data", "metadata": meta(), "content_type": target, "content": {"method": target, "hop": hop}})
    item(sid, {"type": "done", "metadata": meta()})
