# The gate

A service given a gate (`DynamicHub::with_gate`) asks it before routing
every call. The gate reads the method's grant (its schema's `grant`, else
`<activation>.<method>`) and the scope the method's target resolves to (its
schema's `target` parameter, read from the call's params). The call runs
when a role the caller holds on that scope lists the grant, within the
session's ceiling. A service without a gate dispatches every call.

## What is decided

| call | anonymous | signed in |
| -- | -- | -- |
| a `public` method | runs | runs |
| introspection: `<ns>.schema`, the service's `hash`, `hashes`, `schema`, `ir` | runs | runs |
| a method with a `target`, value present | `Unauthenticated` | runs when a role held on a scope in the value's chain lists the grant, and every ceiling layer allows it there |
| a method marked `everywhere` | `Unauthenticated` | runs when a role held on `*` lists the grant, and every ceiling layer allows it on `*` |
| a method without a target, or with the target absent or null | `Unauthenticated` | runs when the grant is held anywhere, within the ceiling |
| a path no schema describes and no slot holds | `Unauthenticated` | the grant is the dotted path, and it runs only when held on `*` |
| `auth.whoami`, `auth.logout`, `auth.requires` | `Unauthenticated` | runs |

A target whose value is a list is checked element by element, and every
element must be allowed. `params` is an object or absent; a bare value is
`InvalidParams`. Introspection answers the caller's own view: each caller
is listed what it may call.

A method that declares a `reach: Reach` parameter receives the gate's
answer: where the caller holds the grant. Without a gate the reach is
everywhere.

## Callers in process

`HubTransport::as_(service, caller)` calls as an `AuthContext`, and
`HubTransport::anonymous(service)` as nobody. Both end in the call a
WebSocket ends in, so the gate applies the same way.

## Doors: a role held on an address

A role is held on a data scope, on `*`, or on an **address**: `/dyn` (an
activation's own methods), `/dyn.*` (it and everything beneath),
`/dyn.peer.shop.*` (one peer). An address opens a **door**, never data.

The gate decides two shapes at the door of the call: a method marked
`everywhere` with no target, and a call into an untyped peer slot
(`dyn.{peer}`). Everything else is decided on its data.

| the routed entry | an address covering the call | a data scope | `*` |
| -- | -- | -- | -- |
| a method marked `everywhere`, no target | admits | never | admits |
| a call into an untyped peer slot | admits | never | admits |
| a method with a declared target | nothing | its chain | admits |
| a method with no target | nothing | admits | admits |
| a method marked `everywhere` with a target | nothing | never | admits |

A path that has no address (a segment outside `A–Z a–z 0–9 _ -`, an empty
segment, or a name that is both a method and a child) is decided on `*`
alone.

## What a role on a peer's address opens

| held | the peer's ordinary methods | its whole-activation methods |
| -- | -- | -- |
| `dyn.{peer}` (the slot's grant) on `/dyn.peer.shop.*`, or `/dyn.*` | yes | no |
| the method's own grant (`dyn.peer.shop.restock`, or `admin`) on `/dyn.peer.shop.*`, or a `.*` above | that method (all, for `admin`) | that method (all, for `admin`) |
| anything on `*` | as the role lists | as the role lists |
| `dyn.{peer}` on a data scope (`KILN`) | no | no |
| the peer's literal path on a data scope: `admin` on `KILN`, a role listing `dyn.peer.shop.stock` on `KILN`, a consented caller | yes | no |

A peer's whole-activation methods belong to its admin: whoever holds the
method's own grant at its address, or on `*`. Across a hop the near side
says so with `limit.door_own` (plexus-wire spec/12), and the child runs
such a method on a door only then. A call the door admitted carries the
door into a remote child for that call alone (`limit.door`).

## `/auth` is admin

A role listing `auth.role_set`, held on `/auth.role_set`, `/auth` or
`/auth.*`, is enough to become `admin` on `*` when the holder has any
membership on `*`: the holder rewrites that role to list `auth.grant`, then
grants itself. Grant an address on `auth` as you would grant `admin`.

`tests/one7_door.rs` runs the door rules.
