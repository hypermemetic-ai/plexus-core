# plexus-core

Core infrastructure for building Plexus RPC services with optional dynamic routing.

## Overview

plexus-core provides the foundation for building Plexus RPC services with hierarchical routing and schema introspection:

- **Activation** - Trait for implementing Plexus RPC services/plugins
- **DynamicHub** - Optional routing layer for hosting multiple activations under one namespace
- **Handle** - Typed references to plugin method results
- **plexus-macros** - Procedural macro for generating activation boilerplate

> **Key Insight**: Any activation can be hosted directly as a Plexus RPC server. DynamicHub is just an activation with `.register()` - it's not required infrastructure.

> **Note**: `Plexus` has been renamed to `DynamicHub` to clarify that it's an activation with dynamic registration, not special infrastructure. The `Plexus` type alias remains for backwards compatibility but is deprecated.

## Quick Start

### Single Activation (Direct Hosting)

For a single Plexus RPC service, host it directly without DynamicHub:

```rust
use plexus_core::activations::echo::Echo;
use std::sync::Arc;

// Single activation - no DynamicHub needed
let echo = Arc::new(Echo::new());
// Use with plexus-transport or your own Plexus RPC server
```

### Multiple Activations (Composition)

For composing multiple Plexus RPC activations under one namespace, use DynamicHub:

```rust
use plexus_core::plexus::DynamicHub;
use plexus_core::{Activation, PlexusError};
use std::sync::Arc;

// Create a dynamic hub with explicit namespace and register your activations
let hub = Arc::new(
    DynamicHub::new("myapp")
        .register(MyActivation::new())
        .register(AnotherActivation::new())
);

// Route calls to activations
let stream = hub.route("myactivation.method", json!({})).await?;
```

> **When to use DynamicHub**: Only when you need to compose multiple top-level activations. For a single service, host the activation directly.

### The service root: a top level that grows while it serves

Underneath the builder, a service's top level is one table of peers
answered by `peer(name)` (NEST-15): `.register(x)` and `--child` add an
entry at build; `hub.root()` reads and changes the table while the service
serves. Routing, the grant gate's index, `<service>.schema` / `.hash` /
`.ir` and the schema's `children` all read it; a change moves the
service's hash and is said on `root().watch()`.

```rust
let service = Arc::new(DynamicHub::new("svc"));               // no activations yet
let root = service.root();
root.insert(Weather)?;                                       // svc weather forecast — now
let peer = root.peer("weather").await?;                      // the primitive: a Box<dyn Peer>
root.insert_peer("sky", Arc::new(Weather) as Arc<dyn Peer>, false)?; // any Peer, under its own name
root.remove("weather");
```

An entry added at runtime is reached through `<service>.call` (what
synapse and the clients send); only entries registered at build also get
direct `<ns>.<method>` RPC names on a service without a grant gate. The
gate admits it as any activation: by the roles that list its grants.

> **Migration Note**: `DynamicHub::new()` now requires an explicit namespace. Choose a namespace that identifies your application (e.g., "myapp", "substrate", "hub"). The `Plexus` type alias still works but is deprecated.

## Creating Activations

Use the `plexus-macros` crate to generate activation implementations:

```rust
use async_stream::stream;

#[derive(Clone)]
pub struct MyApp;

#[plexus_macros::activation(
    namespace = "myapp",
    version = "1.0.0",
    description = "My application"
)]
impl MyApp {
    /// Say hello
    #[plexus_macros::method]
    async fn hello(&self, name: String) -> impl Stream<Item = MyEvent> + Send + 'static {
        stream! {
            yield MyEvent::Greeting { message: format!("Hello, {}!", name) };
        }
    }
}
```

## MCP

plexus-core has no MCP code and no rmcp dependency. To serve a service over MCP, use [plexus-transport](https://github.com/hypermemetic-ai/plexus-transport) with its `mcp` feature, or run [plexus-transport-mcp](https://github.com/hypermemetic-ai/plexus-transport-mcp) beside it.

## Architecture Patterns

### Hub Activations

Any Plexus RPC activation can route to children by implementing `ChildRouter`. This enables nested method routing without DynamicHub:

- **Solar** - Routes to planets (hardcoded children)
- **DynamicHub** - Routes to registered activations (dynamic children via `.register()`)
- **Your custom hub** - Can route to any children you define

```rust
// Solar is a hub activation with hardcoded children
let solar = Arc::new(Solar::new());
// Supports: solar.mercury.info, solar.earth.luna.info

// DynamicHub is a hub activation with dynamic children
let hub = Arc::new(
    DynamicHub::new("app")
        .register(solar)
        .register(echo)
);
// Supports: app.solar.mercury.info, app.echo.echo
```

### When to Use DynamicHub

**Use DynamicHub when:**
- You need to compose multiple top-level Plexus RPC activations
- You want dynamic registration (add activations at runtime)
- You're building a multi-service Plexus RPC server (like substrate)

**Don't use DynamicHub when:**
- You have a single Plexus RPC service (host it directly)
- Your activation already routes to children (like Solar)
- You want a simpler deployment

### Direct Activation Hosting

The recommended pattern for single Plexus RPC services is direct hosting:

```rust
// Good: Direct hosting for single Plexus RPC service
let my_service = Arc::new(MyService::new());
TransportServer::builder(my_service, converter).serve().await?;

// Unnecessary: DynamicHub for single service
let hub = Arc::new(DynamicHub::new("app").register(MyService::new()));
TransportServer::builder(hub, converter).serve().await?;
```

## Example Activations

plexus-core includes two minimal example activations:

- **health** - Health check endpoint (manual Activation impl)
- **echo** - Echo messages back (plexus-macros generated)

See `src/activations/` for implementation examples.

## The rules a keyed peer and its service apply (KEEL-19)

What the code checks, in order — the text a change to `remote_child` or
`peer_token` is checked against.

**Before a peer runs a hop** (`{ns}.call` for method M; a schema call needs
none of this):

1. A child with a key, or verifying tokens addressed to a key, is served
   only by `serve_child_proven`, which takes a `Proven` — a type with no
   constructor from a string, made only by `KeyedUpgrade::verify` checking
   the upgrade's `plexus-key.` proof (`serve_child_ws` does it) — and is
   believed from that principal alone. `serve_child_with` refuses one,
   whatever `ChildPeer` it is given.
2. A keyless, non-verifying child (`serve_child_with`) believes every
   sender its `ChildPeer` takes. Served as `ChildPeer::Pipe` on a
   WebSocket, it believes every sender who can reach that socket, as
   whoever the frame claims to be. **Do not do this**: a keyless child
   belongs on its parent's stdin/stdout or a socket only that parent can
   open; a child reachable over a network has a key and is served with
   `serve_child_ws`. On `ChildPeer::connection` the sender is the string it
   was given, which proves nothing by itself.
3. With a verifier, the hop's token must verify: an EdDSA JWS signed by a trusted
   JWKS key (`iss` = `kid`), `aud` this child, within its times, naming
   `hop.call` and M, its `sub` the hop's caller, its scope holding the
   hop's grant on every scope the hop says.
4. And its sender must be proven by `hop.proof` over (token, M, `hop.call`):
   a token bound to this child's own key (or, to a pipe, to none) is the
   service's forward — the proof by its issuer key, and on a connection a
   sender `ChildPeer` takes; a token bound to another key is an exchanged
   one — the proof by that key, over a connection proven as it, which the
   hop names. Only then is the token's `jti` spent (once).
5. Then the far side's own check (the hop's grant is M or M's slot) and M
   runs as the hop's caller, within the scopes the hop says.

**Before a service mounts a keyed peer** (`RemoteChild::connect`):

1. It dials with its own key proof on the upgrade (`ChildOptions::key`;
   plexus-dyn: `<data_dir>/dial.key` by default), so its principal is the
   `key:` the peer's transport proves.
2. It asks `_info {nonce, asker}`; a peer that names a key must prove it
   with `plexus-peer-key/v2` over (nonce, backend, the asker its connection
   proved), checked against the service's own principal — refused when
   that principal is not a key (`keyed_mount_needs_a_key`) or the proof was
   made for anyone else.
3. The key is pinned with the peer's identity: a remount proving another
   is refused (`identity_changed`); plexus-dyn refuses a key another peer
   holds, mounted or pinned (`identity_changed`, `key_in_use:`), checked
   where the entry is reserved.
4. Tokens are minted for that key only while it is mounted and not
   revoked — asked at the top of each forward and again, after the dial
   it may await, where the token is minted and where its call back is
   opened — by a service whose principal is a key; each forwarded hop
   carries the service's proof (`TokenIssuer::prove_forward`).
5. An exchange (`dyn.exchange`) is decided as a call back is: the presenter
   mounted, not revoked, holding a consented need for the audience and the
   method, within the consent of now; once per (`jti`, audience, method);
   the token bound to the presenter's key.

Replay: an upgrade's key proof is taken once while its 60 s window lasts,
and a token's `jti` once while it lives. `KeyedUpgrade` holds at most 4096
proofs (`UPGRADE_LEDGER_MAX`); full, it **refuses** a new upgrade — never
forgets a proof early — until proofs leave their window: the dialer gets
HTTP 401 with `this child holds 4096 key proofs in their 60 s window: a new
upgrade is refused until some expire`, and the child logs a warning on
target `plexus::audit` (`child upgrade ledger full`, with the count held
and refused) at most once per 10 s. So at most 4096 upgrades a minute are
taken per child (about 68 a second, sustained); a flood can deny upgrades
for a minute, never replay one. Both are kept in memory: a restarted child
forgets, so a proof or token captured in the 60 s before a restart can be
replayed to it once after it (a token only while it lives, at most its
`exp`).

Key files and the data directory are the user's own, 0600 and 0700, never
read through a symbolic link.

A child dial's key proof is spec/00's one form, signed as the reserved agent
`plexus.child-dial` (`CHILD_DIAL_AGENT`; `agent` is in the signed bytes): a
child takes only that agent, so a sign-in proof replayed to a child at
the same URL is refused. A server's sign-in (plexus-auth-core's
`KeyProofAdapter`) takes a dial proof as the dialing key's sign-in, by
design: a dial proof is addressed to the dialed URL and usable only there,
and it is how a service mounts another service behind key sign-in
(`--child far=wss://…`, `dyn.connect`). A context of its own would be a
plexus-wire spec/00 change, not made.

## Doors: a role held on an address (ONE-7)

A role may be held on an **address** — `/dyn` (an activation's own
methods), `/dyn.*` (it and everything beneath), `/dyn.peer.shop.*` (one
peer) — as well as on a data scope or `*`. An address opens a **door**,
never data. The gate decides two shapes at the door of the call: a method
marked `everywhere` with no target, and a call into an untyped peer slot
(`dyn.{peer}`). Everything else is decided on its data, as before.

What a role on a **peer's address** opens, and does not:

| held | the peer's ordinary methods | its whole-activation methods |
| -- | -- | -- |
| `dyn.{peer}` (the slot's grant) on `/dyn.peer.shop.*`, or `/dyn.*` | yes | **no** |
| the method's own grant (`dyn.peer.shop.restock`, or `admin`) on `/dyn.peer.shop.*`, or a `.*` above | that method (all, for `admin`) | that method (all, for `admin`) |
| anything on `*` | as the role lists | as the role lists |
| `dyn.{peer}` on a data scope (`KILN`) | no | no |
| a peer's **literal path** on a data scope — `admin` on `KILN`, a role listing `dyn.peer.shop.stock` on `KILN`, a consented caller | **yes** (not closed: a follow-up to KEEL-44) | no |

So a peer's whole-activation methods — an in-process bridge's `add`,
`replace`, `remove` among them — are its admin's: whoever holds the
method's own grant at its address, or `*`. Across a hop the near side says
so with `limit.door_own` (plexus-wire spec/12), and the child runs such a
method on a door only then.

**`/auth` is admin.** A role listing `auth.role_set` held on
`/auth.role_set` (or `/auth`, `/auth.*`), plus any membership of the holder
on `*`, is enough to make the holder `admin@*`: it rewrites that role to
list `auth.grant`, then grants itself. Grant an address on `auth` as you
would `admin`.

## License

AGPL-3.0-only
