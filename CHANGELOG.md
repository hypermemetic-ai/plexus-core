# Changelog

All notable changes to plexus-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 0.11.0

NEST-16 (breaking: a child's calls back are narrowed; `PluginSchema` and
`ChildOptions` gain a field; plexus-macros and plexus-client 0.11): **a graft
that knows its parent.** `#[plexus_macros::activation(parent = ShopClient)]`
injects the parent's client into a method as `parent: Parent<ShopClient>`
(`plexus::Parent`, over a `ParentTransport`: the mount's connection back
when the child runs behind one, the service's own routing in process; every
call as the original caller). `PluginSchema.needs: Option<Vec<Need>>` — each
method the activation calls of its parent, by path (`shop.items`) and shape
hash (`Interface::method_hash`); absent on the wire when `None`, and kept out
of `PluginSchema`'s own JSON Schema, so no service's hash moves.
`Activation::needs()` (default `None`) answers it without building the
schema. **A graft is checked**: `ServiceRoot::insert`/`replace`/`insert_peer`
refuse an entry whose needs are not served (`RootError::Needs(NeedsMiss)`,
every missing and changed method named); `DynamicHub::check_needs`,
`check_grafts`, `method_at`; serving a service (`into_rpc_module`) refuses a
static graft whose parent is not there. A need below an untyped slot counts
as served (its shape is the peer's). **The calls back**: beyond the standard
upward interface — `host.schema` (and any `<path>.schema`), `host.whoami`,
`host.log`, `host.notify` (answered by the service: `DynamicHub::notices()`
/ `notify`) — a child calls only what its schema's `needs` names; anything
else is refused `forbidden`, reason `not_needed` (new `AuthzDenyReason` /
`DenyReason` variant, kept out of the JSON Schema), and a need is routed
under one more ceiling layer, its own grant on the forwarded call's scopes
(TM-1, DYNAUTH-4). A child that declares no needs has the standard interface
alone, unless the service keeps NEST-11's rule for it for this release:
`ChildOptions::legacy_upcalls` / `with_legacy_upcalls`,
`--child-legacy-upcalls`. `RemoteChild::needs()` (its whole tree's).

DYNAUTH-5 (additive): **a peer proves its key; its needs held to consent.**
A mount asks `_info {nonce}`; a far side with a key (`ServeChild::key`,
`serve_child_with`) answers `{backend, key, proof}` — the nonce and backend
signed Ed25519 over `plexus-peer-key/v1` — and the mount registers and pins
it (`PeerIdentity::key`, `RemoteChild::peer_key`): a restart proving another
key is refused as another certificate key is. A key named and not proved
refuses the mount. `RemoteChild::set_consent(Some(Vec<Consented>))` holds a
child's calls back to the needs an admin consented to, each on its scopes
(a `grant@scope` ceiling layer); a declared need not consented is refused
`forbidden` (`not_needed`), saying so. `None` (the default) keeps NEST-16's
rule. New module `plexus::peer_token` (DYNAUTH-12's tokens; here its keys:
`PeerKey`, `check_key_proof`, `random_nonce`); ed25519-dalek is now a
native dependency (it was `child-ws`'s), with getrandom 0.2 for keys.

DYNAUTH-8 (additive): **transport hardening.** `plexus::redact` — one
redactor for frame logs (`redact_str`, `redact_value`, `CREDENTIAL_KEYS`):
a credential key keeps its name and loses its value. A stdio child's stderr,
relayed into the service's log, goes through it. `child-wss` builds its own
rustls client (ring; the webpki roots plus the new
`ChildOptions::tls_roots`, a PEM file of more CAs) and every mount pins its
child's identity — `RemoteChild::identity()`, a `PeerIdentity` of its
`_info` backend and, on `wss://`, the sha256 of its certificate's public
key; a restart or redial that proves another is refused for good
(`dead()`), as one publishing another schema is.

## 0.10.2 (unreleased; folded into 0.11.0)

NEST-15 (additive): **the service root is the primitive — a table of peers
answered by `peer(name)`, and it can change while the service serves.**
`DynamicHub::root()` is the root ([`ServiceRoot`]): `peer(name)` (a `Box<dyn
Peer>`), `names`, `contains`, `insert` / `replace` (an activation, a
`RemoteChild`), `insert_peer(name, Arc<dyn Peer>, replace)` (any peer, its
schema's grants and roles requalified to `name`), `remove`, `hash` and
`watch` (a `tokio::sync::watch` of the service's hash, told on every
change). Routing is `peer(name)` from the root down: the service's own name
answers the root itself (`call`, `hash`, `schema`, `ir`), every other name
the table. `.register(..)`, `.register_hub(..)` and `--child` are the
table's entries at build, unchanged. The gate's index, the `<service>.call`
input index, `<service>.schema` / `.hash` / `.hashes` / `.ir`, the schema's
`children`, `declared_roles`, `auth.requires` and the activation registry
are read from the table: a change drops what was described and indexed, and
moves the service's hash — in every item's `plexus_hash` too
(`PlexusContext` is moved when the service that set it changes). An entry
added at runtime is reached through `<service>.call`; direct `<ns>.<method>`
JSON-RPC names (a service without a gate) and `<ns>.list_children` stay the
build-time entries'. Refusals: `RootError::{Taken, Shadows, BadName}`.
No wire change for a service whose table does not change.

## [Unreleased] — 0.10.1

NEST-11 (additive): **a child calls its service back, under a call it
serves.** A child mounted by `RemoteChild` (spawned on stdio or dialed on a
WebSocket) may send `_host.call {method, params, under}` on the mount's
connection while a call the service forwarded to it is open, `under` that
call's `hop.call` (plexus-wire spec/14, "A child calls its service back").
The service routes it through its own routing and gate —
`DynamicHub::route_with_ctx` — as the forwarded call's caller, within its
reach (one more `admin@<scope>` ceiling layer), streams its items back as
`_host.call` notifications, takes `_host.call_unsub`, and ends every call
made under a forwarded call when that call ends or its grant is revoked. A
call naming no live forwarded call is refused `unauthenticated` at the
JSON-RPC layer, naming why; outside a call the child may ask for a schema
only, answered from the service's own description. Any other request from
a child is refused as before. New: `remote_child::host()` and
`HostTransport` (a `plexus_client::Transport` back into the service, for
the call being run, on the Rust far side), `HOST_CALL` /
`HOST_CALL_UNSUB`, `WeakService` and `DynamicHub::downgrade`,
`ChildOptions::host` / `with_host` (the service a child is mounted in;
else the one the call it was connected in was routed in, else the first
forwarded call's), `ChildStats::calls_back`, `RemoteChild::calls_open_back`.
`DynamicHub::route_with_ctx` now runs knowing its service (the outermost
one a call entered). Test: `tests/nest11_calls_back.rs`.

NEST-12 (additive): **what a runtime peer set needs of a mount** (plexus-dyn).
`ChildOptions::ping`: a WebSocket child is pinged at that period and marked
down — every open call `child_unavailable`, the next one redialing — when
nothing has come from it for twice as long; a dial whose upgrade never
answers is given the mount's timeout. `RemoteChild::is_up`, `why_down`,
`dead` (why a mount will never take its child back: "schema changed;
restart the service" — a fresh `connect` mounts the new one), `up()` (bring
it up now, within its backoff), `mounted_hash`; `ChildStats::up`. A mount
reached through a slot of its service (a peer in `dyn.{peer}`) tells its
child the method it was admitted for in the child's terms
(`hop.limit.grant` = `{ns}.<method>`) rather than the service's slot grant,
which the child could not read.

## [0.10.0]

ASK-2 / ASK-1 (breaking): **the server no longer asks its caller
mid-call.** The `bidirectional` module goes — `BidirChannel`,
`StandardBidirChannel`, `StandardRequest` / `StandardResponse`,
`SelectOption`, `BidirError`, the pending-request registry,
`create_bidir_stream` / `wrap_stream_with_bidir` — with
`PlexusStreamItem::Request`, `{ns}.respond`, and `MethodSchema`'s
`bidirectional`, `request_type` and `response_type` (and their builders).
Nothing replaces them: Plexus has no in-call or protocol-wide confirmation
(owner, ASK-1); a service that wants one builds it as its own methods. An
older schema's `bidirectional`, `request_type` and `response_type` are read
and ignored. The IR is 3.1: 3.0 without each method's `mdBidirType`,
`mdBidirResponseType` and `mdBidirResponseSchema`. The input half
(`Input<T>`, `{ns}.input`, `DuplexGate`, `answer_by`) is unchanged. Every
schema hash moves (goldens regenerated).

NEST-6: **a mounted child's dynamic children are reachable through the
mount.** The walk keeps each slot on its parent with its type (a `#[peer]`
slot is a slot, no longer walked as a level), so the host's gate decides
`<mount>.solar.earth.info` on the slot grant `<mount>.solar.{planet}.info`
(an untyped slot whole, `<mount>.belt.{rock}`), and `RemoteChild` forwards it
with `hop.limit.grant` the slot grant in the child's terms — it no longer
refuses a call into a slot. The far side (`serve_child*`) checks a hop's
grant against the slot a path goes through as well as the literal path. A
slot's list and search methods are forwarded like any method, and an unknown
name is the child's own not-found, unchanged. `<mount>.<path>.<name>.schema`
is the one schema that crosses the hop (spec/12 rule 7's exception): once per
name, kept under the name and the `plexus_hash` it came with, at most
`--child-schema-cache` names (`ChildArgs::child_schema_cache`,
`ChildOptions::schema_cache`, default 1024, least recently used out); an item
through the name with another `plexus_hash` drops it, a restart drops every
name. `ChildStats` counts `name_schemas`, `name_schema_hits` and
`names_kept`. The hub answers `<activation>.<name>.schema` for a name in an
activation's own slot by routing it (it was `method_not_found` in the
caller's view). `ChildArgs::default()` is the flags' defaults (a derived
`Default` said 0 for every count, so `--child-max-depth` 0).

NEST-7: **the primitive — an activation returns an activation** (`plexus::peer`).
`trait Peer` is the erased activation (`interface`, `call`, `peer`),
blanket-implemented for every `Activation + ChildRouter` (`RemoteChild`
included). `Interface { name, hash, ir, methods, schema }` is a peer's shape
(the hash of each method's shape hash; `satisfies` is the shape check).
`PeerError` (`not_found`, `not_grafted`, `unavailable`, `shape_mismatch`,
`timeout`, `forbidden`) is a typed error item: `ChildRouter::peer_child` is
what routing asks, and a peer that could not be returned is its error, never
"not found". `MethodRole::Peer { list_method, search_method, interface }` is a
`#[plexus_macros::peer]` slot, reached as `<parent>.<slot>.<name>` (on the
wire a `static_child` marked `peer`, so synapse navigates it); `PeerSlot`
routes it, checking a typed peer against the slot's interface. A contract's
client runs over a `PeerTransport`, which checks the backend against the
client's `Stamp` (equal; `drift` once; else `ShapeMismatch`) and again when
an item's `plexus_hash` moves. The slot grant (NEST-5) covers peer slots:
`host.{integration}.repos`, `garden.{dendrite}`.

NEST-5: **slot types and slot grants, in-process.** A dynamic child's role
carries its slot's type (`MethodRole::DynamicChild { child }`, the child
type's schema; absent for `#[child(opaque)]` or a hand-written router), and
the gate grants a slot once: `solar.{planet}.info` is `info` on every name in
the slot, `solar.{planet}` an untyped slot whole (`plexus::slots`). A call to
`solar.earth.info` matches the slot (a static child still wins) and is
decided on the slot's grant, after a grant written as the literal path;
`declared_roles`, `auth.requires`, `auth.role_set` and the caller's view read
slots as they read static children. `Activation::slot_schema()` (the schema
without an instance) is new. Breaking for a crate that builds
`MethodRole::DynamicChild { list_method, search_method }` by hand: add
`child: None`.

### Added

- **NEST-4: a remote child may have children.** `RemoteChild` no longer
  refuses a child whose schema has a child role or lists `children`. At
  mount it walks the static tree depth-first (`{ns}.<path>.schema` for each
  static child; a service root's `children`), at most `--child-max-depth`
  levels (`ChildOptions::max_depth`, default 8) and within the one
  `--child-timeout`, keeps it and hashes it: a restart whose tree hash
  differs is refused `schema changed; restart the service`, as a flat
  child's is. The kept tree is the mount's `static_child_schemas`, so the
  host gates `<mount>.a.b.m` by its full path with the child's roles renamed
  at every level, as it does an in-process child's. `<mount>.a.b.schema` is
  answered from the kept tree (nothing crosses the hop); `<mount>.a.b.m` is
  forwarded as `{ns}.call {method: "{ns}.a.b.m", hop}`, its grant the full
  path. A dynamic child's slot is kept on its parent's schema, and a call
  into it is refused naming the slot (`<mount>.a.{item}`) until NEST-6.

### Fixed

- **A mounted child's method grants are requalified under the mount name**
  (`{ns}.m` → `<mount>.m`), as its roles already were: a child whose schema
  states each method's `grant` (every macro-built one) and is mounted under
  another name was hidden from every caller's view and admin-only.

## [0.9.0] — 2026-11-06

PLEXUS-46 (owner, 2026-11-06: "publish the core however you like"): 0.9.0,
not 0.8.x, because what is below includes RETURNS-47's breaking change
(`grant_gate::current_reach` is `-> Result<Reach, PlexusError>`; it was
`-> Reach`) — a 0.8.x would break every `^0.8` consumer on `cargo update`.
On plexus-macros and plexus-client 0.9.0, released in lockstep. The 0.8 line
stays open: 0.8.1 is left for V2-57's `serve_call`, cut from the v0.8.0 tag.

PLEXUS-45: plexus-core builds **and runs** on `wasm32-unknown-unknown`
(owner, 2026-11-06: "can we make plexus core wasm compatible without
degrading anything?"). No published plexus-core ever built there. Native is
unchanged: the host's `cargo tree -e normal` is the same with default
features, without them and with all of them, and every native call site
makes the same tokio/std call it made before.

### Added

- **wasm32 dependency tables.** Natively tokio stays `full` and jsonrpsee
  `server` + `macros`, in a `cfg(not(target_arch = "wasm32"))` table. On
  wasm32: tokio `sync, macros, rt, time, io-util`; jsonrpsee
  `server-core` + `macros` (RpcModule, the subscription sinks, Params,
  ErrorObject, Extensions — no hyper, no mio); getrandom 0.3 `wasm_js` / 0.2
  `js`, uuid `js`, chrono `wasmbind`; wasm-bindgen-futures, futures-timer
  (`wasm-bindgen`) and web-time for the seam. getrandom 0.3 also needs
  `--cfg getrandom_backend="wasm_js"` in the target's rustflags.
- **One runtime seam, `crate::rt` (crate-private):** `spawn`,
  `spawn_blocking`, `sleep`, `timeout`, `Instant`, `now_unix`. Natively each
  is a re-export of the tokio/std item the call site named before (or, for
  `now_unix`, the same `SystemTime` arithmetic). On wasm32: `spawn` is
  `wasm_bindgen_futures::spawn_local`; `spawn_blocking` runs the closure
  inline (one thread — nowhere else to run it); `sleep` is a `setTimeout`,
  `timeout` races it; `Instant` and `now_unix` read the JS clock. Every
  non-test site goes through it: the health activation (its uptime clock and
  its subscription task), the IR build (`spawn_blocking`), the duplex gate's
  audit drain and expiry, the bidirectional channel's request timeout and
  `auto_respond_channel`, `PlexusStream`'s subscription task, the echo
  activation's delay, the scope gate's timing, the memory auth backend's
  clock.
- `tests/wasm_dispatch.rs`: a `DynamicHub` with activations dispatched in
  wasm32 under Node — a plain call, a streaming call spaced by timers, a
  question that times out, the health activation and the schema read.
  `scripts/wasm-test.sh` runs it (finding or installing the matching
  `wasm-bindgen-test-runner`).
- `tests/wasm32_check.rs`, in the native suite:
  `cargo check --lib --no-default-features --target wasm32-unknown-unknown`
  is green (skipped, with a message, when the target is not installed).

### Changed

- **wasm32 only:** `plexus::remote_child` (and its re-exports `RemoteChild`,
  `ChildSpec`, `ChildOptions`, …) is not built. A browser has no processes,
  and a ws child waits for a browser-WebSocket transport (a later ticket).
  `child-ws`'s tokio-tungstenite is native-only.
- **wasm32 limit:** dispatch in wasm goes through `DynamicHub::route` (or
  the in-process transport). The JSON-RPC module (`into_rpc_module`) spawns
  each subscription with `tokio::spawn` inside jsonrpsee, which needs a
  tokio runtime that wasm32 does not have; it is a server's path.
- Requires plexus-auth-core 0.3.1 (wasm32 builds; natively unchanged).

RETURNS-47: the caller from the call's context, fail closed. Breaking.

### Added

- `plexus_core::call`: `caller()` answers the caller of the call it runs in
  as the service's gate admitted it — the `AuthContext` that stands (after
  AUTH-11's liveness) and the `Reach` the gate answered (`Caller::auth`,
  `Caller::signed_in`, `Caller::reach`) — so a method of a hand-written trait,
  whose signature cannot carry `#[from_auth]`, reaches its caller as an
  inherent one does. `hop()` answers, in a child reached through the seam,
  the hop the call came through (`Hop`: `principal`, `for`, `limit`, `call`;
  `Hop::caller`, `Hop::grant`, `Hop::held_on`, `Hop::allows` — false when
  the hop names no readable caller, agreeing with `caller()?.reach()`). `context()`
  and `scope(ctx, fut)` hand a call's context to a task it spawns, which
  otherwise has none. `InCall`: a stream polled inside a context. Each is an
  error outside a call (`CallError`, as a `PlexusError` `Unauthenticated`),
  never a default.
- `call::verified::<T>()`: what a trait-impl method's verifier
  (`#[plexus_macros::from_auth(…)]` on the method) answered for the call.
  Set once per call, by the dispatch before the body: a second set is
  refused (`CallError::AlreadyVerified`) and the verifier's value stands —
  inside `with_reach` too, which narrows the same call (another caller's
  context, `ungated` or a nested route, starts its own).
- `call::ungated(activation, method, params, auth, raw_ctx)`: one activation
  dispatched as a service with no gate dispatches it — in a context admitting
  `auth` everywhere, said by the caller of the function. The leaf path for a
  bridge that serves a single activation, where there is no service and so no
  gate; a call that passes a gate goes through the service's route instead.
- `call::test::in_call(auth, reach, fut)` (feature `test-util`, never
  default): a test's way into a call.
- `remote_child::serve_child` / `serve_child_stdio`: an activation served as
  a child on stdio (spec/11, 12) — `_info`, `{ns}.call`, `{ns}.call_unsub` —
  each call in its hop's context, schema calls and a dynamic child's lookup
  included. Before the method runs: a call with no hop is `unauthenticated`;
  a hop no gate decided (`limit: null`, no grant) or one admitted for another
  grant than the method called is `forbidden`. **A child receives auth** (owner,
  2026-11-04): through a hop `caller()` is the caller the hop names (`for`'s
  far end; anonymous when `for` is empty), its reach the hop's ceiling
  (`limit.held_on` for `limit.grant`, as a gate of the hop alone answers
  it: no public constructor makes such a reach; nowhere when `for` cannot be
  read), never wider; `required` works in a child (an anonymous hop is refused), and a
  `#[from_auth]` verifier is the child's own, run on that caller.
  (The re-review's start-time refusal of an activation that needs a caller
  is gone with the reason for it.) **Who may send a hop** (`remote_child`'s
  `host` docs hold the trust model): a hop is unsigned, so it is believed
  only from a sender the child trusts. On a pipe its parent owns
  (`serve_child`, `serve_child_stdio`: `ChildPeer::Pipe`) every hop is the
  parent's. On a proven connection (`serve_child_on` with
  `ChildPeer::connection(proven, acts_for_others)`) a hop is taken only when
  the proven principal is one the child trusts to act for others and the hop
  names it as the acting service; any other is refused `forbidden`.
  plexus-core has no WebSocket server for a Rust child: the server that
  proves the connection hands `serve_child_on` its principal.

### Changed

- **In-process children receive auth** (owner, 2026-11-04). A call routed
  into a child (`route_to_child`: static `#[child]`, dynamic, nested) runs in
  a context of its own, under the child's forward policy: its caller the
  context the policy derived (`same_service`, `pass_through`: the caller
  whole; `identity_only`: its identity, roles and metadata dropped but its
  principal kept; `anonymous`: none), its reach the call's when the policy
  keeps the caller's identity and nowhere when not, its verified value its
  own, and its hop (in a child process) kept as its caller is — whole under
  `same_service`, `identity_only`, `pass_through`, none under `anonymous`
  (`hop()` errors there, as outside a hop). So `caller()`, `current_reach()`,
  `reach: Reach`, `hop()`, `#[from_auth]` and `required` answer in a child as
  the policy says; before, `caller()` and
  `reach` answered the outer call whole whatever the policy (`anonymous`
  leaked the caller and its reach), and `identity_only` dropped a `key:`
  caller's principal (plexus-auth-core's fix).
- Every call a `DynamicHub` dispatches runs in its context, and the stream
  it answers carries it (each poll inside it): the gate's reach on a gated
  service; on one without a gate `Reach::everywhere`, said by the dispatch
  (or, routed from inside another call, that call's reach and hop with this
  call's identity); an introspection call the caller's reach for the path,
  asked of the gate only if read. `{ns}.list_children` and
  `{ns}.search_children` run their list and search methods in a context the
  same way (they are not gated — a gap of its own).
- **`current_reach()` returns `Result<Reach, PlexusError>`** (was `Reach`)
  and fails closed: outside a call it is `Unauthenticated`, never
  `Reach::everywhere` (it fell back to everywhere when no gate had set one).
- **`with_reach` returns `Result<F::Output, PlexusError>`** and only narrows
  the reach of the call it runs in: outside a call, or given a scope the
  call does not hold, it is refused. (It built an anonymous caller by hand.)
- **`Activation::call`, called straight** (not through a service), runs in
  no context: a method that takes `reach: Reach`, a trait-impl method under
  `auth = "required"`, and any body reading `caller()` are refused
  (`Unauthenticated`, or in band where the body says so). Call through a
  `DynamicHub`, or `call::ungated`.
- A `RemoteChild` forward outside a call sends nothing and answers
  `unauthenticated`.
- `tests/remote_child.rs`'s `cancel_crosses_hop` asserts the cancel's order
  (the child sent `call_unsub`, took it for a live call, stopped that call;
  the service holds nothing after) within 5 s per cancel, not a 100 ms bound
  on the slowest of twenty, which missed under a loaded run.

### Removed

- The `Echo` and `Auth` traits (`activations::echo::Echo`,
  `plexus::Auth`), which `#[plexus_macros::activation]` emitted for
  `EchoActivation` and `AuthActivation` and no longer does (RETURNS-47: a
  trait only when named); and `FromClientError` for `EchoEvent` and
  `AuthEvent`, which only their clients' trait impls asked for.

### Migration

- **menger** (`menger-tickets-api`, on 0.7.0 today): in `Access::verify`
  (`tickets-api/src/access/mod.rs:774`) `current_reach()` becomes
  `current_reach()?`; its test
  `the_frames_resolver_answers_typed_and_keeps_the_calls_reach`
  (`tickets-api/src/access/tests.rs:616`), which calls `verify` outside any
  call, wraps each `a.verify(..)` in
  `plexus_core::call::test::in_call(None, Reach::everywhere(), …)` (with
  `plexus-core = { …, features = ["test-util"] }` under
  `[dev-dependencies]`). `docs/src/caller.rs:44` takes the same `?`.
- **plexus-ui** (`plexus-ui-service`, on 0.7.0 today): `Callers::verify`
  (`service/src/caller.rs:60`) takes `current_reach()?`, and its direct
  `verify` tests are wrapped in `in_call` the same way.
- **plexus-transport's REST and MCP bridges** (its RETURNS-47 entry): their
  leaf path — one activation, no service, so no gate — runs through
  `call::ungated` in place of `Activation::call`, so a `reach: Reach` method
  and a `caller()` reader are answered there as on a service with no gate.
  The REST bridge names its caller with the session validator and routes over
  a service with it (`with_router_as`), through the gate. The legacy
  `ActivationMcpBridge` names no caller (anonymous); the mounted MCP bridge
  goes through the service's route as the caller its validator names.
- **A child served with `serve_child`** under a service without a gate gets
  `limit: null` hops, and so refuses every call but its schema: gate the
  service that mounts it.

## [0.8.1]

### Added (V2-57)

- `DynamicHub::serve_call(params, pending, ext, ns)`: one `{ns}.call` served
  exactly as the service's own `{ns}.call` serves it — the connection's
  caller, a method with an `Input` taking its input half (BIDIR-6), each item
  piped. For a host that registers `{ns}.call` itself to check its own limits
  first (menger's call layer): before it, such a host could only `route`,
  outside the call's seam, and every `Input` method answered that the
  transport carries none. `tests/host_call.rs`.

## [0.8.0]

### Breaking (TRANSPORT-23: no rmcp in plexus-core)

| Change | Before | After | What to do |
|---|---|---|---|
| `plexus_core::mcp_bridge`, `plexus_core::PlexusMcpBridge` | public, on rmcp 0.12 | removed | Use `plexus-transport` with feature `mcp`: `with_mcp`, or `ActivationMcpBridge` for an rmcp `ServerHandler` |

### Removed (TRANSPORT-23)

- The `rmcp` dependency. plexus-core no longer compiles an MCP stack, and
  `scripts/check-rmcp.sh`, run by `cargo test`, keeps it out.

### Dependencies (PUBLISH-3)

- `plexus-auth-core` 0.3 (was 0.2.2): its `CallCeiling` gained the public
  field `max_buffered`, which plexus-core's input half reads.
- `jsonrpsee` 0.26.1 at least (was 0.26): `plexus::input` reads
  `PendingSubscriptionSink::subscription_id`, which 0.26.0 lacks.

BIDIR-6: the input half of a call. BIDIR-17: binary input frames.

### Added (BIDIR-17)

- `InputTable::take_binary`: a WebSocket binary message
  `[0x01][subscription u64 BE][seq u64 BE][payload]` is one input item, routed
  with no parse to the same slot and admission as `{ns}.input`, its payload a
  slice of the message. `input::BINARY_INPUT`, `input::BINARY_HEADER`.
- `Input<Bytes>`: a binary payload as is, a JSON item as base64; any other
  input refuses a binary frame (`invalid_input`). Its schema is marked binary
  (`x-plexus-binary`, base64 as JSON).
- `bytes` with `serde`, `schemars` with `bytes1`; `base64` always.
- `Input<T>` as a `Stream` needs `T: 'static`.

### Breaking

| Change | Before | After | What to do |
|---|---|---|---|
| `CallCeiling` (plexus-auth-core) | `max_items` 1,000,000, `max_bytes` 64 MiB by default | no lifetime limit by default; `max_buffered` added, 64 MiB, past which credit is held back (never a refusal) | Set the two only for a method that wants them; use `..Default::default()` in a struct literal |
| `duplex_gate::InputFrame` | one item | generic over what it holds, with `items` and `overrun` | `InputFrame::new` is unchanged; a struct literal names the new fields |
| `DuplexRefusal` | seven variants | adds `OutOfSequence`, `InvalidInput` | Add them to an exhaustive match |
| `DuplexRefusal::to_item` | `error_kind`, facts, `message` | a typed error item (spec/05): `metadata` and `code` too | Nothing, for a reader of those keys |
| `{ns}.input`, `{ns}.end` | `-32601` | methods of every service | Answer with `not_this_call` naming no call of the socket |

### Added

- `plexus::Input<T>` and `plexus::input`: a method's input half. The socket's
  `InputTable` takes `{ns}.input` and `{ns}.end` on its reader, the pipe drives
  `DuplexCall::input` beside the method's stream, and `credit` and `ack` move
  as the handler consumes.
- `DuplexGate::admitted` (a call its dispatch decided), `DuplexGate::ungated`,
  `DuplexCall::credit_line`.
- `MethodSchema.input` filled.
- `FrameSink::with_inputs`, `FrameSink::inputs`: a transport hands its
  connection's `InputTable` to its calls on the sink they already carry (an
  extensions entry of its own is an allocation every call).
- BIDIR-17 review: the input half runs from the open, not from the route's
  answer, so a handler may read its input before it returns its stream, and
  a cancel or a lost socket in that window ends the call and frees its
  place and slot. A frame of no items is `invalid_input` (`Overrun::Empty`).
  A refused item leaves the handler's `Input` pending, never `None`.
  `Delivered::Refused`: a frame refused on arrival; a request for it, or for
  a call of this socket that has ended, is answered `false`.
- A method with no `Input` costs what it did: its `{ns}.call` future holds
  nothing of the input half (BIDIR-17; `tests/call_allocation.rs`).

### Not enforced

- An input half is not forwarded across a hop: a method with `input` on a
  `RemoteChild` is refused, naming it.
- A frame of another connection finds no call and is not audited: the table is
  the connection's, so `not_this_call` is said to a request and a notification
  is counted (`InputTable::strays`).
### Added (RETURNS-40: the service writes its IR)

- `plexus::ir` — synapse's IR 3.0 builder in Rust (`build`, `build_one`, `canonical`), equal to synapse's `buildIRFromSchemas` / `buildIRFromSchema` byte for byte in synapse's canonical form, refusals included; a title collision refuses its activation in `build`'s walk (RETURNS-36 review #9) and fails `build_one`.
- `<service>.ir { namespaces? }` on every `DynamicHub` — one IR document for the namespaces asked (none: the whole service), as the caller's view shows it; `Result<ServiceIr, IrError>` (`not_found`, `unreadable`; a title collision is a `title` refusal in the IR). Introspection for the grant gate: it runs for anyone, as `schema` does. `DynamicHub::service_ir` is the same in process. The root's schema lists `ir`, so every service's hash moves once.
  - **Names**: `namespaces` holds at most the names the caller's view of the service has (the service's own, each activation, each static child below one); more, or a name it has not, is `invalid_params` naming it, before any schema is read (a cheap bound first: 1 + activations + static children, counted at `register`); a refusal says what the caller's view shows, never the service's size.
  - **One view**: the IR is built from one snapshot of the caller's view (the service's schema and each activation's from it; a static child's as its activation answers it), never re-checking the gate as it goes; under the R-5 scope gate only the schemas the caller is answered, decided for the namespaces asked alone and written to no audit sink — the `ir` call is audited once.
  - **Kept**: by the view's hash, the roots and — under the scope gate — the namespaces the caller is answered; least recently used out (O(log n)), at most `IR_CACHE_ENTRIES` (128) slots — those being built among them — and `IR_CACHE_BYTES` (64 MiB) of answers, never cleared whole. One build per key at a time: later askers wait for it, and when the asker building it goes, the next takes the build over. An ask with no room (every slot being built) builds without keeping; a slot whose every asker has gone before it was built is removed; a slot being built is never evicted; an answer past the byte bound and a refusal are never kept. The build runs on `spawn_blocking`. `DynamicHub::ir_builds()` counts builds.

### RETURNS-36: precise returns over main

returns/0.7 (RETURNS-1) merged with main.

#### Breaking

| Change | Before (0.7.0) | After | What to do |
|---|---|---|---|
| `MethodSchema.streaming`, `return_shape` | a flag, a shape | `cardinality` (`"one"` / `"many"`, required), `returns` always present, `error`, `progress` | read `cardinality`; `with_cardinality`, `with_error`, `with_progress` |
| `MethodSchema.hash`, the roll-up | `DefaultHasher` of tokens | SHA-256/16 of the canonical schema (RETURNS-10) | every hash changes once; `with_content_hash()` last |
| the `schema` entry's marker | `hash == "auto_schema"` | `MethodSchema::is_auto_schema()` | call it |
| `PlexusStreamItem::Progress` | `message`, `percentage` | `content_type`, `content` (the method's `P`; `Note` by default) | build with `progress(meta, ct, value)` |
| `PlexusStreamItem::Error` | `message`, `code`, `fields` | the same, plus `error: RemoteError` (required) | `error(meta, RemoteError, recoverable)` or `from_plexus_error(meta, &e, recoverable)`; `typed_error` is gone |
| `PlexusError::InvalidParams` | `(String)` | `{ param, problem: ParamProblem }` (same `Display` line) | `PlexusError::invalid_params(..)` / `malformed_param(..)` |
| `error_stream`, `progress_stream` | strings | a `RemoteError`; a content type and value | — |
| `RemoteError` | — | re-exported; `From<&PlexusError>`; JSON-RPC rejections carry it as `data` | — |

#### Added

- The per-form wrappers `wrap_one`, `wrap_one_result`, `wrap_result_stream`,
  `wrap_progress_stream`, `wrap_result_progress_stream` (over PERF-7's
  single-encode stream).
- `types::spec_code` / `spec_fields`: spec/05's `code` and flattened fields
  of a `RemoteError`, which every error item carries beside it.
- The child seam reads a peer still on plexus-wire's spec as main wrote it
  (`streaming`, `{message, percentage}`, an error item without `error`) into
  0.8's shape (`remote_child::peer`).

### Changed

- PERF-27: on a transport with no frame sink (stdio, a module called in memory)
  an item is no longer copied and parsed again on its way to jsonrpsee's sink,
  a call leaves its 8 KiB block for its thread's next one, and it builds no
  notification prefix it will not use. A one-item call falls from 50,842
  instructions and 16,048 bytes allocated to about 42,100 and 7,770. Needs
  serde_json 1.0.151.
- PERF-34: an item's JSON is written by a real scan, not a byte at a time, into
  the pipe's buffer: SSE2 on any x86-64, AVX2 chosen at run time, a byte at a
  time elsewhere; no `target-cpu`. A field's name folds to constants at compile
  time. The bytes are serde_json's, for every value. Down an item's path a ticket
  body takes 4.0× fewer instructions and 200 rows 5.3×.

- **BREAKING (RETURNS-10, 0.7): every schema hash changes value once.** A
  method's `hash` is its schema's content hash —
  `MethodSchema::content_hash()`: the method object minus `hash`, as
  canonical JSON (`plexus::content_hash::canonical_json`), SHA-256, 16 hex —
  set by `MethodSchema::with_content_hash()`, which the code
  `#[plexus_macros::activation]` emits applies once, where it caches the
  method schemas. A change anywhere in a method's params, `returns`, `error`
  or `progress` (down to a nested field) moves its hash, its plugin's and
  every ancestor's. `PluginSchema`'s roll-up and the default
  `Activation::plugin_schema` use SHA-256 too (`content_hash::hash16_lines`),
  same structure and width. New dependency: `sha2` 0.10.

### Added

- PERF-8: batches. `FrameSink::batching(max)` (and `MAX_BATCH`, 64): for a
  client that offered `batch` at its upgrade (plexus-transport reads it), the
  items a stream has ready together go in one notification, `results`, the
  metadata said once (plexus-wire spec/02); a lone item goes at once in
  today's form, and a sink that does not batch writes exactly today's frames.
  A batch stops after the item that brings it to `BATCH_BYTES`, 8 KiB, so a
  large item goes alone. An item's own path falls from 4,145 instructions to
  983, 64 to a notification; a row from 5,195 to 2,082 (35 to one), 1 KB from
  4,917 to 2,113 (8 to one).

## [0.7.0]

Upgrading from 0.6.1, the last published version. 0.6.2 below was never
published, so its changes reach crates.io here.

### Breaking

| Change | Before | After | What to do |
|---|---|---|---|
| `PlexusStreamItem::Data.content` | `Value` | `Content` | Read it with `into_value`; `PlexusStreamItem::data` still takes a `Value` |
| `PlexusStreamItem::Data.metadata` | `StreamMetadata` | `Arc<StreamMetadata>` | Wrap the value in a struct literal; reads go through the `Arc` |
| `PlexusStreamItem::Error` | no `fields` | `fields: serde_json::Map<String, Value>` | Name `fields` in a struct literal, or use `..`; empty serializes as before |
| A response to a bound question | any caller could answer | `BidirError::NotThisCall` from another connection | Add the variant to an exhaustive match; answer from the connection that was asked |
| A key no parameter claims, under `typed_params` | ignored | `-32602` invalid params | Send only declared keys; the echo activation now refuses them too |

### Added

- `plexus::duplex_gate`, the gate over a duplex call, and `answer_by` in
  method schemas.

### Not enforced

- `answer_by` is declared and carried in the schema, but no dispatch path
  checks it. `DuplexGate` is a library: a service must call `DuplexCall::answer`
  itself. A method that declares `answer_by` is not protected by the
  declaration alone.

## [0.6.2] — POLYGLOT-5: the child seam opened

### Added

- `plexus::RemoteChild` — an `Activation + ChildRouter + Clone` whose other end
  is a process on stdio or a service on a WebSocket speaking plexus-wire
  (spec/12, the hop between services): `RemoteChild::connect(ChildSpec,
  ChildOptions)`, `stats() -> ChildStats { open, unasked, restarts, calls }`,
  `pid()`, `principal()`, `mount_timings()`. Registered like any activation:
  its schema and roles merged under the mount name. An item for a call the
  child was not given is dropped, logged and counted `unasked`; one landing
  within 250 ms of an unsubscribe's `true` (spec/04's item in flight) is the
  cancel's tail, dropped quietly.
- `ChildSpec` (`NAME=stdio:CMD` | `NAME=ws://…`), `ChildOptions`, `Backoff`,
  `ChildError`, `ChildMethods`, `parse_duration`; `ChildArgs` behind the new
  `clap` feature (`--child`, `--child-timeout`, `--child-max-calls`,
  `--child-env`, `--child-key`).
- Features `child-ws` (default: a WebSocket child, dialed with the service's
  key proof) and `child-wss` (TLS).
- `PlexusStreamItem::Error { fields }` — the typed error's own fields
  (`error_kind`, `grant`, `scope`, `roles`, `held_on`, …), flattened on the
  wire; empty serializes as before. `PlexusStreamItem::typed_error`,
  `PlexusStreamItem::error_kind`. **A struct literal of `Error` now names
  `fields`** (`fields: Default::default()`), or uses `PlexusStreamItem::error`.

## [Unreleased]

### Changed

- **BREAKING**: `DynamicHub::new()` now requires explicit namespace parameter
  - Forces intentional naming instead of defaulting to "plexus"
  - Example: `DynamicHub::new("substrate")` or `DynamicHub::new("myapp")`
  - Rationale: DynamicHub is a composition tool - its namespace should reflect your application

- **DEPRECATION**: `Plexus` type renamed to `DynamicHub` to clarify architecture
  - `Plexus` remains as a deprecated type alias for backwards compatibility
  - Will be removed in a future major version
  - Rationale: "Plexus" implied special infrastructure, when it's actually just an `Activation` with dynamic registration
  - See architecture documentation for migration guide

### Migration Guide

Replace `Plexus::new()` with `DynamicHub::new(namespace)`:

```rust
// Before
use hub_core::plexus::Plexus;
let hub = Plexus::new().register(activation);

// After
use hub_core::plexus::DynamicHub;
let hub = DynamicHub::new("myapp").register(activation);
```

Choose a namespace that identifies your application:
- "substrate" for substrate server
- "hub" for generic hubs
- "myapp" for your application name

The `Plexus` type alias will continue to work but will show deprecation warnings.
The old `with_namespace()` method is deprecated in favor of `new(namespace)`.

## [0.2.1] - Previous releases

See git history for earlier changes.
