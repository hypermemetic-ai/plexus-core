# Changelog

All notable changes to plexus-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
