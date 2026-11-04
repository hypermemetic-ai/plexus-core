# Changelog

All notable changes to plexus-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (RETURNS-40: the service writes its IR)

- `plexus::ir` — synapse's IR 3.0 builder in Rust (`build`, `build_one`, `canonical`), equal to synapse's `buildIRFromSchemas` / `buildIRFromSchema` byte for byte in synapse's canonical form, refusals and title collisions included.
- `<service>.ir { namespaces? }` on every `DynamicHub` — one IR document for the namespaces asked (none: the whole service), as the caller's view shows it; `Result<ServiceIr, IrError>` (`title_collision`, `not_found`, `unreadable`); kept per (the hash the caller sees, the namespaces). Introspection for the grant gate: it runs for anyone, as `schema` does. `DynamicHub::service_ir` is the same in process. The root's schema lists `ir`, so every service's hash moves once.

### [0.8.0] — unreleased (RETURNS-36: precise returns over main)

returns/0.7 (RETURNS-1) merged with main. Publish nothing until RETURNS-29.

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
