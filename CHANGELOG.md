# Changelog

All notable changes to plexus-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

| Change | Before | After | What to do |
|---|---|---|---|
| `plexus_core::mcp_bridge`, `plexus_core::PlexusMcpBridge` | public, on rmcp 0.12 | removed | Use `plexus-transport` with feature `mcp`: `with_mcp`, or `ActivationMcpBridge` for an rmcp `ServerHandler` |

### Removed

- The `rmcp` dependency. plexus-core no longer compiles an MCP stack, and
  `scripts/check-rmcp.sh`, run by `cargo test`, keeps it out.

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
