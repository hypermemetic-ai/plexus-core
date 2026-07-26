# Changelog

All notable changes to hub-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PLX-102: a handler may mint only the capability set its method declares.**
  - `TurnContext::client<C: CapabilitySet>()` had `C` entirely free: a handler
    serving a method that declared `(FsRead,)` could write
    `turn.client::<(FsWrite,)>()` and get a working accessor. The callback then
    failed at the transport (the runtime pre-flight had checked the peer against
    the *declared* set), so this was a guarantee gap rather than a permission
    hole — but a runtime one, in a design whose point is that this class of
    mistake is a compile error. The guarantee was carried by a doc comment.
  - **BREAKING**: `TurnContext::client` is gone. A capability handle now comes
    from `Turn<C>::client()`, and the only way to obtain a `Turn<C>` is
    `runtime::DeclaredHandler`, which derives the method's `MethodIr::callbacks`
    *and* the handler's `Client<C>` from one `C` at one site. `turn.client()`
    infers the declared set; naming any other set fails to compile with a
    message that names both sets (`capability::Declares` +
    `#[diagnostic::on_unimplemented]`), pinned by
    `tests/ui/widened_capability_set.rs`.
  - Migration: `ErasedHandler::new(|input| { let c = input.turn.client::<C>(); .. })`
    plus `method.with_callbacks(Client::<C>::callbacks())` becomes
    `let h = DeclaredHandler::new::<C, _, _>(|input| { let c = input.turn.client(); .. });`
    with `h.declare(method)` and `h.into_handler()`. Handlers that issue no
    callbacks are unaffected.

- **PLX-101: `Cargo.lock` is now committed, and benchmarks print their resolution.**
  - `.gitignore` no longer ignores `Cargo.lock`. This crate's benchmarks are
    decision inputs (decision gate 2, PLX-88's attribution table), and until now
    every one of them was measured against a resolution nobody recorded.
  - Both bench binaries emit a resolution banner — lock fingerprint, toolchain,
    host, profile, and the perf-relevant resolved versions — before the first
    measurement, and write it to `target/criterion/resolution-<bench>.txt`. See
    `benches/common/resolution.rs`.
  - Committing the lock pins **only this crate's own** builds/tests/benches. The
    manifest still declares `tokio = "1.0"`; cargo ignores a dependency's lock,
    so nothing changes for consumers of `plexus-core`.
  - New `docs/benchmarking.md` records the finding that prompted this: a
    current-thread `block_on(yield_now())` costs 845 ns on tokio 1.49.0 and
    12,736 ns on tokio 1.50.0 (upstream tokio#7834), which is the whole of the
    5.3x `full_turn` cliff PLX-97 hit. Multi-thread is unaffected; no plexus
    verdict changes; PLX-88's attribution *percentages* are resolution-bound.

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
