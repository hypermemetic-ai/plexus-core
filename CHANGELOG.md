# Changelog

All notable changes to hub-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
