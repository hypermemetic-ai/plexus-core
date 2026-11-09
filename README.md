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

## License

AGPL-3.0-only
