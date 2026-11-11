# Activations

An activation is a type that implements `Activation`: a namespace, a
version, a description, its methods and their schemas.
`#[plexus_macros::activation]` on an `impl` block writes that
implementation, the `ChildRouter` implementation, and a typed client.

## Hosting one

An activation is served by itself or registered on a service.

- `InProcessTransport::new(activation)` calls one activation in memory, with
  no service around it.
- `DynamicHub::new("name").register(activation)` puts it on a service, under
  its namespace. The service is an activation too: its own methods are
  `call`, `hash`, `hashes`, `ir` and `schema`.
- [plexus-transport](https://github.com/hypermemetic-ai/plexus-transport)'s
  `TransportServer::builder` takes any `Arc<A>` where `A: Activation`.

A service is for several activations under one name, a top level that
changes while it serves, or a gate. One activation needs none of it.

## Nesting

An activation routes to children through `ChildRouter`: `get_child(name)`
answers the child, and a call to `parent.child.method` runs the child's
method. `#[plexus_macros::child]` on a method that returns an activation
writes the route:

<!-- tests/hub_transport.rs -->
```rust
/// The commits that finished a ticket.
#[plexus_macros::child]
pub fn commits(&self) -> CommitsActivation {
    CommitsActivation
}
```

The generated client reaches it by the same path:
`tickets.commits().link(…)`.

## The two this crate ships

`src/activations/` holds two small activations:

- `health`: one method, `check`, with `Activation` and `ChildRouter` written
  by hand.
- `echo`: `EchoActivation`, written with `#[plexus_macros::activation]`,
  with a typed parameter.

## Handles

`Handle` is a reference to data an activation holds:
`{plugin_id}@{version}::{method}:meta[0]:meta[1]:…`.

## MCP

plexus-core has no MCP code and no `rmcp` dependency;
`tests/rmcp_boundary.rs` holds that.
[plexus-transport](https://github.com/hypermemetic-ai/plexus-transport)
serves a service over MCP with its `mcp` feature, and
[plexus-transport-mcp](https://github.com/hypermemetic-ai/plexus-transport-mcp)
is the bridge by itself.
