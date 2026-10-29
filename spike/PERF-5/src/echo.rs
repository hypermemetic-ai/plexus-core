//! The echo service: one activation, `bench`, built with
//! `#[plexus_macros::activation]` the way menger's are, behind the house's
//! grant gate, served by plexus-transport's WebSocket.
//!
//! - `bench.once` — one item shaped like `tickets.health`, then done.
//! - `bench.count --to N --size S` — N items carrying S bytes each, then done.
//! - `bench.stats` — the process's allocation counters and the runtime's
//!   spawned-task count, for the client to diff around a run.

use std::sync::Arc;

use async_stream::stream;
use futures::Stream;
use plexus_core::plexus::{AuthContext, Gate, MemoryMemberships, Resolve, RoleTable, ScopeRef, SessionValidator};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};

/// A pad shared by every item of a call (no per-item copy of the payload in
/// the method: what is measured is the framework's cost per item).
#[derive(Clone, Debug, JsonSchema, Deserialize)]
#[schemars(transparent)]
pub struct Pad(#[serde(deserialize_with = "de_pad")] Arc<str>);

fn de_pad<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Arc<str>, D::Error> {
    Ok(Arc::from(String::deserialize(d)?))
}

impl Serialize for Pad {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BenchEvent {
    /// `tickets.health`'s shape.
    Health { version: String, unix_now: i64, ticket_count: u64 },
    Item { n: u64, pad: Pad },
    Stats { allocs: u64, reallocs: u64, frees: u64, bytes: u64, spawned_tasks: u64, workers: u64 },
    Error { message: String },
}

impl plexus_client::FromClientError for BenchEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        BenchEvent::Error { message: error.to_string() }
    }
}

#[derive(Clone)]
pub struct BenchActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "PERF-5's echo service",
    roles(viewer = ["once", "count", "stats"]),
)]
impl BenchActivation {
    /// One item, `tickets.health`'s shape.
    #[plexus_macros::method]
    pub async fn once(&self) -> impl Stream<Item = BenchEvent> + Send + 'static {
        futures::stream::once(async move {
            BenchEvent::Health { version: "0.6.2".to_string(), unix_now: 1_793_258_669, ticket_count: 1518 }
        })
    }

    /// `to` items of `size` bytes each.
    #[plexus_macros::method(streaming)]
    pub async fn count(&self, to: u64, size: u64) -> impl Stream<Item = BenchEvent> + Send + 'static {
        let pad = Pad(Arc::from("x".repeat(size as usize)));
        stream! { for n in 0..to { yield BenchEvent::Item { n, pad: pad.clone() }; } }
    }

    /// The process's allocation counters and the runtime's spawned tasks.
    #[plexus_macros::method]
    pub async fn stats(&self) -> impl Stream<Item = BenchEvent> + Send + 'static {
        let s = crate::alloc::snapshot();
        let m = tokio::runtime::Handle::current().metrics();
        let (spawned, workers) = (m.spawned_tasks_count(), m.num_workers() as u64);
        futures::stream::once(async move {
            BenchEvent::Stats { allocs: s.allocs, reallocs: s.reallocs, frees: s.frees, bytes: s.bytes, spawned_tasks: spawned, workers }
        })
    }
}

/// The one principal the bench signs in as: viewer on `*`.
pub const BENCH_PRINCIPAL: &str = "key:5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

/// Every target resolves to `*` alone.
pub struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

pub fn plain_service() -> DynamicHub {
    DynamicHub::new("perf5").register(BenchActivation)
}

/// The service as menger runs one: every call through the grant gate.
pub fn gated_service() -> DynamicHub {
    let declared = plain_service().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = MemoryMemberships::new().with(BENCH_PRINCIPAL, "viewer", "*");
    let gate = Gate::new(Arc::new(members), Arc::new(roles), Arc::new(Everywhere));
    plain_service().with_gate(Arc::new(gate))
}

pub fn bench_auth() -> AuthContext {
    AuthContext::for_principal(&BENCH_PRINCIPAL.parse().unwrap(), "s1", vec![], serde_json::json!({}))
}

/// `Authorization: Bearer bench` → the bench principal.
pub struct BenchValidator;
#[async_trait::async_trait]
impl SessionValidator for BenchValidator {
    async fn validate(&self, token: &str) -> Option<AuthContext> {
        (token == "bench").then(bench_auth)
    }
}

pub fn bench_headers() -> Vec<(String, String)> {
    vec![("Authorization".into(), "Bearer bench".into())]
}

/// Serve `service` on `port` (0: any) through plexus-transport's WebSocket.
pub async fn serve(service: DynamicHub, port: u16, gated: bool) -> anyhow::Result<(jsonrpsee::server::ServerHandle, std::net::SocketAddr)> {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(service))?;
    let validator: Option<Arc<dyn SessionValidator>> = if gated { Some(Arc::new(BenchValidator)) } else { None };
    let opts = plexus_transport::websocket::UpgradeOptions { reject_on_session_failure: gated, ..Default::default() };
    plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(port), validator, opts).await
}
