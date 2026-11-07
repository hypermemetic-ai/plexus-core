//! NEST-7: a host with a typed peer slot and an untyped one, served on a
//! WebSocket — `cargo run --example nest7_host -- PORT`, then
//!
//! ```sh
//! synapse -P PORT svc host integrations
//! synapse -P PORT svc host integration github repos
//! synapse -P PORT svc host integration remote repo --name plexus-core
//! synapse -P PORT svc host integration ghost repos     # not_grafted
//! synapse -P PORT svc garden dendrite greeter hello --name world
//! ```
//!
//! `remote` is the forge contract's client over a `PeerTransport` (here an
//! in-process transport to a second `GitHub`, checked against its stamp);
//! `github` is the local implementation, served.

use std::sync::Arc;

use async_stream::stream;
use futures::Stream;
use plexus_client::BoxFuture;
use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::InProcessTransport;
use plexus_core::DynamicHub;
use plexus_transport::TransportServer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod forge {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    pub struct Repo {
        pub name: String,
    }

    /// Why a forge said no — or could not be reached.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ForgeError {
        Denied { why: String },
        Peer { error: PeerError },
    }

    impl From<PeerError> for ForgeError {
        fn from(error: PeerError) -> Self {
            ForgeError::Peer { error }
        }
    }

    /// A forge: repositories.
    #[plexus_macros::activation(crate_path = "plexus_core")]
    impl ForgeActivation {
        /// Every repository.
        #[plexus_macros::method]
        pub async fn repos(&self) -> Result<Vec<Repo>, ForgeError>;

        /// One repository.
        #[plexus_macros::method]
        pub async fn repo(&self, name: String) -> Result<Repo, ForgeError>;
    }
}

use forge::{Forge, ForgeClient, ForgeError, ForgePeer, Repo};

/// A local forge, written by hand.
#[derive(Clone)]
struct GitHub;

impl Forge for GitHub {
    fn repos(&self) -> BoxFuture<'static, Result<Vec<Repo>, ForgeError>> {
        Box::pin(async { Ok(vec![Repo { name: "plexus-core".into() }, Repo { name: "menger".into() }]) })
    }

    fn repo(&self, name: String) -> BoxFuture<'static, Result<Repo, ForgeError>> {
        Box::pin(async move { Ok(Repo { name }) })
    }
}

type Make = Arc<dyn Fn() -> Box<dyn ForgePeer> + Send + Sync>;

#[derive(Clone)]
pub struct HostActivation {
    remote: Make,
}

/// A host with a typed graft point.
#[plexus_macros::activation(namespace = "host", crate_path = "plexus_core")]
impl HostActivation {
    /// The integrations' names.
    pub async fn integrations(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { for n in ["github", "remote"] { yield n.to_string(); } }
    }

    /// A typed peer: whatever is returned is a Forge.
    #[plexus_macros::peer(list = "integrations")]
    async fn integration(&self, name: &str) -> Result<Box<dyn ForgePeer>, PeerError> {
        match name {
            "github" => Ok(Box::new(GitHub.server())),
            "remote" => Ok((self.remote)()),
            "ghost" => Err(PeerError::NotGrafted { at: "host.integration".into(), name: name.into(), interface: "forge".into() }),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

#[derive(Clone)]
pub struct GreeterActivation;

/// Says hello.
#[plexus_macros::activation(crate_path = "plexus_core")]
impl GreeterActivation {
    /// Hello.
    pub async fn hello(&self, name: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("hello, {name}"); }
    }
}

#[derive(Clone)]
pub struct GardenActivation;

/// A garden of dendrites: an untyped graft point.
#[plexus_macros::activation(namespace = "garden", crate_path = "plexus_core")]
impl GardenActivation {
    /// The dendrites' names.
    pub async fn dendrites(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "greeter".to_string(); }
    }

    /// An untyped peer: any activation.
    #[plexus_macros::peer(list = "dendrites")]
    async fn dendrite(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match name {
            "greeter" => Ok(Box::new(GreeterActivation)),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: nest7_host PORT"))?.parse()?;
    let remote = ForgeClient::peer(InProcessTransport::new(GitHub.server())).await?;
    let host = HostActivation { remote: Arc::new(move || Box::new(remote.clone()) as Box<dyn ForgePeer>) };
    let service = Arc::new(DynamicHub::new("svc").register(host).register(GardenActivation));
    TransportServer::builder(service, |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_allowed_hosts([format!("127.0.0.1:{port}"), format!("localhost:{port}")])
        .build()
        .await?
        .serve()
        .await
}
