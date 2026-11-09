//! VISION-5 · a service with no listening port: it dials a relay, signs in
//! with its key, offers its `greeter` activation on that one socket and is
//! mounted there as `peers.<name>` while the socket lives. Through the same
//! socket it calls the other peers (`greeter ask`).
//!
//! ```sh
//! cargo run --example peer -- --name alice --expose ws://127.0.0.1:4741/ws --key ~/.plexus/keys/alice.key --trust "$(synapse _key show relay)"
//! cargo run --example peer -- --name bob   --expose ws://127.0.0.1:4741/ws --key ~/.plexus/keys/bob.key --trust "$(synapse _key show relay)"
//! synapse --url ws://127.0.0.1:4741/ws relay peers alice ask --peer bob --name carol
//! ```

use std::time::Duration;

use async_stream::stream;
use futures::{Stream, StreamExt};
use plexus_core::plexus::remote_child::{DialOut, DialState, Exposed};
use plexus_core::plexus::PlexusStreamItem;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// What a greeter says.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Said {
    /// A greeting, and who it greets on whose behalf.
    Greeting { text: String, from: String, caller: Option<String> },
    /// What another peer said, reached through the relay.
    Relayed { peer: String, said: serde_json::Value },
    /// Where this service stands.
    State { name: String, principal: String, state: serde_json::Value },
    /// The relay refused, or the peer is gone.
    Failed { message: String },
}

/// The greeter: one activation, served on the socket it dialed.
#[derive(Clone)]
pub struct GreeterActivation {
    name: String,
    exposed: Exposed,
}

fn caller() -> Option<String> {
    let c = plexus_core::call::caller().ok()?;
    c.auth().and_then(|a| a.principal()).map(|p| p.to_string())
}

#[plexus_macros::activation(crate_path = "plexus_core", version = "0.1.0", description = "A greeter behind no listening port, reached through a relay")]
impl GreeterActivation {
    /// Greet someone, saying who asked.
    #[plexus_macros::method(params(name = "Whom to greet"))]
    async fn hello(&self, name: String) -> impl Stream<Item = Said> + Send + 'static {
        let from = self.name.clone();
        let caller = caller();
        stream! {
            yield Said::Greeting { text: format!("hello {name}, from {from}"), from, caller };
        }
    }

    /// Ask another peer at the relay to greet someone: a call out over this
    /// service's own socket, as its key, through the relay's gate.
    #[plexus_macros::method(params(peer = "The peer's mount name at the relay", name = "Whom it should greet"))]
    async fn ask(&self, peer: String, name: String) -> impl Stream<Item = Said> + Send + 'static {
        let exposed = self.exposed.clone();
        stream! {
            let mut items = exposed.call(&format!("peers.{peer}.hello"), json!({ "name": name })).await;
            while let Some(item) = items.next().await {
                match item {
                    PlexusStreamItem::Data { content, .. } => yield Said::Relayed { peer: peer.clone(), said: content.into_value() },
                    PlexusStreamItem::Error { message, .. } => yield Said::Failed { message },
                    _ => {}
                }
            }
        }
    }

    /// This service: its mount name, its key's principal, its socket's state.
    #[plexus_macros::method]
    async fn whoami(&self) -> impl Stream<Item = Said> + Send + 'static {
        let (name, principal) = (self.name.clone(), self.exposed.principal().unwrap_or_default());
        let state = serde_json::to_value(self.exposed.state()).unwrap_or_default();
        stream! { yield Said::State { name, principal, state }; }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "plexus::dial=info,warn".into())).init();
    let (mut name, mut url, mut key, mut trust) = (None, None, None, None);
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyhow::anyhow!("{flag} takes a value"));
        match flag.as_str() {
            "--name" => name = Some(value()?),
            "--expose" => url = Some(value()?),
            "--key" => key = Some(value()?),
            "--trust" => trust = Some(value()?),
            "-h" | "--help" => {
                println!("peer --name NAME --expose ws://RELAY/ws --key FILE --trust RELAY_KEY (key:<64 hex>, which the relay proves)");
                return Ok(());
            }
            other => anyhow::bail!("unknown flag {other} (--help)"),
        }
    }
    let name = name.ok_or_else(|| anyhow::anyhow!("--name NAME"))?;
    let url = url.ok_or_else(|| anyhow::anyhow!("--expose ws://RELAY/ws"))?;
    let home = std::env::var("HOME").unwrap_or_default();
    let key = key.unwrap_or_else(|| format!("~/.plexus/keys/{name}.key"));
    let key = key.strip_prefix("~/").map(|r| format!("{home}/{r}")).unwrap_or(key);

    let mut opts = DialOut::new(url.clone(), key).mount(name.clone()).agent(name.clone());
    if let Some(t) = trust {
        opts = opts.trust(t);
    }
    let exposed = Exposed::new(opts);
    println!("{name}: {} — no listening port; dialing {url}", exposed.principal().map_err(anyhow::Error::msg)?);
    exposed.serve(GreeterActivation { name: name.clone(), exposed: exposed.clone() });
    let mut states = exposed.watch();
    loop {
        let s = states.borrow_and_update().clone();
        match &s {
            DialState::Mounted { path, relay, .. } => println!("{name}: mounted at the relay as {path} (relay {relay})"),
            DialState::Down { why } => println!("{name}: down — {why}"),
            DialState::Refused { why } => {
                println!("{name}: refused — {why}");
                std::process::exit(2);
            }
            _ => {}
        }
        tokio::select! {
            r = states.changed() => if r.is_err() { break },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    exposed.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}
