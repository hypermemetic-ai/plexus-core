//! VISION-5 · a relay: a Plexus service (namespace `relay`) whose `peers`
//! activation mounts each service that dials in and offers a surface
//! (spec/14), by name, for as long as its socket lives. Who is connected is
//! discovery: `relay peers list`, `relay peers watch`.
//!
//! ```sh
//! cargo run --example relay -- --port 4741 --key ~/.plexus/keys/relay.key \
//!     --member "$(synapse _key show builder)" --member key:… --member key:…
//! synapse --url ws://127.0.0.1:4741/ws relay peers list
//! synapse --url ws://127.0.0.1:4741/ws relay peers alice hello --name you
//! ```
//!
//! The relay's gate decides every call: a `--member` holds `peers.list`,
//! `peers.watch`, `peers.offer` (on any mount name) and every method of every
//! peer connected; `--admin` holds everything; `--everyone` makes every
//! signed-in key a member. Anyone else is refused, and an anonymous socket
//! sees the anonymous view.

use std::sync::Arc;

use plexus_auth_core::adapters::{Carriers, KeyProofAdapter};
use async_trait::async_trait;
use plexus_auth_core::identity::{AuthenticatorChain, Principal};
use plexus_auth_core::SessionValidator;
use plexus_core::plexus::remote_child::{key_principal, PeerSocket, Peers};
use plexus_core::plexus::{
    AuthContext, AuthSetup, Gate, Membership, MembershipStore, Memberships, MemoryAuthBackend, MemoryMemberships, MemoryRoles, Resolve, ScopeRef, StoreError,
};
use plexus_core::DynamicHub;
use plexus_transport::ws::{ConnectionHook, Hooks, Outbound};
use plexus_transport::TransportServer;

const NS: &str = "relay";

struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

/// `--member`s and `--admin`s, each on `*`; with `--everyone`, every
/// signed-in principal a member too.
struct Members {
    listed: MemoryMemberships,
    everyone: bool,
}

impl Memberships for Members {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        let mut held = self.listed.held(who);
        if self.everyone {
            held.push(Membership { principal: who.clone(), role: plexus_auth_core::audit::RoleName::new("member"), scope: ScopeRef::Everywhere });
        }
        held
    }
}

/// `auth.grant` / `auth.revoke` edit the listed ones.
#[async_trait]
impl MembershipStore for Members {
    async fn grant(&self, membership: Membership) -> Result<(), StoreError> {
        self.listed.grant(membership).await
    }

    async fn revoke(&self, principal: &Principal, role: Option<&plexus_auth_core::RoleName>, scope: &ScopeRef) -> Result<Vec<plexus_auth_core::RoleName>, StoreError> {
        self.listed.revoke(principal, role, scope).await
    }
}

/// A socket signs in with a key proof (spec/00), or with a session the
/// `auth` activation minted on one (`synapse _login relay --key NAME`).
struct Credentials {
    sessions: Arc<MemoryAuthBackend>,
    keys: Carriers,
}

#[async_trait]
impl SessionValidator for Credentials {
    async fn validate(&self, credential: &str) -> Option<AuthContext> {
        match self.sessions.validate(credential).await {
            Some(ctx) => Some(ctx),
            None => self.keys.validate(credential).await,
        }
    }

    fn alive(&self, ctx: &AuthContext) -> Result<(), String> {
        SessionValidator::alive(self.sessions.as_ref(), ctx)
    }
}

/// The transport's hook on each socket: [`PeerSocket`] reads it first.
struct Hook(Arc<PeerSocket>);

impl ConnectionHook for Hook {
    fn on_frame(&self, frame: &[u8]) -> bool {
        self.0.on_frame(frame)
    }

    fn on_close(&self) {
        self.0.on_close()
    }
}

struct Args {
    port: u16,
    key: Option<String>,
    members: Vec<String>,
    admins: Vec<String>,
    everyone: bool,
    public_url: Vec<String>,
}

fn args() -> anyhow::Result<Args> {
    let mut a = Args { port: 4741, key: None, members: vec![], admins: vec![], everyone: false, public_url: vec![] };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyhow::anyhow!("{flag} takes a value"));
        match flag.as_str() {
            "--port" => a.port = value()?.parse()?,
            "--key" => a.key = Some(value()?),
            "--member" => a.members.push(value()?),
            "--admin" => a.admins.push(value()?),
            "--everyone" => a.everyone = true,
            "--public-url" => a.public_url.push(value()?),
            "-h" | "--help" => {
                println!("relay [--port 4741] [--key FILE] [--member PRINCIPAL]… [--admin PRINCIPAL]… [--everyone] [--public-url URL]…");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown flag {other} (--help)"),
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "plexus::peers=info,plexus::child=warn,warn".into())).init();
    let a = args()?;
    let port = a.port;
    let expand = |p: &str| p.strip_prefix("~/").map(|r| format!("{}/{r}", std::env::var("HOME").unwrap_or_default())).unwrap_or_else(|| p.to_string());
    let principal = match &a.key {
        Some(k) => key_principal(std::path::Path::new(&expand(k))).map_err(anyhow::Error::msg)?,
        None => format!("service:{NS}"),
    };

    let peers = Peers::new("peers", NS, principal.clone());
    let plain = DynamicHub::new(NS).register(peers.clone());
    let mut listed = MemoryMemberships::new();
    for m in &a.members {
        listed = listed.with(m, "member", "*");
    }
    for m in &a.admins {
        listed = listed.with(m, "admin", "*");
    }
    // The gate's roles: what the activations declare, and — for `member` —
    // `peers.list`, `peers.watch`, `peers.offer` and every method of every
    // peer connected, as the table stands at each call.
    let roles = Arc::new(peers.roles(MemoryRoles::from_declared(&plain.declared_roles()), Some("member")));
    let members = Arc::new(Members { listed, everyone: a.everyone });
    let sessions = Arc::new(MemoryAuthBackend::new(format!("http://127.0.0.1:{port}/login")));
    let service = plain.with_auth(AuthSetup::new(sessions.clone(), roles, members, Arc::new(Everywhere)));
    let gate: Arc<Gate> = Arc::clone(service.gate().expect("with_auth sets the gate"));
    peers.set_gate(gate);
    let service = Arc::new(service);
    // A peer mounted or gone: the next `schema` lists the peers as they stand.
    let weak = Arc::downgrade(&service);
    peers.on_change(move || {
        if let Some(s) = weak.upgrade() {
            s.schema_moved();
        }
    });

    // Every form a dialer's proof may name this socket by (spec/00's `aud`).
    let mut audiences: Vec<String> = ["127.0.0.1", "localhost"].iter().flat_map(|h| [format!("ws://{h}:{port}"), format!("ws://{h}:{port}/ws")]).collect();
    audiences.extend(a.public_url.iter().cloned());
    let keys = KeyProofAdapter::new(audiences.iter())?;
    let chain = Credentials { sessions, keys: Carriers::cookie_and_bearer(AuthenticatorChain::new().with(Arc::new(keys))) };

    let for_hook = peers.clone();
    let hooks = Hooks::new(move |conn, ext| {
        let auth = ext.get::<Arc<AuthContext>>().map(|a| (**a).clone());
        let writer = conn.writer()?;
        let (socket, mut out) = for_hook.socket(auth);
        tokio::spawn(async move {
            while let Some(frame) = out.recv().await {
                let text = String::from_utf8(frame).unwrap_or_default();
                if writer.send(Outbound::Text(text)).await.is_err() {
                    break;
                }
            }
        });
        Some(Arc::new(Hook(socket)) as Arc<dyn ConnectionHook>)
    });

    let hosts: Vec<String> = ["127.0.0.1", "localhost"].iter().map(|h| format!("{h}:{port}")).collect();
    println!("relay on ws://127.0.0.1:{port}/ws as {principal}");
    println!("  members: {}{}", a.members.join(", "), if a.everyone { " (and every signed-in key)" } else { "" });
    TransportServer::builder(service, |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_session_validator(Arc::new(chain))
        .anonymous_view()
        .reject_upgrade_on_auth_failure()
        .with_hooks(hooks)
        .with_allowed_hosts(hosts)
        .build()
        .await?
        .serve()
        .await
}
