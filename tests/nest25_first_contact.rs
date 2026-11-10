//! NEST-25 · first contact, the way ssh does it, on the dial-out and the
//! dial-in: the node pins the host's key once a person says yes (its known
//! hosts), a host presenting another key later is refused unasked, both ends
//! derive one pairing code, and a host may hold an offer pending — nothing
//! mounted, the node told only "pending". Ports 4760–4779.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_stream::stream;
use futures::Stream;
use plexus_auth_core::adapters::{Carriers, KeyProofAdapter};
use plexus_auth_core::identity::AuthenticatorChain;
use plexus_core::plexus::remote_child::{key_principal, Admission, Decision, DialOut, DialState, Exposed, FirstContact, Offer, OfferRefused, PeerSocket, Peers, RemoteChild};
use plexus_core::plexus::AuthContext;
use plexus_core::DynamicHub;
use plexus_transport::ws::{ConnectionHook, Hooks, Outbound};
use plexus_transport::TransportServer;
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct GreeterActivation;

#[plexus_macros::activation(crate_path = "plexus_core", version = "0.1.0", description = "a greeter behind no port")]
impl GreeterActivation {
    /// Greet.
    #[plexus_macros::method]
    async fn hello(&self, name: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("hello {name}"); }
    }
}

struct Hook(Arc<PeerSocket>);
impl ConnectionHook for Hook {
    fn on_frame(&self, frame: &[u8]) -> bool {
        self.0.on_frame(frame)
    }
    fn on_close(&self) {
        self.0.on_close()
    }
}

fn port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(4760);
    loop {
        let p = NEXT.fetch_add(1, Ordering::SeqCst);
        assert!(p <= 4779, "no port left in 4760–4779");
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

fn key(dir: &std::path::Path, name: &str, seed: u8) -> (std::path::PathBuf, String) {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("{name}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([seed; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let p = key_principal(&path).unwrap();
    (path, p)
}

/// What the host's admission saw, and how it answers.
#[derive(Default)]
struct Seen {
    offers: Mutex<Vec<Offer>>,
    /// Hold every offer until this is sent.
    hold: Mutex<Option<oneshot::Receiver<()>>>,
}

struct Recording(Arc<Seen>);
impl Admission for Recording {
    fn decide(&self, offer: &Offer) -> Decision {
        self.0.offers.lock().unwrap().push(offer.clone());
        match self.0.hold.lock().unwrap().take() {
            Some(rx) => Decision::Pending(Box::pin(async move { rx.await.map_err(|_| OfferRefused::new("refused", "let go")) })),
            None => Decision::Admit,
        }
    }
    fn vet(&self, _: &Offer, _: &RemoteChild) -> Result<(), OfferRefused> {
        Ok(())
    }
    fn mounted(&self, _: &Offer, _: &RemoteChild, _: &Arc<PeerSocket>) {}
    fn closed(&self, _: u64, _: Option<&str>, _: &str) {}
}

struct Relay {
    url: String,
    principal: String,
    peers: Peers,
    seen: Arc<Seen>,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// A relay proving a key of `seed`, its offers decided by a recording admission.
async fn relay(seed: u8) -> Relay {
    let port = port();
    let key = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]);
    let principal = key.kid().to_string();
    let seen = Arc::new(Seen::default());
    let peers = Peers::new("peers", "relay", "service:relay").with_timeout(Duration::from_secs(5)).with_key(key).with_admission(Arc::new(Recording(seen.clone())));
    let service = Arc::new(DynamicHub::new("relay"));
    let url = format!("ws://127.0.0.1:{port}/ws");
    let keys = KeyProofAdapter::new([url.clone()].iter()).unwrap();
    let chain = Carriers::cookie_and_bearer(AuthenticatorChain::new().with(Arc::new(keys)));
    let for_hook = peers.clone();
    let hooks = Hooks::new(move |conn, ext| {
        let auth = ext.get::<Arc<AuthContext>>().map(|a| (**a).clone());
        let writer = conn.writer()?;
        let (socket, mut out) = for_hook.socket_from(auth, Some(conn.peer().to_string()), None);
        tokio::spawn(async move {
            while let Some(f) = out.recv().await {
                if writer.send(Outbound::Text(String::from_utf8(f).unwrap())).await.is_err() {
                    break;
                }
            }
        });
        Some(Arc::new(Hook(socket)) as Arc<dyn ConnectionHook>)
    });
    let server = TransportServer::builder(Arc::clone(&service), |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_session_validator(Arc::new(chain))
        .reject_upgrade_on_auth_failure()
        .with_hooks(hooks)
        .with_allowed_hosts([format!("127.0.0.1:{port}")])
        .build()
        .await
        .unwrap();
    let serving = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Relay { url, principal, peers, seen, serving }
}

/// A node dialing `relay` with first contact on `hosts`, answering `yes`, and what it was shown.
fn node(relay: &Relay, name: &str, key: &std::path::Path, hosts: &std::path::Path, yes: bool) -> (Exposed, Arc<Mutex<Vec<FirstContact>>>) {
    let shown = Arc::new(Mutex::new(Vec::new()));
    let said = shown.clone();
    let exposed = Exposed::new(DialOut::new(relay.url.clone(), key).mount(name).agent(name)).with_first_contact(hosts, move |c| {
        said.lock().unwrap().push(c);
        async move { yes }
    });
    exposed.serve(GreeterActivation);
    (exposed, shown)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_contact_pins_the_hosts_key_once_a_person_says_yes() {
    let dir = tempfile::tempdir().unwrap();
    let (k, me) = key(dir.path(), "node", 1);
    let hosts = dir.path().join("plexus/known_hosts");
    let relay = relay(31).await;
    let (a, shown) = node(&relay, "alice", &k, &hosts, true);
    assert_eq!(a.mounted(Duration::from_secs(10)).await.unwrap(), "peers.alice");
    let said = shown.lock().unwrap().clone();
    assert_eq!(said.len(), 1, "asked once");
    assert_eq!(said[0].key, relay.principal);
    assert!(said[0].fingerprint.starts_with("SHA256:"), "{:?}", said[0]);
    let pinned = std::fs::read_to_string(&hosts).unwrap();
    assert_eq!(pinned.trim(), format!("{} {}", relay.url, relay.principal));
    // The host's code and the node's are one.
    let host_code = relay.seen.offers.lock().unwrap()[0].code.clone();
    assert!(host_code.is_some() && host_code == a.code(), "{host_code:?} / {:?}", a.code());
    assert!(relay.seen.offers.lock().unwrap()[0].key_proven, "the node's key signed this connection's nonces");
    assert_eq!(relay.seen.offers.lock().unwrap()[0].principal, me);
    a.stop();

    // Again: pinned, nobody asked.
    let (b, shown) = node(&relay, "alice", &k, &hosts, false);
    assert_eq!(b.mounted(Duration::from_secs(10)).await.unwrap(), "peers.alice");
    assert!(shown.lock().unwrap().is_empty(), "a pinned host is not asked about again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_contact_refuses_by_default_and_pins_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (k, _) = key(dir.path(), "node", 2);
    let hosts = dir.path().join("known_hosts");
    let relay = relay(32).await;
    let (a, shown) = node(&relay, "alice", &k, &hosts, false);
    let refused = a.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("first contact refused"), "{refused}");
    assert_eq!(shown.lock().unwrap().len(), 1);
    assert!(!hosts.exists(), "nothing pinned");
    assert!(relay.seen.offers.lock().unwrap().is_empty(), "nothing offered before the yes");
    assert!(relay.peers.names().is_empty());

    // A known-hosts file with no key for it, and nobody to ask: refused before dialing.
    let b = Exposed::new(DialOut::new(relay.url.clone(), &k).mount("bob")).with_known_hosts(&hosts);
    b.serve(GreeterActivation);
    let refused = b.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("no key is known"), "{refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_presenting_another_key_than_the_one_pinned_is_refused_unasked() {
    let dir = tempfile::tempdir().unwrap();
    let (k, _) = key(dir.path(), "node", 3);
    let hosts = dir.path().join("known_hosts");
    let relay = relay(33).await;
    // Pinned: a key the relay does not hold.
    let other = plexus_core::plexus::peer_token::PeerKey::from_seed([99; 32]).kid().to_string();
    plexus_core::plexus::remote_child::pairing::KnownHosts::new(&hosts).add(&relay.url, &other).unwrap();
    let (a, shown) = node(&relay, "alice", &k, &hosts, true);
    let refused = a.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("host_key_changed"), "{refused}");
    assert!(matches!(a.state(), DialState::Refused { .. }));
    assert!(shown.lock().unwrap().is_empty(), "a changed key is never asked about");
    assert!(relay.peers.names().is_empty() && relay.seen.offers.lock().unwrap().is_empty());
    assert!(std::fs::read_to_string(&hosts).unwrap().contains(&other), "the pin stands");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_offer_mounts_nothing_and_the_node_learns_only_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let (k, _) = key(dir.path(), "node", 4);
    let relay = relay(34).await;
    let (tx, rx) = oneshot::channel();
    *relay.seen.hold.lock().unwrap() = Some(rx);
    let a = Exposed::new(DialOut::new(relay.url.clone(), &k).trust(relay.principal.clone()).mount("alice"));
    a.serve(GreeterActivation);
    for _ in 0..200 {
        if a.pending().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let code = a.pending().expect("told pending");
    assert_eq!(Some(code.clone()), relay.seen.offers.lock().unwrap()[0].code, "one code on both sides");
    assert!(relay.peers.names().is_empty(), "nothing mounted while pending");
    assert!(matches!(a.state(), DialState::Connecting), "{:?}", a.state());
    tx.send(()).unwrap();
    assert_eq!(a.mounted(Duration::from_secs(10)).await.unwrap(), "peers.alice");
    assert_eq!(a.pending(), None);
}

/// A relay in the middle answering the node with a key of its own, and
/// offering to the host as itself: the node's code and the host's differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_swapping_keys_shows_each_side_another_code() {
    let dir = tempfile::tempdir().unwrap();
    let (k, _) = key(dir.path(), "node", 5);
    let (km, _) = key(dir.path(), "middle", 6);
    let host = relay(35).await;
    let middle = relay(36).await;
    // The middle reaches the host as itself (its own key, the host's pinned).
    let onward = Exposed::new(DialOut::new(host.url.clone(), &km).trust(host.principal.clone()).mount("alice"));
    onward.serve(GreeterActivation);
    onward.mounted(Duration::from_secs(10)).await.unwrap();
    // The node, at first contact, meets the middle.
    let (a, shown) = node(&middle, "alice", &k, &dir.path().join("known_hosts"), true);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let node_code = shown.lock().unwrap()[0].code.clone().unwrap();
    let host_code = host.seen.offers.lock().unwrap()[0].code.clone().unwrap();
    assert_ne!(node_code, host_code, "a key swapped in the middle shows in the code");
    assert_ne!(shown.lock().unwrap()[0].key, host.principal, "and in the key shown");
}
