//! KEEL-32 (third pass): a mounted child's schema request made **outside
//! any call** is answered as that child — its consented needs, the paths it
//! was mounted to read — never as the service with everything. Before it,
//! such a request was routed with no gate and a reach of everywhere: a child
//! could read every hidden schema and make a dynamic or peer slot look up a
//! name it chose (for plexus-dyn, redial any registered peer). A revoked
//! child is answered nothing.
//!
//! The child is `tests/fixtures/schema_asker.py`, on stdio: told to (`probe`)
//! it asks `_host.call {method}` with no `under`, and answers what came back;
//! it declares one need, `vault.box1.wipe`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{ChildOptions, ChildSpec, RemoteChild};
use plexus_testkit::{Host, World, ADMIN};
use serde_json::{json, Value};

#[derive(Clone)]
struct LeafActivation;

/// An instance.
#[plexus_macros::activation(namespace = "leaf", version = "1.0.0")]
impl LeafActivation {
    /// Wipe it.
    #[plexus_macros::method]
    async fn wipe(&self) -> Value {
        json!("wiped")
    }
}

#[derive(Clone)]
struct HiddenActivation;

/// No role lists it.
#[plexus_macros::activation(namespace = "hidden", version = "1.0.0")]
impl HiddenActivation {
    /// Rotate the master key.
    #[plexus_macros::method]
    async fn rotate_master_key(&self) -> Value {
        json!("rotated")
    }
}

type Asked = Arc<Mutex<Vec<String>>>;

#[derive(Clone)]
struct VaultActivation {
    asked: Asked,
}

/// A vault: a hidden child, a dynamic slot and a peer slot, each lookup counted.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0")]
impl VaultActivation {
    /// Ping.
    #[plexus_macros::method]
    async fn ping(&self) -> Value {
        json!("pong")
    }

    /// The hidden child.
    #[plexus_macros::child]
    fn hidden(&self) -> HiddenActivation {
        HiddenActivation
    }

    /// A dynamic child by name.
    #[plexus_macros::child]
    fn item(&self, name: &str) -> Option<LeafActivation> {
        self.asked.lock().unwrap().push(name.to_string());
        Some(LeafActivation)
    }

    /// A peer by name (dyn's `peer` dials here).
    #[plexus_macros::peer]
    async fn far(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.asked.lock().unwrap().push(format!("peer:{name}"));
        Err(PeerError::NotFound { name: name.into() })
    }
}

async fn mounted() -> (Host, RemoteChild, Asked) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema_asker.py");
    let spec = ChildSpec::Stdio { name: "py".into(), argv: vec!["python3".into(), "-I".into(), fixture.to_string_lossy().into_owned()] };
    let child = RemoteChild::connect(spec, ChildOptions::for_service("svc")).await.expect("the asker mounts");
    let asked: Asked = Arc::default();
    let host = World::new().host().named("svc").with(VaultActivation { asked: asked.clone() }).with(child.clone()).await;
    (host, child, asked)
}

/// What the child got when it asked `ask` outside any call.
async fn probe(host: &Host, ask: &str) -> Value {
    host.as_(ADMIN).call("py.probe", json!({ "ask": ask })).await.answer()
}

fn refused(v: &Value) -> bool {
    v.get("refused").is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_child_reads_only_the_schemas_it_needs() {
    let (host, _child, asked) = mounted().await;
    // Another peer's schema, a name in a dynamic slot it does not need, a
    // hidden child: not found, and nothing looked up.
    let mut answered: Vec<&str> = vec![];
    for ask in ["vault.far.p1.schema", "svc.vault.far.p1.schema", "vault.far.p2.x.schema", "vault.zz.schema", "svc.vault.zz.leaf.schema", "vault.hidden.schema", "vault.hidden.rotate_master_key.schema", "nope.schema"] {
        if !refused(&probe(&host, ask).await) {
            answered.push(ask);
        }
    }
    let looked_up = asked.lock().unwrap().clone();
    assert_eq!((answered, looked_up), (vec![], vec![]), "answered a child that does not need them; looked up names it chose");
    // What it needs, and the paths above it: answered (its need's instance
    // looked up, once).
    let need = probe(&host, "vault.box1.schema").await;
    assert_eq!(need["answered"]["namespace"], "leaf", "{need}");
    let method = probe(&host, "vault.box1.wipe.schema").await;
    assert_eq!(method["answered"]["name"], "wipe", "{method}");
    let vault = probe(&host, "vault.schema").await;
    assert_eq!(vault["answered"]["namespace"], "vault", "{vault}");
    // The standard interface: the service's own schema.
    let own = probe(&host, "host.schema").await;
    assert_eq!(own["answered"]["namespace"], "svc", "{own}");
    assert!(asked.lock().unwrap().iter().all(|n| n == "box1"), "{:?}", asked.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_child_is_answered_no_schema() {
    let (host, child, asked) = mounted().await;
    // Not revoked, asking on its own (no call open): its need is looked up.
    host.as_(ADMIN).call("py.later", json!({ "ask": "vault.box1.schema", "ms": 50 })).await.answers(1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = asked.lock().unwrap().len();
    assert!(before >= 1, "the unrevoked child's own ask was answered");
    // Revoked while its ask is pending: nothing is looked up for it.
    host.as_(ADMIN).call("py.later", json!({ "ask": "vault.box1.schema", "ms": 300 })).await.answers(1);
    child.revoke("a test");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(asked.lock().unwrap().len(), before, "a revoked child's schema ask was routed");
}

/// R3-1: mounted by hand and held between its handshake and any consent —
/// the gap dyn's `vet`, key and pin checks open before `hold`. The vault is
/// the child's service from the start (`with_host`); the child is never
/// registered. Once `connect` has returned (its needs are known), the test
/// lets it ask `ask` on its own, outside any call, and reads what it got.
async fn held_ask(opts: impl FnOnce(ChildOptions) -> ChildOptions, ask: &str) -> (RemoteChild, Value, Asked) {
    let asked: Asked = Arc::default();
    let service = Arc::new(plexus_core::DynamicHub::new("svc").register(VaultActivation { asked: asked.clone() }));
    let dir = tempfile::tempdir().unwrap();
    let (when, out) = (dir.path().join("when"), dir.path().join("out"));
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema_asker.py");
    let argv = vec!["python3".into(), "-I".into(), fixture.to_string_lossy().into_owned(), when.to_string_lossy().into_owned(), ask.into(), out.to_string_lossy().into_owned()];
    let spec = ChildSpec::Stdio { name: "py".into(), argv };
    let child = RemoteChild::connect(spec, opts(ChildOptions::for_service("svc").with_host(&service))).await.expect("the asker mounts");
    std::fs::write(&when, "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !out.exists() {
        assert!(std::time::Instant::now() < deadline, "the child's ask was never answered");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let got = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    (child, got, asked)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_need_counts_for_nothing_until_consent_is_applied() {
    let (child, got, asked) = held_ask(|o| o.with_consent_required(true), "vault.box1.schema").await;
    assert!(refused(&got), "a declared, unconsented need was answered: {got}");
    assert_eq!(*asked.lock().unwrap(), Vec::<String>::new(), "a lookup ran before consent was applied");
    drop(child);
    // The control: a plain mount (no consent kept, R3-2 as it was) answers
    // the same ask, so the refusal above is the held consent's.
    let (_child, got, _) = held_ask(|o| o, "vault.box1.schema").await;
    assert_eq!(got["answered"]["namespace"], "leaf", "{got}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_child_mounted_revoked_looks_nothing_up_from_its_first_ask() {
    // A plain mount (no consent kept: its declared need would count), but
    // mounted revoked — dyn's remount of a revoked peer.
    let (_child, got, asked) = held_ask(|o| o.with_revoked(Some("an admin revoked it".into())), "vault.box1.schema").await;
    assert!(refused(&got), "a revoked child was answered: {got}");
    assert_eq!(*asked.lock().unwrap(), Vec::<String>::new(), "a revoked child's ask was routed");
}
