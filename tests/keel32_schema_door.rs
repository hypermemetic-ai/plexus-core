//! KEEL-32 — every `….schema` is answered from the caller's view: a path the
//! view does not show is refused as not found, never routed past the gate,
//! and no dynamic child or peer is looked up for a name the caller chose
//! unless it holds that slot's grant. The service's own-namespace form
//! (`svc.vault.hidden.schema`) answers what the bare form
//! (`vault.hidden.schema`) does, for every caller.
//!
//! The review's probe (`schema_door.rs`, KEEL-28): anonymously, against a
//! gate that granted nothing, `svc.vault.hidden.schema` returned the hidden
//! child's schema and `svc.vault.<name>.schema` ran the slot's lookup with
//! the caller's name — for plexus-dyn, a redial of any registered peer.

use std::sync::{Arc, Mutex};

use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{PlexusError, PlexusStreamItem, RemoteError};
use plexus_testkit::{Caller, Host, NotFound, World, ADMIN, NOBODY, VIEWER};
use serde_json::{json, Value};

#[derive(Clone)]
struct LeafActivation {
    name: String,
}

/// An instance in the slot.
#[plexus_macros::activation(namespace = "leaf", version = "1.0.0")]
impl LeafActivation {
    /// Wipe it.
    #[plexus_macros::method]
    async fn wipe(&self, really_secret_param: String) -> Value {
        json!(format!("{} {really_secret_param}", self.name))
    }
}

#[derive(Clone)]
struct HiddenActivation;

/// A static child no role lists.
#[plexus_macros::activation(namespace = "hidden", version = "1.0.0")]
impl HiddenActivation {
    /// Rotate the master key.
    #[plexus_macros::method]
    async fn rotate_master_key(&self, new_key: String) -> Value {
        json!(new_key)
    }
}

/// Every name a slot of the vault was asked for.
type Asked = Arc<Mutex<Vec<String>>>;

#[derive(Clone)]
struct VaultActivation {
    asked: Asked,
}

/// A vault: `ping` the viewer's, the rest no role's.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0", roles(viewer = ["ping"]))]
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

    /// A dynamic child by name: counts every lookup.
    #[plexus_macros::child]
    fn item(&self, name: &str) -> Option<LeafActivation> {
        self.asked.lock().unwrap().push(name.to_string());
        Some(LeafActivation { name: name.to_string() })
    }

    /// A peer slot: counts every lookup (dyn's `peer` dials here).
    #[plexus_macros::peer]
    async fn far(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.asked.lock().unwrap().push(format!("peer:{name}"));
        Err(PeerError::NotFound { name: name.into() })
    }
}

/// Holds the dynamic slot's method (`vault.{item}.wipe`) and nothing else.
const SLOTTER: &str = "key:5151515151515151515151515151515151515151515151515151515151515151";
/// Holds the hidden child's method alone.
const KEEPER: &str = "key:4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";

async fn host() -> (Host, Asked) {
    let asked: Asked = Arc::default();
    let host = World::new()
        .host()
        .named("svc")
        .with(VaultActivation { asked: asked.clone() })
        .role("slotter", ["vault.{item}.wipe"])
        .role("keeper", ["vault.hidden.rotate_master_key"])
        .member(SLOTTER, "slotter")
        .member(KEEPER, "keeper")
        .await;
    (host, asked)
}

/// Every path the probe walked, bare; each is asked in both forms.
const DOORS: [&str; 9] = [
    "vault.hidden.schema",
    "vault.hidden.rotate_master_key.schema",
    "vault.item.attacker-name.schema",
    "vault.attacker2.schema",
    "vault.attacker2.wipe.schema",
    "vault.far.attacker3.schema",
    "vault.far.attacker4.x.schema",
    "vault.far.schema",
    "vault.item.schema",
];

fn both(bare: &str) -> [String; 2] {
    [bare.to_string(), format!("svc.{bare}")]
}

#[tokio::test]
async fn a_path_the_view_does_not_show_is_not_found_and_nothing_is_looked_up() {
    let (host, asked) = host().await;
    for caller in [host.anonymous(), host.as_(NOBODY), host.as_(VIEWER)] {
        for door in DOORS {
            for m in both(door) {
                caller.call(&m, json!({})).await.refused(NotFound);
            }
        }
    }
    assert_eq!(*asked.lock().unwrap(), Vec::<String>::new(), "a lookup ran for a name the caller chose");
}

#[tokio::test]
async fn a_slot_is_looked_up_only_for_a_caller_holding_its_grant() {
    let (host, asked) = host().await;
    // Holds `vault.{item}.wipe`: the dynamic slot answers its instance.
    let leaf: Value = host.as_(SLOTTER).call("svc.vault.box1.schema", json!({})).await.answer();
    assert_eq!(leaf["namespace"], "leaf", "{leaf}");
    assert_eq!(*asked.lock().unwrap(), ["box1"]);
    // ... but not the peer slot, whose grant it does not hold.
    host.as_(SLOTTER).call("svc.vault.far.p1.schema", json!({})).await.refused(NotFound);
    host.as_(SLOTTER).call("vault.far.p1.schema", json!({})).await.refused(NotFound);
    assert_eq!(*asked.lock().unwrap(), ["box1"]);
    // An admin holds every slot: the peer is looked up (and is not there).
    let _ = host.as_(ADMIN).call("vault.far.p2.schema", json!({})).await;
    assert_eq!(*asked.lock().unwrap(), ["box1", "peer:p2"]);
}

#[tokio::test]
async fn a_static_child_is_shown_to_the_caller_holding_a_method_in_it() {
    let (host, asked) = host().await;
    for m in both("vault.hidden.schema") {
        let hidden: Value = host.as_(KEEPER).call(&m, json!({})).await.answer();
        assert_eq!(hidden["namespace"], "hidden", "{m}: {hidden}");
    }
    for m in both("vault.hidden.rotate_master_key.schema") {
        let method: Value = host.as_(KEEPER).call(&m, json!({})).await.answer();
        assert_eq!(method["name"], "rotate_master_key", "{m}: {method}");
    }
    // Holding it shows that child, not the slots beside it.
    for m in both("vault.attacker.schema") {
        host.as_(KEEPER).call(&m, json!({})).await.refused(NotFound);
    }
    assert!(asked.lock().unwrap().is_empty());
}

/// What a call said, to compare two: each data item's content, or the
/// refusal as its typed error and message.
async fn said(caller: &Caller, method: &str) -> String {
    use futures::StreamExt;
    match caller.stream(method, json!({})).await {
        Err(e) => format!("refused {:?}: {}", RemoteError::from(&e), e),
        Ok(s) => {
            let items: Vec<PlexusStreamItem> = s.collect().await;
            let shown: Vec<String> = items
                .into_iter()
                .filter_map(|i| match i {
                    PlexusStreamItem::Data { content, .. } => Some(content.into_value().to_string()),
                    PlexusStreamItem::Error { message, .. } => Some(format!("error {message}")),
                    _ => None,
                })
                .collect();
            shown.join("\n")
        }
    }
}

#[tokio::test]
async fn the_own_namespace_form_answers_what_the_bare_form_does() {
    let (host, _) = host().await;
    let callers =
        [host.anonymous(), host.as_(NOBODY), host.as_(VIEWER), host.as_(SLOTTER), host.as_(KEEPER), host.as_(ADMIN)];
    let mut paths: Vec<&str> = vec!["vault.schema", "vault.ping.schema", "vault.nope.schema", "nope.schema", "vault.box9.wipe.schema"];
    paths.extend(DOORS);
    for caller in &callers {
        for bare in &paths {
            let [b, own] = both(bare);
            assert_eq!(said(caller, &b).await, said(caller, &own).await, "{bare} and its own-namespace form differ");
        }
    }
}

#[tokio::test]
async fn legitimate_introspection_still_answers() {
    let (host, _) = host().await;
    // The service's own schema and methods, to anyone.
    let own: Value = host.anonymous().call("svc.schema", json!({})).await.answer();
    assert_eq!(own["namespace"], "svc");
    let call: Value = host.anonymous().call("svc.call.schema", json!({})).await.answer();
    assert_eq!(call["name"], "call", "{call}");
    // A viewer: the vault and its one method.
    let vault: Value = host.as_(VIEWER).call("vault.schema", json!({})).await.answer();
    assert_eq!(vault["namespace"], "vault");
    let ping: Value = host.as_(VIEWER).call("svc.vault.ping.schema", json!({})).await.answer();
    assert_eq!(ping["name"], "ping");
    // An admin: every path.
    let leaf: Value = host.as_(ADMIN).call("svc.vault.box2.wipe.schema", json!({})).await.answer();
    assert_eq!(leaf["name"], "wipe", "{leaf}");
    let _: PlexusError = PlexusError::ActivationNotFound(String::new());
}
