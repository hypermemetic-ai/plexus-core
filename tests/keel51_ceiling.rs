//! KEEL-51 · a session's ceiling holds on a peer's call back.
//!
//! An admin whose session is capped to `viewer@*` is refused `shop.items`
//! (no role but admin lists it) when it calls it itself. Through a peer it
//! may call — `garden.dendrite.<name>`, the viewer's — the peer's call back
//! to `shop.items` must be decided under that same ceiling, and refused:
//!
//! - a peer behind a mount (`restock` on stdio, its connection back), whose
//!   need `shop.items` is one more ceiling layer on the call's context;
//! - a peer in this process (`Restock` itself), whose parent is the
//!   service's own routing, as the caller.
//!
//! Until 0.11.3 the peer was handed the context its forward policy derived
//! (`identity_only` by default), which kept the principal and dropped the
//! metadata — the ceiling with it — so the call back ran as the whole admin.
//!
//! And a sign-in that ends while the call is open (AUTH-11: its
//! `expires_at`) ends what the peer may do on it: a call back made after the
//! end is refused, though the call it is made under was admitted.
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child on stdio.

use std::sync::OnceLock;
use std::time::Duration;

use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{AuthContext, ChildOptions, ChildSpec, Parent, RemoteChild};
use plexus_auth_core::auth::EXPIRES_AT_KEY;
use plexus_auth_core::grants::CEILING_KEY;
use plexus_testkit::{Caller, Host, World, ADMIN, VIEWER};
use serde_json::{json, Value};

// ------------------------------------------------------------------ the parent

pub mod shop {
    use super::*;

    #[derive(Clone)]
    pub struct Shop;

    /// The shop. No role lists `items`: only an admin holds it.
    #[plexus_macros::activation(crate_path = "plexus_core")]
    impl Shop {
        /// What is on the shelves, and for whom it was asked.
        #[plexus_macros::method]
        pub async fn items(&self) -> Value {
            let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
            json!({ "items": ["flour", "salt"], "caller": caller })
        }
    }
}

use shop::ShopClient;

// ------------------------------------------------------------------ the peer

#[derive(Clone)]
pub struct Restock;

/// Knows its parent: calls `shop.items` back on the call it serves.
#[plexus_macros::activation(parent = ShopClient, crate_path = "plexus_core")]
impl Restock {
    /// The parent's `items`, now.
    #[plexus_macros::method]
    pub async fn low(&self, parent: Parent<ShopClient>) -> Value {
        match parent.items().await {
            Ok(v) => json!({ "low": v }),
            Err(e) => json!({ "error": e.to_string() }),
        }
    }
    /// The parent's `items`, after `ms` milliseconds.
    #[plexus_macros::method]
    pub async fn later(&self, parent: Parent<ShopClient>, ms: u64) -> Value {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        match parent.items().await {
            Ok(v) => json!({ "low": v }),
            Err(e) => json!({ "error": e.to_string() }),
        }
    }
}

// ------------------------------------------------------------------ the slot

/// The peer behind a mount, once the host is built.
static MOUNTED: OnceLock<RemoteChild> = OnceLock::new();

#[derive(Clone)]
pub struct GardenActivation;

/// Peers, by name: `restock` behind a mount, `local` in this process.
#[plexus_macros::activation(namespace = "garden", crate_path = "plexus_core")]
impl GardenActivation {
    /// The peers' names.
    #[plexus_macros::method]
    pub async fn dendrites(&self) -> impl futures::Stream<Item = String> + Send + 'static {
        futures::stream::iter(["restock".to_string(), "local".to_string()])
    }

    /// An untyped peer.
    #[plexus_macros::peer(list = dendrites)]
    async fn dendrite(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match name {
            "restock" => MOUNTED.get().cloned().map(|c| Box::new(c) as Box<dyn Peer>).ok_or(PeerError::NotFound { name: name.into() }),
            "local" => Ok(Box::new(Restock)),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

// ------------------------------------------------------------------ the host

/// `svc`: the shop and the garden. The viewer holds the garden's peers;
/// nobody but the admin holds `shop.items`.
/// One for the binary: the mounted child's connection back is to it.
async fn shop_host() -> Host {
    static HOST: OnceLock<Host> = OnceLock::new();
    if let Some(h) = HOST.get() {
        return h.clone();
    }
    let host = World::new().host().named("svc").with(shop::Shop).with(GardenActivation).role("viewer", ["garden.{dendrite}"]).await;
    let spec: ChildSpec = format!("restock=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap();
    let child = RemoteChild::connect(spec, ChildOptions::for_service("svc").with_host(host.service())).await.expect("the child mounts");
    let _ = MOUNTED.set(child);
    HOST.get_or_init(|| host).clone()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// The admin, its session capped to `ceiling`.
fn capped(ceiling: &[&str]) -> AuthContext {
    AuthContext::for_principal(&ADMIN.parse().unwrap(), "capped", vec![], json!({ CEILING_KEY: ceiling }))
}

// ------------------------------------------------------------------ the rows

/// Capped to `viewer@*`, the admin is refused `shop.items` itself, and so is
/// every peer it calls on that session's call: behind a mount and in process.
async fn keel51_a_capped_session_is_refused_through_a_peers_call_back() {
    let host = shop_host().await;
    let as_viewer = Caller::new(host.service().clone(), Some(capped(&["viewer@*"])));
    let direct = as_viewer.call("shop.items", json!({})).await;
    direct.refused(plexus_testkit::Forbidden).naming("shop.items");
    for peer in ["restock", "local"] {
        let got = as_viewer.call(&format!("garden.dendrite.{peer}.low"), json!({})).await.answers(1);
        assert!(got[0].get("low").is_none(), "{peer}: the call back reached shop.items past the session's ceiling: {got:?}");
        assert!(got[0]["error"].as_str().is_some_and(|e| e.contains("shop.items")), "{peer}: refused, naming the grant: {got:?}");
    }
}

/// The same admin, uncapped, reaches `shop.items` through either peer, as
/// itself: the ceiling is what refused, not the peer.
async fn keel51_the_whole_admin_reaches_it_through_either_peer() {
    let host = shop_host().await;
    for peer in ["restock", "local"] {
        let got = host.as_(ADMIN).call(&format!("garden.dendrite.{peer}.low"), json!({})).await.answers(1);
        assert_eq!(got[0]["low"], json!({ "items": ["flour", "salt"], "caller": ADMIN }), "{peer}: {got:?}");
    }
    // And a viewer, who holds the peers and not the shop, is refused it.
    for peer in ["restock", "local"] {
        let got = host.as_(VIEWER).call(&format!("garden.dendrite.{peer}.low"), json!({})).await.answers(1);
        assert!(got[0]["error"].as_str().is_some_and(|e| e.contains("shop.items")), "{peer}: {got:?}");
    }
}

/// A ceiling that allows the call back still allows it: an admin capped to
/// `admin@*` (any grant) is the whole admin.
async fn keel51_a_ceiling_that_allows_it_still_does() {
    let host = shop_host().await;
    let as_admin = Caller::new(host.service().clone(), Some(capped(&["admin@*"])));
    for peer in ["restock", "local"] {
        let got = as_admin.call(&format!("garden.dendrite.{peer}.low"), json!({})).await.answers(1);
        assert_eq!(got[0]["low"]["caller"], ADMIN, "{peer}: {got:?}");
    }
}

/// AUTH-11: a sign-in that ends while the call is open ends the peer's
/// call back on it — admitted at the call, refused after its `expires_at`.
async fn keel51_a_sign_in_that_ended_ends_the_call_back() {
    let host = shop_host().await;
    for peer in ["restock", "local"] {
        let ending = AuthContext::for_principal(&ADMIN.parse().unwrap(), "ending", vec![], json!({ EXPIRES_AT_KEY: now() + 1 }));
        let got = Caller::new(host.service().clone(), Some(ending)).call(&format!("garden.dendrite.{peer}.later"), json!({ "ms": 2100 })).await.answers(1);
        assert!(got[0].get("low").is_none(), "{peer}: the call back ran on a sign-in that had ended: {got:?}");
        // Refused as a sign-in that no longer stands (the typed client's
        // error names the kind, `unauthenticated`).
        assert!(got[0]["error"].as_str().is_some_and(|e| e.contains("unauthenticated")), "{peer}: refused as signed out: {got:?}");
    }
    // Before it ends, the same call back goes through.
    for peer in ["restock", "local"] {
        let standing = AuthContext::for_principal(&ADMIN.parse().unwrap(), "standing", vec![], json!({ EXPIRES_AT_KEY: now() + 600 }));
        let got = Caller::new(host.service().clone(), Some(standing)).call(&format!("garden.dendrite.{peer}.later"), json!({ "ms": 0 })).await.answers(1);
        assert_eq!(got[0]["low"]["caller"], ADMIN, "{peer}: {got:?}");
    }
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Restock)).unwrap();
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{
                // `cargo test --test keel51_ceiling -- NAME`: the rows whose name holds NAME.
                let only: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
                let mut n = 0;
                $( if only.is_empty() || only.iter().any(|o| stringify!($t).contains(o.as_str())) {
                    $t().await; println!("test {} ... ok", stringify!($t)); n += 1;
                } )*
                n
            }};
        }
        let n = run!(
            keel51_a_capped_session_is_refused_through_a_peers_call_back,
            keel51_the_whole_admin_reaches_it_through_either_peer,
            keel51_a_ceiling_that_allows_it_still_does,
            keel51_a_sign_in_that_ended_ends_the_call_back
        );
        println!("\ntest result: ok. {n} passed; 0 failed");
    });
}
