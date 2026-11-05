//! RETURNS-47 · the re-review's core cases.
//!
//! - A trait-impl activation under `auth = "required"` is served as a child
//!   (the owner: children receive auth): `caller()` there is the caller the
//!   hop names, and an anonymous hop is refused by `required`.
//! - `call::verified` is set once per call: a second set (a forgery by any
//!   code inside the call) is an error, and `verified()` still answers the
//!   verifier's value.

use futures::StreamExt;
use plexus_core::call;
use plexus_core::plexus::{AuthContext, PlexusError, PlexusStreamItem, Reach};
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use serde_json::{json, Value};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(PlexusRequest)]
pub struct Req {
    #[from_auth_context]
    pub auth: Option<AuthContext>,
}

#[derive(Debug, Clone)]
pub struct User(String);

#[derive(Clone, Default)]
pub struct Access;
impl Access {
    pub async fn verify(&self, ctx: &AuthContext) -> Result<User, PlexusError> {
        ctx.principal().map(|p| User(p.to_string())).ok_or_else(|| PlexusError::Unauthenticated("no principal".into()))
    }
}

mod guarded {
    #[allow(async_fn_in_trait)]
    pub trait Guarded {
        async fn get(&self) -> String;
        async fn list(&self) -> String;
        async fn open(&self) -> String;
    }
}

#[derive(Clone, Default)]
pub struct G;

#[plexus_macros::activation(auth = "required", request = Req, roles(viewer = ["get", "list", "open"]))]
impl guarded::Guarded for G {
    async fn get(&self) -> String {
        "ran".into()
    }
    async fn list(&self) -> String {
        "ran".into()
    }
    #[plexus_macros::method(public)]
    async fn open(&self) -> String {
        "ran".into()
    }
}

/// One call to `G` served as a child, with `hop`; its first item.
async fn child_call(target: &str, hop: Value) -> Value {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (mut ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(G, r, w));
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "guarded.call", "params": { "method": target, "params": {}, "hop": hop } });
    ours.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let _opened = lines.next_line().await.unwrap().unwrap();
    let item: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    drop(lines);
    drop(ours);
    served.await.unwrap().unwrap();
    item["params"]["result"].clone()
}

// The owner, 2026-11-04 ("I NEED children to be able to receive auth"):
// this replaces the re-review's start-time refusal. Through a hop
// `caller()` is the caller the hop names, so `required` works in a child.
#[tokio::test]
async fn a_required_trait_impl_is_served_as_a_child_and_answers_the_hops_caller() {
    let hop = json!({ "principal": "service:svc", "for": [ADA], "limit": { "grant": "guarded.get", "held_on": ["*"] }, "call": "x" });
    let got = child_call("guarded.get", hop).await;
    assert_eq!(got["content"], json!("ran"), "{got}");
    let anonymous = json!({ "principal": "service:svc", "for": [], "limit": { "grant": "guarded.get", "held_on": ["*"] }, "call": "y" });
    let got = child_call("guarded.get", anonymous).await;
    assert_eq!(got["error_kind"], "unauthenticated", "anonymous, refused by required: {got}");
}

mod forge {
    #[allow(async_fn_in_trait)]
    pub trait Forge {
        async fn types(&self) -> Vec<String>;
    }
}

#[derive(Clone, Default)]
pub struct Plugin {
    access: Access,
}

#[plexus_macros::activation(roles(viewer = ["types"]))]
impl forge::Forge for Plugin {
    /// The verifier's value, after a forged second set.
    #[plexus_macros::from_auth(self.access.verify)]
    async fn types(&self) -> Vec<String> {
        let forged = call::__keep_verified(User("forged".into()));
        vec![
            format!("forged={:?}", forged.err()),
            format!("user={:?}", call::verified::<User>().map(|u| u.0)),
        ]
    }
}

#[tokio::test]
async fn verified_is_set_once_per_call() {
    let service = DynamicHub::new("svc").register(Plugin::default());
    let auth = AuthContext::for_principal(&ADA.parse().unwrap(), "s1", vec![], Value::Null);
    let items: Vec<Value> = service
        .route("forge.types", json!({}), Some(&auth))
        .await
        .unwrap()
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                _ => None,
            }
        })
        .collect()
        .await;
    assert_eq!(items, vec![json!(["forged=Some(AlreadyVerified)", format!("user=Ok({ADA:?})")])]);

    let r = call::test::in_call(Some(&auth), Reach::everywhere(), async {
        call::__keep_verified(User("first".into())).unwrap();
        let second = call::__keep_verified(User("forged".into()));
        (second, call::verified::<User>().map(|u| u.0))
    })
    .await;
    assert_eq!(r.0, Err(call::CallError::AlreadyVerified));
    assert_eq!(r.1, Ok("first".to_string()));
}

#[tokio::test]
async fn verified_is_the_calls_inside_with_reach() {
    let auth = AuthContext::for_principal(&ADA.parse().unwrap(), "s1", vec![], Value::Null);
    let r = call::test::in_call(Some(&auth), Reach::everywhere(), async {
        call::__keep_verified(User("first".into())).unwrap();
        plexus_core::plexus::with_reach(Reach::everywhere(), async {
            let seen = call::verified::<User>().map(|u| u.0);
            let second = call::__keep_verified(User("forged".into()));
            (seen, second)
        })
        .await
        .unwrap()
    })
    .await;
    assert_eq!(r.0, Ok("first".to_string()), "the call's verified value, narrowed");
    assert_eq!(r.1, Err(call::CallError::AlreadyVerified));
}
