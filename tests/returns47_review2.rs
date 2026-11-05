//! RETURNS-47 · the re-review's core cases.
//!
//! - A trait-impl activation under `auth = "required"` cannot be served as a
//!   child (no gate of the child admits a caller: `caller()` is an error
//!   through a hop), so `serve_child` refuses it at start, naming the
//!   methods, rather than refusing every call at runtime. A plugin bounds
//!   itself with `hop()` and declares no `required`.
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

#[tokio::test]
async fn serve_child_refuses_at_start_an_activation_whose_methods_need_a_caller() {
    let (_ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let refused = plexus_core::plexus::remote_child::serve_child(G, r, w).await;
    let e = refused.expect_err("refused at start, not call by call");
    let said = e.to_string();
    assert!(said.contains("guarded.get") && said.contains("guarded.list"), "{said}");
    assert!(!said.contains("guarded.open"), "a public method needs no caller: {said}");
    assert!(said.contains("hop()"), "{said}");
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
