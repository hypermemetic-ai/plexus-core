//! RETURNS-47 · the review's cases (2026-11-04), ported.
//!
//! - r1, r2: a trait-impl method under `auth = "required"` refuses an
//!   anonymous caller before its body, out of band and typed, exactly as a
//!   `#[from_auth]` method does — ungated, and gated on a `public` method; a
//!   trait-impl method's verifier (`#[plexus_macros::from_auth(…)]` on the
//!   method) refuses out of band by the route `#[from_auth]`'s error takes,
//!   and its value is the body's (`call::verified`).
//! - r3: concurrent calls do not leak callers into each other's streams.
//! - r4: `with_reach` narrows a call's reach; outside a call it refuses,
//!   never builds a caller.
//! - r5: `Activation::call` straight, outside any dispatch, is refused for a
//!   method that needs its caller; `call::ungated` is the supported leaf path.
//! - `call::test::in_call` is the supported way into a call for a test.

use futures::stream::{Stream, StreamExt};
use plexus_core::call;
use plexus_core::plexus::{
    current_reach, with_reach, Activation, AuthContext, Gate, Membership, Memberships, PlexusError, PlexusStream,
    PlexusStreamItem, Reach, RemoteError, Resolve, RoleTable, ScopeRef,
};
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Ev {
    Who { by: Option<String>, held_on: Vec<String> },
    Error { message: String },
}

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
        let _ = current_reach()?;
        ctx.principal().map(|p| User(p.to_string())).ok_or_else(|| PlexusError::Unauthenticated("no principal".into()))
    }
}

fn who_ev() -> Ev {
    match call::caller() {
        Ok(c) => Ev::Who {
            by: c.auth().and_then(|a| a.principal()).map(|p| p.to_string()),
            held_on: c.reach().held_on().iter().map(|s| s.as_str().to_string()).collect(),
        },
        Err(e) => Ev::Error { message: e.to_string() },
    }
}

#[derive(Clone, Default)]
pub struct PubActivation {
    access: Access,
}

#[plexus_macros::activation(auth = "required", request = Req, roles(viewer = ["peek", "slow", "naive", "open"]))]
impl PubActivation {
    /// public, from_auth
    #[plexus_macros::method(public)]
    pub async fn peek(&self, #[from_auth(self.access.verify)] user: User) -> impl Stream<Item = Ev> + Send + 'static {
        futures::stream::once(async move { Ev::Who { by: Some(user.0), held_on: vec![] } })
    }

    /// reads caller across awaits, lazily
    pub async fn slow(&self, #[from_auth(self.access.verify)] _u: User) -> impl Stream<Item = Ev> + Send + 'static {
        async_stream::stream! {
            for _ in 0..5 {
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
                yield who_ev();
            }
        }
    }

    /// from_auth, not public
    pub async fn naive(&self, #[from_auth(self.access.verify)] _u: User) -> impl Stream<Item = Ev> + Send + 'static {
        let item = who_ev();
        futures::stream::once(async move { item })
    }

    /// public, no verifier: anyone
    #[plexus_macros::method(public)]
    pub async fn open(&self) -> impl Stream<Item = Ev> + Send + 'static {
        let item = who_ev();
        futures::stream::once(async move { item })
    }
}

mod contract {
    use super::Ev;
    use futures::Stream;
    #[allow(async_fn_in_trait)]
    pub trait Peeker {
        async fn peek(&self) -> impl Stream<Item = Ev> + Send + 'static;
        /// a body that reads caller() but forgets signed_in()
        async fn naive(&self) -> impl Stream<Item = Ev> + Send + 'static;
        async fn open(&self) -> impl Stream<Item = Ev> + Send + 'static;
    }
}

#[derive(Clone, Default)]
pub struct P {
    access: Access,
}

#[plexus_macros::activation(auth = "required", request = Req, roles(viewer = ["naive", "open"]))]
impl contract::Peeker for P {
    /// public, its verifier on the method: the trait's form of `#[from_auth]`
    #[plexus_macros::method(public)]
    #[plexus_macros::from_auth(self.access.verify)]
    async fn peek(&self) -> impl Stream<Item = Ev> + Send + 'static {
        let item = match call::verified::<User>() {
            Ok(u) => Ev::Who { by: Some(u.0), held_on: vec![] },
            Err(e) => Ev::Error { message: e.to_string() },
        };
        futures::stream::once(async move { item })
    }

    async fn naive(&self) -> impl Stream<Item = Ev> + Send + 'static {
        let item = who_ev();
        futures::stream::once(async move { item })
    }

    #[plexus_macros::method(public)]
    async fn open(&self) -> impl Stream<Item = Ev> + Send + 'static {
        let item = who_ev();
        futures::stream::once(async move { item })
    }
}

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}
fn plain() -> DynamicHub {
    DynamicHub::new("svc").register(PubActivation::default()).register(P::default())
}
fn gated() -> DynamicHub {
    let m = Arc::new(Members::default());
    m.0.lock().unwrap().push(Membership { principal: ADA.parse().unwrap(), role: plexus_auth_core::RoleName::new("viewer"), scope: ScopeRef::parse("MENGER") });
    m.0.lock().unwrap().push(Membership { principal: BOB.parse().unwrap(), role: plexus_auth_core::RoleName::new("viewer"), scope: ScopeRef::parse("OTHER") });
    let declared = plain().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    plain().with_gate(Arc::new(Gate::new(m, Arc::new(roles), Arc::new(Shortcodes))))
}
fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::Value::Null)
}
async fn all(s: PlexusStream) -> Vec<serde_json::Value> {
    s.map(|i| match i {
        PlexusStreamItem::Data { content, .. } => content.into_value(),
        other => serde_json::to_value(other).unwrap(),
    })
    .collect()
    .await
}
/// A call's outcome: its items, or its refusal out of band, typed, whole.
async fn outcome(service: &DynamicHub, m: &str, caller: Option<&str>) -> String {
    let auth = caller.map(who);
    match service.route(m, serde_json::json!({}), auth.as_ref()).await {
        Ok(s) => format!("STREAM {}", serde_json::to_string(&all(s).await).unwrap()),
        Err(e) => format!("ERR {} {}", serde_json::to_string(&RemoteError::from(&e)).unwrap(), e),
    }
}

#[tokio::test]
async fn r1_public_method_anonymous_from_auth_vs_caller() {
    let service = gated();
    let a = outcome(&service, "pub.peek", None).await;
    let b = outcome(&service, "peeker.peek", None).await;
    assert!(a.starts_with("ERR") && a.contains("unauthenticated"), "{a}");
    assert_eq!(a, b, "a trait method's verifier refuses as #[from_auth] does");
    // Signed in, the verifier's value is the body's.
    let a = outcome(&service, "pub.peek", Some(ADA)).await;
    let b = outcome(&service, "peeker.peek", Some(ADA)).await;
    assert_eq!(a, b);
    assert!(a.contains(ADA), "{a}");
}

#[tokio::test]
async fn r1_a_public_method_with_no_verifier_runs_for_anyone_on_both_forms() {
    let service = gated();
    let a = outcome(&service, "pub.open", None).await;
    let b = outcome(&service, "peeker.open", None).await;
    assert_eq!(a, b);
    assert!(a.starts_with("STREAM"), "{a}");
}

#[tokio::test]
async fn r2_auth_required_is_enforced_on_a_trait_impl_ungated() {
    let service = plain();
    let a = outcome(&service, "pub.naive", None).await;
    let b = outcome(&service, "peeker.naive", None).await;
    assert!(!b.contains("\"who\""), "anonymous ran the body: {b}");
    assert!(b.starts_with("ERR") && b.contains("unauthenticated"), "{b}");
    assert_eq!(a, b, "refused as #[from_auth] refuses");
    // Signed in, both run, and say the same.
    let a = outcome(&service, "pub.naive", Some(ADA)).await;
    let b = outcome(&service, "peeker.naive", Some(ADA)).await;
    assert_eq!(a, b);
    assert!(a.contains(ADA), "{a}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_concurrent_calls_do_not_leak_callers() {
    let service = Arc::new(gated());
    let mut tasks = Vec::new();
    for i in 0..40 {
        let service = service.clone();
        tasks.push(tokio::spawn(async move {
            let p = if i % 2 == 0 { ADA } else { BOB };
            let s = service.route("pub.slow", serde_json::json!({}), Some(&who(p))).await.unwrap();
            // poll the stream from yet another task
            let got = tokio::spawn(all(s)).await.unwrap();
            for g in &got {
                if g.get("by").is_some() {
                    assert_eq!(g["by"], p, "leak: {got:?}");
                }
            }
            got.len()
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap() >= 5);
    }
}

#[tokio::test]
async fn r4_with_reach_refuses_outside_a_call() {
    let outside = with_reach(Reach::everywhere(), async { call::caller().is_ok() }).await;
    assert!(matches!(outside, Err(PlexusError::Unauthenticated(_))), "with_reach built a caller by hand: {outside:?}");
    // Inside a call it narrows: the same reach (or less) is taken.
    let inside = call::test::in_call(Some(&who(ADA)), Reach::everywhere(), async {
        with_reach(Reach::everywhere(), async { current_reach().map(|r| r.is_everywhere()) }).await
    })
    .await;
    assert!(matches!(inside, Ok(Ok(true))), "{inside:?}");
}

#[tokio::test]
async fn r5_a_direct_activation_call_is_refused_and_call_ungated_is_the_leaf_path() {
    let refused = P::default().call("naive", serde_json::json!({}), Some(&who(ADA)), None).await;
    assert!(matches!(refused, Err(PlexusError::Unauthenticated(_))), "{:?}", refused.as_ref().err());
    let answered = all(call::ungated(&P::default(), "naive", serde_json::json!({}), Some(&who(ADA)), None).await.unwrap()).await;
    assert_eq!(answered, vec![serde_json::json!({ "type": "who", "by": ADA, "held_on": ["*"] })]);
}

#[tokio::test]
async fn in_call_is_the_supported_way_in_for_a_test() {
    let user = call::test::in_call(Some(&who(ADA)), Reach::everywhere(), Access.verify(&who(ADA))).await;
    assert_eq!(user.unwrap().0, ADA);
    let outside = Access.verify(&who(ADA)).await;
    assert!(matches!(outside, Err(PlexusError::Unauthenticated(_))));
}

// ------------------------------------- list_children runs in a call context

#[derive(Clone)]
struct Leaf;

#[plexus_macros::activation(namespace = "leaf", version = "1.0.0", crate_path = "plexus_core")]
impl Leaf {
    /// Health check.
    #[plexus_macros::method]
    async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async { "pong".to_string() })
    }
}

#[derive(Clone)]
struct Shelf;

#[plexus_macros::activation(namespace = "shelf", version = "1.0.0", crate_path = "plexus_core")]
impl Shelf {
    /// Health check.
    #[plexus_macros::method]
    async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async { "pong".to_string() })
    }

    /// A book by name.
    #[plexus_macros::child(list = "names")]
    fn book(&self, _name: &str) -> Option<Leaf> {
        Some(Leaf)
    }

    /// The books: one, named for whether the listing has a caller.
    fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        let named = match call::caller() {
            Ok(c) => format!("caller:{}", c.reach().held_on().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")),
            Err(e) => format!("none:{e:?}"),
        };
        futures::stream::once(async move { named })
    }
}

#[tokio::test]
async fn list_children_runs_in_the_calls_context() {
    let module = DynamicHub::new("svc").register(Shelf).into_rpc_module().unwrap();
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"shelf.list_children","params":{}}"#;
    let (_, mut rx) = module.raw_json_request(req, 1024).await.unwrap();
    let mut seen = Vec::new();
    while let Some(item) = rx.recv().await {
        let t = item.get().to_string();
        let done = t.contains(r#""type":"done""#) || t.contains(r#""type":"error""#);
        seen.push(t);
        if done {
            break;
        }
    }
    let all = seen.join("\n");
    assert!(all.contains("caller:*"), "a service with no gate lists in its context, everywhere: {all}");
}
