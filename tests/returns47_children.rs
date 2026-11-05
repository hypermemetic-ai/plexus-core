//! RETURNS-47 · children receive auth (owner, 2026-11-04: "I NEED children
//! to be able to receive auth").
//!
//! An in-process child — static `#[child]`, dynamic `#[child]`, nested —
//! reads `caller()`, `current_reach()` and its `#[from_auth]` verifier, and
//! declares `required`, exactly as a top-level method does, under its
//! forward policy:
//!
//! | policy | the child's caller | its reach |
//! |---|---|---|
//! | `same_service` (a static child's default) | the caller, whole | the call's |
//! | `identity_only` (a dynamic child's default) | the caller's identity (no roles, no metadata but its principal) | the call's |
//! | `pass_through` | the caller, whole | the call's |
//! | `anonymous` | none | nowhere |
//!
//! The table is checked for each form: a `#[from_auth]` parameter, a body
//! reading `caller()`, a `reach: Reach` parameter, and a method of `impl
//! Trait for Type` under `auth = "required"`.

use futures::{Stream, StreamExt};
use plexus_core::call;
use plexus_core::plexus::{
    Activation, AuthContext, Gate, Grant, Membership, Memberships, PlexusError, PlexusStreamItem, Reach, Resolve,
    RoleTable, ScopeRef,
};
use plexus_macros::PlexusRequest;
use std::sync::{Arc, Mutex};

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

fn held(r: &Reach) -> String {
    r.held_on().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
}

/// `principal@reach`, as the call's context says; `anonymous@…` for none.
fn seen() -> String {
    match call::caller() {
        Ok(c) => format!(
            "{}@{}",
            c.auth().and_then(|a| a.principal()).map(|p| if p.to_string() == ADA { "ADA".to_string() } else { p.to_string() }).unwrap_or("anonymous".into()),
            held(c.reach())
        ),
        Err(e) => format!("none({e:?})"),
    }
}

fn short(p: &str) -> String {
    if p == ADA { "ADA".into() } else { p.into() }
}

// ------------------------------------------------------------------ the kids

#[derive(Clone, Default)]
pub struct KidActivation {
    access: Access,
}

/// A child of plain methods.
#[plexus_macros::activation(request = Req, auth = "mixed")]
impl KidActivation {
    /// The `#[from_auth]` verifier's user.
    #[plexus_macros::method]
    pub async fn by_from_auth(&self, #[from_auth(self.access.verify)] user: User) -> String {
        short(&user.0)
    }

    /// The call's caller.
    #[plexus_macros::method]
    pub async fn by_caller(&self) -> String {
        seen()
    }

    /// The `reach` parameter.
    #[plexus_macros::method]
    pub async fn by_reach(&self, reach: Reach) -> String {
        held(&reach)
    }

    /// A grandchild, the same service.
    #[plexus_macros::child]
    fn deeper(&self) -> TraitKid {
        TraitKid::default()
    }
}

pub mod kid_t {
    #[allow(async_fn_in_trait)]
    pub trait KidT {
        async fn whom(&self) -> String;
    }
}

#[derive(Clone, Default)]
pub struct TraitKid;

/// A child of a trait, under `required`.
#[plexus_macros::activation(auth = "required", request = Req)]
impl kid_t::KidT for TraitKid {
    /// The call's caller, signed in.
    async fn whom(&self) -> String {
        seen()
    }
}

// ------------------------------------------------------------------ the parent

#[derive(Clone, Default)]
pub struct ParentActivation;

/// Children under every policy.
#[plexus_macros::activation]
impl ParentActivation {
    /// Pong.
    pub async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async { "pong".to_string() })
    }

    #[plexus_macros::child]
    fn same(&self) -> KidActivation {
        KidActivation::default()
    }
    #[plexus_macros::child(forward = "identity_only")]
    fn ident(&self) -> KidActivation {
        KidActivation::default()
    }
    #[plexus_macros::child(forward = "pass_through")]
    fn through(&self) -> KidActivation {
        KidActivation::default()
    }
    #[plexus_macros::child(forward = "anonymous")]
    fn nobody(&self) -> KidActivation {
        KidActivation::default()
    }
    #[plexus_macros::child]
    fn tsame(&self) -> TraitKid {
        TraitKid
    }
    #[plexus_macros::child(forward = "identity_only")]
    fn tident(&self) -> TraitKid {
        TraitKid
    }
    #[plexus_macros::child(forward = "pass_through")]
    fn tthrough(&self) -> TraitKid {
        TraitKid
    }
    #[plexus_macros::child(forward = "anonymous")]
    fn tnobody(&self) -> TraitKid {
        TraitKid
    }
    /// A dynamic child (identity_only, the framework's default).
    #[plexus_macros::child]
    fn planet(&self, _name: &str) -> Option<KidActivation> {
        Some(KidActivation::default())
    }
}

// ------------------------------------------------------------------ the call

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
        Some(vec![ScopeRef::named(target), ScopeRef::Everywhere])
    }
}

fn ada() -> AuthContext {
    AuthContext::for_principal(&ADA.parse().unwrap(), "s1", vec!["viewer".into()], serde_json::json!({ "k": "v" }))
}

/// ADA's reach as a gate answers it: viewer on MENGER.
fn menger_reach() -> Reach {
    let m = Arc::new(Members::default());
    m.0.lock().unwrap().push(Membership { principal: ADA.parse().unwrap(), role: plexus_auth_core::RoleName::new("viewer"), scope: ScopeRef::parse("MENGER") });
    let roles = RoleTable::from_lists([("viewer", ["parent.call"].into_iter())]);
    let gate = Gate::new(m, Arc::new(roles), Arc::new(Shortcodes));
    gate.check(Some(&ada()), &Grant::new("parent.call".to_string()), None).expect("ADA views MENGER")
}

/// One call through the parent, inside a call admitted for ADA within MENGER.
async fn through(path: &str) -> String {
    let caller = ada();
    call::test::in_call(Some(&caller), menger_reach(), async {
        match ParentActivation.call(path, serde_json::json!({}), Some(&caller), None).await {
            Ok(s) => {
                let items: Vec<String> = s
                    .filter_map(|i| async move {
                        match i {
                            PlexusStreamItem::Data { content, .. } => content.into_value().as_str().map(str::to_string),
                            PlexusStreamItem::Error { message, .. } => Some(format!("error({message})")),
                            _ => None,
                        }
                    })
                    .collect()
                    .await;
                items.join(";")
            }
            Err(PlexusError::Unauthenticated(_)) => "refused".into(),
            Err(e) => format!("err({e})"),
        }
    })
    .await
}

#[tokio::test]
async fn children_receive_auth_under_their_forward_policy() {
    // (child, from_auth, caller(), reach, trait under required)
    let rows = [
        ("same_service", "same", "tsame"),
        ("identity_only", "ident", "tident"),
        ("pass_through", "through", "tthrough"),
        ("anonymous", "nobody", "tnobody"),
        ("dynamic (identity_only)", "mars", ""),
        ("nested (same_service)", "", "same.deeper"),
    ];
    let want = [
        ["ADA", "ADA@MENGER", "MENGER", "ADA@MENGER"],
        ["ADA", "ADA@MENGER", "MENGER", "ADA@MENGER"],
        ["ADA", "ADA@MENGER", "MENGER", "ADA@MENGER"],
        ["refused", "anonymous@", "", "refused"],
        ["ADA", "ADA@MENGER", "MENGER", "-"],
        ["-", "-", "-", "ADA@MENGER"],
    ];
    let mut got = Vec::new();
    for (_, kid, tkid) in rows {
        let at = |kid: &str, m: &str| if kid.is_empty() { None } else { Some(format!("{kid}.{m}")) };
        let mut row: [String; 4] = Default::default();
        for (i, path) in [at(kid, "by_from_auth"), at(kid, "by_caller"), at(kid, "by_reach"), at(tkid, "whom")].into_iter().enumerate() {
            row[i] = match path {
                Some(p) => through(&p).await,
                None => "-".into(),
            };
        }
        got.push(row);
    }
    let table: Vec<String> = rows
        .iter()
        .zip(&got)
        .map(|((p, _, _), g)| format!("| {p} | {} | {} | {} | {} |", g[0], g[1], g[2], g[3]))
        .collect();
    let table = table.join("\n");
    for (i, (p, _, _)) in rows.iter().enumerate() {
        let g: Vec<&str> = got[i].iter().map(String::as_str).collect();
        assert_eq!(g, want[i].to_vec(), "{p}\n| policy | from_auth | caller() | reach | trait, required |\n{table}");
    }
}

#[tokio::test]
async fn an_anonymous_caller_is_refused_by_a_required_child() {
    let got = call::test::in_call(None, Reach::everywhere(), async {
        ParentActivation.call("tsame.whom", serde_json::json!({}), None, None).await.map(|_| ())
    })
    .await;
    assert!(matches!(got, Err(PlexusError::Unauthenticated(_))), "{got:?}");
}
