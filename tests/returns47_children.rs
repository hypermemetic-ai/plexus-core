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
use plexus_core::plexus::{Activation, AuthContext, Grant, PlexusError, PlexusStreamItem, Reach, Resolve, ScopeRef};
use plexus_macros::PlexusRequest;
use plexus_testkit::World;

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

/// `hop(for, MENGER allowed)`; `nohop` when `hop()` errors.
fn hop_seen() -> String {
    match call::hop() {
        Ok(h) => format!("hop({},{})", h.caller().map(short).unwrap_or("-".into()), h.allows_scope("MENGER")),
        Err(_) => "nohop".into(),
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

    /// The hop, as `call::hop()` answers it here.
    #[plexus_macros::method]
    pub async fn by_hop(&self) -> String {
        hop_seen()
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
        async fn hop(&self) -> String;
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

    /// The hop, as `call::hop()` answers it here.
    async fn hop(&self) -> String {
        hop_seen()
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

/// A target is a scope of its own name, inside everything.
struct OwnName;
impl Resolve for OwnName {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::named(target), ScopeRef::Everywhere])
    }
}

fn ada() -> AuthContext {
    AuthContext::for_principal(&ADA.parse().unwrap(), "s1", vec!["viewer".into()], serde_json::json!({ "k": "v" }))
}

/// ADA's reach as a gate answers it: viewer on MENGER, a role listing
/// `parent.call` alone.
async fn menger_reach() -> Reach {
    let host = World::new()
        .host()
        .resolving(OwnName)
        .without_named_callers()
        .role("viewer", ["parent.call"])
        .member_at(ADA, "viewer", "MENGER")
        .await;
    host.gate().check(Some(&ada()), &Grant::new("parent.call".to_string()), None).expect("ADA views MENGER")
}

/// One call through the parent, inside a call admitted for ADA within MENGER.
async fn through(path: &str) -> String {
    let caller = ada();
    call::test::in_call(Some(&caller), menger_reach().await, async {
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

// ------------------------------------------------------- the hop, per policy

/// One call to the parent served as a child (`serve_child`), its hop for
/// ADA within MENGER for `path`'s grant; the answer's text.
async fn through_the_seam(path: &str) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (mut ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(ParentActivation, r, w));
    let target = format!("parent.{path}");
    let hop = serde_json::json!({ "principal": "service:menger", "for": [ADA], "limit": { "grant": target, "held_on": ["MENGER"] }, "call": "c1" });
    let frame = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "parent.call", "params": { "method": target, "params": {}, "hop": hop } });
    ours.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let _opened = lines.next_line().await.unwrap();
    let mut out = Vec::new();
    while let Ok(Some(l)) = lines.next_line().await {
        let v: serde_json::Value = serde_json::from_str(&l).unwrap();
        let r = v["params"]["result"].clone();
        match r["type"].as_str() {
            Some("data") => out.push(r["content"].as_str().unwrap_or_default().to_string()),
            Some("error") => {
                out.push(format!("error({})", r["error_kind"].as_str().unwrap_or("?")));
                break;
            }
            _ => break,
        }
    }
    drop(lines);
    drop(ours);
    let _ = served.await;
    out.join(";")
}

/// The `hop()` column: in process there is no hop (the call came through
/// none); through the seam a child's hop follows its caller — kept under
/// `same_service`, `identity_only`, `pass_through`, none under `anonymous`
/// (`hop()` errors there, as outside a hop).
#[tokio::test]
async fn a_childs_hop_follows_its_forward_policy() {
    // In process: no hop anywhere.
    for kid in ["same", "ident", "through", "nobody", "mars"] {
        assert_eq!(through(&format!("{kid}.by_hop")).await, "nohop", "{kid}");
    }
    // Through the seam: (path, hop(), caller()).
    let rows = [
        ("same", "hop(ADA,true)", "ADA@MENGER"),
        ("ident", "hop(ADA,true)", "ADA@MENGER"),
        ("through", "hop(ADA,true)", "ADA@MENGER"),
        ("nobody", "nohop", "anonymous@"),
        ("mars", "hop(ADA,true)", "ADA@MENGER"),
    ];
    for (kid, hop, caller) in rows {
        assert_eq!(through_the_seam(&format!("{kid}.by_hop")).await, hop, "{kid}: hop()");
        assert_eq!(through_the_seam(&format!("{kid}.by_caller")).await, caller, "{kid}: caller()");
    }
    // Nested under `anonymous`: a grandchild of a same-service kind sees no
    // hop either, and the trait child under `required` refuses.
    assert_eq!(through_the_seam("tsame.hop").await, "hop(ADA,true)");
    assert_eq!(through_the_seam("tnobody.hop").await, "error(unauthenticated)");
}
