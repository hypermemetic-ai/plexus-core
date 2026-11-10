//! MACRO-20 — a static `#[plexus_macros::child]` under login: the hub's
//! gate indexes its methods by their whole path (`tickets.commits.link`,
//! the child's own `target`), its `roles(...)` are seeded qualified by that
//! path, and the call reaches it with the caller whole (`SameService`):
//! principal stamp, session, ceiling. A child that says
//! `forward = "identity_only"` still gets today's narrowing — less its
//! session key, never less its ceiling (KEEL-51).

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{AuthContext, MethodRole, PlexusStream, PlexusStreamItem};
use plexus_core::{AuthzDenyReason, DynamicHub, PlexusError};
use plexus_testkit::parts::{who, Shortcodes};
use plexus_testkit::{HostBuilder, World, NOBODY};
use serde_json::{json, Value};

/// What a child's method saw of its caller — on the wire, the JSON object
/// itself (MACRO-22: a newtype so the emitted client can carry a failure).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct Seen(Value);

impl plexus_client::FromClientError for Seen {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        Seen(json!({ "error": error.to_string() }))
    }
}

fn seen(auth: &AuthContext) -> Seen {
    Seen(json!({
        "principal": auth.principal().map(|p| p.to_string()),
        "user": auth.user_id,
        "session": auth.session_id,
        "ceiling": auth.metadata.get(plexus_auth_core::CEILING_KEY).cloned(),
        "session_key": auth.metadata.get("session_key").cloned(),
    }))
}

#[derive(Clone)]
struct TicketsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "MACRO-20 parent",
    roles(viewer = ["get"]),
)]
impl TicketsActivation {
    /// One ticket.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// The commits that finished a ticket — the same service (the default).
    #[plexus_macros::child]
    fn commits(&self) -> CommitsActivation {
        CommitsActivation
    }

    /// A deputy: told who called, never the caller's session.
    #[plexus_macros::child(forward = "identity_only")]
    fn mirror(&self) -> MirrorActivation {
        MirrorActivation
    }
}

#[derive(Clone)]
struct CommitsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "MACRO-20 child",
    roles(editor = ["link"]),
)]
impl CommitsActivation {
    /// Link commits to a ticket: answers what the method saw of its caller.
    #[plexus_macros::method(target = "id")]
    async fn link(&self, auth: &AuthContext, id: String) -> impl Stream<Item = Seen> + Send + 'static {
        let mut v = seen(auth);
        v.0["id"] = json!(id);
        stream! { yield v; }
    }

    /// A grandchild.
    #[plexus_macros::child]
    fn audit(&self) -> AuditActivation {
        AuditActivation
    }
}

#[derive(Clone)]
struct AuditActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "MACRO-20 grandchild",
    roles(viewer = ["read"]),
)]
impl AuditActivation {
    /// Read a ticket's audit trail: what the method saw of its caller.
    #[plexus_macros::method(target = "id")]
    async fn read(&self, auth: &AuthContext, id: String) -> impl Stream<Item = Seen> + Send + 'static {
        let mut v = seen(auth);
        v.0["id"] = json!(id);
        stream! { yield v; }
    }
}

#[derive(Clone)]
struct MirrorActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "MACRO-20 identity-only child",
    roles(viewer = ["whoami"]),
)]
impl MirrorActivation {
    /// What the method saw of its caller.
    #[plexus_macros::method]
    async fn whoami(&self, auth: &AuthContext) -> impl Stream<Item = Seen> + Send + 'static {
        let v = seen(auth);
        stream! { yield v; }
    }
}

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

/// A gated hub whose roles are seeded from `declared_roles` alone — no
/// child's roles added by hand; a ticket lives in its shortcode. ADA edits
/// and views MENGER, BOB views everywhere, ROOT is admin.
fn members() -> HostBuilder {
    World::new()
        .host()
        .named("menger")
        .with(TicketsActivation)
        .resolving(Shortcodes)
        .without_named_callers()
        .member_at(ADA, "editor", "MENGER")
        .member_at(ADA, "viewer", "MENGER")
        .member(BOB, "viewer")
        .member(ROOT, "admin")
}

/// `p` signed in as session `s1`: the session the editor's test checks
/// the child sees intact, by that literal (the kit's `who` gives each
/// principal a session of its own, `sess-<p>`).
fn in_session_s1(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

fn ceilinged(p: &str, ceiling: Value) -> AuthContext {
    AuthContext::for_principal(
        &p.parse().unwrap(),
        "s1",
        vec![],
        json!({ "session_key": "k1", plexus_auth_core::CEILING_KEY: ceiling }),
    )
}

async fn data(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                _ => None,
            }
        })
        .collect()
        .await
}

fn missing_grant(err: PlexusError) -> (String, String, Vec<String>) {
    match err {
        PlexusError::Forbidden { reason: AuthzDenyReason::MissingGrant { grant, scope, roles, .. } } => {
            (grant.as_str().to_string(), scope.to_string(), roles.iter().map(|r| r.as_str().to_string()).collect())
        }
        other => panic!("expected MissingGrant, got {other:?}"),
    }
}

#[test]
fn declared_roles_take_the_children_s_qualified_by_their_path() {
    let roles = DynamicHub::new("menger").register(TicketsActivation).declared_roles();
    assert_eq!(roles["editor"], ["tickets.commits.link"]);
    let viewer: Vec<&str> = roles["viewer"].iter().map(String::as_str).collect();
    for g in ["tickets.get", "tickets.commits.audit.read", "tickets.mirror.whoami"] {
        assert!(viewer.contains(&g), "viewer holds {g}: {viewer:?}");
    }
}

#[test]
fn static_children_are_listed_by_path_with_qualified_grants() {
    let hub = DynamicHub::new("menger").register(TicketsActivation);
    let children = hub.static_children();
    let paths: Vec<&str> = children.iter().map(|c| c.namespace.as_str()).collect();
    assert_eq!(paths, ["tickets.commits", "tickets.commits.audit", "tickets.mirror"]);
    let link = children[0].methods.iter().find(|m| m.name == "link").unwrap();
    assert_eq!(link.grant.as_deref(), Some("tickets.commits.link"));
    assert_eq!(link.target.as_deref(), Some("id"));
}

#[tokio::test]
async fn an_editor_calls_a_child_with_principal_session_and_ceiling_intact() {
    let host = members().await;
    let hub = host.service();
    let out = data(hub.route("tickets.commits.link", json!({"id": "MENGER-2"}), Some(&in_session_s1(ADA))).await.unwrap()).await;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["principal"], json!(ADA));
    assert_eq!(out[0]["session"], json!("s1"));
    assert_eq!(out[0]["id"], json!("MENGER-2"));

    // The grandchild, by its whole path, the caller still whole.
    let out =
        data(hub.route("tickets.commits.audit.read", json!({"id": "MENGER-2"}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(out[0]["principal"], json!(ADA));
}

#[tokio::test]
async fn a_child_s_write_is_gated_on_its_target() {
    let host = members().await;
    let hub = host.service();
    // Editor on MENGER is not editor on IDENTITY.
    let err = hub.route("tickets.commits.link", json!({"id": "IDENTITY-1"}), Some(&who(ADA))).await.err().unwrap();
    let (grant, scope, roles) = missing_grant(err);
    assert_eq!(grant, "tickets.commits.link");
    assert_eq!(scope, "IDENTITY");
    assert_eq!(roles, ["editor", "admin"]);
}

#[tokio::test]
async fn a_viewer_is_refused_naming_the_full_grant() {
    let host = members().await;
    let hub = host.service();
    let err = hub.route("tickets.commits.link", json!({"id": "MENGER-2"}), Some(&who(BOB))).await.err().unwrap();
    let (grant, _, roles) = missing_grant(err);
    assert_eq!(grant, "tickets.commits.link");
    assert_eq!(roles, ["editor", "admin"]);
    // A viewer reads the grandchild.
    assert!(hub.route("tickets.commits.audit.read", json!({"id": "X-1"}), Some(&who(BOB))).await.is_ok());
    // An admin anywhere.
    assert!(hub.route("tickets.commits.link", json!({"id": "IDENTITY-1"}), Some(&who(ROOT))).await.is_ok());
    // Anonymous: sign in first.
    let err = hub.route("tickets.commits.link", json!({"id": "MENGER-2"}), None).await.err().unwrap();
    assert!(matches!(err, PlexusError::Unauthenticated(_)), "{err:?}");
}

#[tokio::test]
async fn a_ceiling_holds_inside_the_child() {
    let host = members().await;
    let hub = host.service();
    let viewer_only = ceilinged(ADA, json!(["viewer@MENGER"]));
    // The ceiling narrows an editor to a viewer: the write is refused …
    let err = hub.route("tickets.commits.link", json!({"id": "MENGER-2"}), Some(&viewer_only)).await.err().unwrap();
    assert_eq!(missing_grant(err).0, "tickets.commits.link");
    // … a read inside the ceiling runs, and the child still sees the
    // ceiling (so a check the child makes itself cannot widen).
    let out = data(
        hub.route("tickets.commits.audit.read", json!({"id": "MENGER-2"}), Some(&viewer_only)).await.unwrap(),
    )
    .await;
    assert_eq!(out[0]["principal"], json!(ADA));
    assert_eq!(out[0]["ceiling"], json!(["viewer@MENGER"]));
}

#[tokio::test]
async fn identity_only_when_chosen_drops_the_session_key_and_keeps_the_ceiling() {
    let host = members().await;
    let service = host.service();
    let viewer_only = ceilinged(BOB, json!(["viewer@*"]));
    let out = data(service.route("tickets.mirror.whoami", json!({}), Some(&viewer_only)).await.unwrap()).await;
    // The verified user id and session id are kept, and (RETURNS-47) the
    // principal stamp with them — it is the identity, so a `key:` caller is
    // still named in the child; the rest of the metadata — the session
    // key — is not. KEEL-51: the ceiling is a bound, not a credential: it
    // is kept with the identity, so the deputy cannot act past it.
    assert_eq!(out[0]["user"], json!(viewer_only.user_id));
    assert_eq!(out[0]["session"], json!("s1"));
    assert_eq!(out[0]["session_key"], Value::Null);
    assert_eq!(out[0]["ceiling"], json!(["viewer@*"]));
    assert_eq!(out[0]["principal"], json!(BOB));
}

#[tokio::test]
async fn without_a_gate_a_child_runs_as_before() {
    let hub = DynamicHub::new("menger").register(TicketsActivation);
    let out = data(hub.route("tickets.commits.link", json!({"id": "X-1"}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(out[0]["principal"], json!(ADA));
    assert_eq!(out[0]["id"], json!("X-1"));
}

#[test]
fn the_parent_says_how_each_child_inherits() {
    use plexus_core::plexus::ChildRouter;
    let t = TicketsActivation;
    assert_eq!(t.forward_policy_for("commits").unwrap().name().as_str(), "same_service");
    assert_eq!(t.forward_policy_for("mirror").unwrap().name().as_str(), "identity_only");
    assert!(t.forward_policy_for("nope").is_none());
    // A leaf has no children to speak for.
    assert!(AuditActivation.forward_policy_for("anything").is_none());
}

#[tokio::test]
async fn the_view_keeps_a_child_s_entry_for_who_can_use_something_below_it() {
    let host = members().member(NOBODY, "nobody-role").await;
    let hub = host.service();
    let methods = |ctx: &AuthContext| -> Vec<String> {
        let view = hub.view(Some(ctx));
        view.schema_of("tickets")
            .map(|s| {
                s.methods
                    .iter()
                    .filter(|m| matches!(m.role, MethodRole::StaticChild))
                    .map(|m| m.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    // A viewer reaches audit.read under commits, and mirror.whoami.
    assert_eq!(methods(&who(BOB)), ["commits", "mirror"]);
    // Someone holding nothing sees no tickets at all.
    assert!(methods(&who(NOBODY)).is_empty());
}
