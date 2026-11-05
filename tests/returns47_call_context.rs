//! RETURNS-47 · the caller from the call's context, fail closed.
//!
//! - A menger-shaped activation (`impl NotesActivation`, `auth =
//!   "required"`, `request = …`, `typed_params`, `roles(…)`, every method's
//!   caller `#[from_auth(self.access.verify)] user: User`) builds and serves
//!   with its `…Activation` name unchanged.
//! - The same method on a hand-written trait (`impl jottings::Jottings for
//!   Jot`), whose signature cannot carry `#[from_auth]`, reads its caller
//!   with `plexus_core::call::caller()` — and is refused or answered by the
//!   gate exactly as the `from_auth` one.
//! - Outside a call, `caller()` and `current_reach()` are errors, never
//!   everything.
//! - A spawned task does not see the caller unless handed it
//!   (`call::scope`); the call's stream does.

use futures::stream::{Stream, StreamExt};
use plexus_core::call;
use plexus_core::plexus::{
    current_reach, AuthContext, Gate, Membership, Memberships, PlexusError, PlexusStream, PlexusStreamItem, RemoteError,
    Resolve, RoleTable, ScopeRef,
};
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ------------------------------------------------------------ menger's shape

/// A ticket's id: typed, as `typed_params` asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct NoteId(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotesEvent {
    /// A note, and who read it within what.
    Note { id: String, by: String, held_on: Vec<String> },
    /// Refused in band.
    Error { message: String },
}

/// menger's `MengerRequest`: the identity the upgrade proved.
#[derive(PlexusRequest)]
pub struct NotesRequest {
    #[from_auth_context]
    pub auth: Option<AuthContext>,
}

/// menger's `VerifiedUser`, made by its `Access::verify` and never by hand.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    principal: String,
    held_on: Vec<String>,
}

impl User {
    /// The call's caller, verified: `VerifiedUser::current(&self.access)`.
    pub async fn current(access: &Access) -> Result<User, PlexusError> {
        let caller = call::caller()?;
        access.verify(caller.signed_in()?).await
    }
}

/// menger's `Access`: verifies an identity against the reach the gate
/// answered for the call.
#[derive(Clone, Default)]
pub struct Access;

impl Access {
    pub async fn verify(&self, ctx: &AuthContext) -> Result<User, PlexusError> {
        let reach = current_reach()?;
        let principal = ctx
            .principal()
            .map(|p| p.to_string())
            .ok_or_else(|| PlexusError::Unauthenticated("names no principal".into()))?;
        Ok(User { principal, held_on: reach.held_on().iter().map(|s| s.as_str().to_string()).collect() })
    }
}

fn note(id: NoteId, user: User) -> NotesEvent {
    NotesEvent::Note { id: id.0, by: user.principal, held_on: user.held_on }
}

#[derive(Clone, Default)]
pub struct NotesActivation {
    access: Access,
}

/// Notes, as menger declares an activation.
#[plexus_macros::activation(
    auth = "required",
    request = NotesRequest,
    typed_params,
    roles(viewer = ["get", "lazy"]),
)]
impl NotesActivation {
    /// One note.
    #[plexus_macros::method(target = "id")]
    pub async fn get(&self, #[from_auth(self.access.verify)] user: User, id: NoteId) -> impl Stream<Item = NotesEvent> + Send + 'static {
        futures::stream::once(async move { note(id, user) })
    }

    /// The caller read inside the stream's body, after the method returned.
    pub async fn lazy(&self, #[from_auth(self.access.verify)] _user: User) -> impl Stream<Item = NotesEvent> + Send + 'static {
        async_stream::stream! {
            match call::caller() {
                Ok(c) => yield NotesEvent::Note {
                    id: "lazy".into(),
                    by: c.auth().and_then(|a| a.principal()).map(|p| p.to_string()).unwrap_or_default(),
                    held_on: c.reach().held_on().iter().map(|s| s.as_str().to_string()).collect(),
                },
                Err(e) => yield NotesEvent::Error { message: e.to_string() },
            }
        }
    }
}

// ------------------------------------------------- the same, through a trait

mod jottings {
    use super::{NoteId, NotesEvent};
    use futures::Stream;

    /// A contract written by hand: a signature cannot carry `#[from_auth]`.
    #[allow(async_fn_in_trait)]
    pub trait Jottings {
        async fn get(&self, id: NoteId) -> impl Stream<Item = NotesEvent> + Send + 'static;
        async fn spawned(&self) -> Vec<bool>;
    }
}

#[derive(Clone, Default)]
pub struct Jot {
    access: Access,
}

/// Notes, through a trait.
#[plexus_macros::activation(auth = "required", request = NotesRequest, typed_params, roles(viewer = ["get", "spawned"]))]
impl jottings::Jottings for Jot {
    /// One note.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: NoteId) -> impl Stream<Item = NotesEvent> + Send + 'static {
        let item = match User::current(&self.access).await {
            Ok(user) => note(id, user),
            Err(e) => NotesEvent::Error { message: e.to_string() },
        };
        futures::stream::once(async move { item })
    }

    /// Whether a spawned task sees the caller: not handed it, then handed it.
    async fn spawned(&self) -> Vec<bool> {
        let bare = tokio::spawn(async { call::caller().is_ok() }).await.unwrap();
        let ctx = call::context().expect("inside a call");
        let handed = tokio::spawn(call::scope(ctx, async { call::caller().is_ok() })).await.unwrap();
        vec![call::caller().is_ok(), bare, handed]
    }
}

// ------------------------------------------------------------ the service

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// `CODE-n` → `[CODE, *]`.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

fn plain() -> DynamicHub {
    DynamicHub::new("menger").register(NotesActivation::default()).register(Jot::default())
}

/// ADA views MENGER; BOB holds nothing.
fn gated() -> DynamicHub {
    let members = Arc::new(Members::default());
    members.0.lock().unwrap().push(Membership {
        principal: ADA.parse().unwrap(),
        role: plexus_auth_core::RoleName::new("viewer"),
        scope: ScopeRef::parse("MENGER"),
    });
    let declared = plain().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    plain().with_gate(Arc::new(Gate::new(members, Arc::new(roles), Arc::new(Shortcodes))))
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::Value::Null)
}

async fn data(stream: PlexusStream) -> Vec<serde_json::Value> {
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

/// A call's outcome with the activation's own namespace taken out, so the
/// two activations' answers compare: its data, or its typed refusal.
async fn outcome(service: &DynamicHub, ns: &str, method: &str, params: serde_json::Value, caller: Option<&str>) -> String {
    let auth = caller.map(who);
    let out = match service.route(&format!("{ns}.{method}"), params, auth.as_ref()).await {
        Ok(s) => serde_json::to_string(&data(s).await).unwrap(),
        Err(e) => serde_json::to_string(&RemoteError::from(&e)).unwrap(),
    };
    out.replace(&format!("{ns}."), "NS.")
}

#[test]
fn a_menger_shaped_activation_keeps_its_activation_name() {
    use plexus_core::plexus::Activation;
    assert_eq!(NotesActivation::default().namespace(), "notes");
    assert_eq!(Jot::default().namespace(), "jottings");
    // Its client is named from the stem, as before.
    let _ = NotesClient::new(Arc::new(plexus_client::MemoryTransport::new()));
    let _ = JottingsClient::new(Arc::new(plexus_client::MemoryTransport::new()));
}

#[tokio::test]
async fn a_trait_method_reading_caller_is_refused_and_answered_as_the_from_auth_one() {
    let service = gated();
    let cases: Vec<(serde_json::Value, Option<&str>)> = vec![
        (serde_json::json!({ "id": "MENGER-1" }), None),
        (serde_json::json!({ "id": "MENGER-1" }), Some(BOB)),
        (serde_json::json!({ "id": "OTHER-1" }), Some(ADA)),
        (serde_json::json!({ "id": "MENGER-1" }), Some(ADA)),
    ];
    let mut seen = Vec::new();
    for (params, caller) in cases {
        let by_from_auth = outcome(&service, "notes", "get", params.clone(), caller).await;
        let by_caller = outcome(&service, "jottings", "get", params.clone(), caller).await;
        assert_eq!(by_caller, by_from_auth, "{params} as {caller:?}");
        seen.push(by_from_auth);
    }
    assert!(seen[0].contains("unauthenticated"), "{}", seen[0]);
    assert!(seen[1].contains("missing_grant"), "{}", seen[1]);
    assert!(seen[2].contains("missing_grant") && seen[2].contains("OTHER"), "{}", seen[2]);
    let answered: serde_json::Value = serde_json::from_str(&seen[3]).unwrap();
    assert_eq!(answered, serde_json::json!([{ "type": "note", "id": "MENGER-1", "by": ADA, "held_on": ["MENGER"] }]));
}

#[tokio::test]
async fn caller_and_current_reach_outside_a_call_are_errors_not_everything() {
    assert_eq!(call::caller().unwrap_err(), call::CallError::OutsideCall);
    assert_eq!(call::hop().unwrap_err(), call::CallError::OutsideCall);
    assert!(call::context().is_err());
    let reach = current_reach();
    assert!(matches!(reach, Err(PlexusError::Unauthenticated(_))), "{reach:?}");
    // The same in a task of its own, and as menger's verifier asks.
    let in_task = tokio::spawn(async { (call::caller().is_err(), current_reach().is_err()) }).await.unwrap();
    assert_eq!(in_task, (true, true));
    let verified = Access.verify(&who(ADA)).await;
    assert!(matches!(verified, Err(PlexusError::Unauthenticated(_))), "{verified:?}");
}

#[tokio::test]
async fn a_spawned_task_does_not_see_the_caller_unless_handed_it() {
    let service = gated();
    let got = data(service.route("jottings.spawned", serde_json::json!({}), Some(&who(ADA))).await.unwrap()).await;
    // [in the method, spawned bare, spawned with call::scope]
    assert_eq!(got, vec![serde_json::json!([true, false, true])]);
}

#[tokio::test]
async fn the_calls_stream_carries_its_context() {
    let service = gated();
    let got = data(service.route("notes.lazy", serde_json::json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(got, vec![serde_json::json!({ "type": "note", "id": "lazy", "by": ADA, "held_on": ["MENGER"] })]);
}

#[tokio::test]
async fn a_service_without_a_gate_says_everywhere_and_anonymous_is_refused_closed() {
    let service = plain();
    // Signed in: the reach is everywhere because the dispatch says so.
    let got = data(service.route("jottings.get", serde_json::json!({ "id": "OTHER-1" }), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(got, vec![serde_json::json!({ "type": "note", "id": "OTHER-1", "by": ADA, "held_on": ["*"] })]);
    // Anonymous: the from_auth method is refused before its body; the
    // trait method's verifier refuses in its body, in band.
    let from_auth = service.route("notes.get", serde_json::json!({ "id": "OTHER-1" }), None).await;
    assert!(matches!(from_auth, Err(PlexusError::Unauthenticated(_))));
    let by_caller = data(service.route("jottings.get", serde_json::json!({ "id": "OTHER-1" }), None).await.unwrap()).await;
    assert_eq!(by_caller[0]["type"], "error", "{by_caller:?}");
}
