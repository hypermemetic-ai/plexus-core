//! LOCAL-6 — a whole hub, called in memory: the activations' own generated
//! clients over [`HubTransport`] into a `DynamicHub` of two activations, one
//! with a nested child. Through the hub's routing (a child by its path), its
//! gate (refused without the grant, answered with it), its streams (a long
//! one dropped mid-way drops the hub's), and the same client code answering
//! the same over this transport and over the WebSocket.

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_client::{ClientError, ClientEvent};
use plexus_core::plexus::{AuthContext, Gate, HubTransport, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TicketEvent {
    Ticket { id: String, by: Option<String> },
    Linked { id: String, commits: Vec<String>, by: Option<String> },
    Error { message: String },
}

impl plexus_client::FromClientError for TicketEvent {
    fn from_client_error(error: ClientError) -> Self {
        TicketEvent::Error { message: error.to_string() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TickEvent {
    Tick { n: u64 },
    Error { message: String },
}

impl plexus_client::FromClientError for TickEvent {
    fn from_client_error(error: ClientError) -> Self {
        TickEvent::Error { message: error.to_string() }
    }
}

#[derive(Clone)]
pub struct TicketsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "LOCAL-6 parent",
    roles(viewer = ["get"]),
)]
impl TicketsActivation {
    /// One ticket, and who asked.
    #[plexus_macros::method(target = "id")]
    pub async fn get(&self, auth: Option<&AuthContext>, id: String) -> impl Stream<Item = TicketEvent> + Send + 'static {
        let by = auth.map(|a| a.user_id.clone());
        stream! { yield TicketEvent::Ticket { id, by }; }
    }

    /// The commits that finished a ticket.
    #[plexus_macros::child]
    pub fn commits(&self) -> CommitsActivation {
        CommitsActivation
    }
}

#[derive(Clone)]
pub struct CommitsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "LOCAL-6 nested child",
    roles(editor = ["link"]),
)]
impl CommitsActivation {
    /// Link commits to a ticket.
    #[plexus_macros::method(target = "id")]
    pub async fn link(&self, auth: Option<&AuthContext>, id: String, commits: Vec<String>) -> impl Stream<Item = TicketEvent> + Send + 'static {
        let by = auth.map(|a| a.user_id.clone());
        stream! { yield TicketEvent::Linked { id, commits, by }; }
    }
}

/// Set when a `ticks` stream is dropped, wherever it was dropped from.
static TICKS_DROPPED: AtomicBool = AtomicBool::new(false);
/// How many ticks the hub produced.
static TICKS_MADE: AtomicUsize = AtomicUsize::new(0);

struct DropFlag;
impl Drop for DropFlag {
    fn drop(&mut self) {
        TICKS_DROPPED.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct ClockActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "LOCAL-6 second activation: a long stream",
    roles(viewer = ["ticks", "count"]),
)]
impl ClockActivation {
    /// Ticks until the caller stops listening.
    #[plexus_macros::method(streaming)]
    pub async fn ticks(&self) -> impl Stream<Item = TickEvent> + Send + 'static {
        stream! {
            let _flag = DropFlag;
            let mut n = 0u64;
            loop {
                TICKS_MADE.fetch_add(1, Ordering::SeqCst);
                yield TickEvent::Tick { n };
                n += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    /// `n` ticks, then the end.
    #[plexus_macros::method(streaming)]
    pub async fn count(&self, n: u64) -> impl Stream<Item = TickEvent> + Send + 'static {
        stream! { for i in 0..n { yield TickEvent::Tick { n: i }; } }
    }
}

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Members {
    fn add(&self, who: &str, role: &str, scope: &str) {
        self.0.lock().unwrap().push(Membership {
            principal: who.parse().unwrap(),
            role: plexus_auth_core::RoleName::new(role),
            scope: ScopeRef::parse(scope),
        });
    }
}
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
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

fn plain_hub() -> DynamicHub {
    DynamicHub::new("local").register(TicketsActivation).register(ClockActivation)
}

/// ADA: editor on MENGER (viewer below it); BOB: viewer everywhere.
fn gated_hub() -> Arc<DynamicHub> {
    let members = Arc::new(Members::default());
    members.add(ADA, "editor", "MENGER");
    members.add(ADA, "viewer", "MENGER");
    members.add(BOB, "viewer", "*");
    let declared = plain_hub().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let gate = Gate::new(members, Arc::new(roles), Arc::new(Shortcodes));
    Arc::new(plain_hub().with_gate(Arc::new(gate)))
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::json!({"session_key": "k1"}))
}

/// A refusal as the client sees it: the wire's in-band `error`, with the
/// gate's code (`-32001` sign in first, `-32003` forbidden).
fn assert_refused<T: std::fmt::Debug>(r: Result<Vec<T>, ClientError>, want: &str) {
    match r {
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code.as_deref(), Some(want), "{message}");
        }
        other => panic!("expected the gate's refusal, got {other:?}"),
    }
}

fn assert_forbidden<T: std::fmt::Debug>(r: Result<Vec<T>, ClientError>) {
    assert_refused(r, "-32003")
}

#[tokio::test]
async fn a_generated_client_reaches_both_activations_and_the_nested_child() {
    let hub = Arc::new(plain_hub());
    let t = HubTransport::anonymous(hub);
    let tickets = TicketsClient::new(t.clone());
    assert_eq!(
        tickets.get_all("MENGER-1".into()).await.unwrap(),
        vec![TicketEvent::Ticket { id: "MENGER-1".into(), by: None }]
    );
    // tickets.commits.link — the child by its path.
    assert_eq!(
        tickets.commits().link_all("MENGER-1".into(), vec!["abc".into()]).await.unwrap(),
        vec![TicketEvent::Linked { id: "MENGER-1".into(), commits: vec!["abc".into()], by: None }]
    );
    let clock = ClockClient::new(t);
    assert_eq!(clock.count_all(3).await.unwrap().len(), 3);
}

#[tokio::test]
async fn the_gate_refuses_without_the_grant_and_answers_with_it() {
    let hub = gated_hub();

    // Anonymous: nothing but the hub's anonymous view.
    let anon = TicketsClient::new(HubTransport::anonymous(hub.clone()));
    assert_refused(anon.get_all("MENGER-1".into()).await, "-32001");

    // BOB views everywhere, edits nowhere: get yes, the child's link no.
    let bob = TicketsClient::new(HubTransport::as_(hub.clone(), who(BOB)));
    assert_eq!(
        bob.get_all("MENGER-1".into()).await.unwrap(),
        vec![TicketEvent::Ticket { id: "MENGER-1".into(), by: Some(BOB.into()) }],
        "the caller reaches the method",
    );
    assert_forbidden(bob.commits().link_all("MENGER-1".into(), vec!["abc".into()]).await);

    // ADA edits MENGER: the link is answered there, refused outside it.
    let ada = TicketsClient::new(HubTransport::as_(hub.clone(), who(ADA)));
    assert_eq!(
        ada.commits().link_all("MENGER-1".into(), vec!["abc".into()]).await.unwrap(),
        vec![TicketEvent::Linked { id: "MENGER-1".into(), commits: vec!["abc".into()], by: Some(ADA.into()) }]
    );
    assert_forbidden(ada.commits().link_all("OTHER-1".into(), vec!["abc".into()]).await);
    assert_forbidden(ada.get_all("OTHER-1".into()).await);
}

#[tokio::test]
async fn an_unknown_method_is_answered_in_band_as_the_wire_does() {
    let t = HubTransport::anonymous(Arc::new(plain_hub()));
    let mut s = plexus_client::Transport::call(&t, plexus_client::MethodRef::new("nowhere", "x"), serde_json::json!({}));
    match s.next().await {
        Some(Ok(plexus_client::StreamItem::Error { message, .. })) => assert!(message.contains("nowhere"), "{message}"),
        other => panic!("expected an in-band error, got {other:?}"),
    }
    assert!(s.next().await.is_none(), "the error is the last item");
}

#[tokio::test]
async fn a_long_stream_streams_through_and_dropping_it_drops_the_hubs() {
    let clock = ClockClient::new(HubTransport::as_(gated_hub(), who(BOB)));
    let mut ticks = clock.ticks();
    for want in 0..3u64 {
        match ticks.next().await {
            Some(Ok(ClientEvent::Data(TickEvent::Tick { n }))) => assert_eq!(n, want),
            other => panic!("expected tick {want}, got {other:?}"),
        }
    }
    assert!(!TICKS_DROPPED.load(Ordering::SeqCst), "still streaming");
    drop(ticks);
    assert!(TICKS_DROPPED.load(Ordering::SeqCst), "the hub's stream went with the client's");
    let made = TICKS_MADE.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(TICKS_MADE.load(Ordering::SeqCst), made, "nothing ticks after the drop");
}

/// The same client code, over the WebSocket and in memory.
async fn conversation<T: plexus_client::Transport>(t: T) -> Vec<String> {
    let tickets = TicketsClient::new(t);
    let mut out = vec![
        format!("{:?}", tickets.get_all("MENGER-7".into()).await),
        format!("{:?}", tickets.commits().link_all("MENGER-7".into(), vec!["a".into(), "b".into()]).await),
    ];
    let clock = ClockClient::new(tickets.transport());
    out.push(format!("{:?}", clock.count_all(4).await));
    out
}

#[tokio::test]
async fn the_same_client_answers_the_same_over_the_websocket_and_in_memory() {
    let hub = Arc::new(plain_hub());
    let module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(module);

    let ws = plexus_client::WsTransport::connect(&format!("ws://{addr}"), "local").await.unwrap();
    let over_ws = conversation(ws).await;
    let in_memory = conversation(HubTransport::anonymous(hub)).await;
    assert_eq!(over_ws, in_memory);
    assert!(over_ws.iter().all(|s| s.starts_with("Ok(")), "{over_ws:?}");

    handle.stop().unwrap();
}
