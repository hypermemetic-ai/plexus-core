//! BIDIR-5 — the gate over a duplex call: at open, while items stream in,
//! the ceilings, who may answer, a call into a client, and a hop. Each test
//! is one row of the ticket's `tests` cases, (a)…(f); the two `perf_` tests
//! are its `perf` field (`--ignored`, run in release).

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_auth_core::duplex::{hop_identity, Answerer, CallCeiling, FOR_KEY};
use plexus_core::plexus::duplex_gate::{ConnId, ConnectionCalls, DuplexGate, DuplexRefusal, GrantsGeneration, InputFrame};
use plexus_core::plexus::{
    error_item, AuthContext, ForbiddenItem, Gate, Membership, Memberships, PlexusStream, PlexusStreamItem, Resolve,
    RoleTable, ScopeRef,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HUB_A: &str = "key:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const SERVER: &str = "key:5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
const OWNER: &str = "idp:0b6f4c2e-8f7a-4d3b-9c1e-2a5d7e9f1b3c";

// ---------------------------------------------------------------- fixture

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
    fn revoke(&self, who: &str) {
        let p: plexus_auth_core::identity::Principal = who.parse().unwrap();
        self.0.lock().unwrap().retain(|m| m.principal != p);
    }
}
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// The same table indexed by principal, as a service keeps it (the perf
/// tests: a linear scan of 3,000 rows would measure the fixture).
#[derive(Default)]
struct Indexed(Mutex<std::collections::HashMap<String, Vec<Membership>>>);
impl Indexed {
    fn add(&self, who: &str, role: &str, scope: &str) {
        self.0.lock().unwrap().entry(who.to_string()).or_default().push(Membership {
            principal: who.parse().unwrap(),
            role: plexus_auth_core::RoleName::new(role),
            scope: ScopeRef::parse(scope),
        });
    }
    fn revoke(&self, who: &str) {
        self.0.lock().unwrap().remove(who);
    }
}
impl Memberships for Indexed {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().get(&who.to_string()).cloned().unwrap_or_default()
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

fn roles() -> RoleTable {
    RoleTable::new()
        .define("viewer", ["runs.get"])
        .unwrap()
        .define("editor", ["viewer", "runs.append_log"])
        .unwrap()
        .define("approver", ["runs.approve"])
        .unwrap()
}

fn gate(m: &Arc<Members>) -> Gate {
    Gate::new(m.clone(), Arc::new(roles()), Arc::new(Shortcodes))
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), format!("sess-{}", &p[..6]), vec![], Value::Null)
}

/// Ada edits MENGER, Bob views it, the owner approves there.
fn members() -> Arc<Members> {
    let m = Arc::new(Members::default());
    m.add(ADA, "editor", "MENGER");
    m.add(BOB, "viewer", "MENGER");
    m.add(OWNER, "approver", "MENGER");
    m
}

fn frame(from: u64, seq: u64) -> InputFrame {
    InputFrame::new(ConnId(from), seq, json!({ "line": format!("line {seq}") }))
}

const C1: ConnId = ConnId(1);
const C2: ConnId = ConnId(2);

// ---------------------------------------------------------------- (a) open

#[tokio::test]
async fn a_open_without_the_grant_is_refused_typed_before_the_call_opens() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let err = dg
        .open(C1, &conn, Some(&who(BOB)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller)
        .err()
        .expect("a viewer may not open append_log");
    let item = error_item("menger", &err.clone().into_plexus().expect("a gate refusal"));
    let item = serde_json::to_value(&item).unwrap();
    let f = ForbiddenItem::from_item(&item).expect("typed forbidden");
    assert_eq!(f.grant, "runs.append_log");
    assert_eq!(f.scope, "MENGER");
    assert_eq!(f.held_on, Vec::<String>::new());
    assert!(f.roles.contains(&"editor".to_string()));
    assert_eq!(err.kind(), "forbidden");
    // Nothing opened: no place taken, and the gate asked exactly once.
    assert_eq!(conn.open_count(), 0);
    assert_eq!(dg.gate_checks(), 1);
    // Anonymous: unauthenticated, before the call opens too.
    let err = dg.open(C1, &conn, None, "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller).err().unwrap();
    assert_eq!(err.kind(), "unauthenticated");
    assert_eq!(conn.open_count(), 0);
}

// ---------------------------------------------------------------- (b) mid-stream

/// A handler that collects its input: each `Ok` item, then the error that
/// ended it, if any.
async fn drain(input: impl Stream<Item = Result<Value, DuplexRefusal>>) -> (Vec<Value>, Option<DuplexRefusal>) {
    futures::pin_mut!(input);
    let (mut ok, mut end) = (Vec::new(), None);
    while let Some(i) = input.next().await {
        match i {
            Ok(v) => ok.push(v),
            Err(e) => {
                assert!(end.is_none(), "one error, then the end");
                end = Some(e);
            }
        }
    }
    (ok, end)
}

#[tokio::test]
async fn b_a_revoke_mid_stream_ends_the_input_with_forbidden_and_drops_what_follows() {
    let m = members();
    let generation = GrantsGeneration::new();
    let dg = DuplexGate::new(gate(&m), generation.clone());
    let conn = ConnectionCalls::new(4);
    let call = dg
        .open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller)
        .expect("an editor opens");
    let (tx, rx) = mpsc::unbounded_channel();
    let (refused_tx, _refused_rx) = mpsc::unbounded_channel();
    let input = call.input(UnboundedReceiverStream::new(rx), refused_tx);
    let (got_tx, mut got_rx) = mpsc::unbounded_channel();
    let handler = tokio::spawn(async move {
        futures::pin_mut!(input);
        let mut ok = Vec::new();
        while let Some(i) = input.next().await {
            match i {
                Ok(v) => {
                    ok.push(v);
                    let _ = got_tx.send(());
                }
                Err(e) => return (ok, Some(e)),
            }
        }
        (ok, None)
    });
    for seq in 0..3 {
        tx.send(frame(1, seq)).unwrap();
        got_rx.recv().await.unwrap();
    }
    m.revoke(ADA);
    generation.bump();
    let (ok, end) = handler.await.unwrap();
    assert_eq!(ok.len(), 3);
    let end = end.expect("the input ends with the refusal");
    assert_eq!(end.kind(), "forbidden");
    assert!(ForbiddenItem::from_item(&end.to_item("menger")).is_some(), "typed forbidden {{grant, scope, held_on}}");
    // What follows is dropped: the half is closed, nothing reads it.
    let dropped = (3..5).filter(|seq| tx.send(frame(1, *seq)).is_err()).count();
    assert_eq!(dropped, 2);
    assert_eq!(conn.open_count(), 0, "the call's place is given back with it");
}

#[tokio::test]
async fn b_a_quiet_call_ends_at_the_revoke_not_at_its_next_item() {
    let m = members();
    let generation = GrantsGeneration::new();
    let dg = DuplexGate::new(gate(&m), generation.clone());
    let conn = ConnectionCalls::new(4);
    let call = dg
        .open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller)
        .unwrap();
    let (_tx, rx) = mpsc::unbounded_channel::<InputFrame>();
    let (refused_tx, _r) = mpsc::unbounded_channel();
    let handler = tokio::spawn(drain(call.input(UnboundedReceiverStream::new(rx), refused_tx)));
    tokio::time::sleep(Duration::from_millis(10)).await;
    m.revoke(ADA);
    let at = Instant::now();
    generation.bump();
    let (ok, end) = tokio::time::timeout(Duration::from_millis(50), handler).await.expect("ends within a tick").unwrap();
    eprintln!("revoke → input closed (quiet call): {:?}", at.elapsed());
    assert!(ok.is_empty());
    assert_eq!(end.unwrap().kind(), "forbidden");
}

#[tokio::test]
async fn b_gate_checks_are_per_call_and_per_generation_move_never_per_item() {
    let m = members();
    let generation = GrantsGeneration::new();
    let dg = DuplexGate::new(gate(&m), generation.clone());
    let conn = ConnectionCalls::new(4);
    let ceiling = CallCeiling { credit: 10_000, ..CallCeiling::default() };
    let mut call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), ceiling, Answerer::Caller).unwrap();
    for seq in 0..1000 {
        call.admit(&frame(1, seq)).unwrap();
    }
    assert_eq!(dg.gate_checks(), 1, "once at open, none per item");
    generation.bump(); // a grant elsewhere: Ada still holds hers
    for seq in 1000..2000 {
        call.admit(&frame(1, seq)).unwrap();
    }
    assert_eq!(dg.gate_checks(), 2, "and once per generation move");
}

// ---------------------------------------------------------------- (c) ceilings

#[tokio::test]
async fn c_a_duplex_call_counts_toward_calls_per_connection() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(2);
    let watch = conn.try_open().expect("a stream-out call takes a place");
    let duplex = dg
        .open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller)
        .unwrap();
    assert_eq!(conn.open_count(), 2);
    let err = dg
        .open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-2"), CallCeiling::default(), Answerer::Caller)
        .err()
        .unwrap();
    assert_eq!(err.kind(), "too_many_calls");
    assert_eq!(err.to_item("menger")["max"], 2);
    drop(duplex);
    assert_eq!(conn.open_count(), 1);
    drop(watch);
    assert_eq!(conn.open_count(), 0);
}

#[tokio::test]
async fn c_an_item_past_credit_is_a_typed_error_and_ends_the_call() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let ceiling = CallCeiling { credit: 2, ..CallCeiling::default() };
    let call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), ceiling, Answerer::Caller).unwrap();
    let frames = futures::stream::iter((0..4).map(|s| frame(1, s)));
    let (refused_tx, _r) = mpsc::unbounded_channel();
    let (ok, end) = drain(call.input(frames, refused_tx)).await;
    assert_eq!(ok.len(), 2);
    let end = end.unwrap();
    assert_eq!(end.kind(), "past_credit");
    let item = end.to_item("menger");
    assert_eq!((item["seq"].as_u64(), item["credit"].as_u64()), (Some(2), Some(2)));
    // More credit granted: the next items are taken.
    let mut call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), ceiling, Answerer::Caller).unwrap();
    call.admit(&frame(1, 0)).unwrap();
    call.admit(&frame(1, 1)).unwrap();
    call.grant_credit(2);
    call.admit(&frame(1, 2)).unwrap();
}

#[tokio::test]
async fn c_an_item_past_the_ceiling_is_too_much_input() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let by_items = CallCeiling { credit: 100, max_items: 3, max_bytes: u64::MAX };
    let mut call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), by_items, Answerer::Caller).unwrap();
    for s in 0..3 {
        call.admit(&frame(1, s)).unwrap();
    }
    let e = call.admit(&frame(1, 3)).unwrap_err();
    assert_eq!(e.kind(), "too_much_input");
    assert_eq!(e.to_item("menger")["limit"], "items");
    assert!(call.admit(&frame(1, 4)).is_err(), "the half stays closed");
    let by_bytes = CallCeiling { credit: 100, max_items: 100, max_bytes: 40 };
    let mut call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), by_bytes, Answerer::Caller).unwrap();
    call.admit(&frame(1, 0)).unwrap(); // {"line":"line 0"} is 17 bytes
    call.admit(&frame(1, 1)).unwrap();
    let e = call.admit(&frame(1, 2)).unwrap_err();
    assert_eq!(e.to_item("menger")["limit"], "bytes");
}

// ---------------------------------------------------------------- (d) who answers

#[tokio::test]
async fn d_an_item_from_another_connection_is_refused_and_the_call_runs_on() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller).unwrap();
    let frames = futures::stream::iter(vec![frame(1, 0), frame(2, 1), frame(1, 1)]);
    let (refused_tx, mut refused_rx) = mpsc::unbounded_channel();
    let (ok, end) = drain(call.input(frames, refused_tx)).await;
    assert_eq!(ok.len(), 2, "the caller's two items reach the handler; the stranger's does not");
    assert!(end.is_none(), "the call runs on");
    let (to, item) = refused_rx.recv().await.expect("the stranger is told");
    assert_eq!(to, C2);
    assert_eq!(item["error_kind"], "not_this_call");
}

#[tokio::test]
async fn d_a_question_that_requires_a_person_refuses_an_agents_answer() {
    let m = members();
    m.add(OWNER, "editor", "MENGER");
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let agent_call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Person).unwrap();
    let e = agent_call.answer(C1, Some(&who(ADA))).unwrap_err();
    assert_eq!(e.kind(), "person_required");
    let person_call = dg.open(C2, &conn, Some(&who(OWNER)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Person).unwrap();
    person_call.answer(C2, Some(&who(OWNER))).expect("a person answers their own call's question");
    assert_eq!(person_call.answer(C1, Some(&who(OWNER))).unwrap_err().kind(), "not_this_call");
}

#[tokio::test]
async fn d_a_question_answerable_by_grant_takes_another_connection_holding_it() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let call = dg
        .open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Grant("runs.approve".into()))
        .unwrap();
    call.answer(ConnId(9), Some(&who(OWNER))).expect("the owner holds runs.approve on MENGER");
    let e = call.answer(ConnId(8), Some(&who(BOB))).unwrap_err();
    assert_eq!(e.kind(), "forbidden");
    assert_eq!(e.to_item("menger")["grant"], "runs.approve");
    assert_eq!(call.answer(C1, Some(&who(ADA))).unwrap_err().kind(), "forbidden", "even the caller needs the grant");
    // The default: the call's own connection, as its caller.
    let own = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller).unwrap();
    own.answer(C1, Some(&who(ADA))).unwrap();
    assert_eq!(own.answer(C2, Some(&who(OWNER))).unwrap_err().kind(), "not_this_call");
}

// ---------------------------------------------------------------- (e) into a client

#[derive(Clone)]
struct LocalActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "BIDIR-5: what a client offers the server it is connected to",
    roles(peer = ["confirm"], owner = [peer, "read_file"]),
)]
impl LocalActivation {
    /// Ask the person at the client to confirm: who asks, and for whom.
    #[plexus_macros::method]
    async fn confirm(&self, auth: &AuthContext) -> impl Stream<Item = String> + Send + 'static {
        let asker = auth.user_id.clone();
        let for_ = auth.metadata.get(FOR_KEY).cloned().unwrap_or(Value::Null).to_string();
        stream! { yield format!("{asker} for {for_}"); }
    }

    /// A file on the client's disk: never offered to a peer.
    #[plexus_macros::method]
    async fn read_file(&self, path: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield path; }
    }
}

async fn first(stream: PlexusStream) -> Value {
    let items: Vec<PlexusStreamItem> = stream.collect().await;
    for i in items {
        match i {
            PlexusStreamItem::Data { content, .. } => return content,
            PlexusStreamItem::Error { .. } => return serde_json::to_value(&i).unwrap(),
            _ => {}
        }
    }
    Value::Null
}

#[track_caller]
fn refusal(r: Result<PlexusStream, PlexusError>) -> PlexusError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected the gate to refuse"),
    }
}

#[tokio::test]
async fn e_a_call_into_a_client_is_gated_by_the_clients_gate_as_the_peer() {
    // The client's own hub and gate: the server it connected to holds `peer`.
    let m = Arc::new(Members::default());
    m.add(SERVER, "peer", "*");
    let declared = DynamicHub::new("client").register(LocalActivation).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let client = DynamicHub::new("client")
        .register(LocalActivation)
        .with_gate(Arc::new(Gate::new(m.clone(), Arc::new(roles), Arc::new(Shortcodes))));
    // The server's call, on behalf of Ada, into the client: the peer on that
    // connection is the server's key; Ada is named, and grants nothing.
    let ctx = hop_identity(&who(SERVER), &who(ADA), &[ScopeRef::Everywhere]);
    let answer = first(client.route("local.confirm", json!({}), Some(&ctx)).await.unwrap()).await;
    let answer = answer.as_str().unwrap().to_string();
    assert!(answer.starts_with(&SERVER[4..]) || answer.contains(&SERVER[4..]), "the client's gate sees the server: {answer}");
    assert!(answer.contains(ADA), "and whom it asks for: {answer}");
    // What the client did not offer the peer is refused, typed.
    let err = refusal(client.route("local.read_file", json!({ "path": "/etc/passwd" }), Some(&ctx)).await);
    let item = serde_json::to_value(error_item("client", &err)).unwrap();
    assert_eq!(ForbiddenItem::from_item(&item).expect("typed").grant, "local.read_file");
    // Ada herself holds nothing on the client: naming her does not lend it.
    m.add(ADA, "owner", "*");
    let err = refusal(client.route("local.read_file", json!({ "path": "/etc/passwd" }), Some(&ctx)).await);
    assert!(matches!(err, PlexusError::Forbidden { .. }));
    // A peer nobody proved is anonymous: nothing.
    let err = refusal(client.route("local.confirm", json!({}), None).await);
    assert!(matches!(err, PlexusError::Unauthenticated(_)));
}

// ---------------------------------------------------------------- (f) a hop

#[derive(Clone)]
struct CiActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "BIDIR-5: hub B's method a hop calls",
    roles(runner = ["run"]),
)]
impl CiActivation {
    /// Run a job for a ticket: who B sees, and for whom.
    #[plexus_macros::method(target = "id")]
    async fn run(&self, auth: &AuthContext, id: String) -> impl Stream<Item = String> + Send + 'static {
        let seen = json!({ "id": id, "principal": auth.metadata.get("principal"), "for": auth.metadata.get(FOR_KEY) });
        stream! { yield seen.to_string(); }
    }
}

/// What `ci.run` saw, from its JSON line.
fn seen_by_b(v: Value) -> Value {
    serde_json::from_str(v.as_str().expect("a line")).unwrap()
}

fn hub_b(m: &Arc<Members>) -> DynamicHub {
    let declared = DynamicHub::new("b").register(CiActivation).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    DynamicHub::new("b").register(CiActivation).with_gate(Arc::new(Gate::new(m.clone(), Arc::new(roles), Arc::new(Shortcodes))))
}

#[tokio::test]
async fn f_a_hop_carries_the_hop_and_whom_it_acts_for_and_b_redecides() {
    // On B: hub A's key runs jobs on MENGER and PLEXUS; Ada runs them everywhere.
    let m = Arc::new(Members::default());
    m.add(HUB_A, "runner", "MENGER");
    m.add(HUB_A, "runner", "PLEXUS");
    m.add(ADA, "runner", "*");
    let b = hub_b(&m);
    // A admitted Ada on MENGER (A's verdict), and forwards.
    let hop = hop_identity(&who(HUB_A), &who(ADA), &[ScopeRef::named("MENGER")]);
    let seen = seen_by_b(first(b.route("ci.run", json!({ "id": "MENGER-1" }), Some(&hop)).await.unwrap()).await);
    assert_eq!(seen["principal"], HUB_A, "B decides for the hop");
    assert_eq!(seen["for"], json!([ADA]), "and names whom it acts for");
    // Outside A's verdict: refused, though A's key holds it on B.
    let err = refusal(b.route("ci.run", json!({ "id": "PLEXUS-1" }), Some(&hop)).await);
    assert!(matches!(err, PlexusError::Forbidden { .. }), "the verdict is a ceiling: {err:?}");
    // A's key without the grant on B: refused, though Ada holds it there.
    m.revoke(HUB_A);
    let err = refusal(b.route("ci.run", json!({ "id": "MENGER-1" }), Some(&hop)).await);
    assert!(matches!(err, PlexusError::Forbidden { .. }), "no confused deputy: {err:?}");
    // Two hops: the chain names both, nearest first.
    m.add(HUB_A, "runner", "*");
    let hop2 = hop_identity(&who(SERVER), &hop, &[ScopeRef::Everywhere]);
    m.add(SERVER, "runner", "*");
    let seen = seen_by_b(first(b.route("ci.run", json!({ "id": "MENGER-1" }), Some(&hop2)).await.unwrap()).await);
    assert_eq!(seen["for"], json!([HUB_A, ADA]));
    // A ceiling the hop carried is kept: the second hop is no wider than MENGER.
    let err = refusal(b.route("ci.run", json!({ "id": "PLEXUS-1" }), Some(&hop2)).await);
    assert!(matches!(err, PlexusError::Forbidden { .. }));
}

#[tokio::test]
async fn f_a_hop_never_carries_a_credential() {
    let ada = AuthContext::for_principal(
        &ADA.parse().unwrap(),
        "ada-SECRET-session",
        vec!["editor".into()],
        json!({ "session_key": "sk-SECRET", "token": "tok-SECRET", "proof": "plexus-key.SECRET", "expires_at": 9_999_999_999i64 }),
    );
    let hop = hop_identity(&who(HUB_A), &ada, &[ScopeRef::named("MENGER")]);
    let wire = serde_json::to_string(&hop).unwrap();
    assert!(!wire.contains("SECRET"), "nothing of the caller's credential crosses: {wire}");
    assert_eq!(hop.session_id, who(HUB_A).session_id, "the hop's own session on B");
    assert!(hop.roles.is_empty(), "the caller's roles stay behind");
    assert_eq!(hop.principal().unwrap().to_string(), HUB_A);
}

// ---------------------------------------------------------------- perf

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf: cargo test --release --test duplex_gate perf_ -- --ignored --nocapture"]
async fn perf_reverify_1000_open_calls() {
    // 1,000 calls are 1,000 principals, each an editor on MENGER.
    let m = Arc::new(Indexed::default());
    let keys: Vec<String> = (0..1000).map(|i| format!("key:{i:064x}")).collect();
    for k in &keys {
        m.add(k, "editor", "MENGER");
    }
    let generation = GrantsGeneration::new();
    let dg = DuplexGate::new(Gate::new(m.clone(), Arc::new(roles()), Arc::new(Shortcodes)), generation.clone());
    let conn = ConnectionCalls::new(2000);
    // (1) the cost of one move, synchronously: every call verified again.
    let mut calls: Vec<_> = keys
        .iter()
        .map(|k| dg.open(C1, &conn, Some(&who(k)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller).unwrap())
        .collect();
    let mut runs = Vec::new();
    for _ in 0..20 {
        generation.bump();
        let at = Instant::now();
        for c in calls.iter_mut() {
            c.reverify().unwrap();
        }
        runs.push(at.elapsed().as_nanos() as f64);
    }
    runs.sort_by(f64::total_cmp);
    eprintln!(
        "PERF reverify 1000 calls per generation move: p50 {:.0} µs ({:.0} ns/call), p99 {:.0} µs",
        percentile(&runs, 0.5) / 1e3,
        percentile(&runs, 0.5) / 1000.0,
        percentile(&runs, 0.99) / 1e3
    );
    drop(calls);
    // (2) revoke → every input half closed, 1,000 quiet calls on tasks.
    let mut senders = Vec::new();
    let mut handlers = Vec::new();
    for k in &keys {
        let call = dg.open(C1, &conn, Some(&who(k)), "runs.append_log", Some("MENGER-1"), CallCeiling::default(), Answerer::Caller).unwrap();
        let (tx, rx) = mpsc::unbounded_channel::<InputFrame>();
        let (rtx, _rrx) = mpsc::unbounded_channel();
        senders.push((tx, _rrx));
        handlers.push(tokio::spawn(drain(call.input(UnboundedReceiverStream::new(rx), rtx))));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let checks_before = dg.gate_checks();
    for k in &keys {
        m.revoke(k);
    }
    let at = Instant::now();
    generation.bump();
    for h in handlers {
        let (_, end) = h.await.unwrap();
        assert_eq!(end.unwrap().kind(), "forbidden");
    }
    eprintln!(
        "PERF revoke → 1000 input halves closed: {:?} ({} gate checks for the move)",
        at.elapsed(),
        dg.gate_checks() - checks_before
    );
}

#[tokio::test]
#[ignore = "perf: cargo test --release --test duplex_gate perf_ -- --ignored --nocapture"]
async fn perf_per_frame_admit() {
    let m = members();
    let dg = DuplexGate::new(gate(&m), GrantsGeneration::new());
    let conn = ConnectionCalls::new(4);
    let ceiling = CallCeiling { credit: u64::MAX, max_items: u64::MAX, max_bytes: u64::MAX };
    let mut call = dg.open(C1, &conn, Some(&who(ADA)), "runs.append_log", Some("MENGER-1"), ceiling, Answerer::Caller).unwrap();
    let frames: Vec<InputFrame> = (0..1_000_000u64).map(|s| frame(1, s)).collect();
    let mut samples = Vec::new();
    for batch in frames.chunks(100) {
        let at = Instant::now();
        for f in batch {
            std::hint::black_box(call.admit(f)).unwrap();
        }
        samples.push(at.elapsed().as_nanos() as f64 / batch.len() as f64);
    }
    samples.sort_by(f64::total_cmp);
    eprintln!(
        "PERF per-frame admit (no gate): p50 {:.1} ns, p99 {:.1} ns; gate checks {} for 1,000,000 frames",
        percentile(&samples, 0.5),
        percentile(&samples, 0.99),
        dg.gate_checks()
    );
    // For scale: one gate check, as a per-item design would pay.
    let g = gate(&m);
    let ada = who(ADA);
    let grant = plexus_auth_core::grants::Grant::new("runs.append_log");
    let mut per = Vec::new();
    for _ in 0..10_000 {
        let at = Instant::now();
        for _ in 0..10 {
            std::hint::black_box(g.check(Some(&ada), &grant, Some("MENGER-1"))).unwrap();
        }
        per.push(at.elapsed().as_nanos() as f64 / 10.0);
    }
    per.sort_by(f64::total_cmp);
    eprintln!("PERF one gate check (for scale): p50 {:.0} ns, p99 {:.0} ns", percentile(&per, 0.5), percentile(&per, 0.99));
}
