//! ASK-2 — the proposal's matrix (ASK-1's required behaviour, replacing
//! BIDIR-13's in-call question). A method marked `asks` answers a call it
//! would act on with a `needs_input` item and `done`; the caller calls the
//! same method again with the token in `confirm`:
//!
//! | case | answer |
//! | -- | -- |
//! | no token | `needs_input` (summary, effects, fields, token, expires), then `done`; nothing changed |
//! | nothing to change (`n: 0`) | answered directly: "may ask" is not "always asks" |
//! | the token, the plan unmoved, the same caller, unexpired | it proceeds |
//! | the plan moved (another caller moved the store) | a fresh `needs_input`, nothing done |
//! | the same token twice | the second is a fresh proposal: the first moved the store the plan covers |
//! | expired | a fresh proposal |
//! | another caller's token | a fresh proposal |
//! | a token sealed by a replica with the same key | it proceeds |
//! | over the module (`{ns}.call`) | the item on the wire is ASK-1's table, exactly |
//! | through a hop (spec/12) | the item relayed unchanged; the answer an ordinary call; the schema says `asks` |
//!
//! No test harness: this binary is the service and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the ledger as a child on stdio.

use std::sync::{Arc, Mutex};

use async_stream::stream;
use futures::{Stream, StreamExt};
use plexus_core::plexus::ask::{self, ConfirmKey, ConfirmToken, Field, NeedsInput, Proposal};
use plexus_core::plexus::{
    AuthContext, ChildOptions, ChildSpec, Gate, Membership, Memberships, PlexusStream, PlexusStreamItem, RemoteChild,
    Resolve, RoleTable, ScopeRef,
};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LedgerEvent {
    /// What `bump` would do, and the token that does it.
    NeedsInput(NeedsInput),
    /// The ledger moved.
    Bumped { from: u64, to: u64 },
}

impl plexus_client::FromClientError for LedgerEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        panic!("client error: {error}")
    }
}

/// One number; its value is the store's version.
#[derive(Clone, Default)]
pub struct LedgerActivation {
    value: Arc<Mutex<u64>>,
}

#[plexus_macros::activation(version = "1.0.0", description = "ASK-2: a ledger that asks before it moves", roles(viewer = ["bump"]))]
impl LedgerActivation {
    /// Adds `n` to the ledger once its caller has seen what would change.
    #[plexus_macros::method(asks, params(n = "how much to add", confirm = "the proposal's token"))]
    pub async fn bump(&self, n: Option<u64>, confirm: Option<ConfirmToken>) -> impl Stream<Item = LedgerEvent> + Send + 'static {
        let value = Arc::clone(&self.value);
        stream! {
            let from = *value.lock().unwrap();
            if n == Some(0) {
                // Nothing to change: answered directly.
                yield LedgerEvent::Bumped { from, to: from };
                return;
            }
            // The plan: what the caller is shown, and the store version it was read at.
            let plan = json!({ "value": from });
            match (n, ask::check(confirm.as_ref(), &plan)) {
                (Some(n), Ok(())) => {
                    let to = {
                        let mut v = value.lock().unwrap();
                        *v += n;
                        *v
                    };
                    yield LedgerEvent::Bumped { from, to };
                }
                (n, _) => {
                    let summary = match n {
                        Some(n) => format!("add {n} to {from}"),
                        None => format!("add to {from}"),
                    };
                    let mut p = Proposal::new(summary).effect(json!({ "from": from }));
                    if n.is_none() {
                        p = p.field(Field::new("n").default(1).help("how much to add"));
                    }
                    yield LedgerEvent::NeedsInput(ask::propose(&plan, p));
                }
            }
        }
    }
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

/// A call's items, `data` as its content, anything else as its JSON.
async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .map(|i| match i {
            PlexusStreamItem::Data { content, .. } => content.into_value(),
            other => serde_json::to_value(other).unwrap(),
        })
        .collect()
        .await
}

async fn call(hub: &DynamicHub, as_: &str, params: Value) -> Vec<Value> {
    items(hub.route("ledger.bump", params, Some(&who(as_))).await.unwrap()).await
}

/// The proposal a call answered, checked to be one: the item, then `done`.
fn proposal(got: &[Value]) -> NeedsInput {
    assert_eq!(got.len(), 2, "a proposal, then done: {got:?}");
    assert_eq!(got[0]["type"], "needs_input", "{got:?}");
    assert_eq!(got[1]["type"], "done", "{got:?}");
    serde_json::from_value(got[0].clone()).unwrap()
}

fn bumped(got: &[Value]) -> (u64, u64) {
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0]["type"], "bumped", "{got:?}");
    (got[0]["from"].as_u64().unwrap(), got[0]["to"].as_u64().unwrap())
}

fn hub() -> (DynamicHub, LedgerActivation) {
    let ledger = LedgerActivation::default();
    (DynamicHub::new("svc").register(ledger.clone()), ledger)
}

async fn propose_then_confirm() {
    let (hub, ledger) = hub();
    let p = proposal(&call(&hub, ADA, json!({ "n": 2 })).await);
    assert_eq!(p.summary, "add 2 to 0");
    assert_eq!(p.effects, vec![json!({ "from": 0 })]);
    assert!(p.fields.is_empty(), "a plain confirmation has no fields: {p:?}");
    assert!(p.token.as_str().starts_with("v1."), "{}", p.token);
    assert_eq!(*ledger.value.lock().unwrap(), 0, "a proposal changes nothing");
    let got = call(&hub, ADA, json!({ "n": 2, "confirm": p.token })).await;
    assert_eq!(bumped(&got), (0, 2));
}

async fn nothing_to_change_answers_directly() {
    let (hub, _) = hub();
    assert_eq!(bumped(&call(&hub, ADA, json!({ "n": 0 })).await), (0, 0));
}

async fn a_field_is_answered_under_its_own_name() {
    let (hub, _) = hub();
    let p = proposal(&call(&hub, ADA, json!({})).await);
    assert_eq!(serde_json::to_value(&p.fields).unwrap(), json!([{ "name": "n", "default": 1, "help": "how much to add" }]));
    // The answer: the field's value under its parameter's name, and the token.
    assert_eq!(bumped(&call(&hub, ADA, json!({ "n": 5, "confirm": p.token })).await), (0, 5));
}

async fn the_plan_moved_is_a_fresh_proposal() {
    let (hub, ledger) = hub();
    let ada = proposal(&call(&hub, ADA, json!({ "n": 1 })).await);
    // BOB moves the store under ADA's proposal.
    let bob = proposal(&call(&hub, BOB, json!({ "n": 10 })).await);
    assert_eq!(bumped(&call(&hub, BOB, json!({ "n": 10, "confirm": bob.token })).await), (0, 10));
    let again = proposal(&call(&hub, ADA, json!({ "n": 1, "confirm": ada.token })).await);
    assert_eq!(again.summary, "add 1 to 10", "the fresh proposal is of the store as it is now");
    assert_ne!(again.token, ada.token);
    assert_eq!(*ledger.value.lock().unwrap(), 10, "nothing done on the moved plan");
}

async fn the_same_token_twice_is_refused() {
    let (hub, ledger) = hub();
    let p = proposal(&call(&hub, ADA, json!({ "n": 3 })).await);
    assert_eq!(bumped(&call(&hub, ADA, json!({ "n": 3, "confirm": p.token.clone() })).await), (0, 3));
    // The token covered the store's version 0; the first confirm moved it.
    let replay = proposal(&call(&hub, ADA, json!({ "n": 3, "confirm": p.token })).await);
    assert_eq!(replay.summary, "add 3 to 3");
    assert_eq!(*ledger.value.lock().unwrap(), 3, "the replay did nothing");
}

async fn another_callers_token_is_a_fresh_proposal() {
    let (hub, ledger) = hub();
    let p = proposal(&call(&hub, ADA, json!({ "n": 4 })).await);
    proposal(&call(&hub, BOB, json!({ "n": 4, "confirm": p.token.clone() })).await);
    // Anonymous, too.
    let anon = items(hub.route("ledger.bump", json!({ "n": 4, "confirm": p.token }), None).await.unwrap()).await;
    proposal(&anon);
    assert_eq!(*ledger.value.lock().unwrap(), 0);
}

async fn an_expired_or_forged_token_is_a_fresh_proposal() {
    let key = [9u8; 32];
    let ledger = LedgerActivation::default();
    let hub = DynamicHub::new("svc").register(ledger.clone()).with_confirm_key(ConfirmKey::from_bytes(key));
    let plan = json!({ "value": 0 });
    let past = chrono::Utc::now().timestamp() - 1;
    let expired = ConfirmKey::from_bytes(key).seal(ADA, "ledger.bump", &plan, past);
    proposal(&call(&hub, ADA, json!({ "n": 1, "confirm": expired })).await);
    for forged in ["", "v1", "v2.9999999999.AAAA", "v1.9999999999.AAAA"] {
        proposal(&call(&hub, ADA, json!({ "n": 1, "confirm": forged })).await);
    }
    // The same plan, unexpired, under the service's key: it proceeds — the
    // key is the service's, not the process's.
    let good = ConfirmKey::from_bytes(key).seal(ADA, "ledger.bump", &plan, past + 600);
    assert_eq!(bumped(&call(&hub, ADA, json!({ "n": 1, "confirm": good })).await), (0, 1));
}

async fn a_replica_with_the_same_key_confirms() {
    let key = [5u8; 32];
    let ledger = LedgerActivation::default();
    let a = DynamicHub::new("svc").register(ledger.clone()).with_confirm_key(ConfirmKey::from_bytes(key));
    let b = DynamicHub::new("svc").register(ledger.clone()).with_confirm_key(ConfirmKey::from_bytes(key));
    let c = DynamicHub::new("svc").register(ledger.clone());
    let p = proposal(&call(&a, ADA, json!({ "n": 1 })).await);
    proposal(&call(&c, ADA, json!({ "n": 1, "confirm": p.token.clone() })).await);
    assert_eq!(bumped(&call(&b, ADA, json!({ "n": 1, "confirm": p.token })).await), (0, 1));
}

/// The item as `{ns}.call` puts it on the wire: ASK-1's table, exactly.
async fn the_wire_item_is_the_tables() {
    let (hub, _) = hub();
    let module = DynamicHub::arc_into_rpc_module(Arc::new(hub)).unwrap();
    let frame = r#"{"jsonrpc":"2.0","id":1,"method":"svc.call","params":{"method":"ledger.bump","params":{"n":2}}}"#;
    let (resp, mut rx) = module.raw_json_request(frame, 64).await.unwrap();
    assert!(resp.get().contains("\"result\""), "{}", resp.get());
    let mut got = Vec::new();
    loop {
        let line: Value = serde_json::from_str(rx.recv().await.unwrap().get()).unwrap();
        let item = line["params"]["result"].clone();
        let done = item["type"] == "done";
        got.push(item);
        if done {
            break;
        }
    }
    println!("the proposal on the wire: {}", got[0]);
    assert_eq!(got.len(), 2, "{got:?}");
    let item = &got[0];
    assert_eq!(item["type"], "data");
    assert_eq!(item["content_type"], "ledger.bump");
    let c = item["content"].as_object().unwrap();
    let mut keys: Vec<&str> = c.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["effects", "expires", "fields", "summary", "token", "type"]);
    assert_eq!(c["type"], "needs_input");
    assert_eq!(c["summary"], "add 2 to 0");
    assert_eq!(c["effects"], json!([{ "from": 0 }]));
    assert_eq!(c["fields"], json!([]));
    let token = c["token"].as_str().unwrap();
    let mut parts = token.splitn(3, '.');
    assert_eq!(parts.next(), Some("v1"));
    let expiry: i64 = parts.next().unwrap().parse().unwrap();
    assert_eq!(parts.next().unwrap().len(), 43, "base64url of 32 bytes, unpadded: {token}");
    let expires = chrono::DateTime::parse_from_rfc3339(c["expires"].as_str().unwrap()).unwrap();
    assert_eq!(expires.timestamp(), expiry, "`expires` is the token's expiry");
    assert_eq!(got[1]["type"], "done");
}

/// The schema says `asks`, and `confirm` is an ordinary optional parameter
/// of the standard type.
async fn the_schema_says_asks() {
    let (hub, _) = hub();
    let schema = items(hub.route("ledger.schema", json!({ "method": "bump" }), None).await.unwrap()).await;
    let m = &schema[0];
    assert_eq!(m["asks"], true, "{m}");
    assert!(m.get("bidirectional").is_none(), "{m}");
    let params = &m["params"];
    assert!(!params["required"].as_array().map(|r| r.iter().any(|p| p == "confirm")).unwrap_or(false), "{params}");
    let confirm = &params["properties"]["confirm"];
    let s = confirm.to_string();
    assert!(s.contains("ConfirmToken"), "confirm is the standard type: {params}");
    assert_eq!(params["$defs"]["ConfirmToken"]["type"], "string", "{params}");
}

// ------------------------------------------------------------------ the hop

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}
struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

async fn mounted() -> RemoteChild {
    let exe = std::env::current_exe().unwrap();
    let spec: ChildSpec = format!("ledger=stdio:{}", exe.display()).parse().unwrap();
    RemoteChild::connect(spec, ChildOptions::for_service("svc")).await.expect("the ledger mounts")
}

/// ADA and BOB view everywhere.
fn gated(child: &RemoteChild) -> DynamicHub {
    let plain = DynamicHub::new("svc").register(child.clone());
    let members = Arc::new(Members::default());
    for p in [ADA, BOB] {
        members.0.lock().unwrap().push(Membership {
            principal: p.parse().unwrap(),
            role: plexus_auth_core::RoleName::new("viewer"),
            scope: ScopeRef::Everywhere,
        });
    }
    let declared = plain.declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    DynamicHub::new("svc").register(child.clone()).with_gate(Arc::new(Gate::new(members, Arc::new(roles), Arc::new(Everywhere))))
}

async fn through_a_hop_unchanged() {
    let child = mounted().await;
    let service = gated(&child);
    // The mount read the child's schema: `asks` crossed.
    let schema = items(service.route("ledger.schema", json!({ "method": "bump" }), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(schema[0]["asks"], true, "{:?}", schema[0]);
    // The proposal, relayed as the child made it.
    let raw = service.route("ledger.bump", json!({ "n": 2 }), Some(&who(ADA))).await.unwrap();
    let raw: Vec<PlexusStreamItem> = raw.collect().await;
    match &raw[0] {
        PlexusStreamItem::Data { content_type, .. } => assert_eq!(content_type, "ledger.bump"),
        other => panic!("{other:?}"),
    }
    let got: Vec<Value> = raw.into_iter().map(|i| match i {
        PlexusStreamItem::Data { content, .. } => content.into_value(),
        other => serde_json::to_value(other).unwrap(),
    }).collect();
    let p = proposal(&got);
    // Sealed in the child for the caller the hop names: BOB cannot use it.
    let bob = call(&service, BOB, json!({ "n": 2, "confirm": p.token.clone() })).await;
    proposal(&bob);
    // The answer is an ordinary call through the same hop.
    let (from, to) = bumped(&call(&service, ADA, json!({ "n": 2, "confirm": p.token.clone() })).await);
    assert_eq!(to, from + 2);
    // And the replay, through the hop too, is a fresh proposal.
    proposal(&call(&service, ADA, json!({ "n": 2, "confirm": p.token })).await);
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        // Run by the seam: be the ledger on stdio.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(LedgerActivation::default())).unwrap();
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    let mut n = 0;
    macro_rules! run {
        ($($t:ident),* $(,)?) => {$(
            rt.block_on($t());
            println!("test {} ... ok", stringify!($t));
            n += 1;
        )*};
    }
    run!(
        propose_then_confirm,
        nothing_to_change_answers_directly,
        a_field_is_answered_under_its_own_name,
        the_plan_moved_is_a_fresh_proposal,
        the_same_token_twice_is_refused,
        another_callers_token_is_a_fresh_proposal,
        an_expired_or_forged_token_is_a_fresh_proposal,
        a_replica_with_the_same_key_confirms,
        the_wire_item_is_the_tables,
        the_schema_says_asks,
        through_a_hop_unchanged,
    );
    println!("\ntest result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
}
