//! KEEL-59, review round 2 · what the hold may cut, and whose move it is.
//!
//! - **N1:** a method's body (the call still being routed: a unary method's
//!   whole work) is held only to "the grant is held somewhere" and to the
//!   sign-in's end. A third party's grant-then-revoke on a scope of its own
//!   — which ends another caller's targetless *stream* — never cuts that
//!   caller's *body* between its steps; nor a body on a target, nor one
//!   admitted on `*`. A body whose caller holds the grant nowhere is still
//!   dropped.
//! - **N2:** a caller whose own write takes its right reads the write's
//!   answer: the call that moves the grants generation is not asked about
//!   its own move — whether plexus-core's `auth` moves it after the write or
//!   the tenant's store moves its own generation inside the write
//!   (`AuthSetup::with_generation`, as menger). Once only: a later move, by
//!   anything else, is asked as usual.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use plexus_auth_core::grants::{GrantsGeneration, GrantsMove};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::RoleName;
use plexus_core::plexus::{AuthSetup, Membership, MembershipStore, Memberships, MemoryAuthBackend, MemoryRoles, ScopeRef, StoreError};
use plexus_core::DynamicHub;
use plexus_testkit::parts::{who, Members, Shortcodes};
use plexus_testkit::Caller;
use serde_json::{json, Value};

const ALICE: &str = "key:a11ce00000000000000000000000000000000000000000000000000000000000";
const BOB: &str = "key:b0b0000000000000000000000000000000000000000000000000000000000000";

/// How many times each step of the two-step write ran.
#[derive(Default)]
struct Steps {
    one: AtomicU32,
    two: AtomicU32,
}

#[derive(Clone)]
pub struct WriteActivation {
    steps: Arc<Steps>,
    members: Arc<Members>,
    generation: GrantsGeneration,
}

impl WriteActivation {
    async fn two_steps(&self) -> Value {
        self.steps.one.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.steps.two.fetch_add(1, Ordering::SeqCst);
        json!("written whole")
    }
}

#[plexus_macros::activation(namespace = "write", crate_path = "plexus_core")]
impl WriteActivation {
    /// A write with no target: step one, a wait, step two.
    #[plexus_macros::method]
    pub async fn two_step(&self) -> Value {
        self.two_steps().await
    }

    /// The same, on a target.
    #[plexus_macros::method(target = "id")]
    pub async fn two_step_on(&self, id: String) -> Value {
        let _ = id;
        self.two_steps().await
    }

    /// The same, admitted on `*` only.
    #[plexus_macros::method(everywhere)]
    pub async fn two_step_everywhere(&self) -> Value {
        self.two_steps().await
    }

    /// Its caller's own write takes its right — the membership removed and
    /// the tenant's generation moved — then it works on, saying so.
    #[plexus_macros::method]
    pub async fn give_up_then_work(&self) -> impl futures::Stream<Item = Value> + Send + 'static {
        let (members, generation) = (self.members.clone(), self.generation.clone());
        async_stream::stream! {
            members.forget(ALICE);
            generation.moved(GrantsMove::Revoke);
            yield json!("gave up");
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                yield json!("working");
            }
        }
    }
}

/// The tenant's store: moves the tenant's own generation inside its write,
/// then takes 300 ms to answer (menger's shape).
struct SlowStore {
    inner: Arc<Members>,
    generation: GrantsGeneration,
}

impl Memberships for SlowStore {
    fn held(&self, p: &Principal) -> Vec<Membership> {
        self.inner.held(p)
    }
}

#[async_trait]
impl MembershipStore for SlowStore {
    async fn grant(&self, m: Membership) -> Result<(), StoreError> {
        self.inner.grant(m).await?;
        self.generation.moved(GrantsMove::Grant);
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(())
    }
    async fn revoke(&self, p: &Principal, role: Option<&RoleName>, scope: &ScopeRef) -> Result<Vec<RoleName>, StoreError> {
        let removed = self.inner.revoke(p, role, scope).await?;
        self.generation.moved(GrantsMove::Revoke);
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(removed)
    }
}

struct Served {
    service: Arc<DynamicHub>,
    steps: Arc<Steps>,
    members: Arc<Members>,
    generation: GrantsGeneration,
}

/// Alice `reader` on KILN (or `*`), Bob `admin` on OTHER only; `slow`: the
/// tenant's store moves its own generation inside its write.
fn served(alice_on: &str, slow: bool) -> Served {
    let members = Arc::new(Members::default());
    members.hold_at(ALICE, "reader", alice_on);
    members.hold_at(BOB, "admin", "OTHER");
    let generation = GrantsGeneration::new();
    let steps = Arc::new(Steps::default());
    let roles = Arc::new(MemoryRoles::default());
    let store: Arc<dyn MembershipStore> = if slow { Arc::new(SlowStore { inner: members.clone(), generation: generation.clone() }) } else { members.clone() };
    let activation = WriteActivation { steps: steps.clone(), members: members.clone(), generation: generation.clone() };
    let setup = AuthSetup::new(Arc::new(MemoryAuthBackend::new("http://x/login")), roles.clone(), store, Arc::new(Shortcodes)).with_generation(generation.clone());
    let service = DynamicHub::new("svc").register(activation).with_auth(setup);
    let mut declared = service.declared_roles();
    let reader = declared.entry("reader".to_string()).or_default();
    for g in ["write.two_step", "write.two_step_on", "write.two_step_everywhere", "write.give_up_then_work"] {
        reader.push(g.to_string());
    }
    roles.seed(&declared);
    Served { service: Arc::new(service), steps, members, generation }
}

fn as_(s: &Served, p: &str) -> Caller {
    Caller::new(s.service.clone(), Some(who(p)))
}

/// Every item of a call, as values.
async fn items(c: &Caller, method: &str, params: Value) -> Vec<Value> {
    let s = c.stream(method, params).await.unwrap_or_else(|e| panic!("{method}: {e}"));
    s.map(|i| serde_json::to_value(&i).unwrap()).collect().await
}

fn kinds(items: &[Value]) -> Vec<String> {
    items.iter().map(|i| format!("{}:{}", i["type"].as_str().unwrap_or("?"), i["error_kind"].as_str().or(i["content"].as_str()).unwrap_or(""))).collect()
}

/// Bob grants Alice `reader` on OTHER, Alice's write starts, Bob revokes it
/// 80 ms in: the write runs whole.
async fn kicked(s: &Served, method: &str, params: Value) -> Vec<Value> {
    let bob = as_(s, BOB);
    let granted = items(&bob, "auth.grant", json!({ "principal": ALICE, "role": "reader", "scope": "OTHER" })).await;
    assert_eq!(granted.last().unwrap()["type"], "done", "{granted:?}");
    let alice = as_(s, ALICE);
    let (method, params) = (method.to_string(), params.clone());
    let write = tokio::spawn(async move { items(&alice, &method, params).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    let revoked = items(&bob, "auth.revoke", json!({ "principal": ALICE, "role": "reader", "scope": "OTHER" })).await;
    assert_eq!(revoked.last().unwrap()["type"], "done", "{revoked:?}");
    write.await.unwrap()
}

/// N1: the reviewer's reproduction — both steps of the two-step write run.
#[tokio::test]
async fn a_third_partys_grant_then_revoke_never_cuts_a_write_between_its_steps() {
    let s = served("KILN", false);
    let got = kicked(&s, "write.two_step", json!({})).await;
    assert_eq!(kinds(&got), ["data:written whole", "done:"], "{got:?}");
    assert_eq!((s.steps.one.load(Ordering::SeqCst), s.steps.two.load(Ordering::SeqCst)), (1, 1));
}

/// N1: nor a write on a target, nor one admitted on `*`: neither stands on
/// a third party's unrelated scope.
#[tokio::test]
async fn a_third_party_cannot_end_a_targeted_or_everywhere_body() {
    let s = served("KILN", false);
    let got = kicked(&s, "write.two_step_on", json!({ "id": "KILN-1" })).await;
    assert_eq!(kinds(&got), ["data:written whole", "done:"], "on a target: {got:?}");
    let s = served("*", false);
    let got = kicked(&s, "write.two_step_everywhere", json!({})).await;
    assert_eq!(kinds(&got), ["data:written whole", "done:"], "on *: {got:?}");
    // And Bob, admin of OTHER alone, cannot take Alice's `*`.
    let bob = as_(&s, BOB);
    bob.call("auth.revoke", json!({ "principal": ALICE, "role": "reader", "scope": "*" })).await.refused(plexus_testkit::Forbidden);
}

/// N1: a body whose caller holds the grant nowhere any more is still
/// dropped between its steps.
#[tokio::test]
async fn a_body_whose_grant_is_held_nowhere_is_still_dropped() {
    let s = served("KILN", false);
    let alice = as_(&s, ALICE);
    let write = tokio::spawn(async move { items(&alice, "write.two_step", json!({})).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    s.members.forget(ALICE);
    s.generation.moved(GrantsMove::Revoke);
    let got = write.await.unwrap();
    assert_eq!(kinds(&got), ["error:forbidden"], "{got:?}");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!((s.steps.one.load(Ordering::SeqCst), s.steps.two.load(Ordering::SeqCst)), (1, 0), "step two ran after the revoke");
}

/// N2: Bob revokes his own `admin@OTHER` — with plexus-core's own move after
/// the write, and with the tenant's store moving its generation inside the
/// write: he reads `revoked`, not `forbidden`.
#[tokio::test]
async fn a_caller_whose_own_write_takes_its_right_reads_the_write() {
    for slow in [false, true] {
        let s = served("KILN", slow);
        let got = items(&as_(&s, BOB), "auth.revoke", json!({ "principal": BOB, "role": "admin", "scope": "OTHER" })).await;
        assert_eq!(got.first().map(|i| i["content"]["type"].clone()), Some(json!("revoked")), "slow={slow}: {got:?}");
        assert_eq!(got.last().unwrap()["type"], "done", "slow={slow}: {got:?}");
        assert!(s.members.held(&BOB.parse().unwrap()).is_empty(), "the write landed");
    }
}

/// N2: the exemption is the call's own moves only, once: a later move by
/// anything else is asked as usual, and ends it.
#[tokio::test]
async fn the_own_move_is_no_way_to_stay_alive() {
    let s = served("KILN", false);
    let alice = as_(&s, ALICE);
    let mut call = alice.stream("write.give_up_then_work", json!({})).await.unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let i = tokio::time::timeout(Duration::from_secs(2), call.next()).await.expect("an item").expect("open");
        seen.push(serde_json::to_value(&i).unwrap());
    }
    assert_eq!(kinds(&seen), ["data:gave up", "data:working", "data:working"], "its own move did not end it: {seen:?}");
    s.generation.moved(GrantsMove::RoleEdit);
    let until = std::time::Instant::now() + Duration::from_secs(2);
    let end = loop {
        assert!(std::time::Instant::now() < until, "a later move did not end it: it stays alive");
        let i = tokio::time::timeout(Duration::from_secs(2), call.next()).await.expect("an item").expect("open");
        let v = serde_json::to_value(&i).unwrap();
        if v["type"] != "data" {
            break v;
        }
    };
    assert_eq!(end["error_kind"], "forbidden", "the next move asked it: {end}");
    assert!(tokio::time::timeout(Duration::from_secs(1), call.next()).await.expect("ended").is_none());
}
