//! KEEL-59 · the server ends a call when its right to run ends.
//!
//! A gated service decides a call once, at its dispatch. While the call
//! runs it is held to that decision: when the grants move it is decided
//! again by the rule it was admitted by, and a call that no longer holds
//! ends with one typed item, its work stopped; and a peer the service cuts
//! off ends every call into it. (A sign-in's end on a socket is
//! plexus-transport's: tests/keel59_session_end.rs there.)
//!
//! Each unit of a method's work writes the time to a file of its own every
//! 2 ms — here, and in the child on the far side of a hop — so "the work
//! stops" is measured where the work runs: its last mark is within
//! [`BOUND`] of the cause, and it never moves again.
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child `leaf` on stdio, serving the same
//! work. `cargo test --test keel59_held [filter]` runs the rows whose name
//! holds `filter`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use plexus_auth_core::grants::{GrantsMove, ScopeRef};
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::{ChildOptions, ChildSpec, PlexusStream, RemoteChild};
use plexus_core::DynamicHub;
use plexus_testkit::parts::Shortcodes;
use plexus_testkit::{Caller, Host, World};
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// How soon after its cause a call's work must have stopped.
const BOUND: Duration = Duration::from_millis(100);

const ALICE: &str = "key:a11ce00000000000000000000000000000000000000000000000000000000000";
const BOB: &str = "key:b0b0000000000000000000000000000000000000000000000000000000000000";
const CAROL: &str = "key:ca40100000000000000000000000000000000000000000000000000000000000";

// ------------------------------------------------------------------ marks

/// Where the marks are: the host's, by its pid (the child, which the seam
/// starts with an environment of its own, finds it by its parent's).
fn run_dir() -> String {
    let host = match std::env::var_os("PLEXUS_CHILD_NAME") {
        Some(_) => std::os::unix::process::parent_id(),
        None => std::process::id(),
    };
    std::env::temp_dir().join(format!("keel59-held-{host}")).display().to_string()
}

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

/// One unit of work done, now.
fn mark(tag: &str) {
    let _ = std::fs::write(format!("{}/{tag}", run_dir()), now_ns().to_string());
}

fn last(tag: &str) -> Option<u128> {
    std::fs::read_to_string(format!("{}/{tag}", run_dir())).ok()?.trim().parse().ok()
}

/// The work tagged `tag` stopped within [`BOUND`] of `cause` (unix ns), and
/// stays stopped.
async fn stopped(tag: &str, cause: u128) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    let at = last(tag).unwrap_or_else(|| panic!("{tag}: no work was ever done"));
    let after = (at as f64 - cause as f64) / 1e6;
    assert!(at <= cause + BOUND.as_nanos(), "{tag}: the work ran {after:.1} ms past its cause (bound {BOUND:?})");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(last(tag), Some(at), "{tag}: the work went on");
    println!("    {tag}: last unit of work {after:+.1} ms from its cause");
}

/// The work tagged `tag` is still going.
async fn going(tag: &str) {
    let before = last(tag);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_ne!(last(tag), before, "{tag}: the work stopped");
}

// ------------------------------------------------------------------ the work

#[derive(Clone)]
pub struct WorkActivation;

#[plexus_macros::activation(namespace = "work", crate_path = "plexus_core")]
impl WorkActivation {
    /// A read with no target: says it started, then works, quietly.
    #[plexus_macros::method]
    pub async fn quiet(&self, tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
        work(tag)
    }

    /// The same, on a target.
    #[plexus_macros::method(target = "id")]
    pub async fn on(&self, id: String, tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
        let _ = id;
        work(tag)
    }

    /// The same, open to anyone.
    #[plexus_macros::method(public)]
    pub async fn open(&self, tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
        work(tag)
    }

    /// A watch that follows its own reach (as menger's does): it goes on
    /// while its reach narrows, and ends itself, saying so, when nothing is
    /// held.
    #[plexus_macros::method]
    pub async fn follow(&self, tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
        plexus_core::call::follows_its_reach().expect("in a call");
        let reach = plexus_core::call::context().ok().and_then(|c| c.reach().cloned());
        async_stream::stream! {
            yield json!("started");
            loop {
                mark(&tag);
                tokio::time::sleep(Duration::from_millis(2)).await;
                if reach.as_ref().is_some_and(|r| r.recheck().is_err()) {
                    yield json!("closed: nothing is held");
                    return;
                }
            }
        }
    }

    /// Through the seam: follow `work.quiet` at the service (a call back).
    #[plexus_macros::method]
    pub async fn back(&self, tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
        let t = plexus_core::plexus::remote_child::host();
        async_stream::stream! {
            let t = match t { Ok(t) => t, Err(e) => { yield json!({ "no_host": e.to_string() }); return; } };
            let mut s = t.call(MethodRef::new("work", "quiet"), json!({ "tag": tag }));
            while let Some(i) = s.next().await {
                match i {
                    Ok(StreamItem::Data { content, .. }) => yield content,
                    other => { yield json!({ "end": format!("{other:?}") }); break; }
                }
            }
        }
    }
}

/// Says it started, then a unit of work every 2 ms, saying nothing more.
fn work(tag: String) -> impl futures::Stream<Item = Value> + Send + 'static {
    async_stream::stream! {
        yield json!("started");
        loop {
            mark(&tag);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

// ------------------------------------------------------------------ a call, read

/// A call being read, as a client reads it: every item, as it comes.
struct Open {
    items: mpsc::UnboundedReceiver<Value>,
}

impl Open {
    /// Open `method` as `caller`, read until it says it started and its
    /// work is under way.
    async fn start(caller: &Caller, method: &str, params: Value) -> Open {
        let tag = params["tag"].as_str().unwrap().to_string();
        let _ = std::fs::remove_file(format!("{}/{tag}", run_dir()));
        let s = caller.stream(method, params).await.unwrap_or_else(|e| panic!("{method}: not opened: {e}"));
        Self::reading(s, &tag).await
    }

    async fn reading(mut s: PlexusStream, tag: &str) -> Open {
        let (tx, items) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(item) = s.next().await {
                let _ = tx.send(serde_json::to_value(&item).unwrap());
            }
        });
        let mut open = Open { items };
        let first = open.next().await.expect("an item");
        assert_eq!(first["content"], json!("started"), "{first}");
        for _ in 0..500 {
            if last(tag).is_some() {
                return open;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("{tag}: no work began");
    }

    async fn next(&mut self) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(5), self.items.recv()).await.expect("an item or the end within 5 s")
    }

    /// Its one last item is an error of `kind`, then it ends.
    async fn ends(&mut self, kind: &str) -> Value {
        let item = self.next().await.expect("an end, not silence");
        assert_eq!(item["type"], json!("error"), "{item}");
        assert_eq!(item["error_kind"], json!(kind), "{item}");
        assert_eq!(self.next().await, None, "one item, then the end");
        item
    }

    /// Nothing has ended it.
    fn runs(&mut self) {
        match self.items.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {}
            other => panic!("the call was ended: {other:?}"),
        }
    }
}

// ------------------------------------------------------------------ the host

fn exe_spec(name: &str) -> ChildSpec {
    format!("{name}=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap()
}

const READER: [&str; 6] = ["work.quiet", "work.on", "work.follow", "leaf.quiet", "leaf.back", "leaf2.quiet"];

async fn host_with(members: &[(&str, &str)], leaves: &[RemoteChild]) -> Host {
    let mut b = World::new().host().without_named_callers().resolving(Shortcodes).with(WorkActivation).role("reader", READER);
    for l in leaves {
        b = b.with(l.clone());
    }
    for (who, scope) in members {
        b = b.member_at(who, "reader", scope);
    }
    b.await
}

/// `who` no longer holds `reader` on `scope`; the gate is told.
fn revoke(host: &Host, who_: &str, scope: &str) -> u128 {
    let p: plexus_auth_core::identity::Principal = who_.parse().unwrap();
    let s = ScopeRef::parse(scope);
    host.members().0.lock().unwrap().retain(|m| !(m.principal == p && m.scope == s));
    let at = now_ns();
    host.gate().moved(GrantsMove::Revoke);
    at
}

async fn mount(name: &str, service: &DynamicHub) -> RemoteChild {
    let opts = ChildOptions::for_service("host").with_host(service).with_legacy_upcalls(true);
    RemoteChild::connect(exe_spec(name), opts).await.unwrap_or_else(|e| panic!("{name} mounts: {e:?}"))
}

// ------------------------------------------------------------------ the rows

async fn a_viewer_whose_grant_is_revoked_mid_stream_is_told_forbidden_and_the_work_stops() {
    let host = host_with(&[(ALICE, "*")], &[]).await;
    let mut call = Open::start(&host.as_(ALICE), "work.quiet", json!({ "tag": "revoked" })).await;
    let cause = revoke(&host, ALICE, "*");
    let end = call.ends("forbidden").await;
    assert_eq!(end["grant"], json!("work.quiet"), "{end}");
    stopped("revoked", cause).await;
}

async fn across_a_hop_the_caller_is_told_and_the_peers_work_stops() {
    let base = Arc::new(DynamicHub::new("host"));
    let leaf = mount("leaf", &base).await;
    let host = host_with(&[(ALICE, "*")], &[leaf.clone()]).await;
    let mut call = Open::start(&host.as_(ALICE), "leaf.quiet", json!({ "tag": "hop" })).await;
    let cause = revoke(&host, ALICE, "*");
    let end = call.ends("forbidden").await;
    assert_eq!(end["grant"], json!("leaf.quiet"), "{end}");
    // The far side's work, in the child's process.
    stopped("hop", cause).await;
    assert_eq!(leaf.stats().open, 0, "the service keeps no call into the peer");
}

async fn a_call_back_ends_with_the_call_it_was_made_under() {
    let base = Arc::new(DynamicHub::new("host").register(WorkActivation));
    let leaf = mount("leaf", &base).await;
    let host = host_with(&[(ALICE, "*")], &[leaf.clone()]).await;
    // `leaf.back`: the child calls the service's `work.quiet` back.
    let mut call = Open::start(&host.as_(ALICE), "leaf.back", json!({ "tag": "back" })).await;
    let cause = revoke(&host, ALICE, "*");
    call.ends("forbidden").await;
    // The call back's work, in this process, under the forwarded call.
    stopped("back", cause).await;
    for _ in 0..50 {
        if leaf.calls_open_back() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("a call back still open: {}", leaf.calls_open_back());
}

async fn a_read_whose_reach_narrowed_ends_and_one_that_follows_its_reach_runs_on() {
    let host = host_with(&[(ALICE, "KILN"), (ALICE, "GLAZE")], &[]).await;
    let alice = host.as_(ALICE);
    let mut list = Open::start(&alice, "work.quiet", json!({ "tag": "narrowed-list" })).await;
    let mut watch = Open::start(&alice, "work.follow", json!({ "tag": "narrowed-watch" })).await;
    let mut kiln = Open::start(&alice, "work.on", json!({ "id": "KILN-1", "tag": "narrowed-kiln" })).await;

    // GLAZE goes: the read that answered from it ends, naming what it lost.
    let cause = revoke(&host, ALICE, "GLAZE");
    let end = list.ends("forbidden").await;
    assert_eq!(end["scope"], json!("GLAZE"), "{end}");
    assert_eq!(end["held_on"], json!(["KILN"]), "{end}");
    stopped("narrowed-list", cause).await;
    // The watch follows its own reach; the call on KILN-1 still holds.
    watch.runs();
    kiln.runs();
    going("narrowed-watch").await;
    going("narrowed-kiln").await;

    // KILN goes: the call on it ends; the watch ends itself, saying so.
    let cause = revoke(&host, ALICE, "KILN");
    let end = kiln.ends("forbidden").await;
    assert_eq!(end["grant"], json!("work.on"), "{end}");
    stopped("narrowed-kiln", cause).await;
    let closed = watch.next().await.expect("the watch's own end");
    assert_eq!(closed["content"], json!("closed: nothing is held"), "{closed}");
    stopped("narrowed-watch", cause).await;
}

async fn a_revoke_ends_only_the_calls_that_stood_on_it() {
    let host = host_with(&[(ALICE, "KILN"), (ALICE, "*"), (BOB, "*"), (CAROL, "*")], &[]).await;
    let mut alice = Open::start(&host.as_(ALICE), "work.on", json!({ "id": "KILN-1", "tag": "only-alice" })).await;
    let mut bob = Open::start(&host.as_(BOB), "work.open", json!({ "tag": "only-bob-public" })).await;
    let mut nobody = Open::start(&host.anonymous(), "work.open", json!({ "tag": "only-anonymous" })).await;

    // Someone else's revoke ends nothing of theirs.
    revoke(&host, CAROL, "*");
    // Alice still holds KILN-1 through `*`: her call did not stand on KILN.
    revoke(&host, ALICE, "KILN");
    // A public call stands on no grant.
    revoke(&host, BOB, "*");
    tokio::time::sleep(Duration::from_millis(50)).await;
    for (call, tag) in [(&mut alice, "only-alice"), (&mut bob, "only-bob-public"), (&mut nobody, "only-anonymous")] {
        call.runs();
        going(tag).await;
    }
}

async fn a_peer_cut_off_ends_the_calls_into_it() {
    let base = Arc::new(DynamicHub::new("host"));
    let leaf = mount("leaf", &base).await;
    let leaf2 = mount("leaf2", &base).await;
    let host = host_with(&[(ALICE, "*")], &[leaf.clone(), leaf2.clone()]).await;

    // A revoke.
    let mut call = Open::start(&host.as_(ALICE), "leaf.quiet", json!({ "tag": "cut-revoked" })).await;
    let cause = now_ns();
    leaf.revoke("by the test");
    let end = call.ends("child_unavailable").await;
    assert!(end["message"].as_str().unwrap().contains("revoked: by the test"), "{end}");
    stopped("cut-revoked", cause).await;
    let again = host.as_(ALICE).call("leaf.quiet", json!({ "tag": "cut-again" })).await;
    assert!(format!("{:?}", again.raw()).contains("revoked"), "nothing more is forwarded: {:?}", again.raw());

    // A disconnect.
    let mut call = Open::start(&host.as_(ALICE), "leaf2.quiet", json!({ "tag": "cut-disconnected" })).await;
    let cause = now_ns();
    leaf2.stop("disconnected");
    let end = call.ends("child_unavailable").await;
    assert!(end["message"].as_str().unwrap().contains("disconnected"), "{end}");
    stopped("cut-disconnected", cause).await;
    let again = host.as_(ALICE).call("leaf2.quiet", json!({ "tag": "cut-again2" })).await;
    assert!(format!("{:?}", again.raw()).contains("disconnected"), "nothing more is forwarded: {:?}", again.raw());
}

// ------------------------------------------------------------------ main

fn main() {
    if std::env::var("PLEXUS_CHILD_NAME").is_ok() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(WorkActivation)).unwrap();
        return;
    }
    std::fs::create_dir_all(run_dir()).unwrap();
    let filter: Option<String> = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    macro_rules! rows {
        ($($row:ident),* $(,)?) => {{
            let mut ran = 0;
            $(
                if filter.as_deref().is_none_or(|f| stringify!($row).contains(f)) {
                    println!("test {} ...", stringify!($row));
                    rt.block_on($row());
                    println!("test {} ... ok", stringify!($row));
                    ran += 1;
                }
            )*
            println!("\ntest result: ok. {ran} passed");
            let _ = std::fs::remove_dir_all(run_dir());
        }};
    }
    rows!(
        a_viewer_whose_grant_is_revoked_mid_stream_is_told_forbidden_and_the_work_stops,
        across_a_hop_the_caller_is_told_and_the_peers_work_stops,
        a_call_back_ends_with_the_call_it_was_made_under,
        a_read_whose_reach_narrowed_ends_and_one_that_follows_its_reach_runs_on,
        a_revoke_ends_only_the_calls_that_stood_on_it,
        a_peer_cut_off_ends_the_calls_into_it,
    );
}
