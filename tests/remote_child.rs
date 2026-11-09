//! POLYGLOT-5 — the child seam opened: plexus-wire's reference child
//! (`conformance/examples/stub_child.py`) mounted by a gated `DynamicHub`
//! through `RemoteChild`, on stdio and on a WebSocket dialed with the
//! service's key, called in memory (`HubTransport`, the service's own
//! stream) and over the service's WebSocket.
//!
//!   cargo test -p plexus-core --test remote_child
//!
//! The hop is spec/12's: `{ns}.call {method, params, hop {principal, for,
//! limit {grant, held_on} | null, call}}`; an error is terminal (spec/03).

mod child_support;

use child_support::*;
use futures::StreamExt;
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::{ChildError, ChildOptions, ChildSpec, HubTransport, RemoteChild};
use plexus_core::DynamicHub;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hub_transport(r: &Rig, caller: &str) -> HubTransport {
    HubTransport::as_(r.service.clone(), who(caller))
}

// ------------------------------------------------------------- the mount

/// The stub's methods under `echo`; the roles qualified by the mount; the
/// mount timed and logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mounts_schema_under_name() {
    for via in [Via::Stdio, Via::Ws] {
        let r = rig(via).await;
        let all: Vec<String> = plexus_core::plexus::Activation::plugin_schema(&r.child).methods.iter().map(|m| m.name.clone()).collect();
        assert_eq!(all, ["echo", "shout", "count", "whoami", "fail"]);
        let roles = r.service.declared_roles();
        assert!(roles["viewer"].contains(&"echo.echo".to_string()) && !roles["viewer"].contains(&"echo.shout".to_string()), "{roles:?}");
        assert!(roles["editor"].contains(&"echo.shout".to_string()));
        // In the service's schema, and `echo.schema` answered from what was kept — in the caller's view.
        let items = route(&r, ADA, "echo.schema", json!({})).await;
        assert_eq!(items[0]["content"]["namespace"], "echo");
        let names: Vec<_> = items[0]["content"]["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect();
        assert!(!names.contains(&"shout".to_string()), "a viewer's view: {names:?}");
        let svc = route(&r, ADA, "service.schema", json!({})).await;
        assert!(svc.iter().any(|i| i.to_string().contains("\"echo\"")), "{svc:?}");
        let t = r.child.mount_timings();
        assert!(t.merge_ms <= 20.0, "{t:?}");
        assert!(t.spawn_ms > 0.0 && t.schema_ms > 0.0, "{t:?}");
    }
}

/// The golden: the merged roles and the mounted schema's surface, exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn merged_schema_and_roles_golden() {
    let r = rig(Via::Stdio).await;
    let roles = r.service.declared_roles();
    let mut viewer = roles["viewer"].clone();
    viewer.sort();
    let mut editor = roles["editor"].clone();
    editor.sort();
    assert_eq!(viewer, ["echo.count", "echo.echo", "echo.fail", "echo.whoami", "rsecho.count", "rsecho.echo"]);
    assert_eq!(editor, ["echo.count", "echo.echo", "echo.fail", "echo.shout", "echo.whoami"]);
    let s = plexus_core::plexus::Activation::plugin_schema(&r.child);
    // RETURNS-36: the stub (plexus-wire's spec, `streaming`) is read as
    // 0.8 by its own declaration: `streaming: true` is many, else one.
    let surface: Vec<Value> = s.methods.iter().map(|m| json!({ "name": m.name, "cardinality": m.cardinality })).collect();
    assert_eq!(serde_json::to_value(&surface).unwrap(), json!([
        { "name": "echo", "cardinality": "many" }, { "name": "shout", "cardinality": "one" }, { "name": "count", "cardinality": "many" },
        { "name": "whoami", "cardinality": "one" }, { "name": "fail", "cardinality": "one" }
    ]));
    assert_eq!((s.namespace.as_str(), s.version.as_str()), ("echo", "0.1.0"));
}

/// SYNAPSE-CC-9: the walk holds over a mounted child. Its schema is the
/// child's declaration, kept whole under the mount name, and walked like any
/// activation's: the stub declares no `returns`, so each of its five methods
/// is named under `echo` (what synapse refuses at IR build); the service's
/// own schemas, the in-process `rsecho` and the service itself, have none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_walk_names_a_mounted_childs_sites_under_its_mount() {
    use plexus_core::plexus::schema::{foreign_keywords, untyped_sites};
    let r = rig(Via::Stdio).await;
    let child = plexus_core::plexus::Activation::plugin_schema(&r.child);
    assert_eq!(untyped_sites(&child), [
        "echo.count returns", "echo.echo returns", "echo.fail returns", "echo.shout returns", "echo.whoami returns"
    ]);
    assert_eq!(foreign_keywords(&child), Vec::<String>::new());
    let all = r.service.list_plugin_schemas();
    let names: Vec<&str> = all.iter().map(|s| s.namespace.as_str()).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    for ns in ["service", "rsecho", "echo"] {
        assert!(names.contains(&ns), "{names:?}");
    }
    for s in all.iter().filter(|s| s.namespace != "echo") {
        assert_eq!(untyped_sites(s), Vec::<String>::new(), "{}", s.namespace);
        assert_eq!(foreign_keywords(s), Vec::<String>::new(), "{}", s.namespace);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_child_with_children() {
    let dir = tempfile::tempdir().unwrap();
    let e = RemoteChild::connect(stdio_spec("echo", &dir.path().join("l"), "--nested"), ChildOptions::default()).await.unwrap_err();
    let ChildError::Start(name, why) = &e else { panic!("{e:?}") };
    assert_eq!(name, "echo");
    assert!(why.contains("`inner`") && why.contains("child"), "{why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_start_on_silent_child() {
    let timeout = Duration::from_millis(300);
    let t0 = Instant::now();
    let e = RemoteChild::connect("mute=stdio:sleep 30".parse().unwrap(), ChildOptions { timeout, ..ChildOptions::default() }).await.unwrap_err();
    let took = t0.elapsed();
    assert!(matches!(&e, ChildError::Start(n, why) if n == "mute" && why.contains("_info")), "{e}");
    // The contract is the timeout + 100 ms (alone: 0.30–0.33 s); the slack
    // is for a suite starting twenty children at once on a busy machine.
    assert!(took <= timeout + Duration::from_millis(250), "{took:?}");
    let e = RemoteChild::connect("gone=stdio:/nonexistent/child".parse().unwrap(), ChildOptions::default()).await.unwrap_err();
    assert!(e.to_string().contains("gone") && e.to_string().contains("spawning"), "{e}");
}

// ------------------------------------------------------------- the hop

/// The child is told who acts (the service), for whom (the caller), within
/// what (the gate's verdict) — and nothing of the caller's credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_principal_and_verdict() {
    for via in [Via::Stdio, Via::Ws] {
        let r = rig(via).await;
        let items = collect(&hub_transport(&r, ADA), "echo", "whoami", json!({})).await;
        let StreamItem::Data { content, .. } = &items[0] else { panic!("{items:?}") };
        let hop = content["hop"].clone();
        let principal = if r.ws.is_some() { r.key.principal.clone() } else { "service:service".to_string() };
        assert_eq!(hop["principal"], principal);
        assert_eq!(hop["for"], json!([ADA]));
        assert_eq!(hop["limit"], json!({ "grant": "echo.whoami", "held_on": ["*"] }));
        assert!(hop["call"].as_str().is_some_and(|c| c.len() == 36));
        let keys: Vec<_> = hop.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["call", "for", "limit", "principal"], "nothing else crosses");
        let log = std::fs::read_to_string(&r.log).unwrap();
        let env = r.child.pid().map(|p| std::fs::read_to_string(format!("/proc/{p}/environ")).unwrap_or_default()).unwrap_or_default();
        for secret in [SESSION_SECRET, KEY_SECRET] {
            assert!(!log.contains(secret) && !env.contains(secret), "{secret} reached the child");
        }
        if let Some(pid) = r.child.pid() {
            let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
            let mut keys: Vec<String> = env.split(|b| *b == 0).filter(|e| !e.is_empty()).map(|e| String::from_utf8_lossy(e).split('=').next().unwrap().to_string()).collect();
            keys.sort();
            keys.retain(|k| !["PATH", "HOME", "LANG"].contains(&k.as_str()));
            assert_eq!(keys, ["PLEXUS_CHILD_NAME"], "a cleared environment");
        }
    }
}

/// Refused by the service's gate exactly as an in-process activation is;
/// the child never hears of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forbidden_never_reaches_child() {
    let r = rig(Via::Stdio).await;
    let child = route(&r, NOBODY, "echo.echo", json!({ "text": "never-sent-7f3a", "times": 1 })).await;
    let inproc = route(&r, NOBODY, "rsecho.echo", json!({ "text": "never-sent-7f3a", "times": 1 })).await;
    assert_eq!(child.len(), 1, "{child:?}");
    // The same refusal but the activation's name and the roles that list
    // its grant (the stub's `echo` is a viewer's and an editor's; rsecho's a viewer's).
    let strip = |v: &Value| {
        let mut v = v.clone();
        v["metadata"]["timestamp"] = json!(0);
        v.as_object_mut().unwrap().remove("roles");
        // RETURNS-36: and the typed error's copy of them.
        if let Some(e) = v.get_mut("error").and_then(Value::as_object_mut) {
            e.remove("roles");
        }
        v.to_string().replace("rsecho.", "echo.")
    };
    assert_eq!(strip(&child[0]), strip(&inproc[0]), "byte-identical but the activation's name and roles");
    assert_eq!(child[0]["roles"], json!(["editor", "viewer", "admin"]));
    assert_eq!(child[0]["error_kind"], "forbidden");
    assert_eq!(child[0]["grant"], "echo.echo");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!std::fs::read_to_string(&r.log).unwrap().contains("never-sent-7f3a"), "the child heard a refused call");
}

// ------------------------------------------------------------- items back

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn items_errors_done_in_order() {
    let r = rig(Via::Stdio).await;
    let t = hub_transport(&r, ADA);
    let items = collect(&t, "echo", "echo", json!({ "text": "hi", "times": 3 })).await;
    assert_eq!(kinds(&items), ["data", "data", "data", "done"]);
    for i in &items[..3] {
        let StreamItem::Data { content, .. } = i else { unreachable!() };
        assert_eq!(content.to_string(), r#"{"text":"hi","type":"said"}"#);
    }
    let n = collect(&t, "echo", "count", json!({ "to": 500 })).await;
    let ns: Vec<u64> = n.iter().filter_map(|i| match i { StreamItem::Data { content, .. } => content["n"].as_u64(), _ => None }).collect();
    assert_eq!(ns, (1..=500).collect::<Vec<_>>(), "in order");
    // An error item is the end (spec/03): nothing after it.
    let e = route(&r, ADA, "echo.fail", json!({ "kind": "teapot" })).await;
    assert_eq!(types(&e), ["error"]);
    assert_eq!(e[0]["error_kind"], "teapot");
}

/// RETURNS-36 (review #4): an error item the service cannot decode is never
/// skipped — skipped, the call would wait for an end that never comes. It
/// ends the call with an error naming what could not be read, and the child
/// is told to stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_error_item_it_cannot_read_ends_the_call() {
    let r = rig(Via::Stdio).await;
    let sent = unix_ns();
    let e = tokio::time::timeout(Duration::from_secs(5), route(&r, ADA, "echo.fail", json!({ "kind": "garbled" })))
        .await
        .expect("the call ends, it does not hang");
    assert_eq!(types(&e), ["error"], "{e:?}");
    assert!(e[0]["message"].as_str().unwrap_or_default().contains("could not read"), "{}", e[0]);
    assert!(child_event(&r.log, "unsub", sent, Duration::from_secs(2)).await.is_some(), "the child was told");
}

/// RETURNS-36 (re-review #3): a progress item as main wrote it carries no
/// `content_type`; the seam names it the call's method — the child's
/// `echo.fail`, as its data items say — never the mount's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_main_wire_progress_is_named_for_the_calls_method() {
    let r = rig(Via::Stdio).await;
    let p = route(&r, ADA, "echo.fail", json!({ "kind": "progress" })).await;
    assert_eq!(types(&p), ["progress", "done"], "{p:?}");
    assert_eq!(p[0]["content_type"], "echo.fail", "{}", p[0]);
    assert_eq!(p[0]["content"], json!({ "message": "halfway", "percentage": 50.0 }));
}

/// RETURNS-36 (re-review #4): a child's error item with no `message` is
/// passed on with none — not `""` — so a reader shows the typed error's own
/// line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_error_item_without_a_message_is_passed_on_without_one() {
    let r = rig(Via::Stdio).await;
    let e = route(&r, ADA, "echo.fail", json!({ "kind": "bare" })).await;
    assert_eq!(types(&e), ["error"], "{e:?}");
    assert!(e[0].get("message").is_none(), "no message made up: {}", e[0]);
    assert_eq!(e[0]["error"]["kind"], "teapot", "{}", e[0]);
    assert_eq!(e[0]["error_kind"], "teapot", "{}", e[0]);
}

/// A child's typed refusal crosses whole — `error_kind` and `forbidden`'s
/// own fields — in the service's stream and on its WebSocket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn typed_refusal_relayed_whole() {
    for via in [Via::Stdio, Via::Ws] {
        let r = rig(via).await;
        let e = route(&r, ADA, "echo.fail", json!({ "kind": "forbidden" })).await;
        assert_eq!(types(&e), ["error"]);
        for (k, v) in [("error_kind", json!("forbidden")), ("grant", json!("echo.secret")), ("scope", json!("MENGER")), ("roles", json!(["editor", "admin"])), ("held_on", json!(["OTHER"])), ("code", json!("-32003"))] {
            assert_eq!(e[0][k], v, "{k} in {}", e[0]);
        }
        // On the wire: an ungated service of the same child, read raw.
        let open = Arc::new(DynamicHub::new("service").register(r.child.clone()));
        let (addr, handle) = serve(open).await;
        use jsonrpsee::core::client::SubscriptionClientT;
        let c = jsonrpsee::ws_client::WsClientBuilder::default().build(format!("ws://{addr}")).await.unwrap();
        let mut p = jsonrpsee::core::params::ObjectParams::new();
        p.insert("method", "echo.fail").unwrap();
        p.insert("params", json!({ "kind": "forbidden" })).unwrap();
        let mut sub: jsonrpsee::core::client::Subscription<Value> = c
            .subscribe("service.call", p, "service.call_unsub")
            .await
            .unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(5), sub.next()).await.unwrap().unwrap().unwrap();
        assert_eq!((wire["type"].clone(), wire["error_kind"].clone(), wire["grant"].clone(), wire["held_on"].clone()), (json!("error"), json!("forbidden"), json!("echo.secret"), json!(["OTHER"])), "{wire}");
        handle.stop().unwrap();
    }
}

// ------------------------------------------------------------- cancel

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_crosses_hop() {
    // RETURNS-47: ordering, not latency. A bound of 100 ms on the slowest of
    // twenty cancels missed under a loaded run (one at 120 ms); what the seam
    // owes is the order — the caller lets go, the child is told, the child
    // stops that call, the service holds nothing after — within a generous
    // 5 s per cancel.
    const WITHIN: Duration = Duration::from_secs(5);
    for via in [Via::Stdio, Via::Ws] {
        let r = rig(via).await;
        let t = hub_transport(&r, ADA);
        for _ in 0..20 {
            let mut s = t.call(MethodRef::new("echo", "count"), json!({ "to": 100000, "delay_ms": 1 }));
            let mut got = 0;
            while got < 100 {
                if let Some(Ok(StreamItem::Data { .. })) = s.next().await {
                    got += 1;
                }
            }
            let dropped = unix_ns();
            drop(s);
            let stopped = child_event(&r.log, "stopped", dropped, WITHIN).await.expect("the child stopped the call within 5 s");
            let log = child_log(&r.log);
            let at = |e: &Value| e["t"].as_u64().map(u128::from).unwrap_or(0);
            let told = log
                .iter()
                .find(|e| at(e) >= dropped && e["in"]["method"].as_str().is_some_and(|m| m.ends_with(".call_unsub")))
                .expect("the cancel crossed: the child was sent its call_unsub");
            let unsub = log
                .iter()
                .find(|e| at(e) >= dropped && e["ev"] == "unsub")
                .expect("the child took the unsubscribe");
            assert_eq!(unsub["live"], true, "it stopped a call still running: {unsub}");
            let stop = log.iter().find(|e| at(e) == stopped && e["ev"] == "stopped").expect("its stop");
            assert_eq!(stop["sub"], unsub["sub"], "the call it stopped is the one it was told of");
            assert!(at(told) <= at(unsub) && at(unsub) <= stopped, "told, then unsubscribed, then stopped: {told} {unsub} {stop}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(r.child.stats().open, 0, "the service keeps no open call");
        assert_eq!(r.child.routed(), 0, "and no route for one");
        assert_eq!(r.child.stats().unasked, 0, "a cancel's tail is not an unasked item");
    }
}

/// spec/04: an item already in flight may land just after the unsubscribe's
/// `true` (the reference echo's does, now and then) — still the cancel's
/// tail: dropped quietly, never counted as unasked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_tail_after_true_is_quiet() {
    for via in [Via::Stdio, Via::Ws] {
        let r = rig_with(via, ChildOptions::default(), "--tail-after-unsub").await;
        let t = hub_transport(&r, ADA);
        for _ in 0..5 {
            let mut s = t.call(MethodRef::new("echo", "count"), json!({ "to": 100000, "delay_ms": 1 }));
            let mut got = 0;
            while got < 10 {
                if let Some(Ok(StreamItem::Data { .. })) = s.next().await {
                    got += 1;
                }
            }
            let dropped = unix_ns();
            drop(s);
            child_event(&r.log, "unsub", dropped, Duration::from_secs(2)).await.expect("the child was told");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(r.child.stats().unasked, 0, "an item just after the unsubscribe's `true` is the cancel's tail");
        assert_eq!(r.child.routed(), 0, "and leaves no route");
    }
}

// ------------------------------------------------------------- a child gone

/// SIGKILL mid-stream: one `child_unavailable`, the end, within 1 s; the
/// next call starts the child again and is answered; counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_killed_mid_stream() {
    let r = rig(Via::Stdio).await;
    let mut s = r.service.route_with_ctx("echo.count", json!({ "to": 1000000, "delay_ms": 1 }), Some(&who(ADA)), None).await.unwrap();
    let mut got = 0;
    while got < 50 {
        if let Some(plexus_core::plexus::types::PlexusStreamItem::Data { .. }) = s.next().await {
            got += 1;
        }
    }
    let pid = r.child.pid().unwrap();
    let t0 = Instant::now();
    std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap();
    let tail: Vec<Value> = tokio::time::timeout(Duration::from_secs(1), s.map(|i| serde_json::to_value(i).unwrap()).collect::<Vec<_>>()).await.expect("the stream ended within 1 s");
    let after: Vec<_> = tail.iter().filter(|i| i["type"] != "data").collect();
    assert_eq!(after.len(), 1, "one item after the data, and the end: {after:?}");
    assert_eq!(after[0]["error_kind"], "child_unavailable");
    assert_eq!(after[0]["child"], "echo");
    assert!(t0.elapsed() < Duration::from_secs(1));
    let next = collect(&hub_transport(&r, ADA), "echo", "echo", json!({ "text": "after", "times": 1 })).await;
    assert_eq!(kinds(&next), ["data", "done"], "the next call restarts the child: {next:?}");
    assert_ne!(r.child.pid(), Some(pid));
    assert_eq!(r.child.stats().restarts, 1);
    assert_eq!(r.child.stats().open, 0);
}

/// The socket dropped: the same one error; the next call redials.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_child_dropped_then_redialed() {
    let r = rig(Via::Ws).await;
    let e = route(&r, ADA, "echo.fail", json!({ "kind": "drop" })).await;
    assert_eq!(types(&e), ["error"]);
    assert_eq!(e[0]["error_kind"], "child_unavailable");
    let next = route(&r, ADA, "echo.echo", json!({ "text": "again", "times": 1 })).await;
    assert_eq!(types(&next), ["data", "done"], "{next:?}");
    assert_eq!(r.child.stats().restarts, 1);
}

/// Restarts back off and stop: five a minute, the sixth crash answered at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_backoff_bounded() {
    let backoff = plexus_core::plexus::Backoff { initial: Duration::from_millis(20), max: Duration::from_millis(200), per_minute: 5 };
    let r = rig_with(Via::Stdio, ChildOptions { backoff, ..ChildOptions::default() }, "").await;
    let mut waits = vec![];
    for crash in 1..=6 {
        let e = route(&r, ADA, "echo.fail", json!({ "kind": "exit" })).await;
        assert_eq!(e.last().unwrap()["error_kind"], "child_unavailable", "crash {crash}: {e:?}");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let t0 = Instant::now();
        let next = route(&r, ADA, "echo.echo", json!({ "text": "x", "times": 1 })).await;
        waits.push(t0.elapsed());
        if crash <= 5 {
            assert_eq!(types(&next), ["data", "done"], "crash {crash}: {next:?}");
        } else {
            assert_eq!(next[0]["error_kind"], "child_unavailable", "{next:?}");
            assert!(next[0]["reason"].as_str().unwrap().contains("restarted 5 times"), "{next:?}");
            assert!(waits[5] < Duration::from_millis(20), "at once: {waits:?}");
        }
    }
    assert_eq!(r.child.stats().restarts, 5);
    // The backoff doubled: 20, 40, 80, 160 ms after each death (less the 30 ms slept), then capped.
    assert!(waits[3] >= Duration::from_millis(120), "{waits:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schema_change_on_restart_refused() {
    let dir = tempfile::tempdir().unwrap();
    let flag = dir.path().join("extra");
    let r = rig_with(Via::Stdio, ChildOptions::default(), &format!("--extra-method-file {}", flag.display())).await;
    std::fs::write(&flag, "brand_new\n").unwrap();
    let pid = r.child.pid().unwrap();
    std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..2 {
        let e = route(&r, ADA, "echo.echo", json!({ "text": "x", "times": 1 })).await;
        assert_eq!(types(&e), ["error"]);
        assert_eq!(e[0]["error_kind"], "child_unavailable");
        assert_eq!(e[0]["reason"], "schema changed; restart the service");
    }
    assert_eq!(r.child.stats().restarts, 1, "tried once, then refused at once");
}

// ------------------------------------------------------------- strays and limits

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unasked_item_dropped() {
    for via in [Via::Stdio, Via::Ws] {
        let r = rig(via).await;
        let items = collect(&hub_transport(&r, ADA), "echo", "fail", json!({ "kind": "unasked" })).await;
        let strays = items.iter().filter(|i| matches!(i, StreamItem::Data { content, .. } if content["type"] == "stray")).count();
        assert_eq!(strays, 0);
        assert_eq!(kinds(&items), ["data", "done"]);
        assert_eq!(r.child.stats().unasked, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_timeout() {
    let timeout = Duration::from_millis(1000);
    let r = rig_with(Via::Stdio, ChildOptions { timeout, ..ChildOptions::default() }, "").await;
    let t0 = Instant::now();
    let e = route(&r, ADA, "echo.fail", json!({ "kind": "silent" })).await;
    assert!(t0.elapsed() >= timeout && t0.elapsed() < timeout + Duration::from_millis(200));
    assert_eq!(types(&e), ["error"]);
    assert_eq!(e[0]["error_kind"], "child_timeout");
    assert_eq!(r.child.stats().open, 0);
    let next = route(&r, ADA, "echo.echo", json!({ "text": "x", "times": 1 })).await;
    assert_eq!(types(&next), ["data", "done"], "the child is not given up on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn too_many_calls() {
    assert_eq!(ChildOptions::default().max_calls, 1024);
    let r = rig_with(Via::Stdio, ChildOptions { max_calls: 8, ..ChildOptions::default() }, "").await;
    let mut open = vec![];
    for _ in 0..8 {
        let mut s = r.service.route_with_ctx("echo.count", json!({ "to": 100000, "delay_ms": 20 }), Some(&who(ADA)), None).await.unwrap();
        assert!(matches!(s.next().await, Some(plexus_core::plexus::types::PlexusStreamItem::Data { .. })));
        open.push(s);
    }
    let e = route(&r, ADA, "echo.echo", json!({ "text": "x", "times": 1 })).await;
    assert_eq!(types(&e), ["error"]);
    assert_eq!((e[0]["error_kind"].clone(), e[0]["max"].clone()), (json!("too_many_calls"), json!(8)));
    open.pop();
    let next = route(&r, ADA, "echo.echo", json!({ "text": "x", "times": 1 })).await;
    assert_eq!(types(&next), ["data", "done"]);
}

/// A caller that stops reading: its call's buffer holds `buffer` items and
/// the child's reader waits — memory bounded, nothing lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_buffer_slow_consumer() {
    let r = rig_with(Via::Stdio, ChildOptions { buffer: 256, ..ChildOptions::default() }, "").await;
    let warm = route(&r, ADA, "echo.count", json!({ "to": 50000, "burst": true })).await;
    assert_eq!(warm.len(), 50001);
    let before = rss_kib();
    let mut s = r.service.route_with_ctx("echo.count", json!({ "to": 50000, "burst": true }), Some(&who(ADA)), None).await.unwrap();
    let _ = s.next().await;
    tokio::time::sleep(Duration::from_millis(500)).await; // the caller reads nothing
    let held = rss_kib().saturating_sub(before);
    let rest: Vec<_> = s.collect().await;
    assert_eq!(rest.len(), 50000, "lossless: 49,999 data and done");
    println!("ROW {}", json!({ "row": "slow caller", "rss_growth_kib_while_stalled": held, "buffer": 256 }));
    assert!(held < 4096, "memory bounded while the caller stalls: +{held} KiB");
}

// ------------------------------------------------------------- regate

/// The caller's grant revoked mid-stream (the gate's generation moves): its
/// next item is `forbidden`, and the child is told to stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regate_mid_stream() {
    let r = rig(Via::Stdio).await;
    let mut s = r.service.route_with_ctx("echo.count", json!({ "to": 100000, "delay_ms": 2 }), Some(&who(ADA)), None).await.unwrap();
    for _ in 0..20 {
        assert!(matches!(s.next().await, Some(plexus_core::plexus::types::PlexusStreamItem::Data { .. })));
    }
    r.members.0.lock().unwrap().clear();
    let revoked = unix_ns();
    r.gate.moved(plexus_auth_core::grants::GrantsMove::Revoke);
    let mut rest = vec![];
    while let Some(i) = tokio::time::timeout(Duration::from_secs(2), s.next()).await.unwrap() {
        rest.push(serde_json::to_value(i).unwrap());
    }
    let last = rest.last().unwrap();
    assert_eq!((last["type"].clone(), last["error_kind"].clone(), last["grant"].clone()), (json!("error"), json!("forbidden"), json!("echo.count")), "{last}");
    assert!(rest.len() <= 2, "the next item: {rest:?}");
    assert!(child_event(&r.log, "unsub", revoked, Duration::from_secs(1)).await.is_some(), "the child was told");
}

// ------------------------------------------------------------- the WebSocket child

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_child_signs_in_with_service_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = test_key(dir.path(), "service", [9u8; 32]);
    let stranger = test_key(dir.path(), "stranger", [3u8; 32]);
    let s = ws_stub(dir.path(), &key.principal, &[]);
    let spec: ChildSpec = format!("far=ws://127.0.0.1:{}", s.port).parse().unwrap();
    let ok = RemoteChild::connect(spec.clone(), ChildOptions { key: Some(key.path.clone()), ..ChildOptions::default() }).await.unwrap();
    assert_eq!(ok.principal(), key.principal);
    for (opts, why) in [(ChildOptions::default(), "no key"), (ChildOptions { key: Some(stranger.path.clone()), ..ChildOptions::default() }, "an untrusted key")] {
        let e = RemoteChild::connect(spec.clone(), opts).await.unwrap_err();
        assert!(matches!(&e, ChildError::Start(n, w) if n == "far" && w.contains("401")), "{why}: {e}");
    }
    // A key file others may read is refused before any dial.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let e = RemoteChild::connect(spec, ChildOptions { key: Some(key.path.clone()), ..ChildOptions::default() }).await.unwrap_err();
    assert!(e.to_string().contains("readable by others"), "{e}");
}

/// LOCAL-6's promise across a process: the same macro-emitted client, over
/// `HubTransport` to a Rust echo and over a WebSocket to a service mounting
/// the stub, answers the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_answers_as_in_process() {
    let r = rig(Via::Stdio).await;
    let inproc = Arc::new(DynamicHub::new("service").register(EchoActivation));
    let mounted = Arc::new(DynamicHub::new("service").register(r.child.clone()));
    let (addr, handle) = serve(mounted).await;
    let ws = plexus_client::WsTransport::connect(&format!("ws://{addr}"), "service").await.unwrap();
    let a = EchoClient::new(HubTransport::anonymous(inproc));
    let b = EchoClient::new(ws);
    let shown = |r: Result<EchoEvent, plexus_client::ClientError>| format!("{:?}", r.expect("no client error"));
    let x: Vec<String> = a.echo("hi".into(), 3).map(shown).collect().await;
    let y: Vec<String> = b.echo("hi".into(), 3).map(shown).collect().await;
    assert_eq!(x, y);
    assert_eq!(x.len(), 3, "{x:?}");
    assert!(x[0].contains("Said") && x[0].contains("\"hi\""), "{x:?}");
    let x: Vec<String> = a.count(200).map(shown).collect().await;
    let y: Vec<String> = b.count(200).map(shown).collect().await;
    assert_eq!(x, y);
    assert_eq!(x.len(), 200);
    handle.stop().unwrap();
}

// ------------------------------------------------------------- DYNAUTH-8

/// A child that logs a frame carrying a credential on its stderr (as
/// plexus-transport's stdio did at debug): the line the service relays
/// holds none of the credential's bytes.
#[tokio::test]
async fn a_childs_stderr_is_relayed_without_its_credentials() {
    use std::sync::Mutex;
    const SECRET: &str = "ghu_dynauth8StderrSecret";
    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Log {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let log = Log::default();
    let w = log.clone();
    let sub = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_writer(move || w.clone()).finish();
    let _g = tracing::subscriber::set_default(sub);
    let line = format!(r#"Received request: {{"method":"x.call","params":{{"repo":"a/b","credential":"{SECRET}"}}}}"#);
    let spec = ChildSpec::Stdio { name: "talky".into(), argv: vec!["sh".into(), "-c".into(), format!("echo '{line}' >&2; sleep 2")] };
    let e = RemoteChild::connect(spec, ChildOptions { timeout: Duration::from_millis(500), ..ChildOptions::default() }).await.unwrap_err();
    assert!(e.to_string().contains("_info"), "{e}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let text = String::from_utf8_lossy(&log.0.lock().unwrap()).to_string();
    assert!(text.contains("Received request") && text.contains("a/b"), "relayed: {text}");
    assert!(!text.contains(SECRET), "a credential relayed: {text}");
}
