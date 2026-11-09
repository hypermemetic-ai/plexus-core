//! NEST-21 · configuration at runtime: typed settings, the library, the
//! `config` activation behind the grant gate.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use plexus_core::plexus::config::{
    settings, Config, ConfigAction, ConfigAudit, ConfigRecord, Millis, Reload, Sensitivity, Setting, Source,
};
use plexus_core::plexus::{
    AuthContext, AuthSetup, MemoryAuthBackend, MemoryMemberships, MemoryRoles, PlexusStream, PlexusStreamItem, Resolve, ScopeRef,
};
use plexus_core::{setting, DynamicHub, PlexusError};
use serde_json::{json, Value};

const WORKERS: Setting<u32> = setting!("test.workers", default = 4, reload = Restart, doc = "workers at start");
const TOKEN: Setting<String> = setting!("test.secret_token", default = String::new(), sensitivity = Secret);
const LOCAL: Setting<bool> = setting!("test.host_only", default = false, remote = false);
const MODE: Setting<String> = setting!("test.mode", default = "calm".to_string());

#[derive(Default)]
struct Sink(Mutex<Vec<ConfigRecord>>);
impl ConfigAudit for Sink {
    fn record(&self, r: &ConfigRecord) {
        self.0.lock().unwrap().push(r.clone());
    }
}

// ------------------------------------------------------------------ the library

#[test]
fn a_setting_is_declared_once_by_its_macro() {
    assert_eq!((WORKERS.key, WORKERS.reload, WORKERS.doc), ("test.workers", Reload::Restart, "workers at start"));
    assert_eq!(TOKEN.sensitivity, Sensitivity::Secret);
    assert!(!LOCAL.remote && LOCAL.reload == Reload::Live);
    assert!(settings::TRANSPORT_INSECURE_WS.critical && !settings::TRANSPORT_TLS_ROOTS.remote);
    let c = Config::new();
    let keys = c.keys();
    for k in ["transport.insecure_ws", "transport.tls_roots", "child.legacy_upcalls", "child.timeout", "child.max_calls", "child.backoff", "log.redact.keys"] {
        assert!(keys.contains(&k.to_string()), "{k} declared by plexus-core: {keys:?}");
    }
    assert_eq!(c.get(&settings::CHILD_TIMEOUT), Millis::secs(5));
    assert_eq!(c.get(&WORKERS), 4, "declared at first use");
    let bad: Setting<u32> = setting!("test.workers", default = 1);
    let _ = bad;
    let other: Setting<String> = setting!("test.workers", default = String::new());
    assert!(c.try_declare(&other).is_err(), "another type under a key is refused");
    let reserved: Setting<bool> = setting!("test.set", default = false);
    assert!(c.try_declare(&reserved).is_err(), "a node's method is no segment");
    let prefix: Setting<bool> = setting!("test.workers.more", default = false);
    assert!(c.try_declare(&prefix).is_err(), "a key is no other's prefix");
}

#[tokio::test]
async fn sources_layer_default_file_flag_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.json");
    std::fs::write(&file, r#"{ "test.mode": "from-file" }"#).unwrap();
    let c = Config::with_file(&file).unwrap();
    assert_eq!((c.get(&MODE), c.source(&MODE)), ("from-file".to_string(), Source::File));
    c.seed(&MODE, Source::Flag, Some("from-flag".into()));
    assert_eq!((c.get(&MODE), c.source(&MODE)), ("from-flag".to_string(), Source::Flag));
    let prev = c.set(&MODE, "at-runtime".into()).unwrap();
    assert_eq!((prev.value.as_str(), prev.source), ("from-flag", Source::Flag));
    assert_eq!((c.get(&MODE), c.source(&MODE)), ("at-runtime".to_string(), Source::Runtime));
    // Persisted: written to the file, 0600; at the next start the file layer.
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(kept["test.mode"], "at-runtime");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let again = Config::with_file(&file).unwrap();
    assert_eq!((again.get(&MODE), again.source(&MODE)), ("at-runtime".to_string(), Source::File));
    // A reset goes back below the runtime and out of the file.
    assert_eq!(c.reset(&MODE).unwrap(), "from-flag");
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert!(kept.get("test.mode").is_none(), "{kept}");
    // No file: nothing persists.
    let mem = Config::new();
    mem.set(&MODE, "x".into()).unwrap();
    assert!(mem.file().is_none());
}

#[tokio::test]
async fn a_restart_setting_waits_and_a_live_one_is_watched() {
    let c = Config::new();
    c.declare(&WORKERS);
    c.set(&WORKERS, 9).unwrap();
    assert_eq!(c.get(&WORKERS), 4, "a Restart setting keeps what it started with");
    let info = c.info("test.workers").unwrap();
    assert_eq!(info.pending, Some(json!(9)), "{info:?}");
    let mut w = c.watch(&MODE);
    assert_eq!(w.current(), "calm");
    let c2 = c.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        c2.set(&MODE, "busy".into()).unwrap();
    });
    let got = tokio::time::timeout(Duration::from_secs(2), w.changed()).await.unwrap();
    assert_eq!(got.as_deref(), Some("busy"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    c.on_change(&MODE, move |v| s2.lock().unwrap().push(v));
    c.set(&MODE, "calm".into()).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["busy".to_string(), "calm".to_string()], "now, then each change");
}

#[tokio::test]
async fn a_secret_is_never_read_back_and_every_set_is_audited_by_hash() {
    let sink = Arc::new(Sink::default());
    let c = Config::new().with_audit(sink.clone());
    c.declare(&TOKEN);
    c.set(&TOKEN, "hunter2".into()).unwrap();
    let info = c.info("test.secret_token").unwrap();
    assert!(info.value.is_none() && info.default.is_none() && info.set, "{info:?}");
    assert!(info.hash.starts_with("salted:"), "{info:?}");
    assert!(!serde_json::to_string(&c.list()).unwrap().contains("hunter2"));
    c.set(&MODE, "loud".into()).unwrap();
    let records = sink.0.lock().unwrap().clone();
    assert_eq!(records.len(), 2);
    let r = &records[1];
    assert_eq!((r.action, r.key.as_str(), r.actor.clone()), (ConfigAction::Set, "test.mode", vec!["host".to_string()]));
    assert!(r.old_hash.is_some() && r.new_hash.is_some() && r.old_hash != r.new_hash);
    assert!(!format!("{records:?}").contains("hunter2") && !format!("{records:?}").contains("loud"), "hashes, never values");
}

#[tokio::test]
async fn an_unconfirmed_change_reverts() {
    let sink = Arc::new(Sink::default());
    let c = Config::new().with_audit(sink.clone());
    c.declare(&MODE);
    c.set_value("test.mode", json!("risky"), Some(Duration::from_millis(150)), vec!["admin".into()]).unwrap();
    assert_eq!(c.get(&MODE), "risky");
    assert!(c.info("test.mode").unwrap().confirm_until.is_some());
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!((c.get(&MODE), c.source(&MODE)), ("calm".to_string(), Source::Default), "reverted");
    assert!(sink.0.lock().unwrap().iter().any(|r| r.action == ConfigAction::Reverted));
    // Confirmed in time: kept.
    c.set_value("test.mode", json!("steady"), Some(Duration::from_millis(150)), vec!["admin".into()]).unwrap();
    c.confirm("test.mode", vec!["admin".into()]).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(c.get(&MODE), "steady");
    assert!(c.confirm("test.mode", vec![]).is_err(), "nothing waits now");
}

#[test]
fn log_redact_keys_reaches_the_redactor() {
    let c = Config::new();
    assert!(!plexus_core::plexus::redact::is_credential_key("session_hint"));
    c.set(&settings::LOG_REDACT_KEYS, vec!["session-hint".into()]).unwrap();
    assert!(plexus_core::plexus::redact::is_credential_key("session_hint"));
    assert_eq!(plexus_core::plexus::redact::redact_str(r#"{"session_hint":"abc"}"#), r#"{"session_hint":"…"}"#);
    c.reset(&settings::LOG_REDACT_KEYS).unwrap();
    assert!(!plexus_core::plexus::redact::is_credential_key("session_hint"));
    assert!(plexus_core::plexus::redact::is_credential_key("token"), "the fixed list stays");
}

#[test]
fn child_options_follow_the_settings() {
    use plexus_core::plexus::ChildOptions;
    let c = Config::new();
    let o = ChildOptions::default().configured(&c);
    assert_eq!((o.timeout, o.max_calls, o.legacy_upcalls), (Duration::from_secs(5), 1024, false), "untouched: the options as given");
    let given = ChildOptions { timeout: Duration::from_secs(9), ..ChildOptions::default() };
    assert_eq!(given.clone().configured(&c).timeout, Duration::from_secs(9), "a default setting does not override");
    given.seed(&c);
    assert_eq!(c.source(&settings::CHILD_TIMEOUT), Source::Flag);
    c.set_value("child.timeout", json!("250ms"), None, vec![]).unwrap();
    c.set_value("child.max_calls", json!("8"), None, vec![]).unwrap();
    c.set_value("child.backoff", json!({ "initial": "1s", "max": "10s", "per_minute": 2 }), None, vec![]).unwrap();
    c.set_value("transport.tls_roots", json!("/etc/ca.pem"), None, vec![]).unwrap();
    let o = ChildOptions::default().configured(&c);
    assert_eq!((o.timeout, o.max_calls, o.backoff.initial, o.backoff.per_minute), (Duration::from_millis(250), 8, Duration::from_secs(1), 2));
    assert_eq!(o.tls_roots.as_deref(), Some(std::path::Path::new("/etc/ca.pem")));
    assert!(c.set_value("child.max_calls", json!("lots"), None, vec![]).is_err(), "checked against its type");
}

// ------------------------------------------------------------------ the activation

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VIEWER: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const KEYHOLDER: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

fn hub(c: &Config) -> Arc<DynamicHub> {
    let roles = Arc::new(MemoryRoles::default());
    let members = MemoryMemberships::new().with(ADMIN, "admin", "*").with(VIEWER, "viewer", "*").with(KEYHOLDER, "keyholder", "*");
    let hub = DynamicHub::new("svc")
        .with_config(c.clone())
        .with_config_service()
        .with_auth(AuthSetup::new(Arc::new(MemoryAuthBackend::new("http://x/login")), roles.clone(), Arc::new(members), Arc::new(Everywhere)));
    let mut declared = hub.declared_roles();
    // One key's methods, by their literal paths (NEST-5: the slot grant is additive).
    declared.insert("keyholder".into(), vec!["config.test.mode.get".into(), "config.test.mode.set".into(), "config.transport.insecure_ws.set".into()]);
    roles.seed(&declared);
    Arc::new(hub)
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], json!({}))
}

async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                PlexusStreamItem::Error { message, fields, .. } => Some(json!({ "error": message, "fields": fields })),
                _ => None,
            }
        })
        .collect()
        .await
}

async fn call(hub: &DynamicHub, p: &str, method: &str, params: Value) -> Vec<Value> {
    match hub.route(method, params, Some(&who(p))).await {
        Ok(s) => items(s).await,
        Err(PlexusError::Forbidden { reason: plexus_core::AuthzDenyReason::MissingGrant { grant, .. } }) => vec![json!({ "forbidden": grant.as_str() })],
        Err(e) => vec![json!({ "route_error": e.to_string() })],
    }
}

#[tokio::test]
async fn the_config_activation_serves_each_key_on_its_own_grant() {
    let sink = Arc::new(Sink::default());
    let c = Config::new().with_audit(sink.clone());
    c.declare(&MODE);
    c.declare(&TOKEN);
    c.declare(&LOCAL);
    let h = hub(&c);
    // The admin: list, get, set.
    let listed = call(&h, ADMIN, "config.list", json!({})).await;
    assert!(listed.iter().any(|k| k["key"] == "transport.insecure_ws" && k["value"] == false && k["critical"] == true), "{listed:?}");
    let got = call(&h, ADMIN, "config.test.mode.get", json!({})).await;
    assert_eq!((got[0]["type"].as_str(), got[0]["value"].as_str(), got[0]["source"].as_str()), (Some("setting"), Some("calm"), Some("default")), "{got:?}");
    let set = call(&h, ADMIN, "config.test.mode.set", json!({ "value": "busy" })).await;
    assert_eq!((set[0]["type"].as_str(), set[0]["previous"].as_str(), set[0]["setting"]["value"].as_str()), (Some("set"), Some("calm"), Some("busy")), "{set:?}");
    assert_eq!(c.get(&MODE), "busy");
    let r = sink.0.lock().unwrap().last().cloned().unwrap();
    assert_eq!((r.action, r.actor.clone()), (ConfigAction::Set, vec![ADMIN.to_string()]), "the caller is the actor: {r:?}");
    // A viewer holds nothing of it.
    assert_eq!(call(&h, VIEWER, "config.list", json!({})).await[0]["forbidden"], "config.list");
    // Below the first segment the slot repeats its own type: untyped there, every method on one grant.
    assert_eq!(call(&h, VIEWER, "config.test.mode.get", json!({})).await[0]["forbidden"], "config.{key}.{key}");
    assert!(call(&h, VIEWER, "config.test.mode.set", json!({ "value": "x" })).await[0].get("forbidden").is_some());
    // A role listing one key's path holds that key alone.
    assert_eq!(call(&h, KEYHOLDER, "config.test.mode.get", json!({})).await[0]["value"], "busy");
    assert_eq!(call(&h, KEYHOLDER, "config.test.mode.set", json!({ "value": "x" })).await[0]["type"], "set");
    assert!(call(&h, KEYHOLDER, "config.test.mode.reset", json!({})).await[0].get("forbidden").is_some());
    assert!(call(&h, KEYHOLDER, "config.log.redact.keys.get", json!({})).await[0].get("forbidden").is_some());
    // A CLI's string, read as JSON where the type wants it.
    let n = call(&h, ADMIN, "config.child.max_calls.set", json!({ "value": "16" })).await;
    assert_eq!(n[0]["setting"]["value"], 16, "{n:?}");
    let bad = call(&h, ADMIN, "config.child.max_calls.set", json!({ "value": "many" })).await;
    assert_eq!((bad[0]["type"].as_str(), bad[0]["reason"].as_str()), (Some("refused"), Some("invalid")), "{bad:?}");
    // A group is not a key; an unknown key is unknown.
    let g = call(&h, ADMIN, "config.transport.get", json!({})).await;
    assert_eq!(g[0]["reason"], "not_a_key", "{g:?}");
    assert!(call(&h, ADMIN, "config.nothing.here.get", json!({})).await[0].get("route_error").is_some());
}

#[tokio::test]
async fn guards_remote_false_critical_secret_and_confirm() {
    let sink = Arc::new(Sink::default());
    let c = Config::new().with_audit(sink.clone());
    c.declare(&TOKEN);
    c.declare(&LOCAL);
    let h = hub(&c);
    // remote = false: readable, never set over the wire.
    for (m, p) in [("config.transport.tls_roots.set", json!({ "value": "/x.pem" })), ("config.test.host_only.set", json!({ "value": true })), ("config.test.host_only.reset", json!({}))] {
        let got = call(&h, ADMIN, m, p).await;
        assert_eq!((got[0]["type"].as_str(), got[0]["reason"].as_str()), (Some("refused"), Some("not_remote")), "{m}: {got:?}");
    }
    assert_eq!(call(&h, ADMIN, "config.transport.tls_roots.get", json!({})).await[0]["type"], "setting");
    assert!(c.get(&settings::TRANSPORT_TLS_ROOTS).is_none());
    assert!(sink.0.lock().unwrap().iter().any(|r| r.action == ConfigAction::Refused && r.key == "transport.tls_roots"), "a refusal is audited");
    // Critical: an admin's, and only as a confirmed commit.
    let got = call(&h, ADMIN, "config.transport.insecure_ws.set", json!({ "value": true })).await;
    assert_eq!(got[0]["reason"], "confirm_required", "{got:?}");
    let got = call(&h, KEYHOLDER, "config.transport.insecure_ws.set", json!({ "value": true, "confirm_within": "5s" })).await;
    assert_eq!(got[0]["reason"], "critical", "the key's grant alone is not enough: {got:?}");
    let got = call(&h, ADMIN, "config.transport.insecure_ws.set", json!({ "value": true, "confirm_within": "200ms" })).await;
    assert_eq!(got[0]["type"], "set", "{got:?}");
    assert!(got[0]["setting"]["confirm_until"].is_number(), "{got:?}");
    assert!(c.get(&settings::TRANSPORT_INSECURE_WS), "applied at once");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!c.get(&settings::TRANSPORT_INSECURE_WS), "reverted: never confirmed");
    let got = call(&h, ADMIN, "config.transport.insecure_ws.set", json!({ "value": true, "confirm_within": "1s" })).await;
    assert_eq!(got[0]["type"], "set");
    assert_eq!(call(&h, ADMIN, "config.transport.insecure_ws.confirm", json!({})).await[0]["type"], "confirmed");
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(c.get(&settings::TRANSPORT_INSECURE_WS), "confirmed: kept");
    // A secret: write-only.
    let got = call(&h, ADMIN, "config.test.secret_token.set", json!({ "value": "s3cret" })).await;
    assert!(got[0].get("previous").is_none() && got[0]["setting"].get("value").is_none(), "{got:?}");
    let got = call(&h, ADMIN, "config.test.secret_token.get", json!({})).await;
    assert!(got[0].get("value").is_none() && got[0]["set"] == true, "{got:?}");
    assert!(!format!("{got:?}").contains("s3cret"));
    // Watch: each change, as it is made.
    let mut w = h.route("config.watch", json!({ "key": "test" }), Some(&who(ADMIN))).await.unwrap();
    let c2 = c.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        c2.set(&MODE, "watched".into()).unwrap();
    });
    let item = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match w.next().await {
                Some(PlexusStreamItem::Data { content, .. }) => return content.into_value(),
                Some(_) => continue,
                None => panic!("ended"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!((item["key"].as_str(), item["value"].as_str(), item["action"].as_str()), (Some("test.mode"), Some("watched"), Some("set")), "{item}");
}
