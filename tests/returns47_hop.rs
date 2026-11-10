//! RETURNS-47 · through the child seam, a plugin's `call::hop()` names the
//! caller and the ceiling, and its reads are bounded by them.
//!
//! No test harness: this binary is the service and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set in its cleared environment), the plugin on
//! stdio — a Rust child served by `remote_child::serve_child_stdio`, whose
//! stdout carries the protocol alone.

use plexus_core::call;
use plexus_core::plexus::{AuthContext, ChildOptions, ChildSpec, RemoteChild, ScopeRef};
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use plexus_testkit::parts::{items, who};
use plexus_testkit::{Host, World};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// What the plugin was told about the call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Seen {
    pub principal: String,
    pub caller: Option<String>,
    pub grant: Option<String>,
    pub held_on: Vec<String>,
    /// The caller `call::caller()` answers: the one the hop names.
    pub caller_principal: Option<String>,
    /// Its reach: the hop's ceiling.
    pub reach: Vec<String>,
}

#[derive(PlexusRequest)]
pub struct Req {
    #[from_auth_context]
    pub auth: Option<AuthContext>,
}

#[derive(Debug, Clone)]
pub struct User(String);

/// The child's own verifier: the principal, within the call's reach.
#[derive(Clone, Default)]
pub struct Access;
impl Access {
    pub async fn verify(&self, ctx: &AuthContext) -> Result<User, plexus_core::plexus::PlexusError> {
        let reach = plexus_core::plexus::current_reach()?;
        let p = ctx.principal().ok_or_else(|| plexus_core::plexus::PlexusError::Unauthenticated("no principal".into()))?;
        Ok(User(format!("{p}@{}", reach.held_on().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","))))
    }
}

mod forge {
    use super::Seen;

    /// The interface the plugin fills.
    #[allow(async_fn_in_trait)]
    pub trait Forge {
        async fn whoami(&self) -> Option<Seen>;
        async fn repos(&self) -> Vec<String>;
        async fn verified(&self) -> String;
    }
}

/// The plugin: repositories, each in a scope.
#[derive(Clone, Default)]
pub struct Plugin {
    access: Access,
}

/// A forge plugin, behind the seam, its methods `required`.
#[plexus_macros::activation(auth = "required", request = Req, roles(viewer = ["whoami", "repos", "verified"]))]
impl forge::Forge for Plugin {
    /// The hop, and the caller, as this plugin reads them.
    #[plexus_macros::method(public)]
    async fn whoami(&self) -> Option<Seen> {
        let hop = call::hop().ok()?;
        let caller = call::caller().ok();
        Some(Seen {
            principal: hop.principal.clone(),
            caller: hop.caller().map(str::to_string),
            grant: hop.grant().map(str::to_string),
            held_on: hop.held_on().iter().map(|s| s.as_str().to_string()).collect(),
            caller_principal: caller.as_ref().and_then(|c| c.auth()).and_then(|a| a.principal()).map(|p| p.to_string()),
            reach: caller.map(|c| c.reach().held_on().iter().map(|s| s.as_str().to_string()).collect()).unwrap_or_default(),
        })
    }

    /// The repositories within the caller's reach (the hop's ceiling): what
    /// `current_reach()` covers, never wider.
    async fn repos(&self) -> Vec<String> {
        let Ok(reach) = plexus_core::plexus::current_reach() else { return vec![] };
        [("MENGER", "menger"), ("MENGER", "menger-skills"), ("OTHER", "secret")]
            .iter()
            .filter(|(scope, _)| reach.covers(&[ScopeRef::named(*scope), ScopeRef::Everywhere]))
            .map(|(_, name)| name.to_string())
            .collect()
    }

    /// The child's own verifier, run on the caller the hop names.
    #[plexus_macros::from_auth(self.access.verify)]
    async fn verified(&self) -> String {
        call::verified::<User>().map(|u| u.0).unwrap_or_else(|e| format!("{e:?}"))
    }
}

async fn mounted() -> RemoteChild {
    let exe = std::env::current_exe().unwrap();
    let spec: ChildSpec = format!("forge=stdio:{}", exe.display()).parse().unwrap();
    RemoteChild::connect(spec, ChildOptions::for_service("menger")).await.expect("the plugin mounts")
}

/// ADA views MENGER; BOB holds nothing.
async fn gated(child: &RemoteChild) -> Host {
    World::new().host().named("menger").with(child.clone()).without_named_callers().member_at(ADA, "viewer", "MENGER").await
}

async fn the_plugins_hop_names_the_caller_and_the_ceiling() {
    let child = mounted().await;
    let host = gated(&child).await;
    let got = host.as_(ADA).call("forge.whoami", json!({})).await;
    assert_eq!(
        got[0],
        json!({ "principal": "service:menger", "caller": ADA, "grant": "forge.whoami", "held_on": ["MENGER"], "caller_principal": ADA, "reach": ["MENGER"] }),
        "the caller is the hop's, its reach the hop's ceiling: {got:?}"
    );
    let verified = host.as_(ADA).call("forge.verified", json!({})).await;
    assert_eq!(verified[0], json!(format!("{ADA}@MENGER")), "the child's own verifier, on the hop's caller: {verified:?}");
}

async fn the_plugins_reads_are_bounded_by_the_ceiling() {
    let child = mounted().await;
    let host = gated(&child).await;
    let got = host.as_(ADA).call("forge.repos", json!({})).await;
    assert_eq!(got[0], json!(["menger", "menger-skills"]), "{got:?}");
    // Refused at the gate: the plugin never hears of it.
    let refused = host.as_(BOB).route("forge.repos", json!({})).await;
    assert!(refused.is_err(), "BOB holds nothing");
}

async fn with_no_gate_deciding_the_plugin_refuses_before_the_method() {
    // A service without a gate sends `limit: null`: no ceiling crossed, so
    // the plugin refuses the call before its method runs (fail closed). Its
    // schema, asked at the mount with no limit either, was answered.
    let child = mounted().await;
    let service = DynamicHub::new("menger").register(child.clone());
    let got = items(service.route("forge.repos", json!({}), Some(&who(ADA))).await).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["type"], "error", "{got:?}");
    assert_eq!(got[0]["error_kind"], "forbidden", "{got:?}");
}

/// One raw `forge.call` to a plugin served on a pipe, its first item back.
async fn raw(call: Value) -> Value {
    let (mut ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(Plugin::default(), r, w));
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "forge.call", "params": call });
    ours.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let opened: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(opened["id"], 1, "{opened}");
    let item: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    drop(lines);
    drop(ours);
    served.await.unwrap().unwrap();
    item["params"]["result"].clone()
}

async fn a_hop_for_another_grant_is_forbidden() {
    let hop = json!({ "principal": "service:menger", "for": [ADA], "limit": { "grant": "forge.whoami", "held_on": ["*"] }, "call": "c1" });
    let got = raw(json!({ "method": "forge.repos", "params": {}, "hop": hop })).await;
    assert_eq!(got["type"], "error", "{got}");
    assert_eq!(got["error_kind"], "forbidden", "{got}");
    assert_eq!(got["grant"], "forge.repos", "{got}");
}

async fn a_hop_with_no_limit_is_refused_before_the_method() {
    let hop = json!({ "principal": "service:menger", "for": [ADA], "limit": null, "call": "c2" });
    let got = raw(json!({ "method": "forge.repos", "params": {}, "hop": hop })).await;
    assert_eq!(got["type"], "error", "{got}");
    assert_eq!(got["error_kind"], "forbidden", "{got}");
}

async fn a_schema_call_runs_in_the_hops_context() {
    let hop = json!({ "principal": "service:menger", "for": [], "limit": null, "call": "c3" });
    let got = raw(json!({ "method": "forge.schema", "params": {}, "hop": hop })).await;
    assert_eq!(got["type"], "data", "{got}");
}

async fn a_call_with_no_hop_is_refused_by_the_plugin() {
    // The far side decides again (spec/12 rule 2): no hop, nobody.
    let got = raw(json!({ "method": "forge.repos", "params": {} })).await;
    assert_eq!(got["type"], "error", "{got}");
    assert_eq!(got["error_kind"], "unauthenticated", "{got}");
}

async fn an_anonymous_hop_is_refused_by_required() {
    let hop = json!({ "principal": "service:menger", "for": [], "limit": { "grant": "forge.repos", "held_on": ["*"] }, "call": "c4" });
    let got = raw(json!({ "method": "forge.repos", "params": {}, "hop": hop })).await;
    assert_eq!(got["type"], "error", "{got}");
    assert_eq!(got["error_kind"], "unauthenticated", "{got}");
}

async fn the_child_sees_no_wider_than_the_ceiling() {
    let hop = json!({ "principal": "service:menger", "for": [ADA], "limit": { "grant": "forge.repos", "held_on": ["MENGER"] }, "call": "c5" });
    let got = raw(json!({ "method": "forge.repos", "params": {}, "hop": hop })).await;
    assert_eq!(got["content"], json!(["menger", "menger-skills"]), "{got}");
}

/// One raw call over a connection proven as `proven`, the child trusting
/// `trusted` to act for others.
async fn over_a_connection(proven: &str, trusted: &[&str], hop_principal: &str) -> Value {
    use plexus_core::plexus::remote_child::{serve_child_on, ChildPeer};
    let (mut ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let peer = ChildPeer::connection(proven, trusted.iter().map(|s| s.to_string()));
    let served = tokio::spawn(serve_child_on(Plugin::default(), r, w, peer));
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let hop = json!({ "principal": hop_principal, "for": [ADA], "limit": { "grant": "forge.repos", "held_on": ["*"] }, "call": "c6" });
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "forge.call", "params": { "method": "forge.repos", "params": {}, "hop": hop } });
    ours.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let _opened = lines.next_line().await.unwrap().unwrap();
    let item: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    drop(lines);
    drop(ours);
    served.await.unwrap().unwrap();
    item["params"]["result"].clone()
}

async fn an_unreadable_caller_reaches_nowhere() {
    // `for` names no principal it can read: anonymous, and no ceiling either.
    let hop = json!({ "principal": "service:menger", "for": ["not a principal"], "limit": { "grant": "forge.whoami", "held_on": ["MENGER"] }, "call": "c7" });
    let got = raw(json!({ "method": "forge.whoami", "params": {}, "hop": hop })).await;
    assert_eq!(got["content"]["caller_principal"], Value::Null, "{got}");
    assert_eq!(got["content"]["reach"], json!([]), "{got}");
}

const PARENT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MALLORY: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

async fn a_hop_over_a_connection_is_taken_only_from_a_trusted_service() {
    // Trusted to act for others, and the hop names it: taken.
    let got = over_a_connection(PARENT, &[PARENT], PARENT).await;
    assert_eq!(got["content"], json!(["menger", "menger-skills", "secret"]), "{got}");
    // A connection proven as someone not trusted to act for others: refused.
    let got = over_a_connection(MALLORY, &[PARENT], MALLORY).await;
    assert_eq!(got["error_kind"], "forbidden", "{got}");
    // Trusted, but the hop names another acting service: refused.
    let got = over_a_connection(PARENT, &[PARENT], MALLORY).await;
    assert_eq!(got["error_kind"], "forbidden", "{got}");
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        // Run by the seam: be the plugin on stdio.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Plugin::default())).unwrap();
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        the_plugins_hop_names_the_caller_and_the_ceiling().await;
        println!("test the_plugins_hop_names_the_caller_and_the_ceiling ... ok");
        the_plugins_reads_are_bounded_by_the_ceiling().await;
        println!("test the_plugins_reads_are_bounded_by_the_ceiling ... ok");
        with_no_gate_deciding_the_plugin_refuses_before_the_method().await;
        println!("test with_no_gate_deciding_the_plugin_refuses_before_the_method ... ok");
        a_call_with_no_hop_is_refused_by_the_plugin().await;
        println!("test a_call_with_no_hop_is_refused_by_the_plugin ... ok");
        a_hop_for_another_grant_is_forbidden().await;
        println!("test a_hop_for_another_grant_is_forbidden ... ok");
        a_hop_with_no_limit_is_refused_before_the_method().await;
        println!("test a_hop_with_no_limit_is_refused_before_the_method ... ok");
        a_schema_call_runs_in_the_hops_context().await;
        println!("test a_schema_call_runs_in_the_hops_context ... ok");
        an_anonymous_hop_is_refused_by_required().await;
        println!("test an_anonymous_hop_is_refused_by_required ... ok");
        the_child_sees_no_wider_than_the_ceiling().await;
        println!("test the_child_sees_no_wider_than_the_ceiling ... ok");
        a_hop_over_a_connection_is_taken_only_from_a_trusted_service().await;
        println!("test a_hop_over_a_connection_is_taken_only_from_a_trusted_service ... ok");
        an_unreadable_caller_reaches_nowhere().await;
        println!("test an_unreadable_caller_reaches_nowhere ... ok");
    });
    println!("\ntest result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
}
