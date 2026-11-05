//! RETURNS-47 · through the child seam, a plugin's `call::hop()` names the
//! caller and the ceiling, and its reads are bounded by them.
//!
//! No test harness: this binary is the service and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set in its cleared environment), the plugin on
//! stdio — a Rust child served by `remote_child::serve_child_stdio`, whose
//! stdout carries the protocol alone.

use futures::StreamExt;
use plexus_core::call;
use plexus_core::plexus::{
    AuthContext, ChildOptions, ChildSpec, Gate, Membership, Memberships, PlexusStream, PlexusStreamItem, RemoteChild,
    Resolve, RoleTable, ScopeRef,
};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// What the plugin was told about the call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Seen {
    pub principal: String,
    pub caller: Option<String>,
    pub grant: Option<String>,
    pub held_on: Vec<String>,
    /// Whether `call::caller()` answered (it must not: no gate here).
    pub caller_admitted: bool,
}

mod forge {
    use super::Seen;

    /// The interface the plugin fills.
    #[allow(async_fn_in_trait)]
    pub trait Forge {
        async fn whoami(&self) -> Option<Seen>;
        async fn repos(&self) -> Vec<String>;
    }
}

/// The plugin: repositories, each in a scope.
#[derive(Clone)]
pub struct Plugin;

/// A forge plugin, behind the seam.
#[plexus_macros::activation(roles(viewer = ["whoami", "repos"]))]
impl forge::Forge for Plugin {
    /// The hop, as this plugin reads it.
    async fn whoami(&self) -> Option<Seen> {
        let hop = call::hop().ok()?;
        Some(Seen {
            principal: hop.principal.clone(),
            caller: hop.caller().map(str::to_string),
            grant: hop.grant().map(str::to_string),
            held_on: hop.held_on().iter().map(|s| s.as_str().to_string()).collect(),
            caller_admitted: call::caller().is_ok(),
        })
    }

    /// The repositories within the hop's ceiling; none without a hop.
    async fn repos(&self) -> Vec<String> {
        let Ok(hop) = call::hop() else { return vec![] };
        [("MENGER", "menger"), ("MENGER", "menger-skills"), ("OTHER", "secret")]
            .iter()
            .filter(|(scope, _)| hop.allows(&[ScopeRef::named(*scope), ScopeRef::Everywhere]))
            .map(|(_, name)| name.to_string())
            .collect()
    }
}

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

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .map(|i| match i {
            PlexusStreamItem::Data { content, .. } => content.into_value(),
            other => serde_json::to_value(other).unwrap(),
        })
        .collect()
        .await
}

async fn mounted() -> RemoteChild {
    let exe = std::env::current_exe().unwrap();
    let spec: ChildSpec = format!("forge=stdio:{}", exe.display()).parse().unwrap();
    RemoteChild::connect(spec, ChildOptions::for_service("menger")).await.expect("the plugin mounts")
}

/// ADA views MENGER; BOB holds nothing.
fn gated(child: &RemoteChild) -> DynamicHub {
    let plain = DynamicHub::new("menger").register(child.clone());
    let members = Arc::new(Members::default());
    members.0.lock().unwrap().push(Membership {
        principal: ADA.parse().unwrap(),
        role: plexus_auth_core::RoleName::new("viewer"),
        scope: ScopeRef::parse("MENGER"),
    });
    let declared = plain.declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    DynamicHub::new("menger").register(child.clone()).with_gate(Arc::new(Gate::new(members, Arc::new(roles), Arc::new(Everywhere))))
}

async fn the_plugins_hop_names_the_caller_and_the_ceiling() {
    let child = mounted().await;
    let hub = gated(&child);
    let got = items(hub.route("forge.whoami", json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(
        got[0],
        json!({ "principal": "service:menger", "caller": ADA, "grant": "forge.whoami", "held_on": ["MENGER"], "caller_admitted": false }),
        "{got:?}"
    );
}

async fn the_plugins_reads_are_bounded_by_the_ceiling() {
    let child = mounted().await;
    let hub = gated(&child);
    let got = items(hub.route("forge.repos", json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(got[0], json!(["menger", "menger-skills"]), "{got:?}");
    // Refused at the gate: the plugin never hears of it.
    let refused = hub.route("forge.repos", json!({}), Some(&who(BOB))).await;
    assert!(refused.is_err(), "BOB holds nothing");
}

async fn with_no_gate_deciding_the_plugin_reads_nothing() {
    // A service without a gate sends `limit: null`: no ceiling crossed, and
    // a read bounded by the hop is bounded to nothing (fail closed).
    let child = mounted().await;
    let hub = DynamicHub::new("menger").register(child.clone());
    let got = items(hub.route("forge.repos", json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(got[0], json!([]), "{got:?}");
    let seen = items(hub.route("forge.whoami", json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(seen[0]["grant"], Value::Null, "{seen:?}");
    assert_eq!(seen[0]["caller"], ADA, "{seen:?}");
}

async fn a_call_with_no_hop_is_refused_by_the_plugin() {
    // The far side decides again (spec/12 rule 2): no hop, nobody.
    let (mut ours, theirs) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(Plugin, r, w));
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    ours.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"forge.call\",\"params\":{\"method\":\"forge.repos\",\"params\":{}}}\n").await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let opened: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(opened["id"], 1, "{opened}");
    let item: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let result = &item["params"]["result"];
    assert_eq!(result["type"], "error", "{item}");
    assert_eq!(result["error_kind"], "unauthenticated", "{item}");
    drop(lines);
    drop(ours);
    served.await.unwrap().unwrap();
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        // Run by the seam: be the plugin on stdio.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Plugin)).unwrap();
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        the_plugins_hop_names_the_caller_and_the_ceiling().await;
        println!("test the_plugins_hop_names_the_caller_and_the_ceiling ... ok");
        the_plugins_reads_are_bounded_by_the_ceiling().await;
        println!("test the_plugins_reads_are_bounded_by_the_ceiling ... ok");
        with_no_gate_deciding_the_plugin_reads_nothing().await;
        println!("test with_no_gate_deciding_the_plugin_reads_nothing ... ok");
        a_call_with_no_hop_is_refused_by_the_plugin().await;
        println!("test a_call_with_no_hop_is_refused_by_the_plugin ... ok");
    });
    println!("\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
}
