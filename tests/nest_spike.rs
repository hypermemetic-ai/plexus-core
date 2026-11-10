//! NEST-3's spike, then NEST-4's gate: a remote child with children.
//!
//! A Rust child served by `serve_child_stdio` — the root `nest`, a static
//! child `a` with a grandchild `b` and a great-grandchild `c`, one method
//! each; `a` has a dynamic slot `{item}` (listed and searched), `b` an
//! opaque one — mounted as `mnt` by a gated host. Every row of NEST-3's
//! sheet for this child is a check here.
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child on stdio. With `PULSE_URL` set it
//! also mounts a running starter app (`pulse=ws://…`, NEST-3's child 2) and
//! calls `pulse.greeter.hello` through it.

// NEST-4's end to end: `NEST_SERVE=PORT NEST_GRANT=key:… nest_spike`
// serves a gated host on PORT (plexus-wire's reference service, key proofs)
// mounting this binary's tree as `mnt`, for synapse to reach.
#[allow(dead_code)]
#[path = "../../plexus-wire/reference/echo-rs/src/echo.rs"]
mod echo;
#[allow(dead_code)]
#[path = "../../plexus-wire/reference/echo-rs/src/service.rs"]
mod service;

use plexus_core::plexus::{AuthContext, ChildOptions, ChildSpec, RemoteChild, RoleTable};
use plexus_core::plexus::Activation;
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use plexus_testkit::parts::{every_item, items};
use plexus_testkit::{Host, World, EDITOR, VIEWER};
use serde_json::{json, Value};

#[derive(PlexusRequest)]
pub struct Req {
    #[from_auth_context]
    pub auth: Option<AuthContext>,
}

fn seen(at: &str) -> Value {
    let hop = plexus_core::call::hop().ok();
    json!({ "at": at, "grant": hop.as_ref().and_then(|h| h.grant().map(str::to_string)), "for": hop.as_ref().and_then(|h| h.caller().map(str::to_string)) })
}

#[derive(Clone, Default)]
pub struct CActivation;
/// The grandchild.
#[plexus_macros::activation(request = Req, auth = "mixed", roles(viewer = ["m"]))]
impl CActivation {
    /// c's method.
    #[plexus_macros::method]
    pub async fn m(&self) -> Value {
        seen("c")
    }
}

#[derive(Clone, Default)]
pub struct BActivation;
/// The child of a.
#[plexus_macros::activation(request = Req, auth = "mixed", roles(editor = ["m"]))]
impl BActivation {
    /// b's method, the editor's.
    #[plexus_macros::method]
    pub async fn m(&self) -> Value {
        seen("b")
    }
    #[plexus_macros::child]
    fn c(&self) -> CActivation {
        CActivation
    }
    /// An opaque slot: no list, no search.
    #[plexus_macros::child]
    fn opaque(&self, _name: &str) -> Option<ItemActivation> {
        Some(ItemActivation)
    }
}

#[derive(Clone, Default)]
pub struct ItemActivation;
/// An instance in a's slot.
#[plexus_macros::activation(request = Req, auth = "mixed", roles(viewer = ["m"]))]
impl ItemActivation {
    /// item's method.
    #[plexus_macros::method]
    pub async fn m(&self) -> Value {
        seen("item")
    }
}

#[derive(Clone, Default)]
pub struct AActivation;
/// The child of the root.
#[plexus_macros::activation(request = Req, auth = "mixed", roles(viewer = ["m"]))]
impl AActivation {
    /// a's method, the viewer's.
    #[plexus_macros::method]
    pub async fn m(&self) -> Value {
        seen("a")
    }
    #[plexus_macros::child]
    fn b(&self) -> BActivation {
        BActivation
    }
    /// A dynamic slot, listed and searched.
    #[plexus_macros::child(list = "names", search = "find")]
    fn item(&self, name: &str) -> Option<ItemActivation> {
        (name == "earth" || name == "mars").then_some(ItemActivation)
    }
    /// The slot's names.
    fn names(&self) -> impl futures::Stream<Item = String> + Send + 'static {
        futures::stream::iter(["earth".to_string(), "mars".to_string()])
    }
    /// The slot's names matching `query`.
    fn find(&self, query: &str) -> impl futures::Stream<Item = String> + Send + 'static {
        let query = query.to_string();
        futures::stream::iter(["earth", "mars"].into_iter().filter(move |n| n.contains(query.as_str())).map(str::to_string).collect::<Vec<_>>())
    }
}

#[derive(Clone, Default)]
pub struct NestActivation;
/// The root the seam serves.
#[plexus_macros::activation(request = Req, auth = "mixed", roles(viewer = ["ping"]))]
impl NestActivation {
    /// Pong.
    #[plexus_macros::method]
    pub async fn ping(&self) -> Value {
        seen("nest")
    }
    #[plexus_macros::child]
    fn a(&self) -> AActivation {
        AActivation
    }
}


// The same tree with one change three levels down (`c` has a second
// method): what a restarted child publishes in `restart_with_a_changed_grandchild`.
mod variant {
    use super::{seen, Req};
    use serde_json::Value;

    #[derive(Clone, Default)]
    pub struct C2Activation;
    /// The grandchild, changed.
    #[plexus_macros::activation(namespace = "c", request = Req, auth = "mixed", roles(viewer = ["m"]))]
    impl C2Activation {
        /// c's method.
        #[plexus_macros::method]
        pub async fn m(&self) -> Value {
            seen("c")
        }
        /// A method the first c did not have.
        #[plexus_macros::method]
        pub async fn n(&self) -> Value {
            seen("c2")
        }
    }
    #[derive(Clone, Default)]
    pub struct B2Activation;
    /// The child of a.
    #[plexus_macros::activation(namespace = "b", request = Req, auth = "mixed", roles(editor = ["m"]))]
    impl B2Activation {
        /// b's method, the editor's.
        #[plexus_macros::method]
        pub async fn m(&self) -> Value {
            seen("b")
        }
        #[plexus_macros::child]
        fn c(&self) -> C2Activation {
            C2Activation
        }
    }
    #[derive(Clone, Default)]
    pub struct A2Activation;
    /// The child of the root.
    #[plexus_macros::activation(namespace = "a", request = Req, auth = "mixed", roles(viewer = ["m"]))]
    impl A2Activation {
        /// a's method, the viewer's.
        #[plexus_macros::method]
        pub async fn m(&self) -> Value {
            seen("a")
        }
        #[plexus_macros::child]
        fn b(&self) -> B2Activation {
            B2Activation
        }
    }
    #[derive(Clone, Default)]
    pub struct Nest2Activation;
    /// The root the seam serves.
    #[plexus_macros::activation(namespace = "nest", request = Req, auth = "mixed", roles(viewer = ["ping"]))]
    impl Nest2Activation {
        /// Pong.
        #[plexus_macros::method]
        pub async fn ping(&self) -> Value {
            seen("nest")
        }
        #[plexus_macros::child]
        fn a(&self) -> A2Activation {
            A2Activation
        }
    }
}
use variant::Nest2Activation;

/// VIEWER holds viewer, EDITOR editor, both on `*`; the roles the host
/// declares are the mount's, renamed at every level.
async fn gated(child: &RemoteChild) -> Host {
    World::new().host().with(child.clone()).await
}

fn spec(name: &str) -> ChildSpec {
    format!("{name}=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap()
}

async fn mount(name: &str) -> RemoteChild {
    let mut opts = ChildOptions::for_service("host");
    opts.env = vec!["NEST_VARIANT".into()];
    RemoteChild::connect(spec(name), opts).await.expect("a child with children mounts")
}

async fn the_mount_keeps_the_tree_and_the_host_declares_it() {
    let child = mount("mnt").await;
    let kept: Vec<String> = child.static_child_schemas().into_iter().map(|(p, _)| p).collect();
    assert_eq!(kept, ["a", "a.b", "a.b.c"], "depth-first, every static child");
    let roles = DynamicHub::new("host").register(child.clone()).declared_roles();
    // NEST-5 (merged on `vision`): a typed slot's roles come with it, as
    // slot grants, renamed under the mount like every other grant.
    assert_eq!(roles["viewer"], ["mnt.ping", "mnt.a.m", "mnt.a.b.c.m", "mnt.a.{item}.m", "mnt.a.b.{opaque}.m"], "{roles:?}");
    assert_eq!(roles["editor"], ["mnt.a.b.m"], "{roles:?}");
    println!("mount timings: {:?}", child.mount_timings());
}

async fn each_level_schema_is_answered_from_the_kept_tree() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let before = child.stats().calls;
    let top = host.as_(VIEWER).call("mnt.schema", json!({})).await;
    assert_eq!(top[0]["namespace"], "mnt", "{top:?}");
    let names: Vec<&str> = top[0]["methods"].as_array().unwrap().iter().filter_map(|m| m["name"].as_str()).collect();
    assert!(names.contains(&"a"), "the root lists its child: {names:?}");
    let a = host.as_(VIEWER).call("mnt.a.schema", json!({})).await;
    assert_eq!(a[0]["namespace"], "a", "{a:?}");
    let b = host.as_(VIEWER).call("mnt.a.b.schema", json!({})).await;
    assert_eq!(b[0]["namespace"], "b", "{b:?}");
    let one = host.as_(VIEWER).call("mnt.a.b.c.schema", json!({ "method": "m" })).await;
    assert_eq!(one[0]["name"], "m", "{one:?}");
    assert_eq!(child.stats().calls, before, "no schema call crossed the hop (spec/12 rule 7)");
}

async fn every_method_is_gated_by_its_full_path() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.a.b.c.m", json!({})).await;
    assert_eq!(got[0], json!({ "at": "c", "grant": "nest.a.b.c.m", "for": VIEWER }), "routed four levels, the far side's grant the full path, its caller the hop's: {got:?}");
    let got = host.as_(VIEWER).call("mnt.a.m", json!({})).await;
    assert_eq!(got[0]["at"], "a", "{got:?}");
    let refused = host.as_(VIEWER).call("mnt.a.b.m", json!({})).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|r| r.contains("mnt.a.b.m") && r.contains("editor")), "a viewer is refused the editor's: {refused:?}");
    let got = host.as_(EDITOR).call("mnt.a.b.m", json!({})).await;
    assert_eq!(got[0], json!({ "at": "b", "grant": "nest.a.b.m", "for": EDITOR }), "{got:?}");
}

async fn a_call_into_a_dynamic_slot_is_forwarded_on_the_slot_grant() {
    // NEST-6 (was NEST-4's refusal, naming the slot): the host's gate decides
    // a name in a slot on the slot grant (NEST-5), and the mount forwards it
    // with that grant in the child's terms; the far side checks the slot.
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.a.earth.m", json!({})).await;
    assert_eq!(got[0], json!({ "at": "item", "grant": "nest.a.{item}.m", "for": VIEWER }), "{got:?}");
    let got = host.as_(VIEWER).call("mnt.a.b.zz.m", json!({})).await;
    assert_eq!(got[0], json!({ "at": "item", "grant": "nest.a.b.{opaque}.m", "for": VIEWER }), "{got:?}");
    // An unknown name: the child's own not-found, relayed.
    let got = host.as_(VIEWER).call("mnt.a.pluto.m", json!({})).await;
    assert_eq!(got[0]["error"]["kind"], "activation_not_found", "{got:?}");
    // An instance's schema: crosses once.
    let got = host.as_(VIEWER).call("mnt.a.earth.schema", json!({})).await;
    assert_eq!(got[0]["namespace"], "item", "{got:?}");
}

async fn past_the_depth_the_mount_fails_naming_the_path() {
    let mut opts = ChildOptions::for_service("host");
    opts.max_depth = 2;
    let e = RemoteChild::connect(spec("mnt"), opts).await.unwrap_err().to_string();
    assert!(e.contains("`a.b.c`") && e.contains("--child-max-depth"), "{e}");
}

async fn restart_with_a_changed_grandchild_is_refused() {
    std::env::remove_var("NEST_VARIANT");
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let pid = child.pid().expect("a stdio child has a pid");
    std::env::set_var("NEST_VARIANT", "2");
    let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let got = loop {
        let got = every_item(host.as_(VIEWER).route("mnt.a.m", json!({})).await).await;
        if got[0].get("at").is_none() || std::time::Instant::now() > deadline {
            break got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let got = if got[0]["message"].as_str().is_some_and(|m| m.contains("schema changed")) {
        got
    } else {
        // the first call after the exit may meet the old connection going
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        every_item(host.as_(VIEWER).route("mnt.a.m", json!({})).await).await
    };
    std::env::remove_var("NEST_VARIANT");
    assert!(got[0]["message"].as_str().is_some_and(|m| m.contains("schema changed; restart the service")), "{got:?}");
}

/// The far side, raw: one `nest.call` on a pipe, every item back.
async fn raw(call: Value) -> Vec<Value> {
    let (mut ours, theirs) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(NestActivation, r, w));
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "nest.call", "params": call });
    ours.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(&mut ours).lines();
    let _opened = lines.next_line().await.unwrap().unwrap();
    let mut out = vec![];
    loop {
        let item: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        let r = item["params"]["result"].clone();
        let t = r["type"].as_str().unwrap_or_default().to_string();
        out.push(r);
        if t == "done" || t == "error" {
            break;
        }
    }
    drop(lines);
    drop(ours);
    served.await.unwrap().unwrap();
    out
}

/// NEST-3: the far side needs no change for static nesting — it routes the
/// full path and checks the hop's grant against it.
async fn the_far_side_routes_and_checks_the_full_path() {
    let hop = |g: &str| json!({ "principal": "service:host", "for": [VIEWER], "limit": { "grant": g, "held_on": ["*"] }, "call": "c" });
    let got = raw(json!({ "method": "nest.a.b.c.m", "params": {}, "hop": hop("nest.a.b.c.m") })).await;
    assert_eq!(got[0]["content"], json!({ "at": "c", "grant": "nest.a.b.c.m", "for": VIEWER }), "{got:?}");
    let got = raw(json!({ "method": "nest.a.b.m", "params": {}, "hop": hop("nest.a.m") })).await;
    assert_eq!(got[0]["error_kind"], "forbidden", "a grant for another path: {got:?}");
    // A dynamic child, reached by its name: the grant is the literal path.
    let got = raw(json!({ "method": "nest.a.earth.m", "params": {}, "hop": hop("nest.a.earth.m") })).await;
    assert_eq!(got[0]["content"]["at"], "item", "{got:?}");
    let got = raw(json!({ "method": "nest.a.pluto.m", "params": {}, "hop": hop("nest.a.pluto.m") })).await;
    assert_eq!(got[0]["error"]["kind"], "activation_not_found", "the child's own not-found: {got:?}");
}

/// NEST-3 rows measured, not gated: one dynamic instance's schema across a
/// pipe, and how a slot grant's braces fare.
async fn measured() {
    let none = json!({ "principal": "service:host", "for": [], "limit": null, "call": "s" });
    let mut ms: Vec<f64> = Vec::new();
    for _ in 0..21 {
        let t = std::time::Instant::now();
        let got = raw(json!({ "method": "nest.a.earth.schema", "params": {}, "hop": none })).await;
        ms.push(t.elapsed().as_secs_f64() * 1e3);
        assert_eq!(got[0]["content"]["namespace"], "item");
    }
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("measure: one dynamic instance's schema (nest.a.earth.schema) on a pipe, median of 21: {:.2} ms", ms[10]);
    let path = plexus_auth_core::MethodPath::try_new("mnt.a.{item}.m");
    println!("measure: MethodPath::try_new(\"mnt.a.{{item}}.m\") = {path:?}");
    let roles = RoleTable::from_lists([("viewer", ["mnt.a.{item}.m"].into_iter())]);
    println!("measure: a RoleTable takes `mnt.a.{{item}}.m` as written: {}", format!("{roles:?}").contains("{item}"));
}

async fn pulse(url: &str) {
    let spec: ChildSpec = format!("pulse={url}").parse().unwrap();
    let child = RemoteChild::connect(spec, ChildOptions::for_service("host")).await.expect("the starter's app mounts whole");
    let kept: Vec<String> = child.static_child_schemas().into_iter().map(|(p, _)| p).collect();
    assert_eq!(kept, ["greeter"]);
    let host = DynamicHub::new("host").register(child.clone());
    let got = items(host.route("pulse.greeter.hello", json!({ "name": "world" }), None).await).await;
    assert_eq!(got[0], json!({ "type": "greeting", "message": "Hello, world!" }), "{got:?}");
    let s = items(host.route("pulse.greeter.schema", json!({}), None).await).await;
    assert_eq!(s[0]["namespace"], "greeter", "{s:?}");
    println!("test pulse_through_the_mount ... ok");
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        if std::env::var("NEST_VARIANT").as_deref() == Ok("2") {
            rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Nest2Activation)).unwrap();
        } else {
            rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(NestActivation)).unwrap();
        }
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    if let Ok(port) = std::env::var("NEST_SERVE") {
        let grants = std::env::var("NEST_GRANT").into_iter().flat_map(|g| g.split(',').map(|kv| {
            let (who, role) = kv.split_once('=').unwrap_or((kv, "viewer"));
            (who.to_string(), role.to_string())
        }).collect::<Vec<_>>()).collect();
        rt.block_on(async {
            let child = mount("mnt").await;
            println!("mounted mnt: {:?}", child.static_child_schemas().into_iter().map(|(p, _)| p).collect::<Vec<_>>());
            let opts = service::Serve { port: port.parse().unwrap(), grants, ..Default::default() };
            service::serve_over(DynamicHub::new("host").register(child), opts).await.unwrap();
        });
        return;
    }
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( $t().await; println!("test {} ... ok", stringify!($t)); n += 1; )* n }};
        }
        let n = run!(
            the_far_side_routes_and_checks_the_full_path,
            the_mount_keeps_the_tree_and_the_host_declares_it,
            each_level_schema_is_answered_from_the_kept_tree,
            every_method_is_gated_by_its_full_path,
            a_call_into_a_dynamic_slot_is_forwarded_on_the_slot_grant,
            past_the_depth_the_mount_fails_naming_the_path,
            restart_with_a_changed_grandchild_is_refused
        );
        measured().await;
        let mut n = n;
        if let Ok(url) = std::env::var("PULSE_URL") {
            pulse(&url).await;
            n += 1;
        }
        println!("\ntest result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
    });
}
