//! NEST-6's gate: a mounted child's dynamic children, through the mount.
//!
//! A Rust child served by `serve_child_stdio` — the root `sky` with a static
//! child `solar` (a typed slot `{planet}`, listed by `names` and searched by
//! `find`), a static child `belt` (an opaque, untyped slot `{rock}`) and an
//! untyped peer slot `{dendrite}` (NEST-7) — mounted as `mnt` by a gated
//! host. Every row of NEST-6's table is a check here.
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child on stdio. `NEST6_SERVE=PORT
//! NEST6_GRANT=key:…=viewer` serves the gated host on PORT (plexus-wire's
//! reference service, key proofs) for synapse to reach.

#[allow(dead_code)]
#[path = "../../plexus-wire/reference/echo-rs/src/echo.rs"]
mod echo;
#[allow(dead_code)]
#[path = "../../plexus-wire/reference/echo-rs/src/service.rs"]
mod service;

use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{Activation, AuthContext, ChildOptions, ChildSpec, RemoteChild};
use plexus_core::DynamicHub;
use plexus_macros::PlexusRequest;
use plexus_testkit::parts::items;
use plexus_testkit::{Host, World, EDITOR, VIEWER};
use serde_json::{json, Value};

#[derive(PlexusRequest)]
pub struct Req {
    #[from_auth_context]
    pub auth: Option<AuthContext>,
}

/// What a method saw of its call: where it ran, the hop's grant and caller.
fn seen(at: &str) -> Value {
    let hop = plexus_core::call::hop().ok();
    json!({ "at": at, "grant": hop.as_ref().and_then(|h| h.grant().map(str::to_string)), "for": hop.as_ref().and_then(|h| h.caller().map(str::to_string)) })
}

// ------------------------------------------------------------------ the child

#[derive(Clone)]
pub struct PlanetActivation {
    name: String,
}

/// A planet.
#[plexus_macros::activation(namespace = "planet", request = Req, auth = "mixed")]
impl PlanetActivation {
    /// What it is.
    #[plexus_macros::method]
    pub async fn info(&self) -> Value {
        seen(&format!("planet {}", self.name))
    }
    /// Rename it: the editor's.
    #[plexus_macros::method]
    pub async fn rename(&self, to: String) -> Value {
        seen(&format!("{} -> {to}", self.name))
    }
}

const PLANETS: [&str; 3] = ["earth", "mars", "venus"];

#[derive(Clone, Default)]
pub struct SolarActivation;

/// The system: a typed slot, listed and searched.
#[plexus_macros::activation(namespace = "solar", request = Req, auth = "mixed", roles(viewer = ["names", "search", "{planet}.info"], editor = ["{planet}.rename"]))]
impl SolarActivation {
    /// Every planet's name.
    #[plexus_macros::method]
    pub async fn names(&self) -> impl futures::Stream<Item = String> + Send + 'static {
        futures::stream::iter(PLANETS.map(str::to_string))
    }
    /// The slot's search (`#[child(search)]` takes a plain `fn(&str)`).
    fn find(&self, query: &str) -> impl futures::Stream<Item = String> + Send + 'static {
        futures::stream::iter(PLANETS.into_iter().filter(|n| n.contains(query)).map(str::to_string).collect::<Vec<_>>())
    }
    /// The planets whose name holds `query`: the search, as a method.
    #[plexus_macros::method]
    pub async fn search(&self, query: String) -> impl futures::Stream<Item = String> + Send + 'static {
        self.find(&query)
    }
    /// A planet by name.
    #[plexus_macros::child(list = "names", search = "find")]
    fn planet(&self, name: &str) -> Option<PlanetActivation> {
        PLANETS.contains(&name).then(|| PlanetActivation { name: name.to_string() })
    }
}

#[derive(Clone, Default)]
pub struct BeltActivation;

/// The asteroid belt: an opaque, untyped slot, granted whole.
#[plexus_macros::activation(namespace = "belt", request = Req, auth = "mixed", roles(viewer = ["count", "{rock}"]))]
impl BeltActivation {
    /// How many.
    #[plexus_macros::method]
    pub async fn count(&self) -> Value {
        json!("many")
    }
    /// A rock by name.
    #[plexus_macros::child(opaque)]
    fn rock(&self, name: &str) -> Option<PlanetActivation> {
        (!name.starts_with("dust")).then(|| PlanetActivation { name: name.to_string() })
    }
}

#[derive(Clone, Default)]
pub struct GreeterActivation;

/// Says hello: a dendrite.
#[plexus_macros::activation(namespace = "greeter", request = Req, auth = "mixed")]
impl GreeterActivation {
    /// Hello.
    #[plexus_macros::method]
    pub async fn hello(&self, name: String) -> Value {
        let mut v = seen("greeter");
        v["text"] = json!(format!("hello, {name}"));
        v
    }
}

#[derive(Clone, Default)]
pub struct SkyActivation;

/// The root the seam serves.
#[plexus_macros::activation(namespace = "sky", request = Req, auth = "mixed", roles(viewer = ["ping", "dendrites", "{dendrite}"]))]
impl SkyActivation {
    /// Pong.
    #[plexus_macros::method]
    pub async fn ping(&self) -> Value {
        seen("sky")
    }
    #[plexus_macros::child]
    fn solar(&self) -> SolarActivation {
        SolarActivation
    }
    #[plexus_macros::child]
    fn belt(&self) -> BeltActivation {
        BeltActivation
    }
    /// The dendrites' names.
    #[plexus_macros::method]
    pub async fn dendrites(&self) -> impl futures::Stream<Item = String> + Send + 'static {
        futures::stream::iter(["greeter".to_string()])
    }
    /// An untyped peer: any activation, admitted whole.
    #[plexus_macros::peer(list = "dendrites")]
    async fn dendrite(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match name {
            "greeter" => Ok(Box::new(GreeterActivation)),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

// ------------------------------------------------------------------ the host

/// VIEWER holds viewer, EDITOR editor, both on `*`; the roles the host
/// declares are the mount's, renamed at every level.
async fn gated(child: &RemoteChild) -> Host {
    World::new().host().with(child.clone()).await
}

fn spec(name: &str) -> ChildSpec {
    format!("{name}=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap()
}

async fn mount_with(name: &str, cache: usize) -> RemoteChild {
    let mut opts = ChildOptions::for_service("host");
    opts.schema_cache = cache;
    RemoteChild::connect(spec(name), opts).await.expect("a child with slots mounts")
}

async fn mount(name: &str) -> RemoteChild {
    mount_with(name, 1024).await
}

// ------------------------------------------------------------------ the rows

/// The walk meets a dynamic child: it keeps the slot and its type; a peer
/// slot is a slot too, not a level to walk; the host declares the slot
/// grants, renamed under the mount.
async fn the_walk_keeps_each_slot_and_its_type() {
    let child = mount("mnt").await;
    let kept: Vec<String> = child.static_child_schemas().into_iter().map(|(p, _)| p).collect();
    assert_eq!(kept, ["solar", "belt"], "the static levels; the peer slot `dendrite` is not walked");
    let solar = child.static_child_schemas().into_iter().find(|(p, _)| p == "solar").unwrap().1;
    let slot = solar.methods.iter().find(|m| m.name == "planet").unwrap();
    let typed = slot.role.slot_schema().expect("the slot's type is kept");
    assert_eq!(typed.namespace, "planet");
    assert!(typed.methods.iter().any(|m| m.name == "rename"));
    let roles = DynamicHub::new("host").register(child.clone()).declared_roles();
    for g in ["mnt.solar.{planet}.info", "mnt.belt.{rock}", "mnt.{dendrite}", "mnt.solar.names"] {
        assert!(roles["viewer"].contains(&g.to_string()), "viewer holds {g}: {roles:?}");
    }
    assert!(roles["editor"].contains(&"mnt.solar.{planet}.rename".to_string()), "{roles:?}");
}

/// A call into a typed slot is decided on the slot grant and forwarded with
/// it, in the child's terms; the far side checks it against the slot.
async fn a_typed_slot_is_gated_by_its_slot_grant_and_forwarded() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.solar.earth.info", json!({})).await.values();
    assert_eq!(got[0], json!({ "at": "planet earth", "grant": "sky.solar.{planet}.info", "for": VIEWER }), "{got:?}");
    let got = host.as_(VIEWER).call("mnt.solar.mars.info", json!({})).await.values();
    assert_eq!(got[0]["at"], "planet mars", "every name in the slot, one grant: {got:?}");
    let refused = host.as_(VIEWER).call("mnt.solar.earth.rename", json!({ "to": "terra" })).await.values();
    let why = refused[0]["route_error"].as_str().unwrap_or_default();
    assert!(why.contains("rename") && why.contains("editor"), "a viewer holding solar.{{planet}}.info is refused rename: {refused:?}");
    let got = host.as_(EDITOR).call("mnt.solar.earth.rename", json!({ "to": "terra" })).await.values();
    assert_eq!(got[0], json!({ "at": "earth -> terra", "grant": "sky.solar.{planet}.rename", "for": EDITOR }), "{got:?}");
}

/// An unknown name is the child's own not-found, relayed unchanged.
async fn an_unknown_name_is_the_childs_own_not_found() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.solar.pluto.info", json!({})).await.values();
    assert_eq!(got[0]["type"], "error", "{got:?}");
    assert_eq!(got[0]["error"]["kind"], "activation_not_found", "{got:?}");
    let got = host.as_(VIEWER).call("mnt.dendrite.ghost.hello", json!({ "name": "x" })).await.values();
    assert_eq!(got[0]["error_kind"], "not_found", "a peer slot's PeerError, relayed: {got:?}");
    assert_eq!(got[0]["name"], "ghost");
}

/// The slot's list and search methods are forwarded like any method; the
/// names stream back unchanged.
async fn names_are_listed_and_searched_live() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.solar.names", json!({})).await.values();
    assert_eq!(got, [json!("earth"), json!("mars"), json!("venus")]);
    let got = host.as_(VIEWER).call("mnt.solar.search", json!({ "query": "ar" })).await.values();
    assert_eq!(got, [json!("earth"), json!("mars")]);
    let got = host.as_(VIEWER).call("mnt.dendrites", json!({})).await.values();
    assert_eq!(got, [json!("greeter")]);
}

/// An untyped slot is gated whole and the child decides again inside it;
/// an untyped peer slot the same.
async fn an_untyped_slot_is_gated_whole() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let got = host.as_(VIEWER).call("mnt.belt.ceres.info", json!({})).await.values();
    assert_eq!(got[0], json!({ "at": "planet ceres", "grant": "sky.belt.{rock}", "for": VIEWER }), "{got:?}");
    let got = host.as_(VIEWER).call("mnt.belt.ceres.rename", json!({ "to": "x" })).await.values();
    assert_eq!(got[0]["grant"], "sky.belt.{rock}", "the whole slot, every method: {got:?}");
    let refused = host.as_(EDITOR).call("mnt.belt.ceres.info", json!({})).await.values();
    assert!(refused[0]["route_error"].as_str().is_some_and(|r| r.contains("mnt.belt.{rock}")), "the editor holds no rock: {refused:?}");
    let got = host.as_(VIEWER).call("mnt.belt.dust1.info", json!({})).await.values();
    assert_eq!(got[0]["error"]["kind"], "activation_not_found", "{got:?}");
    let got = host.as_(VIEWER).call("mnt.dendrite.greeter.hello", json!({ "name": "world" })).await.values();
    assert_eq!(got[0], json!({ "at": "greeter", "grant": "sky.{dendrite}", "for": VIEWER, "text": "hello, world" }), "{got:?}");
}

/// One instance's schema crosses the hop once per name, answered from the
/// cache after; an unknown name's not-found is relayed and not kept; a
/// static level never crosses.
async fn one_schema_per_name_crosses_once() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let before = child.stats();
    for _ in 0..10 {
        let s = host.as_(VIEWER).call("mnt.solar.earth.schema", json!({})).await.values();
        assert_eq!(s[0]["namespace"], "planet", "{s:?}");
        let names: Vec<&str> = s[0]["methods"].as_array().unwrap().iter().filter_map(|m| m["name"].as_str()).collect();
        assert!(names.contains(&"info") && names.contains(&"rename"), "{names:?}");
    }
    let one = host.as_(VIEWER).call("mnt.solar.earth.schema", json!({ "method": "info" })).await.values();
    assert_eq!(one[0]["name"], "info", "{one:?}");
    let after = child.stats();
    assert_eq!((after.name_schemas - before.name_schemas, after.name_schema_hits - before.name_schema_hits), (1, 10), "{after:?}");
    assert_eq!(after.calls - before.calls, 1, "one hop for eleven asks");
    assert_eq!(after.names_kept, 1);
    println!("measure: `mnt.solar.earth.schema` asked 11 times: {} hop, {} from the cache ({after:?})", after.name_schemas, after.name_schema_hits);
    // An unknown name: the child's not-found, relayed, not kept.
    let got = host.as_(VIEWER).call("mnt.solar.pluto.schema", json!({})).await.values();
    assert_eq!(got[0]["error"]["kind"], "activation_not_found", "{got:?}");
    assert_eq!(child.stats().names_kept, 1);
    // A peer, and an untyped slot's name.
    let g = host.as_(VIEWER).call("mnt.dendrite.greeter.schema", json!({})).await.values();
    assert_eq!(g[0]["namespace"], "greeter", "{g:?}");
    let r = host.as_(VIEWER).call("mnt.belt.ceres.schema", json!({})).await.values();
    assert_eq!(r[0]["namespace"], "planet", "{r:?}");
    // The static levels: from the kept tree, nothing crosses.
    let calls = child.stats().calls;
    let s = host.as_(VIEWER).call("mnt.solar.schema", json!({})).await.values();
    assert_eq!(s[0]["namespace"], "solar", "{s:?}");
    assert_eq!(child.stats().calls, calls, "a static path never crosses for its schema");
}

/// At most `--child-schema-cache` names, the least recently used out.
async fn the_cache_is_bounded() {
    let child = mount_with("mnt", 2).await;
    let host = DynamicHub::new("host").register(child.clone());
    for n in ["earth", "mars", "earth", "venus", "earth", "mars"] {
        let s = items(host.route(&format!("mnt.solar.{n}.schema"), json!({}), None).await).await;
        assert_eq!(s[0]["namespace"], "planet", "{s:?}");
    }
    let st = child.stats();
    // earth, mars cross; earth hit; venus crosses (mars out); earth hit; mars crosses (venus out)
    assert_eq!((st.name_schemas, st.name_schema_hits, st.names_kept), (4, 2, 2), "{st:?}");
}

/// The child restarts: every kept name is dropped.
async fn a_restart_drops_every_name() {
    let child = mount("mnt").await;
    let host = gated(&child).await;
    let _ = host.as_(VIEWER).call("mnt.solar.earth.schema", json!({})).await.values();
    let _ = host.as_(VIEWER).call("mnt.solar.mars.schema", json!({})).await.values();
    assert_eq!(child.stats().names_kept, 2);
    let pid = child.pid().expect("a stdio child has a pid");
    let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = host.as_(VIEWER).call("mnt.solar.names", json!({})).await.values();
        if got.first() == Some(&json!("earth")) && child.pid() != Some(pid) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the child never came back: {got:?}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let hops = child.stats().name_schemas;
    let s = host.as_(VIEWER).call("mnt.solar.earth.schema", json!({})).await.values();
    assert_eq!(s[0]["namespace"], "planet", "{s:?}");
    let st = child.stats();
    assert!(st.restarts >= 1);
    assert_eq!((st.name_schemas - hops, st.names_kept), (1, 1), "asked again after the restart: {st:?}");
}

/// The far side, raw: one `sky.call` on a pipe, every item back.
async fn raw(call: Value) -> Vec<Value> {
    let (mut ours, theirs) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(theirs);
    let served = tokio::spawn(plexus_core::plexus::remote_child::serve_child(SkyActivation, r, w));
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "sky.call", "params": call });
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

/// The far side checks a hop's grant against the slot a path goes through,
/// not only the literal path.
async fn the_far_side_is_slot_aware() {
    let hop = |g: &str| json!({ "principal": "service:host", "for": [VIEWER], "limit": { "grant": g, "held_on": ["*"] }, "call": "c" });
    let call = |m: &str, g: &str| json!({ "method": m, "params": {}, "hop": hop(g) });
    let got = raw(call("sky.solar.earth.info", "sky.solar.{planet}.info")).await;
    assert_eq!(got[0]["content"]["at"], "planet earth", "{got:?}");
    let got = raw(call("sky.solar.earth.rename", "sky.solar.{planet}.info")).await;
    assert_eq!(got[0]["error_kind"], "forbidden", "another method's slot grant: {got:?}");
    let got = raw(json!({ "method": "sky.belt.ceres.rename", "params": { "to": "x" }, "hop": hop("sky.belt.{rock}") })).await;
    assert_eq!(got[0]["content"]["at"], "ceres -> x", "an untyped slot's grant is every method: {got:?}");
    let got = raw(json!({ "method": "sky.belt.ceres.info", "params": {}, "hop": hop("sky.belt.{rock}") })).await;
    assert_eq!(got[0]["content"]["at"], "planet ceres", "an untyped slot, whole: {got:?}");
    let got = raw(call("sky.dendrite.greeter.hello", "sky.{dendrite}")).await;
    assert_ne!(got[0]["error_kind"], "forbidden", "a peer slot, whole: {got:?}");
    let got = raw(call("sky.solar.earth.info", "sky.solar.earth.info")).await;
    assert_eq!(got[0]["content"]["at"], "planet earth", "the literal path still decides: {got:?}");
    let got = raw(call("sky.solar.earth.info", "sky.belt.{rock}")).await;
    assert_eq!(got[0]["error_kind"], "forbidden", "another slot's grant: {got:?}");
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(SkyActivation)).unwrap();
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    if let Ok(port) = std::env::var("NEST6_SERVE") {
        let grants = std::env::var("NEST6_GRANT").into_iter().flat_map(|g| g.split(',').map(|kv| {
            let (who, role) = kv.split_once('=').unwrap_or((kv, "viewer"));
            (who.to_string(), role.to_string())
        }).collect::<Vec<_>>()).collect();
        rt.block_on(async {
            let child = mount("mnt").await;
            println!("mounted mnt: {:?}", child.static_child_schemas().into_iter().map(|(p, _)| p).collect::<Vec<_>>());
            let opts = service::Serve { port: port.parse().unwrap(), grants, ..Default::default() };
            let watch = child.clone();
            tokio::spawn(async move {
                let mut last = None;
                loop {
                    let st = watch.stats();
                    if last != Some(st) {
                        println!("stats: {st:?}");
                        last = Some(st);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            });
            service::serve_over(DynamicHub::new("host").register(child), opts).await.unwrap();
        });
        return;
    }
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( $t().await; println!("test {} ... ok", stringify!($t)); n += 1; )* n }};
        }
        let n = run!(
            the_walk_keeps_each_slot_and_its_type,
            a_typed_slot_is_gated_by_its_slot_grant_and_forwarded,
            an_unknown_name_is_the_childs_own_not_found,
            names_are_listed_and_searched_live,
            an_untyped_slot_is_gated_whole,
            one_schema_per_name_crosses_once,
            the_cache_is_bounded,
            a_restart_drops_every_name,
            the_far_side_is_slot_aware
        );
        println!("\ntest result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
    });
}
