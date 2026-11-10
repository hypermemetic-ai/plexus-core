//! RETURNS-40's review: how a service serves its `ir` — the reviewer's five
//! reproductions (dos, race, leak, big, eq), each turned into what must hold.
//!
//! - **dos**: `namespaces` is capped at the names the caller's view of the
//!   service has, and a name it has not is refused as `invalid_params`
//!   naming it — before any work: 40,000 names refused in under a
//!   millisecond.
//! - **race**: the IR is built from one view snapshot and kept under that
//!   view's hash — a grant that moves mid-build never puts one caller's
//!   view in another's answer.
//! - **leak**: under the R-5 scope gate the key is the caller's effective
//!   view: a caller refused a schema never gets an answer built for another.
//! - **big**: the build runs off the runtime (`spawn_blocking`), once per
//!   key at a time (single-flight), and a refusal is not kept.
//! - **eq**: the service's IR of the reviewer's hard shapes is synapse's,
//!   byte for byte (`tests/fixtures/ir-hard/`, written by synapse's
//!   ir3-test from `schemas.json`, which `IR_HARD_ACCEPT=1` writes here).

mod ir_hard_service;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_auth_core::grants::GrantsGeneration;
use plexus_auth_core::ScopeRegistry;
use plexus_core::plexus::{ir, Activation, AuthContext, Gate, Membership, Memberships, PlexusStreamItem, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use plexus_testkit::parts::{who, Everywhere};
use plexus_testkit::World;
use serde_json::{json, Value};

async fn call(service: &DynamicHub, method: &str, params: Value, auth: Option<&AuthContext>) -> Vec<Value> {
    match service.route(method, params, auth).await {
        Ok(stream) => stream.map(|i: PlexusStreamItem| serde_json::to_value(i).unwrap()).collect().await,
        Err(e) => vec![plexus_core::plexus::error_item(service.runtime_namespace(), &e)],
    }
}

fn content(items: &[Value]) -> Value {
    items.iter().find(|i| i["type"] == "data").unwrap_or_else(|| panic!("no data item: {items:?}"))["content"].clone()
}

/// The IR an `ir` call answers, or its call failure.
async fn ir_of(service: &DynamicHub, params: Value, auth: Option<&AuthContext>) -> Result<Value, Value> {
    let items = call(service, &format!("{}.ir", service.runtime_namespace()), params, auth).await;
    match items.iter().find(|i| i["type"] == "data") {
        Some(d) => Ok(d["content"]["ok"].clone()),
        None => Err(items.into_iter().find(|i| i["type"] == "error").expect("an error item")),
    }
}

fn methods_under(ir: &Value, prefix: &str) -> Vec<String> {
    let mut v: Vec<String> = ir["irMethods"]
        .as_object()
        .unwrap_or_else(|| panic!("not an IR: {ir}"))
        .keys()
        .filter(|k| k.starts_with(prefix) && !k.ends_with(".schema"))
        .cloned()
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// dos
// ---------------------------------------------------------------------------

/// A service whose `beta` counts every time its schema is built: what
/// `ir` reads of a service, seen from outside it.
#[derive(Clone)]
struct Counted(ir_hard_service::Beta);

static SCHEMAS_READ: AtomicUsize = AtomicUsize::new(0);

#[async_trait::async_trait]
impl Activation for Counted {
    type Methods = <ir_hard_service::Beta as Activation>::Methods;
    fn namespace(&self) -> &str {
        self.0.namespace()
    }
    fn version(&self) -> &str {
        self.0.version()
    }
    fn description(&self) -> &str {
        self.0.description()
    }
    fn methods(&self) -> Vec<&str> {
        self.0.methods()
    }
    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&plexus_core::request::RawRequestContext>) -> Result<plexus_core::plexus::PlexusStream, plexus_core::plexus::PlexusError> {
        Activation::call(&self.0, method, params, auth, raw).await
    }
    fn into_rpc_methods(self) -> jsonrpsee::core::server::Methods {
        self.0.into_rpc_methods()
    }
    fn plugin_schema(&self) -> plexus_core::plexus::PluginSchema {
        SCHEMAS_READ.fetch_add(1, Ordering::SeqCst);
        self.0.plugin_schema()
    }
}

#[async_trait::async_trait]
impl plexus_core::plexus::ChildRouter for Counted {
    fn router_namespace(&self) -> &str {
        self.0.router_namespace()
    }
    async fn router_call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&plexus_core::request::RawRequestContext>) -> Result<plexus_core::plexus::PlexusStream, plexus_core::plexus::PlexusError> {
        self.0.router_call(method, params, auth, raw).await
    }
    async fn get_child(&self, name: &str) -> Option<Box<dyn plexus_core::plexus::ChildRouter>> {
        self.0.get_child(name).await
    }
}

/// The reviewer's 40,000 names: refused as invalid_params, naming the
/// parameter — before any schema is read or any IR built (a generous time
/// bound beside: the refusal does no work to wait on).
#[tokio::test]
async fn dos_forty_thousand_names_are_refused_at_once() {
    let service = DynamicHub::new("xsvc").register(ir_hard_service::Alpha).register(Counted(ir_hard_service::Beta));
    let read_before = SCHEMAS_READ.load(Ordering::SeqCst);
    let names: Vec<String> = (0..40_000).map(|i| format!("n{i}")).collect();
    let params = json!({ "namespaces": names });
    let t = std::time::Instant::now();
    let answer = ir_of(&service, params, None).await;
    let took = t.elapsed();
    let err = answer.expect_err("refused");
    assert_eq!(err["error"]["kind"], "invalid_params", "{err}");
    assert!(err["message"].as_str().unwrap_or("").contains("namespaces"), "{err}");
    assert_eq!(service.ir_builds(), 0, "no IR was built");
    assert_eq!(SCHEMAS_READ.load(Ordering::SeqCst), read_before, "no schema was read");
    assert!(took < std::time::Duration::from_millis(100), "refused in {took:?}");
}

/// RETURNS-40 re-review #3: the refusal of too many names says what the
/// caller's view shows, never how big the service behind it is.
#[tokio::test]
async fn dos_too_many_names_is_counted_in_the_callers_view() {
    // the whole service: menger, tickets, alpha, alpha.inner, beta — five; a stranger sees only menger
    let host = World::new().host().named("menger").with(TicketsActivation).with(ir_hard_service::Alpha).with(ir_hard_service::Beta).await;
    let service = host.service().clone();
    for asked in [json!(["menger", "tickets"]), json!(["a", "b", "c", "d", "e", "f"])] {
        let err = ir_of(&service, json!({ "namespaces": asked }), None).await.expect_err("more than the view shows");
        let msg = err["message"].as_str().unwrap();
        assert_eq!(err["error"]["kind"], "invalid_params", "{err}");
        assert!(!msg.contains('5') && !msg.contains("at most"), "the service's size said: {msg}");
        assert!(msg.contains("shows you"), "{msg}");
    }
}

/// More names than the service has is refused; so is a name it has not,
/// named; the names it has are answered.
#[tokio::test]
async fn dos_names_are_the_services_own() {
    let service = ir_hard_service::service();
    // root, alpha, alpha.inner, beta: four
    let five = json!({ "namespaces": ["alpha", "beta", "alpha.inner", "xsvc", "alpha"] });
    let err = ir_of(&service, five, None).await.expect_err("five is more than four");
    assert_eq!(err["error"]["kind"], "invalid_params", "{err}");
    let err = ir_of(&service, json!({ "namespaces": ["beta", "delta"] }), None).await.expect_err("no delta");
    assert_eq!(err["error"]["kind"], "invalid_params", "{err}");
    assert!(err["message"].as_str().unwrap().contains("delta"), "{err}");
    let ok = ir_of(&service, json!({ "namespaces": ["beta", "alpha.inner"] }), None).await.expect("both are the service's");
    assert_eq!(ok["irPlugins"].as_object().unwrap().keys().cloned().collect::<Vec<_>>(), ["alpha.inner", "beta"]);
    assert_eq!(service.ir_builds(), 1);
}

// ---------------------------------------------------------------------------
// race
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TicketsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "race",
    crate_path = "plexus_core",
    roles(viewer = ["get"], editor = [viewer, "set_status"])
)]
impl TicketsActivation {
    /// get
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// set
    #[plexus_macros::method(target = "id")]
    async fn set_status(&self, id: String, status: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("{id}{status}"); }
    }
}

const CAT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DAN: &str = "key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// CAT is a viewer until the `flip_at`-th time the gate asks what CAT
/// holds; right after that answer CAT is an editor and the grants
/// generation moves — a grant landing mid-build. DAN is a viewer throughout.
struct Rows {
    calls: AtomicUsize,
    flip_at: usize,
    promoted: Mutex<bool>,
    generation: GrantsGeneration,
}

impl Memberships for Rows {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        let mut role = "viewer";
        if who.to_string() == CAT {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let mut p = self.promoted.lock().unwrap();
            if *p {
                role = "editor";
            }
            if n == self.flip_at && !*p {
                *p = true;
                self.generation.bump();
            }
        }
        vec![Membership { principal: who.clone(), role: plexus_auth_core::RoleName::new(role), scope: ScopeRef::parse("*") }]
    }
}

/// Whatever moment the grant lands at, each answer is one view: DAN (a
/// viewer) never sees CAT's promotion, and CAT's IR is the view its own
/// hash names. (Its gate is built here: its memberships, `Rows`, move a
/// grant from inside the gate's own ask, which no host's members do.)
#[tokio::test]
async fn race_a_grant_that_moves_mid_build_never_crosses_views() {
    for flip_at in 1..=6 {
        let generation = GrantsGeneration::new();
        let rows = Arc::new(Rows { calls: AtomicUsize::new(0), flip_at, promoted: Mutex::new(false), generation: generation.clone() });
        let declared = DynamicHub::new("x").register(TicketsActivation).declared_roles();
        let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
        let gate = Gate::new(rows.clone(), Arc::new(roles), Arc::new(Everywhere)).with_generation(generation);
        let service = DynamicHub::new("menger").register(TicketsActivation).with_gate(Arc::new(gate));

        let cat_ir = ir_of(&service, json!({}), Some(&who(CAT))).await.expect("CAT's IR");
        let dan_ir = ir_of(&service, json!({}), Some(&who(DAN))).await.expect("DAN's IR");
        let cat = methods_under(&cat_ir, "tickets.");
        let dan = methods_under(&dan_ir, "tickets.");
        assert_eq!(dan, ["tickets.get"], "flip_at {flip_at}: DAN, a viewer, was answered {dan:?}");
        assert!(
            cat == ["tickets.get"] || cat == ["tickets.get", "tickets.set_status"],
            "flip_at {flip_at}: CAT's IR is no one view: {cat:?}"
        );
        // CAT's IR is one view, hashes and methods alike: unpromoted, CAT
        // holds what DAN holds — the same view, so the same hashes as DAN's
        // IR; promoted, a view of its own, hashed apart (a view hash is over
        // what the view shows)
        let same_view = cat == dan;
        assert_eq!(cat_ir["irHash"] == dan_ir["irHash"], same_view, "flip_at {flip_at}: root hash vs methods {cat:?}");
        assert_eq!(
            cat_ir["irPluginHashes"]["tickets"] == dan_ir["irPluginHashes"]["tickets"],
            same_view,
            "flip_at {flip_at}: tickets' hash vs methods {cat:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// leak
// ---------------------------------------------------------------------------

fn authed(user: &str, roles: &[&str]) -> AuthContext {
    AuthContext::new(user.to_string(), "s".to_string(), roles.iter().map(|r| r.to_string()).collect(), Value::Null)
}

fn scoped() -> DynamicHub {
    let reg = ScopeRegistry::builder()
        .role("full", &["xsvc.ir", "xsvc.schema", "alpha.*", "beta.*"])
        .role("basic", &["xsvc.ir", "xsvc.schema", "beta.*"])
        .build()
        .unwrap();
    ir_hard_service::service().with_default_deny(true).with_scope_registry(reg)
}

/// Under the R-5 scope gate, in either order, each caller is answered its
/// own effective view: basic (refused alpha's schema) sees nothing of
/// alpha, full sees it.
#[tokio::test]
async fn leak_the_scope_gate_keys_by_the_callers_view() {
    let full = authed("u-full", &["full"]);
    let basic = authed("u-basic", &["basic"]);
    let refused = call(&scoped(), "alpha.schema", json!({}), Some(&basic)).await;
    assert_eq!(refused[0]["type"], "error", "basic is refused alpha.schema: {refused:?}");

    for basic_first in [true, false] {
        let service = scoped();
        let (b, f) = if basic_first {
            let b = ir_of(&service, json!({}), Some(&basic)).await.expect("basic's IR");
            (b, ir_of(&service, json!({}), Some(&full)).await.expect("full's IR"))
        } else {
            let f = ir_of(&service, json!({}), Some(&full)).await.expect("full's IR");
            (ir_of(&service, json!({}), Some(&basic)).await.expect("basic's IR"), f)
        };
        assert_eq!(methods_under(&b, "alpha."), Vec::<String>::new(), "basic_first {basic_first}: basic sees alpha");
        assert!(!methods_under(&f, "alpha.").is_empty(), "basic_first {basic_first}: full does not see alpha");
        assert!(!methods_under(&b, "beta.").is_empty(), "basic_first {basic_first}: basic does not see beta");
    }
}

// ---------------------------------------------------------------------------
// big
// ---------------------------------------------------------------------------

/// The build runs off the runtime: on a one-thread runtime, a task spawned
/// after the ask runs before the ask's answer is made.
#[test]
fn big_the_build_does_not_hold_the_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let service = Arc::new(ir_hard_service::service());
        let order = Arc::new(Mutex::new(Vec::new()));
        let (h, o) = (service.clone(), order.clone());
        let ask = tokio::spawn(async move {
            ir_of(&h, json!({}), None).await.expect("the IR");
            o.lock().unwrap().push("answered");
        });
        let o = order.clone();
        let other = tokio::spawn(async move {
            o.lock().unwrap().push("other task ran");
        });
        ask.await.unwrap();
        other.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["other task ran", "answered"]);
    });
}

/// Many asking at once for one key: one build, every answer the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn big_one_build_per_key_at_a_time() {
    let service = Arc::new(ir_hard_service::service());
    let asks: Vec<_> = (0..16)
        .map(|_| {
            let h = service.clone();
            tokio::spawn(async move { ir_of(&h, json!({}), None).await.expect("the IR") })
        })
        .collect();
    let mut answers = Vec::new();
    for a in asks {
        answers.push(a.await.unwrap());
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(service.ir_builds(), 1, "one build for sixteen asks");
    // another key builds again; the first is kept
    ir_of(&service, json!({"namespaces": ["beta"]}), None).await.unwrap();
    ir_of(&service, json!({}), None).await.unwrap();
    assert_eq!(service.ir_builds(), 2);
}

/// A refusal is not kept: under the scope gate, a caller refused the
/// service's own schema is refused the IR (not_found), and asking again
/// builds again.
#[tokio::test]
async fn big_a_refusal_is_not_kept() {
    let reg = ScopeRegistry::builder().role("bare", &["xsvc.ir"]).build().unwrap();
    let service = ir_hard_service::service().with_default_deny(true).with_scope_registry(reg);
    let bare = authed("u-bare", &["bare"]);
    for n in 1..=2 {
        let items = call(&service, "xsvc.ir", json!({}), Some(&bare)).await;
        let c = content(&items);
        assert_eq!(c["err"]["type"], "not_found", "{c}");
        assert_eq!(service.ir_builds(), n, "asked {n} times, built {n} times");
    }
}

// ---------------------------------------------------------------------------
// eq
// ---------------------------------------------------------------------------

fn hard(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ir-hard").join(rel)
}

/// Every schema synapse's walk reads, by dotted path.
async fn walk(service: &DynamicHub) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let mut todo = vec![String::new()];
    while let Some(path) = todo.pop() {
        let method = if path.is_empty() { format!("{}.schema", service.runtime_namespace()) } else { format!("{path}.schema") };
        let schema = content(&call(service, &method, Value::Null, None).await);
        for k in schema.get("children").and_then(Value::as_array).into_iter().flatten() {
            let ns = k["namespace"].as_str().unwrap();
            todo.push(if path.is_empty() { ns.to_string() } else { format!("{path}.{ns}") });
        }
        out.insert(path, schema);
    }
    out
}

/// The reviewer's hard shapes: the service's IR is synapse's, for the
/// whole service, `alpha`, and `beta` with `alpha.inner`.
#[tokio::test]
async fn eq_the_hard_shapes_are_synapses() {
    let service = ir_hard_service::service();
    let schemas = serde_json::to_value(walk(&service).await).unwrap();
    let accept = std::env::var("IR_HARD_ACCEPT").as_deref() == Ok("1");
    if accept {
        std::fs::write(hard("schemas.json"), serde_json::to_string_pretty(&schemas).unwrap() + "\n").unwrap();
    }
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(hard("schemas.json")).unwrap()).unwrap();
    assert!(schemas == kept, "the served schemas moved (IR_HARD_ACCEPT=1 writes them; then synapse's ir3-test the IR)");
    for (file, params) in [
        ("ir.json", json!({})),
        ("ir.alpha.json", json!({"namespaces": ["alpha"]})),
        ("ir.beta-inner.json", json!({"namespaces": ["beta", "alpha.inner"]})),
    ] {
        let served = ir_of(&service, params, None).await.expect("the IR");
        // The IR too (plexus-core's is held equal to synapse's:
        // regenerate synapse's goldens from the same schemas).
        if accept {
            std::fs::write(hard(file), ir::canonical(&served)).unwrap();
        }
        let golden = std::fs::read_to_string(hard(file)).unwrap();
        assert!(ir::canonical(&served) == golden, "{file}: the service's IR is not synapse's");
    }
}

// ---------------------------------------------------------------------------
// audit (re-review #4)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Sink(Mutex<Vec<plexus_auth_core::AuditRecord>>);

#[async_trait::async_trait]
impl plexus_auth_core::AuditSink for Sink {
    async fn write(&self, r: plexus_auth_core::AuditRecord) {
        self.0.lock().unwrap().push(r);
    }
}

/// Under R-5 an `ir` call is audited once — the call itself — however many
/// schemas its walk decides, kept or built: no Deny for a schema the caller
/// did not ask for.
#[tokio::test]
async fn audit_an_ir_call_once() {
    let sink = Arc::new(Sink::default());
    let reg = ScopeRegistry::builder().role("basic", &["xsvc.ir", "xsvc.schema", "beta.*"]).build().unwrap();
    let service = ir_hard_service::service().with_audit_sink(sink.clone()).with_default_deny(true).with_scope_registry(reg);
    let basic = authed("u", &["basic"]);
    for i in 0..3 {
        let before = sink.0.lock().unwrap().len();
        ir_of(&service, json!({"namespaces": ["beta"]}), Some(&basic)).await.expect("beta's IR");
        let records: Vec<String> = sink.0.lock().unwrap()[before..].iter().map(|r| format!("{r:?}")).collect();
        assert_eq!(records.len(), 1, "call {i}: {records:#?}");
        assert!(records[0].contains("xsvc.ir"), "call {i}: {records:#?}");
    }
}
