//! KEEL-26: a call's outcome — answered, refused (before it opened, or in
//! band), failed — and what a failed assertion on it says.

use std::panic::{catch_unwind, AssertUnwindSafe};

use async_stream::stream;
use futures::stream::Stream;
use plexus_core::plexus::{DenyReason, PlexusStreamItem, RemoteError, StreamMetadata};
use plexus_core::{AuthzDenyReason, DynamicHub, PlexusError};
use plexus_testkit::parts::who;
use plexus_testkit::{Caller, Forbidden, InvalidParams, NotFound, Outcome, Unauthenticated, World, EDITOR, NOBODY, VIEWER};
use serde_json::json;

#[derive(Clone)]
struct ShopActivation;

/// A shop: the viewer reads the shelves, the editor restocks.
#[plexus_macros::activation(namespace = "shop", roles(viewer = ["items"], editor = ["items", "restock"]))]
impl ShopActivation {
    /// What is on the shelves.
    #[plexus_macros::method]
    async fn items(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "flour".to_string(); yield "salt".to_string(); yield "rye".to_string(); }
    }
    /// Put more on them.
    #[plexus_macros::method]
    async fn restock(&self, what: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("restocked {what}"); }
    }
}

/// What a failed assertion said.
fn panic_of(f: impl FnOnce()) -> String {
    let err = catch_unwind(AssertUnwindSafe(f)).expect_err("the assertion holds, and was meant to fail");
    err.downcast_ref::<String>().cloned().or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

fn meta() -> StreamMetadata {
    StreamMetadata::new(vec!["shop".into()], "h".into())
}

fn data(v: serde_json::Value) -> PlexusStreamItem {
    PlexusStreamItem::data(meta(), "shop.items".into(), v)
}

fn error(e: RemoteError) -> PlexusStreamItem {
    PlexusStreamItem::error(meta(), e, false)
}

fn done() -> PlexusStreamItem {
    PlexusStreamItem::done(meta())
}

#[tokio::test]
async fn a_call_is_its_items_in_order_and_its_done() {
    let host = World::new().host().with(ShopActivation).await;
    let got = host.as_(VIEWER).call("shop.items", json!({})).await;
    assert_eq!(got.answers(3), [json!("flour"), json!("salt"), json!("rye")]);
    assert_eq!(got.items(), got.answers(3));
    // raw(): every item, the closing done kept.
    let raw = got.raw();
    assert_eq!(raw.len(), 4);
    assert_eq!(raw[3]["type"], "done");
}

#[tokio::test]
async fn answer_reads_exactly_one_item_typed() {
    let host = World::new().host().with(ShopActivation).await;
    let got = host.as_(EDITOR).call("shop.restock", json!({ "what": "rye" })).await;
    assert_eq!(got.answer::<String>(), "restocked rye");
    let said = panic_of(|| {
        got.answer::<u64>();
    });
    assert!(said.contains("expected its answer to read as u64"), "{said}");
    // One answer is one item: three are not.
    let three = host.as_(VIEWER).call("shop.items", json!({})).await;
    let said = panic_of(|| {
        three.answer::<String>();
    });
    assert!(said.starts_with("expected 1 data item, got 3"), "{said}");
}

#[test]
fn progress_and_done_are_not_data() {
    let progress = PlexusStreamItem::progress(meta(), "shop.items".into(), json!({ "message": "halfway" }));
    let got = Outcome::of("shop.items", "VIEWER", vec![progress, data(json!("flour")), done()]);
    assert_eq!(got.answers(1), [json!("flour")]);
    // An answer closes with done: a stream that ended open did not answer.
    let open = Outcome::of("shop.items", "VIEWER", vec![data(json!("flour"))]);
    let said = panic_of(|| {
        open.answers(1);
    });
    assert!(said.contains("expected an answer closed with done") && said.contains("(no done: the stream ended open)"), "{said}");
}

#[tokio::test]
async fn refused_is_the_gates_typed_refusal() {
    let host = World::new().host().with(ShopActivation).await;
    let got = host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await;
    let refusal = got.refused(Forbidden).naming("shop.restock").at("*").listed_by(["editor", "admin"]).held_on([]);
    assert_eq!(refusal.message(), "needs shop.restock");
    // The service's own error, kept whole.
    assert!(matches!(
        refusal.plexus_error(),
        Some(PlexusError::Forbidden { reason: AuthzDenyReason::MissingGrant { grant, .. } }) if grant.as_str() == "shop.restock"
    ));
    host.as_(NOBODY).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items").listed_by(["editor", "viewer", "admin"]);
    host.anonymous().call("shop.items", json!({})).await.refused(Unauthenticated);
}

#[tokio::test]
async fn refused_by_the_router_not_found_or_bad_params() {
    // No gate: what the router says.
    let service = Caller::new(DynamicHub::new("store").register(ShopActivation), Some(who(VIEWER)));
    service.call("shop.nothing", json!({})).await.refused(NotFound);
    service.call("cellar.items", json!({})).await.refused(NotFound);
    service.call("shop.restock", json!({})).await.refused(InvalidParams);
}

#[tokio::test]
async fn a_refusal_of_another_kind_or_naming_another_grant_says_so() {
    let host = World::new().host().with(ShopActivation).await;
    let got = host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await;
    let said = panic_of(|| {
        got.refused(Unauthenticated);
    });
    assert!(said.starts_with("expected it refused (Unauthenticated) before it opened"), "{said}");
    let said = panic_of(|| {
        got.refused(Forbidden).naming("shop.items");
    });
    assert!(said.starts_with("expected the refusal to name shop.items, it names shop.restock"), "{said}");
    let said = panic_of(|| {
        got.refused(Forbidden).listed_by(["editor"]);
    });
    assert!(said.contains(r#"expected the grant listed by ["editor"], it is listed by ["editor", "admin"]"#), "{said}");
    // An unauthenticated refusal names no grant.
    let anon = host.anonymous().call("shop.items", json!({})).await;
    let said = panic_of(|| {
        anon.refused(Unauthenticated).naming("shop.items");
    });
    assert!(said.starts_with("expected a missing grant's refusal, which names a grant"), "{said}");
}

#[test]
fn refused_in_band_is_a_refusal_the_stream_carried_alone() {
    let forbidden = RemoteError::Forbidden {
        reason: DenyReason::MissingGrant { grant: "forge.repos".into(), scope: "*".into(), roles: vec!["admin".into()], held_on: vec![] },
    };
    let got = Outcome::of("forge.repos", "ADA", vec![error(forbidden.clone())]);
    got.refused_in_band(Forbidden).naming("forge.repos").listed_by(["admin"]);
    // Not before it opened: refused() says so.
    let said = panic_of(|| {
        got.refused(Forbidden);
    });
    assert!(said.starts_with("expected it refused (Forbidden) before it opened"), "{said}");
    // Data before the refusal: not a refusal alone.
    let after_data = Outcome::of("forge.repos", "ADA", vec![data(json!("menger")), error(forbidden)]);
    let said = panic_of(|| {
        after_data.refused_in_band(Forbidden);
    });
    assert!(said.starts_with("expected it refused (Forbidden) in band, the refusal its only item"), "{said}");
    Outcome::of("forge.repos", "anonymous", vec![error(RemoteError::Unauthenticated)]).refused_in_band(Unauthenticated);
}

#[test]
fn failed_is_an_error_that_is_no_refusal() {
    let got = Outcome::of("shop.add", "EDITOR", vec![error(RemoteError::Execution { message: "a name is required".into() })]);
    let failure = got.failed().saying("name");
    assert_eq!(failure.message(), "execution failed: a name is required");
    let said = panic_of(|| {
        got.failed().saying("price");
    });
    assert!(said.starts_with(r#"expected the failure to say "price", it says "execution failed: a name is required""#), "{said}");
    // A refusal is not a failure.
    let refused = Outcome::of("shop.add", "EDITOR", vec![error(RemoteError::Unauthenticated)]);
    let said = panic_of(|| {
        refused.failed();
    });
    assert!(said.starts_with("expected it failed, not refused"), "{said}");
    // Nor is an answer.
    let said = panic_of(|| {
        Outcome::of("shop.add", "EDITOR", vec![done()]).failed();
    });
    assert!(said.starts_with("expected it failed"), "{said}");
}

#[tokio::test]
async fn a_failed_assertion_says_the_method_the_caller_and_the_whole_outcome() {
    let host = World::new().host().with(ShopActivation).await;
    // Expected refused; it answered.
    let got = host.as_(EDITOR).call("shop.items", json!({})).await;
    let said = panic_of(|| {
        got.refused(Forbidden);
    });
    assert_eq!(
        said,
        "expected it refused (Forbidden) before it opened\n  shop.items as EDITOR opened, and sent 4 item(s):\n    data      \"flour\"\n    data      \"salt\"\n    data      \"rye\"\n    done"
    );
    // Expected an answer; it was refused: the refusal whole.
    let got = host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await;
    let said = panic_of(|| {
        got.answers(1);
    });
    assert!(said.starts_with("expected an answer\n  shop.restock as VIEWER was refused before it opened: forbidden\n"), "{said}");
    assert!(said.contains("    needs shop.restock\n") && said.contains(r#""roles":["editor","admin"]"#), "{said}");
    // A caller the test names is its principal; no one is anonymous.
    let clerk = "key:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    let said = panic_of(|| {
        futures::executor::block_on(host.as_(clerk).call("shop.items", json!({}))).answers(3);
    });
    assert!(said.contains(&format!("shop.items as {clerk} was refused")), "{said}");
    let said = panic_of(|| {
        futures::executor::block_on(host.anonymous().call("shop.items", json!({}))).answers(3);
    });
    assert!(said.contains("shop.items as anonymous was refused before it opened: unauthenticated"), "{said}");
    // Without the named callers seated, a principal sharing VIEWER's key is
    // its principal, not VIEWER.
    let bare = World::new().host().with(ShopActivation).without_named_callers().await;
    let said = panic_of(|| {
        futures::executor::block_on(bare.as_(VIEWER).call("shop.items", json!({}))).answers(3);
    });
    assert!(said.contains(&format!("shop.items as {VIEWER} was refused")), "{said}");
}

#[test]
fn a_failed_assertion_points_at_the_tests_line() {
    let got = Outcome::of("shop.items", "VIEWER", vec![done()]);
    let location = std::sync::Arc::new(std::sync::Mutex::new(None));
    let (seen, me) = (location.clone(), std::thread::current().id());
    let before = std::panic::take_hook();
    // Another test's panic, on another thread, is not this one's.
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == me {
            *seen.lock().unwrap() = info.location().map(|l| (l.file().to_string(), l.line()));
        }
    }));
    let line = line!(); let _ = catch_unwind(AssertUnwindSafe(|| got.answers(1)));
    std::panic::set_hook(before);
    let (file, at) = location.lock().unwrap().clone().expect("it panicked");
    assert!(file.ends_with("tests/outcome.rs"), "{file}");
    assert_eq!(at, line, "the panic is at the test's line");
}
