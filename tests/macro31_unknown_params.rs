//! MACRO-31 · the echo activation (`typed_params`, MACRO-12's example)
//! refuses a key no parameter claims, through the service's route, with
//! `-32602 invalid_params` and synapse's heal word `unknown field`, before
//! the method runs. A call naming only its own parameters runs as before.

use futures::StreamExt;
use plexus_core::activations::echo::EchoActivation;
use plexus_core::plexus::{error_item, PlexusError};
use plexus_core::DynamicHub;
use serde_json::json;

fn service() -> DynamicHub {
    DynamicHub::new("service").register(EchoActivation::new())
}

async fn refused(method: &str, params: serde_json::Value) -> PlexusError {
    match service().route(method, params.clone(), None).await {
        Err(e) => e,
        Ok(_) => panic!("{method} {params}: expected a refusal, the method ran"),
    }
}

#[tokio::test]
async fn the_echo_refuses_a_misspelled_parameter() {
    let e = refused("echo.once", json!({ "mesage": "hi" })).await;
    let item = error_item("echo", &e);
    assert_eq!(item["code"], "-32602", "{item}");
    assert_eq!(item["error_kind"], "invalid_params", "{item}");
    assert_eq!(item["message"], "Invalid params: unknown field `mesage`; echo.once takes: message", "{item}");
}

#[tokio::test]
async fn the_echo_refuses_an_extra_key_beside_its_own() {
    let e = refused("echo.echo", json!({ "message": "hi", "count": 1, "mesage": "x" })).await;
    let item = error_item("echo", &e);
    assert_eq!(item["code"], "-32602", "{item}");
    let message = item["message"].as_str().unwrap_or_default();
    assert_eq!(message, "Invalid params: unknown field `mesage`; echo.echo takes: count, message");
    assert!(message.contains("unknown field"), "synapse's heal word: {message}");
}

#[tokio::test]
async fn the_echo_still_echoes_its_own_parameters() {
    let stream = service().route("echo.once", json!({ "message": "hi" }), None).await.expect("echo.once runs");
    let items: Vec<_> = stream.collect().await;
    assert!(!items.is_empty(), "echo.once answered nothing");
    let stream = service().route("echo.once", json!("hi"), None).await.expect("the bare value runs");
    assert!(!stream.collect::<Vec<_>>().await.is_empty());
}
