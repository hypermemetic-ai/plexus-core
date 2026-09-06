//! MACRO-2.B3 · the in-process transport, driven by a generated client.
//!
//! MACRO-2 acceptance criterion 2, second half: "over the in-process
//! transport it runs with no server". No port is opened here, no runtime is
//! configured beyond `#[tokio::test]`, and no `DynamicHub` is built — the
//! client's calls land in `Activation::call` and come back as typed events.

use futures::StreamExt;
use plexus_client::{ClientError, ClientEvent, MethodRef, Transport};
use plexus_core::plexus::{Activation, InProcessTransport, PlexusError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NoteEvent {
    Note { id: String, body: String },
    NotFound { id: String },
    Error { message: String },
}

#[derive(Clone, Default)]
pub struct Notes {
    fail_dispatch: bool,
}

#[plexus_macros::activation(
    namespace = "notes",
    description = "Notes for the in-process transport test",
    client,
    crate_path = "plexus_core"
)]
impl Notes {
    /// One note by id.
    #[plexus_macros::method]
    pub async fn get(&self, id: String) -> impl futures::Stream<Item = NoteEvent> + Send + 'static {
        let ev = if id == "N-1" {
            NoteEvent::Note {
                id,
                body: "the first note".into(),
            }
        } else {
            NoteEvent::NotFound { id }
        };
        futures::stream::iter(vec![ev])
    }

    /// All notes, optionally filtered.
    #[plexus_macros::method]
    pub async fn list(
        &self,
        prefix: Option<String>,
    ) -> impl futures::Stream<Item = NoteEvent> + Send + 'static {
        let all = vec![
            NoteEvent::Note {
                id: "N-1".into(),
                body: "the first note".into(),
            },
            NoteEvent::Note {
                id: "M-1".into(),
                body: "another".into(),
            },
        ];
        let out: Vec<NoteEvent> = match prefix {
            None => all,
            Some(p) => all
                .into_iter()
                .filter(|e| matches!(e, NoteEvent::Note { id, .. } if id.starts_with(&p)))
                .collect(),
        };
        futures::stream::iter(out)
    }

    /// Emits the activation's own error variant — an in-band error.
    #[plexus_macros::method]
    pub async fn boom(&self) -> impl futures::Stream<Item = NoteEvent> + Send + 'static {
        futures::stream::iter(vec![NoteEvent::Error {
            message: "the activation said no".into(),
        }])
    }
}

#[tokio::test]
async fn a_generated_client_runs_against_the_activation_with_no_server() {
    let client = NotesClient::new(InProcessTransport::new(Notes::default()));

    let events = client.get_all("N-1".to_string()).await.expect("ok");
    assert_eq!(
        events,
        vec![NoteEvent::Note {
            id: "N-1".into(),
            body: "the first note".into()
        }]
    );

    assert_eq!(
        client.list_all(None).await.expect("ok").len(),
        2,
        "no params, no filter"
    );
    assert_eq!(
        client.list_all(Some("N".into())).await.expect("ok").len(),
        1,
        "the Option param reached the activation"
    );
}

#[tokio::test]
async fn the_streaming_form_works_the_same_in_process() {
    let client = NotesClient::new(InProcessTransport::new(Notes::default()));

    let mut ids = Vec::new();
    let mut stream = client.list(None);
    while let Some(ev) = stream.next().await {
        if let ClientEvent::Data(NoteEvent::Note { id, .. }) = ev.expect("ok") {
            ids.push(id);
        }
    }
    assert_eq!(ids, vec!["N-1".to_string(), "M-1".to_string()]);
}

/// The activation's *own* error variant is a data event. Distinguishing it
/// from a failed call is the whole point of the two error layers.
#[tokio::test]
async fn an_activation_error_variant_arrives_as_data() {
    let client = NotesClient::new(InProcessTransport::new(Notes::default()));
    assert_eq!(
        client.boom_all().await.expect("not a client error"),
        vec![NoteEvent::Error {
            message: "the activation said no".into()
        }]
    );
}

/// `Activation::call` returning `Err` means nothing was answered — the same
/// class as a dropped connection, so it reports as a transport error.
#[tokio::test]
async fn a_failed_dispatch_is_a_transport_error_not_a_remote_one() {
    let transport = InProcessTransport::new(Notes::default());
    // An unknown method is the cleanest way to make `call` return Err.
    let stream = Transport::call(&transport, MethodRef::new("notes", "nope"), json!({}));
    let items: Vec<_> = stream.collect().await;
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err(), "{items:?}");

    // And through a typed decode, it lands in the transport layer.
    let decoded: Vec<Result<ClientEvent<NoteEvent>, ClientError>> = plexus_client::decode(
        Transport::call(&transport, MethodRef::new("notes", "nope"), json!({})),
    )
    .collect()
    .await;
    assert!(decoded[0].as_ref().unwrap_err().is_transport());
}

/// Wiring a client for one activation to a transport bound to another must
/// not silently dispatch on whichever method names happen to collide.
#[tokio::test]
async fn a_namespace_mismatch_is_refused_before_dispatch() {
    let transport = InProcessTransport::new(Notes::default());
    let items: Vec<_> = Transport::call(&transport, MethodRef::new("tickets", "get"), json!({}))
        .collect()
        .await;

    assert_eq!(items.len(), 1);
    let err = items[0].as_ref().unwrap_err();
    assert!(err.message.contains("notes"), "{err}");
    assert!(err.message.contains("tickets.get"), "{err}");
}

/// The metadata the wire transports carry is carried here too — in-process
/// drops nothing, so a consumer that reads provenance behaves the same.
#[tokio::test]
async fn in_process_carries_the_full_envelope() {
    let transport = InProcessTransport::new(Notes::default());
    let items: Vec<_> = Transport::call(
        &transport,
        MethodRef::new("notes", "get"),
        json!({"id": "N-1"}),
    )
    .collect()
    .await;

    let first = items[0].as_ref().expect("ok");
    let meta = first.metadata().expect("in-process carries metadata");
    assert!(
        meta.provenance.contains(&"notes".to_string()),
        "provenance: {:?}",
        meta.provenance
    );
    assert!(
        items.last().unwrap().as_ref().unwrap().is_terminal(),
        "the stream still ends with done"
    );
}

/// The activation is still an activation: `InProcessTransport` wraps it, it
/// does not replace it.
#[tokio::test]
async fn the_activation_is_reachable_through_the_transport() {
    let transport = InProcessTransport::new(Notes::default());
    assert_eq!(transport.activation().namespace(), "notes");

    // and dispatching by hand still works, unchanged
    let direct = transport
        .activation()
        .call("get", json!({"id": "N-1"}), None, None)
        .await;
    assert!(matches!(direct, Ok(_)));

    let missing: Result<_, PlexusError> = transport
        .activation()
        .call("nope", json!({}), None, None)
        .await;
    assert!(missing.is_err());
}
