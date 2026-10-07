//! MACRO-2.B3 · the in-process transport, driven by a generated client.
//!
//! MACRO-2 acceptance criterion 2, second half: "over the in-process
//! transport it runs with no server". No port is opened here, no runtime is
//! configured beyond `#[tokio::test]`, and no `DynamicHub` is built — the
//! client's calls land in `Activation::call` and come back as typed items.
//!
//! RETURNS-9: a dispatch that fails (`Activation::call` returning `Err`) is a
//! typed error frame here, as it is from a hub's `call` route — so the
//! client sees `ClientError::Remote(RemoteError)` in-process exactly as it
//! would over a socket.

use futures::{StreamExt, TryStreamExt};
use plexus_client::{ClientError, MethodRef, ParamProblem, RemoteError, StreamItem, Transport};
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

    let events: Vec<NoteEvent> = client.get("N-1".to_string()).try_collect().await.expect("ok");
    assert_eq!(
        events,
        vec![NoteEvent::Note {
            id: "N-1".into(),
            body: "the first note".into()
        }]
    );

    let all: Vec<NoteEvent> = client.list(None).try_collect().await.expect("ok");
    assert_eq!(all.len(), 2, "no params, no filter");
    let some: Vec<NoteEvent> = client.list(Some("N".into())).try_collect().await.expect("ok");
    assert_eq!(some.len(), 1, "the Option param reached the activation");
}

#[tokio::test]
async fn the_streaming_form_works_the_same_in_process() {
    let client = NotesClient::new(InProcessTransport::new(Notes::default()));

    let mut ids = Vec::new();
    let mut stream = client.list(None);
    while let Some(ev) = stream.next().await {
        if let NoteEvent::Note { id, .. } = ev.expect("ok") {
            ids.push(id);
        }
    }
    assert_eq!(ids, vec!["N-1".to_string(), "M-1".to_string()]);

    // …and as the activation's derived aggregate.
    let events: Vec<NotesEvent> = client.list(None).events().try_collect().await.expect("ok");
    assert!(
        matches!(&events[..], [NotesEvent::List(NoteEvent::Note { .. }), NotesEvent::List(NoteEvent::Note { .. })]),
        "{events:?}"
    );
}

/// The activation's *own* error variant is a data event. Distinguishing it
/// from a failed call is the whole point of the two error layers.
#[tokio::test]
async fn an_activation_error_variant_arrives_as_data() {
    let client = NotesClient::new(InProcessTransport::new(Notes::default()));
    let events: Vec<NoteEvent> = client.boom().try_collect().await.expect("not a client error");
    assert_eq!(
        events,
        vec![NoteEvent::Error {
            message: "the activation said no".into()
        }]
    );
}

/// `Activation::call` returning `Err` is the call failing, typed: one error
/// frame carrying `RemoteError::from(&e)` — provenance the activation, not
/// recoverable, no `done` — as a hub's `call` route sends it.
#[tokio::test]
async fn a_failed_dispatch_is_a_typed_error_frame() {
    let transport = InProcessTransport::new(Notes::default());
    // An unknown method is the cleanest way to make `call` return Err.
    let items: Vec<_> = Transport::call(&transport, MethodRef::new("notes", "nope"), json!({}))
        .collect()
        .await;
    match &items[..] {
        [Ok(StreamItem::Error {
            metadata,
            recoverable: false,
            error,
        })] => {
            assert_eq!(
                *error,
                RemoteError::MethodNotFound {
                    activation: "notes".into(),
                    method: "nope".into()
                }
            );
            let meta = metadata.as_ref().expect("in-process carries metadata");
            assert_eq!(meta.provenance, vec!["notes".to_string()]);
        }
        other => panic!("expected exactly one error frame, got {other:?}"),
    }
}

/// Through the generated client, a failed dispatch is
/// `ClientError::Remote(RemoteError)` — the same value a wire transport
/// yields for the same failure.
#[tokio::test]
async fn through_the_client_a_failed_dispatch_is_client_error_remote() {
    let transport = InProcessTransport::new(Notes::default());

    let decoded: Vec<Result<NoteEvent, ClientError>> = plexus_client::decode(Transport::call(
        &transport,
        MethodRef::new("notes", "nope"),
        json!({}),
    ))
    .collect()
    .await;
    assert_eq!(
        decoded,
        vec![Err(ClientError::Remote(RemoteError::MethodNotFound {
            activation: "notes".into(),
            method: "nope".into()
        }))]
    );

    // A missing required param, through the same typed path a generated
    // method uses.
    let missing: Vec<Result<NoteEvent, ClientError>> = plexus_client::decode(Transport::call(
        &transport,
        NotesClient::<InProcessTransport<Notes>>::METHOD_GET,
        json!({}),
    ))
    .collect()
    .await;
    assert_eq!(
        missing,
        vec![Err(ClientError::Remote(RemoteError::InvalidParams {
            param: Some("id".into()),
            problem: ParamProblem::Missing,
        }))]
    );
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
