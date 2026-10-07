//! The drift gate between the server envelope and the client one.
//!
//! MACRO-2 put this test in `plexus-macros`; RETURNS-6 moves it here —
//! plexus-core already depends on plexus-client, so the envelope's own crate
//! gates its mirror.
//!
//! `plexus_client::StreamItem` is a deliberately *looser* mirror of
//! `plexus_core::plexus::PlexusStreamItem` — it has to be, because the REST
//! bridge drops `metadata` and `content_type` (see `plexus-client`'s
//! `src/envelope.rs`). Looser is not the same as *different*: every 0.7
//! frame plexus-core serializes must deserialize into the client mirror and
//! serialize back **byte-identical**, and read back into the server type.

use plexus_client::{Note, StreamItem as ClientItem};
use plexus_core::plexus::{
    DenyReason, ParamProblem, PlexusStreamItem as ServerItem, RemoteError,
    StreamMetadata as ServerMetadata,
};
use serde_json::json;

fn meta() -> ServerMetadata {
    ServerMetadata {
        provenance: vec!["menger".into(), "tickets".into()],
        plexus_hash: "abc123".into(),
        timestamp: 1_735_052_400,
    }
}

/// One `RemoteError` per wire shape: every kind, both `ParamProblem`s, every
/// `DenyReason`, `param` present and absent.
fn every_remote_error() -> Vec<RemoteError> {
    vec![
        RemoteError::ActivationNotFound {
            activation: "tickets".into(),
        },
        RemoteError::MethodNotFound {
            activation: "tickets".into(),
            method: "frob".into(),
        },
        RemoteError::InvalidParams {
            param: Some("id".into()),
            problem: ParamProblem::Missing,
        },
        RemoteError::InvalidParams {
            param: Some("id".into()),
            problem: ParamProblem::Malformed {
                detail: "invalid type: integer `5`, expected a string".into(),
            },
        },
        RemoteError::InvalidParams {
            param: None,
            problem: ParamProblem::Malformed {
                detail: "expected object".into(),
            },
        },
        RemoteError::Unauthenticated,
        RemoteError::Forbidden {
            reason: DenyReason::MissingScope {
                scope: "tickets:write".into(),
            },
        },
        RemoteError::Forbidden {
            reason: DenyReason::TenantBoundary,
        },
        RemoteError::Forbidden {
            reason: DenyReason::NotAccepted,
        },
        RemoteError::HandleNotSupported {
            activation: "tickets".into(),
        },
        RemoteError::Execution {
            message: "database is locked".into(),
        },
    ]
}

/// Every 0.7 frame plexus-core can put on the wire.
fn every_frame() -> Vec<ServerItem> {
    let mut frames = vec![
        ServerItem::data(
            meta(),
            "tickets.watch".into(),
            json!({"type": "created", "ticket": {"id": "WIRE-1"}}),
        ),
        // A Result item (RETURNS-1 decision 4) is plain data content.
        ServerItem::data(meta(), "tickets.get".into(), json!({"err": {"type": "not_found", "id": "MNG-999"}})),
        // Progress: the default `Note`, with and without a percentage…
        ServerItem::progress(
            meta(),
            "tickets.import".into(),
            serde_json::to_value(Note::new("scanning").with_percentage(42.5)).unwrap(),
        ),
        ServerItem::progress(
            meta(),
            "tickets.import".into(),
            serde_json::to_value(Note::new("scanning")).unwrap(),
        ),
        // …and a method's own typed progress `P`.
        ServerItem::progress(
            meta(),
            "tickets.import".into(),
            json!({"type": "chunk", "done": 0, "of": 10}),
        ),
        ServerItem::error(meta(), RemoteError::Unauthenticated, true),
        ServerItem::request("r-1".into(), json!({"prompt": "continue?"}), 30_000),
        ServerItem::done(meta()),
    ];
    frames.extend(
        every_remote_error()
            .into_iter()
            .map(|e| ServerItem::error(meta(), e, false)),
    );
    frames
}

/// Serialize with the server's impl, deserialize with the client's.
fn cross(server: &ServerItem) -> ClientItem {
    let wire = serde_json::to_string(server).expect("server serializes");
    serde_json::from_str(&wire).unwrap_or_else(|e| panic!("client cannot read server wire {wire}: {e}"))
}

/// AC 2: server → client → wire is byte-identical, and the client's bytes
/// read back into the server type to the same bytes again.
#[test]
fn every_07_frame_round_trips_through_the_client_mirror_byte_identical() {
    for server in every_frame() {
        let wire = serde_json::to_string(&server).unwrap();
        let client = cross(&server);
        let back = serde_json::to_string(&client).unwrap();
        assert_eq!(back, wire, "client re-serializes differently");

        let server_again: ServerItem = serde_json::from_str(&back)
            .unwrap_or_else(|e| panic!("server cannot read client wire {back}: {e}"));
        assert_eq!(serde_json::to_string(&server_again).unwrap(), wire);
    }
}

#[test]
fn data_variant_survives_the_crossing() {
    let server = ServerItem::data(
        meta(),
        "tickets.watch".into(),
        json!({"type": "created", "ticket": {"id": "WIRE-1"}}),
    );

    match cross(&server) {
        ClientItem::Data {
            metadata,
            content_type,
            content,
        } => {
            let m = metadata.expect("websocket transport carries metadata");
            assert_eq!(m.provenance, vec!["menger".to_string(), "tickets".to_string()]);
            assert_eq!(m.plexus_hash, "abc123");
            assert_eq!(m.timestamp, 1_735_052_400);
            assert_eq!(content_type.as_deref(), Some("tickets.watch"));
            assert_eq!(content["ticket"]["id"], "WIRE-1");
        }
        other => panic!("expected data, got {other:?}"),
    }
}

#[test]
fn progress_variant_survives_the_crossing() {
    let server = ServerItem::progress(
        meta(),
        "tickets.import".into(),
        serde_json::to_value(Note::new("scanning").with_percentage(42.5)).unwrap(),
    );
    match cross(&server) {
        ClientItem::Progress {
            metadata,
            content_type,
            content,
        } => {
            assert!(metadata.is_some());
            assert_eq!(content_type.as_deref(), Some("tickets.import"));
            // f32 on both sides of `Note`. plexus-codegen-rust said f64 —
            // that is the drift this assertion exists to notice.
            let note: Note = serde_json::from_value(content).expect("a Note");
            assert_eq!(note.message, "scanning");
            assert_eq!(note.percentage, Some(42.5f32));
        }
        other => panic!("expected progress, got {other:?}"),
    }
}

#[test]
fn error_variant_survives_the_crossing() {
    let error = RemoteError::Forbidden {
        reason: DenyReason::MissingScope {
            scope: "tickets:write".into(),
        },
    };
    let server = ServerItem::error(meta(), error.clone(), true);
    match cross(&server) {
        ClientItem::Error {
            metadata,
            recoverable,
            error: got,
        } => {
            assert!(metadata.is_some());
            assert!(recoverable, "the flag must survive, not default");
            assert_eq!(got, error, "the typed error survives whole");
        }
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn request_variant_survives_the_crossing() {
    let server = ServerItem::request("r-1".into(), json!({"prompt": "continue?"}), 30_000);
    match cross(&server) {
        ClientItem::Request {
            request_id,
            request_data,
            timeout_ms,
        } => {
            assert_eq!(request_id, "r-1");
            assert_eq!(request_data["prompt"], "continue?");
            assert_eq!(timeout_ms, 30_000);
        }
        other => panic!("expected request, got {other:?}"),
    }
}

#[test]
fn done_variant_survives_the_crossing() {
    let server = ServerItem::done(meta());
    match cross(&server) {
        ClientItem::Done { metadata } => assert!(metadata.is_some()),
        other => panic!("expected done, got {other:?}"),
    }
}

/// The 0.7 shapes, literally (RETURNS-6's frame table).
#[test]
fn the_progress_and_error_frames_are_the_07_shapes() {
    let progress = ServerItem::progress(meta(), "tickets.import".into(), json!({"type": "chunk", "done": 0, "of": 10}));
    assert_eq!(
        serde_json::to_value(&progress).unwrap(),
        json!({
            "type": "progress",
            "metadata": {"provenance": ["menger", "tickets"], "plexus_hash": "abc123", "timestamp": 1_735_052_400},
            "content_type": "tickets.import",
            "content": {"type": "chunk", "done": 0, "of": 10}
        })
    );

    let error = ServerItem::error(
        meta(),
        RemoteError::InvalidParams {
            param: Some("id".into()),
            problem: ParamProblem::Missing,
        },
        false,
    );
    assert_eq!(
        serde_json::to_value(&error).unwrap(),
        json!({
            "type": "error",
            "metadata": {"provenance": ["menger", "tickets"], "plexus_hash": "abc123", "timestamp": 1_735_052_400},
            "recoverable": false,
            "error": {"kind": "invalid_params", "param": "id", "problem": "missing"}
        })
    );
}

/// Every variant's discriminant, side by side. If plexus-core ever renames a
/// tag or adds a variant, this is what says so.
#[test]
fn every_server_variant_tag_is_readable_by_the_client() {
    let cases: Vec<(&str, ServerItem)> = vec![
        ("data", ServerItem::data(meta(), "t".into(), json!({}))),
        ("progress", ServerItem::progress(meta(), "t".into(), json!({"message": "m"}))),
        ("error", ServerItem::error(meta(), RemoteError::Unauthenticated, false)),
        ("request", ServerItem::request("r".into(), json!({}), 0)),
        ("done", ServerItem::done(meta())),
    ];

    for (expected_tag, server) in cases {
        let wire = serde_json::to_value(&server).unwrap();
        assert_eq!(wire["type"], expected_tag, "plexus-core changed a variant tag: {wire}");
        let client = cross(&server);
        let back = serde_json::to_value(&client).unwrap();
        assert_eq!(back["type"], expected_tag, "client re-serializes under a different tag: {back}");
    }
}

/// No back-compat (RETURNS-1 decision 12): a 0.6 error frame — `message` /
/// `code`, no `error` — is readable by neither side.
#[test]
fn a_06_error_frame_is_readable_by_neither_side() {
    let old = json!({
        "type": "error",
        "metadata": {"provenance": [], "plexus_hash": "h", "timestamp": 1},
        "message": "Method not found: tickets.frob",
        "code": "-32601",
        "recoverable": false
    });
    assert!(serde_json::from_value::<ServerItem>(old.clone()).is_err());
    assert!(serde_json::from_value::<ClientItem>(old).is_err());
}

/// The optional-field difference is *one-directional and deliberate*: the
/// client accepts an item with no metadata (what SSE produces), the server
/// type does not. Pinning it stops someone "fixing" the client type back to
/// required fields and silently breaking the REST transport.
#[test]
fn the_client_type_is_looser_by_design() {
    for sse_shaped in [
        json!({"type": "data", "content": {"ok": true}}),
        json!({"type": "progress", "content": {"message": "m"}}),
        json!({"type": "error", "error": {"kind": "unauthenticated"}}),
    ] {
        let client: Result<ClientItem, _> = serde_json::from_value(sse_shaped.clone());
        assert!(client.is_ok(), "client must accept metadata-less items: {sse_shaped}");

        let server: Result<ServerItem, _> = serde_json::from_value(sse_shaped.clone());
        assert!(
            server.is_err(),
            "if plexus-core ever makes metadata optional, plexus-client's envelope \
             doc-comment needs updating — the split may no longer be needed: {sse_shaped}"
        );
    }
}
