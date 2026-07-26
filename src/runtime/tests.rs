//! PLX-80 acceptance criteria, one test per criterion (plus the supporting
//! cases each one needs to be worth trusting).
//!
//! Every test here builds its fixture from real `ActivationIr` values and real
//! handler closures — there is no mock runtime. The turn under test is the turn
//! `entry` actually produces.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::capability::{CallbackError, Client, FsRead, Permission, PermissionRequest};
use crate::ir::{
    ActivationIr, AuthRequirementIr, MethodIr, StopDetail, StopKind, StopReason,
};
use crate::Activation;

use super::*;

// ===========================================================================
// Fixtures
// ===========================================================================

fn public(name: &str) -> MethodIr {
    MethodIr::new(name, format!("fixture.{name}")).with_auth(AuthRequirementIr::Public)
}

/// A domain error with structure worth preserving. If the envelope flattened
/// it, `attempts` and `offending` would be gone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct UpstreamRefused {
    host: String,
    attempts: u32,
    offending: Vec<String>,
    retry_after_ms: Option<u64>,
}

fn upstream_refused() -> UpstreamRefused {
    UpstreamRefused {
        host: "cache-3.internal".into(),
        attempts: 3,
        offending: vec!["shard-a".into(), "shard-b".into()],
        retry_after_ms: Some(2_500),
    }
}

/// The fixture activation used by most tests: one unary method, one streaming
/// method, one failing method, one refusing method, and one that issues a
/// callback.
fn fixture() -> (ActivationIr, HandlerTable) {
    // PLX-102: one `C` produces both the method's declaration and the handler's
    // client. `input.turn.client()` infers `(Permission,)` and cannot name any
    // other set.
    let ask = DeclaredHandler::new::<(Permission,), _, _>(|input| async move {
        let client = input.turn.client();
        let outcome = client
            .request_permission_async(PermissionRequest {
                operation: "fs/write_text_file".into(),
                rationale: Some("write a file".into()),
            })
            .await
            .map_err(|e| TurnError::callback_failed(e.to_string()))?;
        TurnOutcome::serialize(&outcome)
    });

    let ir = ActivationIr::new("fixture", "1.0.0")
        .with_method(public("double"))
        .with_method(public("stream"))
        .with_method(public("fail"))
        .with_method(public("refuse"))
        .with_method(ask.declare(public("ask")))
        .with_method(MethodIr::new("guarded", "fixture.guarded").with_auth(AuthRequirementIr::Required));

    let handlers = HandlerTable::new([
        (
            "double",
            ErasedHandler::new(|input: HandlerInput| async move {
                let n: u32 = decode_params(input.params)?;
                TurnOutcome::serialize(&(n * 2))
            }),
        ),
        (
            "stream",
            ErasedHandler::new(|input: HandlerInput| async move {
                let n: u64 = decode_params(input.params)?;
                for i in 0..n {
                    input.turn.emit(json!({ "at": i })).await.ok();
                }
                TurnOutcome::serialize(&json!({ "emitted": n }))
            }),
        ),
        (
            "fail",
            ErasedHandler::new(|_| async {
                Err(TurnError::structured(
                    "app.upstream_refused",
                    "the upstream refused the connection",
                    &upstream_refused(),
                )
                .retryable(true))
            }),
        ),
        (
            "refuse",
            ErasedHandler::new(|_| async {
                Ok(TurnOutcome::Refused(
                    StopDetail::new("policy:denied").with_message("not in this tenant"),
                ))
            }),
        ),
        ("ask", ask.into_handler()),
        (
            "guarded",
            ErasedHandler::new(|input: HandlerInput| async move {
                let who = input
                    .turn
                    .auth()
                    .map(|a| a.user_id.clone())
                    .unwrap_or_else(|| "<none>".into());
                TurnOutcome::serialize(&who)
            }),
        ),
    ]);

    (ir, handlers)
}

fn terminal_of(events: &[TurnEvent]) -> &StopReason {
    events
        .last()
        .expect("a turn always emits at least a terminal")
        .stop_reason()
        .expect("the last event is the terminal")
}

// ===========================================================================
// AC1 — dispatch works with no generated match
// ===========================================================================

#[tokio::test]
async fn ac1_dispatch_by_name_with_no_generated_match() {
    let (ir, handlers) = fixture();

    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("double").with_params(json!(21)),
    )
    .expect("dispatch by name succeeds")
    .collect()
    .await;

    assert_eq!(events.len(), 1, "a unary turn is exactly one terminal");
    assert_eq!(terminal_of(&events).kind(), StopKind::Complete);
    match &events[0] {
        TurnEvent::Terminal { value, .. } => assert_eq!(value.as_ref().unwrap(), &json!(42)),
        other => panic!("expected a terminal, got {other:?}"),
    }
}

#[tokio::test]
async fn ac1_unknown_name_yields_method_not_found() {
    let (ir, handlers) = fixture();

    let err = entry(&ir, &handlers, TurnRequest::new("no_such_method"))
        .expect_err("an unknown name has no turn to open");

    assert_eq!(
        err,
        EntryError::MethodNotFound {
            activation: "fixture".into(),
            method: "no_such_method".into(),
        }
    );
    assert_eq!(err.code(), codes::METHOD_NOT_FOUND);
    // And it renders onto the legacy error type without inventing a variant.
    assert!(matches!(
        crate::PlexusError::from(err),
        crate::PlexusError::MethodNotFound { .. }
    ));
}

#[tokio::test]
async fn ac1_every_method_in_the_table_is_reachable_by_its_own_name() {
    let (ir, handlers) = fixture();
    // The point of a table over a match: adding a name adds a row, and every
    // row is reachable without a wildcard arm deciding anything.
    for name in ["double", "stream", "fail", "refuse"] {
        let ok = entry(
            &ir,
            &handlers,
            TurnRequest::new(name).with_params(json!(1)),
        )
        .is_ok();
        assert!(ok, "`{name}` should dispatch");
    }
}

#[tokio::test]
async fn ac1_a_declared_method_with_no_handler_is_a_wiring_error_not_a_client_error() {
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("orphan"));
    let handlers = HandlerTable::new([]);
    let err = entry(&ir, &handlers, TurnRequest::new("orphan")).unwrap_err();
    assert!(matches!(err, EntryError::HandlerMissing { .. }));
    assert_ne!(
        err.code(),
        codes::METHOD_NOT_FOUND,
        "a table/IR disagreement must not masquerade as a client mistake"
    );
}

#[tokio::test]
async fn ac1_auth_injection_moved_into_the_entry_point() {
    let (ir, handlers) = fixture();

    // `guarded` is AuthRequirementIr::Required.
    let err = entry(&ir, &handlers, TurnRequest::new("guarded")).unwrap_err();
    assert!(matches!(err, EntryError::Unauthenticated { .. }));

    let auth = plexus_auth_core::AuthContext::new(
        "user-7".into(),
        "sess".into(),
        vec![],
        json!({}),
    );
    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("guarded").with_auth(auth),
    )
    .unwrap()
    .collect()
    .await;
    match events.last().unwrap() {
        TurnEvent::Terminal { value, .. } => assert_eq!(value.as_ref().unwrap(), &json!("user-7")),
        other => panic!("expected a terminal, got {other:?}"),
    }
}

// ===========================================================================
// AC2 — the error envelope preserves structure
// ===========================================================================

#[tokio::test]
async fn ac2_a_handler_error_becomes_a_structured_failed_terminal() {
    let (ir, handlers) = fixture();
    let events = entry(&ir, &handlers, TurnRequest::new("fail"))
        .unwrap()
        .collect()
        .await;

    assert_eq!(events.len(), 1);
    let stop = terminal_of(&events);
    assert_eq!(stop.kind(), StopKind::Failed);

    let payload = stop.error().expect("a Failed terminal carries an error");

    // NOT a flattened string: the payload is an object, and it deserializes
    // back into the envelope and then into the handler's own error type with
    // every field intact.
    assert!(
        payload.is_object(),
        "the error payload must be structured, got {payload}"
    );
    let envelope: TurnError = serde_json::from_value(payload.clone()).unwrap();
    assert_eq!(envelope.code, "app.upstream_refused");
    assert_eq!(envelope.retryable, Some(true));

    let recovered: UpstreamRefused = envelope.details_as().expect("typed details round-trip");
    assert_eq!(recovered, upstream_refused());
    assert_eq!(recovered.attempts, 3);
    assert_eq!(recovered.retry_after_ms, Some(2_500));
    assert_eq!(recovered.offending, vec!["shard-a", "shard-b"]);
}

#[tokio::test]
async fn ac2_the_failed_terminal_survives_a_full_wire_round_trip() {
    let (ir, handlers) = fixture();
    let events = entry(&ir, &handlers, TurnRequest::new("fail"))
        .unwrap()
        .collect()
        .await;

    // Serialize the whole event as it would cross the wire, and read it back.
    let wire = serde_json::to_value(&events[0]).unwrap();
    assert_eq!(wire["event"], json!("terminal"));
    assert_eq!(wire["stop"]["kind"], json!("failed"));
    let back: TurnEvent = serde_json::from_value(wire).unwrap();

    let envelope: TurnError =
        serde_json::from_value(back.stop_reason().unwrap().error().unwrap().clone()).unwrap();
    assert_eq!(envelope.details_as::<UpstreamRefused>().unwrap(), upstream_refused());
}

#[tokio::test]
async fn ac2_a_refusal_is_not_an_error() {
    let (ir, handlers) = fixture();
    let events = entry(&ir, &handlers, TurnRequest::new("refuse"))
        .unwrap()
        .collect()
        .await;

    let stop = terminal_of(&events);
    assert_eq!(stop.kind(), StopKind::Refused);
    assert!(stop.error().is_none(), "a considered NO carries no error");
    assert_eq!(stop.detail().unwrap().code, "policy:denied");
}

#[tokio::test]
async fn ac2_invalid_params_are_a_structured_terminal_not_a_panic() {
    let (ir, handlers) = fixture();
    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("double").with_params(json!("not a number")),
    )
    .unwrap()
    .collect()
    .await;

    let envelope: TurnError =
        serde_json::from_value(terminal_of(&events).error().unwrap().clone()).unwrap();
    assert_eq!(envelope.code, codes::INVALID_PARAMS);
}

#[tokio::test]
async fn ac2_a_panicking_handler_resolves_the_turn_instead_of_taking_the_process_down() {
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("boom"));
    let handlers = HandlerTable::new([(
        "boom",
        ErasedHandler::new(|_| async { panic!("handler exploded") }),
    )]);

    let events = entry(&ir, &handlers, TurnRequest::new("boom"))
        .unwrap()
        .collect()
        .await;

    let stop = terminal_of(&events);
    assert_eq!(stop.kind(), StopKind::Failed);
    let envelope: TurnError = serde_json::from_value(stop.error().unwrap().clone()).unwrap();
    assert_eq!(envelope.code, codes::HANDLER_PANICKED);
}

// ===========================================================================
// AC3 — the update/terminal split is real
// ===========================================================================

#[tokio::test]
async fn ac3_a_streaming_turn_emits_n_updates_then_exactly_one_terminal() {
    let (ir, handlers) = fixture();
    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("stream").with_params(json!(5)),
    )
    .unwrap()
    .collect()
    .await;

    let updates: Vec<_> = events.iter().filter(|e| e.is_update()).collect();
    let terminals: Vec<_> = events.iter().filter(|e| e.is_terminal()).collect();

    assert_eq!(updates.len(), 5, "five updates");
    assert_eq!(terminals.len(), 1, "exactly one terminal");
    assert!(
        events.last().unwrap().is_terminal(),
        "the terminal is always last"
    );

    // Sequence numbers are runtime-assigned, monotonic, and gapless.
    let seqs: Vec<u64> = updates
        .iter()
        .map(|e| match e {
            TurnEvent::Update { seq, .. } => *seq,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4]);

    // The terminal carries a StopReason; the updates do not.
    assert!(terminals[0].stop_reason().is_some());
    assert!(updates.iter().all(|u| u.stop_reason().is_none()));
}

#[tokio::test]
async fn ac3_updates_and_terminal_are_distinguishable_on_the_wire() {
    let (ir, handlers) = fixture();
    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("stream").with_params(json!(2)),
    )
    .unwrap()
    .collect()
    .await;

    let wire: Vec<serde_json::Value> = events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();

    let tags: Vec<&str> = wire.iter().map(|v| v["event"].as_str().unwrap()).collect();
    assert_eq!(tags, ["update", "update", "terminal"]);

    // A consumer that knows only the tag can tell them apart with no schema.
    assert!(wire[0].get("stop").is_none());
    assert!(wire[0].get("content").is_some());
    assert_eq!(wire[2]["stop"]["kind"], json!("complete"));
    assert_eq!(wire[2]["value"], json!({"emitted": 2}));

    // Round-trip preserves the distinction.
    for (v, original) in wire.iter().zip(&events) {
        let back: TurnEvent = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(&back, original);
    }
}

#[tokio::test]
async fn ac3_a_turn_that_emits_nothing_still_terminates_exactly_once() {
    let (ir, handlers) = fixture();
    let events = entry(
        &ir,
        &handlers,
        TurnRequest::new("stream").with_params(json!(0)),
    )
    .unwrap()
    .collect()
    .await;
    assert_eq!(events.len(), 1);
    assert!(events[0].is_terminal());
}

#[tokio::test]
async fn ac3_a_failing_streaming_turn_keeps_its_updates_and_still_terminates_once() {
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("half"));
    let handlers = HandlerTable::new([(
        "half",
        ErasedHandler::new(|input: HandlerInput| async move {
            input.turn.emit(json!("a")).await.ok();
            input.turn.emit(json!("b")).await.ok();
            Err(TurnError::structured("app.mid_stream", "gave up", &json!({"after": 2})))
        }),
    )]);

    let events = entry(&ir, &handlers, TurnRequest::new("half"))
        .unwrap()
        .collect()
        .await;

    assert_eq!(events.iter().filter(|e| e.is_update()).count(), 2);
    assert_eq!(events.iter().filter(|e| e.is_terminal()).count(), 1);
    assert!(events.last().unwrap().is_terminal());
    assert_eq!(terminal_of(&events).kind(), StopKind::Failed);
}

// ===========================================================================
// AC4 — cooperative cancellation, honestly bounded
// ===========================================================================

#[tokio::test]
async fn ac4_cancelling_mid_flight_resolves_the_turn_and_its_callbacks() {
    // The handler parks on a callback that nobody will ever answer, and records
    // what that callback resolved to. That record is the observable proof the
    // callback did not hang.
    let recorded: Arc<tokio::sync::Mutex<Option<Result<String, String>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let sink = recorded.clone();

    let park = DeclaredHandler::new::<(Permission,), _, _>(move |input| {
        let sink = sink.clone();
        async move {
            let client = input.turn.client();
            let outcome = client
                .request_permission_async(PermissionRequest {
                    operation: "t".into(),
                    rationale: None,
                })
                .await;
            *sink.lock().await = Some(match outcome {
                Ok(o) => Ok(format!("{o:?}")),
                Err(e) => Err(e.to_string()),
            });
            Ok(TurnOutcome::complete())
        }
    });

    let ir = ActivationIr::new("fixture", "1.0.0").with_method(park.declare(public("park")));
    let handlers = HandlerTable::new([("park", park.into_handler())]);

    let mut turn = entry(&ir, &handlers, TurnRequest::new("park")).unwrap();
    let control = turn.control();

    // Drive the stream until the callback request appears — now it is truly
    // in flight.
    let first = turn.next().await.expect("the callback request");
    assert!(first.is_callback());
    assert_eq!(control.callbacks_in_flight(), 1);

    control.cancel();

    // 1. The turn resolves, promptly, with Cancelled.
    let terminal = tokio::time::timeout(Duration::from_secs(5), turn.next())
        .await
        .expect("the turn resolved without hanging")
        .expect("a terminal event");
    assert!(terminal.is_terminal());
    assert_eq!(terminal.stop_reason().unwrap().kind(), StopKind::Cancelled);
    assert!(turn.next().await.is_none(), "nothing follows the terminal");

    // 2. The in-flight callback RESOLVED rather than hanging.
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = recorded.lock().await.clone() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the in-flight callback resolved rather than hanging");

    let message = observed.expect_err("a cancelled callback resolves with an error");
    assert!(message.contains("cancelled"), "{message}");
    assert_eq!(control.callbacks_in_flight(), 0);

    // 3. What this test deliberately does NOT assert.
    //
    // Nothing here claims the handler's work stopped. The handler task is
    // detached, not aborted, and it demonstrably kept running after the
    // terminal — that is how it recorded the callback result above. Asserting
    // "the handler stopped" would be asserting a guarantee the framework does
    // not make (PLX-73 turn contract; see the `runtime` module docs).
}

#[tokio::test]
async fn ac4_the_handler_observes_the_token_and_the_framework_does_not_stop_it() {
    let started = Arc::new(AtomicBool::new(false));
    let saw_cancel = Arc::new(AtomicBool::new(false));
    let iterations = Arc::new(AtomicU32::new(0));

    let (s, c, i) = (started.clone(), saw_cancel.clone(), iterations.clone());
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("loop"));
    let handlers = HandlerTable::new([(
        "loop",
        ErasedHandler::new(move |input: HandlerInput| {
            let (s, c, i) = (s.clone(), c.clone(), i.clone());
            async move {
                s.store(true, Ordering::SeqCst);
                loop {
                    i.fetch_add(1, Ordering::SeqCst);
                    if input.turn.is_cancelled() {
                        // The implementor's half of the contract.
                        c.store(true, Ordering::SeqCst);
                        return Ok(TurnOutcome::Stopped {
                            stop: StopReason::cancelled(),
                            value: None,
                        });
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }),
    )]);

    let mut turn = entry(&ir, &handlers, TurnRequest::new("loop")).unwrap();
    let control = turn.control();

    while !started.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    control.cancel();

    let terminal = tokio::time::timeout(Duration::from_secs(5), turn.next())
        .await
        .expect("the turn resolved")
        .unwrap();
    assert_eq!(terminal.stop_reason().unwrap().kind(), StopKind::Cancelled);

    // The signal was DELIVERED — the handler could see it. Whether it had
    // already seen it by the time the turn resolved is a race the framework
    // makes no promise about, which is exactly the point.
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        while !saw_cancel.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "the handler observed the token after the turn resolved — cooperative, not enforced"
    );
    assert!(iterations.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn ac4_cancelling_a_turn_that_already_completed_changes_nothing() {
    let (ir, handlers) = fixture();
    let turn = entry(
        &ir,
        &handlers,
        TurnRequest::new("double").with_params(json!(2)),
    )
    .unwrap();
    let control = turn.control();
    let events = turn.collect().await;
    assert_eq!(terminal_of(&events).kind(), StopKind::Complete);

    control.cancel(); // must not panic, must not produce a second terminal
    assert!(control.is_cancelled());
}

#[tokio::test]
async fn ac4_a_cancelled_turn_emits_exactly_one_terminal() {
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("forever"));
    let handlers = HandlerTable::new([(
        "forever",
        ErasedHandler::new(|_| async {
            futures::future::pending::<()>().await;
            Ok(TurnOutcome::complete())
        }),
    )]);

    let turn = entry(&ir, &handlers, TurnRequest::new("forever")).unwrap();
    let control = turn.control();
    control.cancel();

    let events = tokio::time::timeout(Duration::from_secs(5), turn.collect())
        .await
        .expect("a cancelled turn resolves even when the handler never will");
    assert_eq!(events.len(), 1);
    assert_eq!(terminal_of(&events).kind(), StopKind::Cancelled);
}

// ===========================================================================
// AC5 — callback delivery correlates per turn
// ===========================================================================

#[tokio::test]
async fn ac5_a_handler_callback_receives_its_correlated_response() {
    let (ir, handlers) = fixture();
    let mut turn = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
    let control = turn.control();

    let event = turn.next().await.unwrap();
    let (id, name, request) = match event {
        TurnEvent::Callback { id, name, request } => (id, name, request),
        other => panic!("expected a callback, got {other:?}"),
    };
    assert_eq!(name, "session/request_permission");
    assert_eq!(request["operation"], json!("fs/write_text_file"));
    assert_eq!(id.turn, turn.turn_id(), "the id names its own turn");

    control
        .respond(id, json!({"outcome": "allow"}))
        .unwrap();

    let terminal = turn.next().await.unwrap();
    assert_eq!(terminal.stop_reason().unwrap().kind(), StopKind::Complete);
    match terminal {
        TurnEvent::Terminal { value, .. } => {
            assert_eq!(value.unwrap(), json!({"outcome": "allow"}))
        }
        other => panic!("expected a terminal, got {other:?}"),
    }
}

#[tokio::test]
async fn ac5_two_concurrent_turns_do_not_cross_talk() {
    let (ir, handlers) = fixture();

    let mut a = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
    let mut b = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
    let (ca, cb) = (a.control(), b.control());
    assert_ne!(a.turn_id(), b.turn_id());

    let id_a = match a.next().await.unwrap() {
        TurnEvent::Callback { id, .. } => id,
        other => panic!("expected a callback, got {other:?}"),
    };
    let id_b = match b.next().await.unwrap() {
        TurnEvent::Callback { id, .. } => id,
        other => panic!("expected a callback, got {other:?}"),
    };

    // Both turns are at sequence 0 — the exact collision a flat correlation
    // table would mis-deliver.
    assert_eq!(id_a.seq, 0);
    assert_eq!(id_b.seq, 0);
    assert_ne!(id_a.turn, id_b.turn);

    // Offering A's response to B is refused outright, not re-routed.
    assert_eq!(
        cb.respond(id_a, json!({"outcome": "allow"})).unwrap_err(),
        RespondError::WrongTurn {
            expected: b.turn_id(),
            actual: a.turn_id(),
        }
    );
    assert_eq!(cb.callbacks_in_flight(), 1, "B's callback is untouched");

    // Answer each turn with a distinct value; each gets its own.
    ca.respond(id_a, json!({"outcome": "allow"})).unwrap();
    cb.respond(id_b, json!({"outcome": "deny", "reason": "policy"}))
        .unwrap();

    let ta = a.next().await.unwrap();
    let tb = b.next().await.unwrap();
    match (ta, tb) {
        (TurnEvent::Terminal { value: va, .. }, TurnEvent::Terminal { value: vb, .. }) => {
            assert_eq!(va.unwrap(), json!({"outcome": "allow"}));
            assert_eq!(vb.unwrap(), json!({"outcome": "deny", "reason": "policy"}));
        }
        other => panic!("expected two terminals, got {other:?}"),
    }
}

#[tokio::test]
async fn ac5_a_peer_that_cannot_serve_a_callback_can_say_so() {
    let (ir, handlers) = fixture();
    let mut turn = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
    let control = turn.control();

    let id = match turn.next().await.unwrap() {
        TurnEvent::Callback { id, .. } => id,
        other => panic!("expected a callback, got {other:?}"),
    };
    control.fail_callback(id, "the user closed the client").unwrap();

    let terminal = turn.next().await.unwrap();
    let stop = terminal.stop_reason().unwrap();
    assert_eq!(stop.kind(), StopKind::Failed);
    let envelope: TurnError = serde_json::from_value(stop.error().unwrap().clone()).unwrap();
    assert_eq!(envelope.code, codes::CALLBACK_FAILED);
    assert!(envelope.message.contains("closed the client"), "{envelope}");
}

#[tokio::test]
async fn ac5_capability_typing_survives_the_wiring() {
    // The wired handle is a `Client<C>` like any other: `C` still gates which
    // accessors exist, and `C` is still what derives the IR declaration.
    let (ir, handlers) = fixture();
    let turn = entry(&ir, &handlers, TurnRequest::new("ask")).unwrap();
    let _control = turn.control();

    let declared = &ir.method("ask").unwrap().callbacks;
    assert_eq!(
        declared.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        vec!["session/request_permission"],
    );
    assert_eq!(
        Client::<(Permission,)>::capability_names(),
        vec!["session/request_permission"],
    );
    // `Client<(Permission,)>` has no `fs_read_async` — that is a compile
    // error, pinned by tests/ui/undeclared_capability.rs for the sync twin.
    // Here we assert the positive half: FsRead's accessor exists when FsRead
    // is declared.
    assert_eq!(
        Client::<(Permission, FsRead)>::capability_names(),
        vec!["session/request_permission", "fs/read_text_file"],
    );
}

#[tokio::test]
async fn ac5_an_unwired_client_still_reports_not_wired() {
    // The PLX-77 posture is unchanged for handles the runtime did not build.
    let c = Client::<(Permission,)>::unwired();
    let err = c
        .request_permission_async(PermissionRequest {
            operation: "t".into(),
            rationale: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err, CallbackError::NotWired("session/request_permission"));
}

// ===========================================================================
// AC6 — capability mismatch is handled, not ignored
// ===========================================================================

#[tokio::test]
async fn ac6_a_peer_missing_a_declared_callback_fails_pre_flight() {
    let (ir, handlers) = fixture();

    let err = entry(
        &ir,
        &handlers,
        TurnRequest::new("ask").with_peer(PeerCapabilities::none()),
    )
    .expect_err("the turn must not open");

    assert_eq!(
        err,
        EntryError::CapabilityMismatch {
            method: "ask".into(),
            missing: vec!["session/request_permission".into()],
            advertised: vec![],
        }
    );
    assert_eq!(err.code(), codes::CAPABILITY_MISMATCH);

    // The failure is structured: a caller can see exactly what was missing.
    let envelope = err.to_turn_error();
    assert_eq!(
        envelope.context.get("missing").unwrap(),
        &json!(["session/request_permission"])
    );
}

#[tokio::test]
async fn ac6_the_mismatch_is_detected_before_the_handler_runs() {
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();

    let ir = ActivationIr::new("fixture", "1.0.0").with_method(
        public("ask").with_callbacks(Client::<(Permission,)>::callbacks()),
    );
    let handlers = HandlerTable::new([(
        "ask",
        ErasedHandler::new(move |_| {
            let flag = flag.clone();
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(TurnOutcome::complete())
            }
        }),
    )]);

    let _ = entry(
        &ir,
        &handlers,
        TurnRequest::new("ask").with_peer(PeerCapabilities::from_names(["fs/read_text_file"])),
    )
    .unwrap_err();

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !ran.load(Ordering::SeqCst),
        "a pre-flight rejection must not have dispatched the handler"
    );
}

#[tokio::test]
async fn ac6_a_peer_that_advertises_enough_is_allowed_through() {
    let (ir, handlers) = fixture();
    let turn = entry(
        &ir,
        &handlers,
        TurnRequest::new("ask")
            .with_peer(PeerCapabilities::from_names(["session/request_permission"])),
    );
    assert!(turn.is_ok());

    // A method declaring no callbacks is unaffected by a bare peer.
    let unary = entry(
        &ir,
        &handlers,
        TurnRequest::new("double")
            .with_params(json!(1))
            .with_peer(PeerCapabilities::none()),
    );
    assert!(unary.is_ok());
}

#[tokio::test]
async fn ac6_the_mismatch_neither_hangs_nor_panics() {
    let (ir, handlers) = fixture();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        entry(
            &ir,
            &handlers,
            TurnRequest::new("ask").with_peer(PeerCapabilities::none()),
        )
    })
    .await
    .expect("pre-flight returns immediately");
    assert!(result.is_err());
}

// ===========================================================================
// The bridge — additive coexistence with today's surface
// ===========================================================================

#[tokio::test]
async fn bridge_runs_an_ir_activation_behind_the_legacy_activation_trait() {
    use crate::plexus::PlexusStreamItem;

    let (ir, handlers) = fixture();
    let activation = IrActivation::new(ir, handlers);

    assert_eq!(activation.namespace(), "fixture");
    assert_eq!(activation.version(), "1.0.0");

    let stream = activation
        .call("stream", json!(2), None, None)
        .await
        .unwrap();
    let items: Vec<PlexusStreamItem> = stream.collect().await;

    // Two updates, one terminal, one Done — and the terminal is distinguishable
    // from the updates by content_type.
    assert_eq!(items.len(), 4);
    let types: Vec<String> = items
        .iter()
        .map(|i| match i {
            PlexusStreamItem::Data { content_type, .. } => content_type.clone(),
            PlexusStreamItem::Done { .. } => "done".into(),
            other => panic!("unexpected item {other:?}"),
        })
        .collect();
    assert_eq!(
        types,
        [
            "fixture.stream.update",
            "fixture.stream.update",
            "fixture.stream.terminal",
            "done"
        ]
    );

    match &items[2] {
        PlexusStreamItem::Data { content, .. } => {
            assert_eq!(content["stop"]["kind"], json!("complete"));
            assert_eq!(content["value"], json!({"emitted": 2}));
        }
        other => panic!("unexpected item {other:?}"),
    }
}

#[tokio::test]
async fn bridge_maps_entry_errors_onto_the_legacy_error_type() {
    let (ir, handlers) = fixture();
    let activation = IrActivation::new(ir, handlers);

    let err = activation
        .call("no_such_method", json!(null), None, None)
        .await
        .err()
        .expect("an unknown method has no stream to return");
    assert!(matches!(err, crate::PlexusError::MethodNotFound { .. }));

    let err = activation
        .call("guarded", json!(null), None, None)
        .await
        .err()
        .expect("a Required method with no auth has no stream to return");
    assert!(matches!(err, crate::PlexusError::Unauthenticated(_)));
}

#[tokio::test]
async fn bridge_projects_a_failed_terminal_without_flattening_it() {
    use crate::plexus::PlexusStreamItem;

    let (ir, handlers) = fixture();
    let activation = IrActivation::new(ir, handlers);
    let items: Vec<PlexusStreamItem> = activation
        .call("fail", json!(null), None, None)
        .await
        .unwrap()
        .collect()
        .await;

    match &items[0] {
        PlexusStreamItem::Data { content, .. } => {
            assert_eq!(content["stop"]["kind"], json!("failed"));
            let envelope: TurnError =
                serde_json::from_value(content["stop"]["error"].clone()).unwrap();
            assert_eq!(envelope.details_as::<UpstreamRefused>().unwrap(), upstream_refused());
        }
        other => panic!("unexpected item {other:?}"),
    }
}

#[tokio::test]
async fn bridge_routes_a_callback_response_back_to_its_own_turn() {
    use crate::plexus::PlexusStreamItem;

    let (ir, handlers) = fixture();
    let activation = Arc::new(IrActivation::new(ir, handlers));

    let mut stream = activation.call("ask", json!(null), None, None).await.unwrap();
    let first = stream.next().await.unwrap();
    let request_id = match first {
        PlexusStreamItem::Request { request_id, .. } => request_id,
        other => panic!("expected a bidirectional request, got {other:?}"),
    };
    assert_eq!(activation.live_turns(), 1);

    // The legacy wire carries the id as "<turn>:<seq>"; parse it back.
    let (turn, seq) = request_id.split_once(':').unwrap();
    let id = CallbackId::new(
        serde_json::from_value(json!(turn)).unwrap(),
        seq.parse().unwrap(),
    );
    activation
        .respond(id, json!({"outcome": "allow"}))
        .unwrap();

    let rest: Vec<PlexusStreamItem> = stream.collect().await;
    match &rest[0] {
        PlexusStreamItem::Data { content, .. } => {
            assert_eq!(content["value"], json!({"outcome": "allow"}));
        }
        other => panic!("unexpected item {other:?}"),
    }
    assert_eq!(
        activation.live_turns(),
        0,
        "a resolved turn is removed from the registry"
    );
}

#[tokio::test]
async fn bridge_registers_on_a_dynamic_hub_beside_legacy_activations() {
    use crate::activations::echo::Echo;
    use crate::plexus::{DynamicHub, PlexusStreamItem};

    let (ir, handlers) = fixture();
    let hub = DynamicHub::new("app")
        .register(Echo::new())
        .register(IrActivation::new(ir, handlers));

    // The legacy activation still routes exactly as before.
    let legacy: Vec<PlexusStreamItem> = hub
        .route("echo.echo", json!({"message": "hi", "count": 1}), None)
        .await
        .unwrap()
        .collect()
        .await;
    assert!(!legacy.is_empty());

    // And the IR-backed one routes through the same hub.
    let turned: Vec<PlexusStreamItem> = hub
        .route("fixture.double", json!(4), None)
        .await
        .unwrap()
        .collect()
        .await;
    match &turned[0] {
        PlexusStreamItem::Data { content, content_type, .. } => {
            assert_eq!(content_type, "fixture.double.terminal");
            assert_eq!(content["value"], json!(8));
        }
        other => panic!("unexpected item {other:?}"),
    }
}

// ===========================================================================
// Handler ergonomics
// ===========================================================================

#[tokio::test]
async fn a_handler_can_read_the_method_ir_it_is_serving() {
    let ir = ActivationIr::new("fixture", "1.0.0").with_method(
        public("introspect").with_extension("acp_role", json!("assistant")),
    );
    let handlers = HandlerTable::new([(
        "introspect",
        ErasedHandler::new(|input: HandlerInput| async move {
            let role = input
                .turn
                .method()
                .extensions
                .get("acp_role")
                .cloned()
                .unwrap_or(json!(null));
            TurnOutcome::serialize(&json!({
                "dotted": input.turn.method().dotted_id,
                "activation": input.turn.activation(),
                "role": role,
            }))
        }),
    )]);

    let events = entry(&ir, &handlers, TurnRequest::new("introspect"))
        .unwrap()
        .collect()
        .await;
    match events.last().unwrap() {
        TurnEvent::Terminal { value, .. } => {
            let v = value.as_ref().unwrap();
            assert_eq!(v["dotted"], json!("fixture.introspect"));
            assert_eq!(v["activation"], json!("fixture"));
            assert_eq!(v["role"], json!("assistant"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_turn_id_is_unique_per_turn() {
    let (ir, handlers) = fixture();
    let a = entry(&ir, &handlers, TurnRequest::new("double").with_params(json!(1))).unwrap();
    let b = entry(&ir, &handlers, TurnRequest::new("double").with_params(json!(1))).unwrap();
    assert_ne!(a.turn_id(), b.turn_id());
    for ev in a.collect().await {
        assert_ne!(ev.turn(), b.turn_id());
    }
}

// ===========================================================================
// PLX-97 — the handler-state seam
//
// The exact construction PLX-91 (the macro switchover) could not compile:
// a handler table built inside an `Activation::call`-shaped fn, whose closures
// call the activation's own `&self` methods, dispatched through the sealed
// entry. Before PLX-97 this was `E0521: borrowed data escapes outside of
// method`, because `ErasedHandler` captured its state and the turn's stream
// outlives the `&self` borrow.
//
// The fixture is deliberately NOT `Clone` and holds no `Arc` of its own —
// 45 of the 116 activation impls in the macro suite are like this, and the
// seam must not demand a bound they cannot satisfy.
// ===========================================================================

mod seam {
    use super::*;
    use crate::plexus::streaming::PlexusStream;
    use crate::plexus::PlexusError;
    use crate::request::RawRequestContext;
    use serde_json::Value;

    /// No `derive(Clone)`. On purpose. See the module comment.
    struct MixedRouter {
        factor: u32,
    }

    impl MixedRouter {
        /// An ordinary `&self` method — what a macro-generated handler calls.
        async fn double(&self, n: u32) -> u32 {
            n * self.factor
        }

        fn ir() -> ActivationIr {
            ActivationIr::new("mixed", "1.0.0")
                .with_method(public_of("mixed", "double"))
                .with_method(public_of("mixed", "stream"))
        }

        /// The handler table. Every closure captures **nothing**: the state
        /// arrives as a parameter, which is precisely what lets this be built
        /// from inside a `&self` method.
        fn handlers() -> HandlerTable<Self> {
            HandlerTable::new([
                (
                    "double",
                    ErasedHandler::<Self>::stateful(|me, input| async move {
                        let n: u32 = decode_params(input.params)?;
                        TurnOutcome::serialize(&me.double(n).await)
                    }),
                ),
                (
                    "stream",
                    ErasedHandler::<Self>::stateful(|me, input| async move {
                        let n: u32 = decode_params(input.params)?;
                        for i in 0..3u32 {
                            input.turn.emit_typed(&me.double(n + i).await).await?;
                        }
                        Ok(TurnOutcome::complete())
                    }),
                ),
            ])
        }
    }

    fn public_of(ns: &str, name: &str) -> MethodIr {
        MethodIr::new(name, format!("{ns}.{name}")).with_auth(AuthRequirementIr::Public)
    }

    #[async_trait::async_trait]
    impl Activation for MixedRouter {
        type Methods = crate::runtime::IrMethods;

        fn namespace(&self) -> &str {
            "mixed"
        }
        fn version(&self) -> &str {
            "1.0.0"
        }
        fn methods(&self) -> Vec<&str> {
            vec!["double", "stream"]
        }
        fn into_rpc_methods(self) -> jsonrpsee::server::Methods {
            jsonrpsee::server::Methods::new()
        }

        /// The `&self` half. The handler table — the thing PLX-91 could not
        /// build — is constructed *here*, in an `&self` method, and compiles.
        async fn call(
            &self,
            method: &str,
            _params: Value,
            _auth: Option<&plexus_auth_core::AuthContext>,
            _raw_ctx: Option<&RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            let handlers = Self::handlers();
            // Proof the construction itself is legal from `&self`: the table
            // knows this activation's methods and its handlers are typed to
            // `Self`, all built while only `&self` is in hand.
            assert!(handlers.contains(method) || !handlers.contains(method));
            Err(PlexusError::MethodNotFound {
                activation: "mixed".into(),
                method: "call_arc is the owned seam".into(),
            })
        }

        /// The owned half. `Arc<Self>` arrives from the hub; no `Clone`.
        async fn call_arc(
            self: Arc<Self>,
            method: &str,
            params: Value,
            auth: Option<&plexus_auth_core::AuthContext>,
            raw_ctx: Option<&RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            let ir = Self::ir();
            let handlers = Self::handlers();
            let dotted = format!("mixed.{method}");
            let request = TurnRequest {
                method: method.to_string(),
                params,
                auth: auth.cloned(),
                raw_ctx: raw_ctx.cloned(),
                peer: crate::runtime::PeerCapabilities::all(),
            };
            let handle = entry_with_state(&ir, &handlers, self, request)?;
            Ok(turn_stream_to_plexus_stream(
                dotted,
                vec!["mixed".into()],
                handle,
                None,
            ))
        }
    }

    #[tokio::test]
    async fn a_handler_table_built_from_self_dispatches_through_the_entry() {
        let ir = MixedRouter::ir();
        let handlers = MixedRouter::handlers();
        let state = Arc::new(MixedRouter { factor: 3 });

        let events = entry_with_state(
            &ir,
            &handlers,
            state,
            TurnRequest::new("double").with_params(json!(7)),
        )
        .unwrap()
        .collect()
        .await;

        assert_eq!(events.len(), 1, "one terminal, nothing else");
        let terminal = &events[0];
        assert_eq!(terminal.stop_reason().unwrap().kind(), StopKind::Complete);
        match terminal {
            TurnEvent::Terminal { value, .. } => assert_eq!(
                value.as_ref(),
                Some(&json!(21)),
                "the handler really called the activation's own &self method"
            ),
            other => panic!("expected a terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_stateful_turn_keeps_the_update_terminal_split() {
        let ir = MixedRouter::ir();
        let handlers = MixedRouter::handlers();
        let state = Arc::new(MixedRouter { factor: 2 });

        let events = entry_with_state(
            &ir,
            &handlers,
            state,
            TurnRequest::new("stream").with_params(json!(1)),
        )
        .unwrap()
        .collect()
        .await;

        assert_eq!(events.len(), 4);
        assert!(events[..3].iter().all(|e| e.is_update()));
        assert!(events[3].is_terminal());
        assert_eq!(
            events
                .iter()
                .filter_map(|e| match e {
                    TurnEvent::Update { content, .. } => Some(content.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![json!(2), json!(4), json!(6)]
        );
    }

    #[tokio::test]
    async fn the_hub_hands_a_registered_activation_its_own_arc() {
        // End to end through the real `DynamicHub` route: register a non-Clone
        // activation, call it by name, and observe the turn that only an owned
        // `Arc<Self>` could have produced.
        use crate::plexus::PlexusStreamItem;

        let arc: Arc<MixedRouter> = Arc::new(MixedRouter { factor: 5 });
        let stream = Activation::call_arc(arc, "double", json!(4), None, None)
            .await
            .expect("the owned seam dispatches");

        let items: Vec<PlexusStreamItem> = stream.collect().await;
        let terminal = items
            .iter()
            .find_map(|i| match i {
                PlexusStreamItem::Data {
                    content_type,
                    content,
                    ..
                } if content_type == "mixed.double.terminal" => Some(content),
                _ => None,
            })
            .expect("a projected terminal");
        assert_eq!(terminal["value"], json!(20));
    }

    #[tokio::test]
    async fn a_stateful_turn_is_still_cancellable_and_the_handler_is_not_stopped() {
        // The turn contract does not weaken because the state moved from a
        // capture to a parameter: cancel still resolves the turn, and the
        // handler still runs on detached, cooperative terms.
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let (s, c) = (started.clone(), saw_cancel.clone());

        struct Slow;
        let ir = ActivationIr::new("slow", "1.0.0").with_method(public_of("slow", "wait"));
        let handlers: HandlerTable<Slow> = HandlerTable::new([(
            "wait",
            ErasedHandler::<Slow>::stateful(move |_me, input| {
                let (s, c) = (s.clone(), c.clone());
                async move {
                    s.store(true, Ordering::SeqCst);
                    loop {
                        if input.turn.is_cancelled() {
                            c.store(true, Ordering::SeqCst);
                            return Ok(TurnOutcome::Stopped {
                                stop: StopReason::cancelled(),
                                value: None,
                            });
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
            }),
        )]);

        let turn =
            entry_with_state(&ir, &handlers, Arc::new(Slow), TurnRequest::new("wait")).unwrap();
        let control = turn.control();
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        control.cancel();

        let events = tokio::time::timeout(Duration::from_secs(5), turn.collect())
            .await
            .expect("the turn resolved");
        assert_eq!(events.len(), 1);
        assert_eq!(terminal_of(&events).kind(), StopKind::Cancelled);

        tokio::time::timeout(Duration::from_secs(5), async {
            while !saw_cancel.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the detached handler observed the token after the turn resolved");
    }
}

// ===========================================================================
// PLX-97 — the evidence against option 1 (inline-poll-until-cancel)
//
// PLX-88 follow-up #2 proposed polling the handler inside the turn loop and
// spawning it only on cancel, and PLX-97 was dispatched believing that one
// change would also close the handler-state seam. It does neither:
//
//  (a) It does not close the seam. Whether the handler future is polled by a
//      task or by the stream generator, it lives inside the `'static` stream
//      `entry` returns, so it must itself be `'static`. Relocating the poll
//      does not shorten the lifetime the handler needs. `seam::` above is the
//      construction that actually compiles, and it needed owned state.
//
//  (b) It contradicts PLX-80's ac4. The test below pins the property ac4
//      depends on: the handler makes progress *before anyone polls the turn's
//      event stream*. `ac4_the_handler_observes_the_token_and_the_framework_
//      does_not_stop_it` waits on `started` before its first `turn.next()`,
//      so a handler that only runs when the stream is polled deadlocks it —
//      and that test may not be modified.
//
// Both are mechanical, not matters of taste. Delete this test only together
// with the eager-start guarantee it describes.
// ===========================================================================

#[tokio::test]
async fn plx97_the_handler_starts_before_the_turn_stream_is_polled() {
    let started = Arc::new(AtomicBool::new(false));
    let s = started.clone();

    let ir = ActivationIr::new("fixture", "1.0.0").with_method(public("eager"));
    let handlers = HandlerTable::new([(
        "eager",
        ErasedHandler::new(move |_input: HandlerInput| {
            let s = s.clone();
            async move {
                s.store(true, Ordering::SeqCst);
                futures::future::pending::<()>().await;
                Ok(TurnOutcome::complete())
            }
        }),
    )]);

    let turn = entry(&ir, &handlers, TurnRequest::new("eager")).unwrap();

    // Nothing has touched `turn` as a stream. The handler still runs.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect(
        "the handler must make progress without the turn stream being polled — \
         PLX-80's ac4 cancellation test depends on it, which is why \
         inline-poll-until-cancel (PLX-88 follow-up #2) cannot be adopted as-is",
    );

    turn.control().cancel();
    let events = tokio::time::timeout(Duration::from_secs(5), turn.collect())
        .await
        .expect("the turn still resolves");
    assert_eq!(terminal_of(&events).kind(), StopKind::Cancelled);
}
