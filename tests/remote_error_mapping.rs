//! RETURNS-6 · `PlexusError` → `RemoteError`, and where the typed error
//! reaches the wire.
//!
//! - one test per row of the ticket's mapping table (AC 1);
//! - the JSON-RPC rejection carries `RemoteError` in `data` (AC 3);
//! - the dispatch paths that build error frames carry it typed;
//! - the `#[activation]`-emitted param extraction builds the structured
//!   `InvalidParams { param, problem }`.

use futures::StreamExt;
use plexus_core::activations::echo::Echo;
use plexus_core::plexus::{
    plexus_error_to_jsonrpc, Activation, AuthzDenyReason, DenyReason, DynamicHub, ParamProblem,
    PlexusError, PlexusStreamItem, RemoteError, TransportErrorKind,
};
use plexus_auth_core::Scope;
use serde_json::json;

fn remote(e: PlexusError) -> RemoteError {
    RemoteError::from(&e)
}

// ------------------------------------------------------- AC 1: one per row

#[test]
fn activation_not_found_maps_to_activation_not_found() {
    assert_eq!(
        remote(PlexusError::ActivationNotFound("tickets".into())),
        RemoteError::ActivationNotFound {
            activation: "tickets".into()
        }
    );
}

#[test]
fn method_not_found_maps_to_method_not_found() {
    assert_eq!(
        remote(PlexusError::MethodNotFound {
            activation: "tickets".into(),
            method: "frob".into(),
        }),
        RemoteError::MethodNotFound {
            activation: "tickets".into(),
            method: "frob".into(),
        }
    );
}

#[test]
fn invalid_params_maps_field_for_field() {
    for (param, problem) in [
        (Some("id".to_string()), ParamProblem::Missing),
        (
            Some("id".to_string()),
            ParamProblem::Malformed {
                detail: "expected a string".into(),
            },
        ),
        (
            None,
            ParamProblem::Malformed {
                detail: "expected object".into(),
            },
        ),
    ] {
        assert_eq!(
            remote(PlexusError::InvalidParams {
                param: param.clone(),
                problem: problem.clone(),
            }),
            RemoteError::InvalidParams { param, problem }
        );
    }
}

#[test]
fn execution_error_maps_to_execution() {
    assert_eq!(
        remote(PlexusError::ExecutionError("database is locked".into())),
        RemoteError::Execution {
            message: "database is locked".into()
        }
    );
}

#[test]
fn handle_not_supported_maps_to_handle_not_supported() {
    assert_eq!(
        remote(PlexusError::HandleNotSupported("tickets".into())),
        RemoteError::HandleNotSupported {
            activation: "tickets".into()
        }
    );
}

/// A hub forwarding upstream failed: an execution failure whose message is
/// the transport error's `Display`.
#[test]
fn transport_error_maps_to_execution_with_the_kinds_display() {
    let kind = TransportErrorKind::ConnectionRefused {
        host: "127.0.0.1".into(),
        port: 4455,
    };
    assert_eq!(
        remote(PlexusError::TransportError(kind.clone())),
        RemoteError::Execution {
            message: kind.to_string()
        }
    );
    assert_eq!(kind.to_string(), "Connection refused to 127.0.0.1:4455");
}

/// The server-side reason stays server-side.
#[test]
fn unauthenticated_maps_to_unauthenticated_without_its_reason() {
    let e = remote(PlexusError::Unauthenticated("session sid=abc expired".into()));
    assert_eq!(e, RemoteError::Unauthenticated);
    assert_eq!(serde_json::to_value(&e).unwrap(), json!({"kind": "unauthenticated"}));
}

/// `MissingScope` renders the one unmet scope; `TenantBoundary` and
/// `NotAccepted` carry nothing.
#[test]
fn forbidden_maps_each_deny_reason() {
    let missing = remote(PlexusError::Forbidden {
        reason: AuthzDenyReason::MissingScope {
            scope: Scope::new("vault.write"),
        },
    });
    assert_eq!(
        missing,
        RemoteError::Forbidden {
            reason: DenyReason::MissingScope {
                scope: "vault.write".into()
            }
        }
    );
    assert_eq!(
        serde_json::to_value(&missing).unwrap(),
        json!({"kind": "forbidden", "reason": "missing_scope", "scope": "vault.write"})
    );

    assert_eq!(
        remote(PlexusError::Forbidden {
            reason: AuthzDenyReason::TenantBoundary
        }),
        RemoteError::Forbidden {
            reason: DenyReason::TenantBoundary
        }
    );
    assert_eq!(
        remote(PlexusError::Forbidden {
            reason: AuthzDenyReason::NotAccepted
        }),
        RemoteError::Forbidden {
            reason: DenyReason::NotAccepted
        }
    );
}

// --------------------------------------------- AC 3: the JSON-RPC rejection

#[test]
fn a_jsonrpc_rejection_for_an_unknown_method_carries_method_not_found_in_data() {
    let rejection = plexus_error_to_jsonrpc(&PlexusError::MethodNotFound {
        activation: "tickets".into(),
        method: "frob".into(),
    });
    let wire = serde_json::to_value(&rejection).unwrap();

    assert_eq!(wire["data"]["kind"], "method_not_found");
    assert_eq!(
        wire,
        json!({
            "code": -32601,
            "message": "method not found: tickets.frob",
            "data": {"kind": "method_not_found", "activation": "tickets", "method": "frob"}
        })
    );
}

/// Every variant's rejection keeps its semantic code, says the
/// `RemoteError`'s `Display` as `message`, and carries it in `data`.
#[test]
fn every_jsonrpc_rejection_carries_its_remote_error() {
    let cases = [
        (PlexusError::ActivationNotFound("tickets".into()), -32601),
        (
            PlexusError::MethodNotFound {
                activation: "tickets".into(),
                method: "frob".into(),
            },
            -32601,
        ),
        (
            PlexusError::InvalidParams {
                param: Some("id".into()),
                problem: ParamProblem::Missing,
            },
            -32602,
        ),
        (PlexusError::ExecutionError("boom".into()), -32000),
        (PlexusError::HandleNotSupported("tickets".into()), -32000),
        (
            PlexusError::TransportError(TransportErrorKind::NetworkError {
                message: "reset".into(),
            }),
            -32000,
        ),
        (PlexusError::Unauthenticated("no session".into()), -32001),
        (
            PlexusError::Forbidden {
                reason: AuthzDenyReason::TenantBoundary,
            },
            -32003,
        ),
    ];
    for (e, code) in cases {
        let expected = RemoteError::from(&e);
        let rejection = plexus_error_to_jsonrpc(&e);
        assert_eq!(rejection.code(), code, "{e:?}");
        assert_eq!(rejection.message(), expected.to_string(), "{e:?}");
        let data: RemoteError =
            serde_json::from_str(rejection.data().expect("data is always present").get()).unwrap();
        assert_eq!(data, expected, "{e:?}");
    }
}

// ------------------------------------------- error frames from dispatch

/// Subscribe to `plexus.call` on the hub's JSON-RPC module and return the
/// first frame it sends.
async fn first_call_frame(module: jsonrpsee::RpcModule<()>, method: &str) -> serde_json::Value {
    let mut params = jsonrpsee::core::params::ObjectParams::new();
    params.insert("method", method).unwrap();
    let mut sub = module
        .subscribe_unbounded("plexus.call", params)
        .await
        .expect("plexus.call accepts the subscription");
    let (frame, _id) = sub
        .next::<serde_json::Value>()
        .await
        .expect("one frame")
        .expect("a frame, not a methods error");
    frame
}

/// The WebSocket path (`{ns}.call`, both module builders): a routing failure
/// answers with an error frame carrying the typed `RemoteError` — no
/// `message`, no `code`.
#[tokio::test]
async fn the_call_subscription_reports_a_routing_failure_as_a_typed_error_frame() {
    let modules = [
        DynamicHub::new("plexus")
            .register(Echo::new())
            .into_rpc_module()
            .unwrap(),
        DynamicHub::arc_into_rpc_module(std::sync::Arc::new(
            DynamicHub::new("plexus").register(Echo::new()),
        ))
        .unwrap(),
    ];
    for module in modules {
        let wire = first_call_frame(module, "nope.x").await;
        assert_eq!(wire["type"], "error", "{wire}");
        assert_eq!(wire["recoverable"], false, "{wire}");
        assert_eq!(
            wire["error"],
            json!({"kind": "activation_not_found", "activation": "nope"}),
            "{wire}"
        );
        assert!(wire.get("message").is_none() && wire.get("code").is_none(), "{wire}");

        let frame: PlexusStreamItem = serde_json::from_value(wire).expect("a 0.7 frame");
        assert!(matches!(
            frame,
            PlexusStreamItem::Error {
                error: RemoteError::ActivationNotFound { .. },
                ..
            }
        ));
    }
}

/// `plexus.call` as an activation method: the routed failure is a typed
/// error frame. (Dispatched through `Activation::call`, the method's own
/// frames arrive wrapped as data content — `call` yields
/// `PlexusStreamItem`s and dispatch wraps every item; that predates 0.7.)
#[tokio::test]
async fn the_hubs_call_method_reports_a_routing_failure_as_a_typed_error_frame() {
    let hub = DynamicHub::new("plexus").register(Echo::new());
    let stream = Activation::call(&hub, "call", json!({"method": "nope.x"}), None, None)
        .await
        .expect("plexus.call itself dispatches");
    let items: Vec<PlexusStreamItem> = stream.collect().await;

    let inner = items
        .iter()
        .find_map(|i| match i {
            PlexusStreamItem::Data { content, .. } => {
                serde_json::from_value::<PlexusStreamItem>(content.clone()).ok()
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("the routed frame: {items:?}"));
    match inner {
        PlexusStreamItem::Error {
            error, recoverable, ..
        } => {
            assert_eq!(
                error,
                RemoteError::ActivationNotFound {
                    activation: "nope".into()
                }
            );
            assert!(!recoverable);
        }
        other => panic!("expected an error frame, got {other:?}"),
    }
}

/// A method name with no `.` is a malformed `method` param.
#[tokio::test]
async fn a_method_without_a_namespace_is_a_malformed_method_param() {
    let hub = DynamicHub::new("plexus").register(Echo::new());
    let err = match hub.route("noperiod", json!({}), None).await {
        Err(e) => e,
        Ok(_) => panic!("routing `noperiod` must fail"),
    };
    match &err {
        PlexusError::InvalidParams {
            param: Some(p),
            problem: ParamProblem::Malformed { .. },
        } => assert_eq!(p, "method"),
        other => panic!("expected InvalidParams on `method`, got {other:?}"),
    }
}

// ------------------------------- the emitted param extraction (paired bridge)

async fn call_err(method: &str, params: serde_json::Value) -> PlexusError {
    match Activation::call(&Echo::new(), method, params, None, None).await {
        Err(e) => e,
        Ok(_) => panic!("`echo.{method}` must reject these params"),
    }
}

/// One-param method (`echo.once(message)`): absent → `missing`.
#[tokio::test]
async fn a_missing_required_param_names_the_param() {
    let e = call_err("once", json!({})).await;
    assert_eq!(
        RemoteError::from(&e),
        RemoteError::InvalidParams {
            param: Some("message".into()),
            problem: ParamProblem::Missing,
        }
    );
}

/// One-param method: present but the wrong JSON type → `malformed`.
#[tokio::test]
async fn a_param_of_the_wrong_type_is_malformed_and_named() {
    let e = call_err("once", json!({"message": 5})).await;
    match RemoteError::from(&e) {
        RemoteError::InvalidParams {
            param: Some(p),
            problem: ParamProblem::Malformed { detail },
        } => {
            assert_eq!(p, "message");
            assert!(detail.contains("expected a string"), "{detail}");
        }
        other => panic!("expected malformed `message`, got {other:?}"),
    }
}

/// Two-param method (`echo.echo(message, count)`): each param is named.
#[tokio::test]
async fn a_multi_param_method_names_the_missing_and_the_malformed_param() {
    let e = call_err("echo", json!({"message": "hi"})).await;
    assert_eq!(
        RemoteError::from(&e),
        RemoteError::InvalidParams {
            param: Some("count".into()),
            problem: ParamProblem::Missing,
        }
    );

    let e = call_err("echo", json!({"message": "hi", "count": "three"})).await;
    assert!(matches!(
        RemoteError::from(&e),
        RemoteError::InvalidParams {
            param: Some(ref p),
            problem: ParamProblem::Malformed { .. },
        } if p == "count"
    ));
}

/// Params that are not an object at all name no param.
#[tokio::test]
async fn non_object_params_are_malformed_with_no_param() {
    let e = call_err("echo", json!(["hi", 1])).await;
    assert_eq!(
        RemoteError::from(&e),
        RemoteError::InvalidParams {
            param: None,
            problem: ParamProblem::Malformed {
                detail: "expected object".into()
            },
        }
    );
}
