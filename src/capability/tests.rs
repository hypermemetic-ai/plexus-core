//! PLX-77 acceptance tests for the typed capability handle.
//!
//! The *negative* halves — calling an undeclared capability, and implementing
//! the marker trait externally — are compile-fail fixtures, because a runtime
//! test cannot observe a method that does not exist. See
//! `tests/compile_fail.rs` and `tests/ui/`.

use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::ir::CallbackIr;

// ---------------------------------------------------------------------------
// AC4 — declaration and use are the same thing by construction
// ---------------------------------------------------------------------------

#[test]
fn ac4_capability_set_derives_exactly_the_declared_callbacks() {
    let derived = Client::<(Permission, FsRead)>::callbacks();

    assert_eq!(derived.len(), 2, "exactly the two declared capabilities");
    assert_eq!(
        derived.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["session/request_permission", "fs/read_text_file"],
        "names, in declaration order"
    );

    // …and the schemas are the markers' own, not a re-description of them.
    assert_eq!(derived[0], Permission::descriptor());
    assert_eq!(derived[1], FsRead::descriptor());

    for c in &derived {
        assert!(!c.request.type_name().is_empty());
        assert!(!c.response.type_name().is_empty());
    }
    assert_eq!(derived[1].request.type_name(), "FsReadRequest");
    assert_eq!(derived[1].response.type_name(), "FsReadResponse");
}

#[test]
fn ac4_the_empty_set_derives_an_empty_vec() {
    let derived: Vec<CallbackIr> = Client::<()>::callbacks();
    assert!(derived.is_empty(), "Client<()> declares nothing");
    assert_eq!(<() as CapabilitySet>::ARITY, 0);
    assert!(Client::<()>::capability_names().is_empty());
}

#[test]
fn ac4_derivation_covers_the_whole_supported_tuple_range() {
    // 0..=8 — the range the ticket requires. Arities above 4 reuse markers,
    // which is fine for *derivation* (only membership inference cares about
    // duplicates, and these are never called through).
    assert_eq!(<() as CapabilitySet>::ARITY, 0);
    assert_eq!(<(Permission,) as CapabilitySet>::ARITY, 1);
    assert_eq!(<(Permission, FsRead) as CapabilitySet>::ARITY, 2);
    assert_eq!(<(Permission, FsRead, FsWrite) as CapabilitySet>::ARITY, 3);
    assert_eq!(
        <(Permission, FsRead, FsWrite, Terminal) as CapabilitySet>::ARITY,
        4
    );
    type Five = (Permission, FsRead, FsWrite, Terminal, Permission);
    type Six = (Permission, FsRead, FsWrite, Terminal, Permission, FsRead);
    type Seven = (
        Permission,
        FsRead,
        FsWrite,
        Terminal,
        Permission,
        FsRead,
        FsWrite,
    );
    type Eight = (
        Permission,
        FsRead,
        FsWrite,
        Terminal,
        Permission,
        FsRead,
        FsWrite,
        Terminal,
    );
    assert_eq!(<Five as CapabilitySet>::ARITY, 5);
    assert_eq!(<Six as CapabilitySet>::ARITY, 6);
    assert_eq!(<Seven as CapabilitySet>::ARITY, 7);
    assert_eq!(<Eight as CapabilitySet>::ARITY, 8);
    assert_eq!(Eight::callbacks().len(), 8);

    // The full four-capability set is exactly the ACP `session/prompt` set.
    assert_eq!(
        <(Permission, FsRead, FsWrite, Terminal)>::names(),
        [
            "session/request_permission",
            "fs/read_text_file",
            "fs/write_text_file",
            "terminal/create",
        ]
    );
}

#[test]
fn every_marker_descriptor_is_valid() {
    // `Capability::descriptor` builds `SchemaRef`s with `expect`; this is the
    // test that keeps that honest.
    for (name, d) in [
        ("Permission", Permission::descriptor()),
        ("FsRead", FsRead::descriptor()),
        ("FsWrite", FsWrite::descriptor()),
        ("Terminal", Terminal::descriptor()),
    ] {
        assert!(!d.name.is_empty(), "{name} has an empty wire name");
        assert!(d.name.contains('/'), "{name} wire name is namespaced");
        // A `SchemaRef` cannot exist in a degenerate form, so its mere
        // construction is the assertion; check it carries real type info too.
        // (`PermissionOutcome` is a tagged enum, so schemars describes it with
        // `oneOf` rather than a top-level `type`.)
        for (half, s) in [("request", &d.request), ("response", &d.response)] {
            let v = s.schema().as_value();
            assert!(
                ["type", "oneOf", "anyOf", "properties", "$ref"]
                    .iter()
                    .any(|k| v.get(k).is_some()),
                "{name}'s {half} schema carries no structure: {v}"
            );
        }
    }

    assert_eq!(Permission::NAME, "session/request_permission");
    assert_eq!(FsRead::NAME, "fs/read_text_file");
    assert_eq!(FsWrite::NAME, "fs/write_text_file");
    assert_eq!(Terminal::NAME, "terminal/create");
}

#[test]
fn descriptors_are_deterministic() {
    assert_eq!(FsWrite::descriptor(), FsWrite::descriptor());
}

// ---------------------------------------------------------------------------
// Membership gating — the positive half (the negative half is trybuild)
// ---------------------------------------------------------------------------

/// A transport that records what it was asked to do and answers canned JSON.
struct RecordingTransport {
    calls: Mutex<Vec<String>>,
    reply: serde_json::Value,
}

impl CallbackTransport for RecordingTransport {
    fn call(
        &self,
        callback: &CallbackIr,
        _request: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.calls.lock().unwrap().push(callback.name.clone());
        Ok(self.reply.clone())
    }
}

#[test]
fn a_declared_capability_is_callable_and_routes_to_its_own_descriptor() {
    let t = Arc::new(RecordingTransport {
        calls: Mutex::new(Vec::new()),
        reply: json!({ "content": "hello" }),
    });
    let client: Client<(Permission, FsRead)> = Client::new(t.clone());
    assert!(client.is_wired());

    let resp = client
        .fs_read(FsReadRequest {
            path: "/etc/hosts".into(),
        })
        .expect("fs_read is declared, so it is callable");
    assert_eq!(resp.content, "hello");
    assert_eq!(t.calls.lock().unwrap().as_slice(), ["fs/read_text_file"]);
}

#[test]
fn membership_holds_at_every_position_of_the_tuple() {
    // Exercises `Here`, `There<Here>`, `There<There<Here>>` and
    // `There<There<There<Here>>>` — the index-disambiguated impls.
    let c: Client<(Permission, FsRead, FsWrite, Terminal)> = Client::unwired();
    assert!(matches!(
        c.request_permission(PermissionRequest {
            operation: "x".into(),
            rationale: None
        }),
        Err(CallbackError::NotWired("session/request_permission"))
    ));
    assert!(matches!(
        c.fs_read(FsReadRequest { path: "p".into() }),
        Err(CallbackError::NotWired("fs/read_text_file"))
    ));
    assert!(matches!(
        c.fs_write(FsWriteRequest {
            path: "p".into(),
            content: "c".into()
        }),
        Err(CallbackError::NotWired("fs/write_text_file"))
    ));
    assert!(matches!(
        c.terminal_create(TerminalCreateRequest {
            command: "ls".into(),
            args: vec![]
        }),
        Err(CallbackError::NotWired("terminal/create"))
    ));
}

#[test]
fn an_unwired_handle_errors_rather_than_panicking() {
    let client: Client<(FsWrite,)> = Client::default();
    assert!(!client.is_wired());
    let err = client
        .fs_write(FsWriteRequest {
            path: "p".into(),
            content: "c".into(),
        })
        .unwrap_err();
    assert_eq!(err, CallbackError::NotWired("fs/write_text_file"));
    assert!(err.to_string().contains("build C"));
}

#[test]
fn transport_failures_are_surfaced_not_swallowed() {
    struct Failing;
    impl CallbackTransport for Failing {
        fn call(
            &self,
            _c: &CallbackIr,
            _r: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("peer closed the connection".into())
        }
    }
    let client: Client<(Permission,)> = Client::new(Arc::new(Failing));
    let err = client
        .request_permission(PermissionRequest {
            operation: "delete".into(),
            rationale: Some("cleanup".into()),
        })
        .unwrap_err();
    assert!(matches!(err, CallbackError::Transport { .. }), "{err:?}");

    struct Garbage;
    impl CallbackTransport for Garbage {
        fn call(
            &self,
            _c: &CallbackIr,
            _r: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(json!({ "not": "a permission outcome" }))
        }
    }
    let client: Client<(Permission,)> = Client::new(Arc::new(Garbage));
    let err = client
        .request_permission(PermissionRequest {
            operation: "delete".into(),
            rationale: None,
        })
        .unwrap_err();
    assert!(matches!(err, CallbackError::Payload { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// PLX-78 — a capability set is a SET
// ---------------------------------------------------------------------------

#[test]
fn a_capabilitys_identity_is_its_wire_name_and_the_names_are_distinct() {
    // The *guarantee* that no two markers share a wire name is not this test —
    // it is the crate-level `const _: () = assert!(!has_duplicate_names(..))`
    // that `declare_capabilities!` emits, which fails `cargo build` of this
    // crate. This test guards the thing that assertion cannot see: that the
    // list it ranges over really is every marker. A marker declared outside the
    // macro would slip past the proof, so pin the inventory.
    assert_eq!(
        ALL_CAPABILITY_NAMES,
        [
            Permission::NAME,
            FsRead::NAME,
            FsWrite::NAME,
            Terminal::NAME
        ],
        "ALL_CAPABILITY_NAMES must list every marker; a marker declared outside \
         `declare_capabilities!` would escape the compile-time distinctness proof"
    );
    assert!(!has_duplicate_names(ALL_CAPABILITY_NAMES));

    // …and spelled out pairwise, so a failure names the colliding pair.
    for (i, a) in ALL_CAPABILITY_NAMES.iter().enumerate() {
        for b in &ALL_CAPABILITY_NAMES[i + 1..] {
            assert_ne!(a, b, "two capability markers share the wire name {a:?}");
        }
    }
}

#[test]
fn has_duplicate_names_is_exact() {
    assert!(!has_duplicate_names(&[]));
    assert!(!has_duplicate_names(&["a"]));
    assert!(!has_duplicate_names(&["a", "b", "c"]));
    assert!(has_duplicate_names(&["a", "a"]));
    // Duplicates at either end and in the middle of a longer list.
    assert!(has_duplicate_names(&["a", "b", "c", "a"]));
    assert!(has_duplicate_names(&["a", "b", "b", "c"]));
    // A prefix is not a duplicate — the comparison is on the whole string.
    assert!(!has_duplicate_names(&["fs/read", "fs/read_text_file"]));
    assert!(!has_duplicate_names(&["", "x"]));
    assert!(has_duplicate_names(&["", ""]));
}

#[test]
fn the_const_name_list_agrees_with_the_runtime_one() {
    // `NAMES` is what the const check reads; `names()` is what callers read.
    // If they ever disagree, the compile-time check is checking a fiction.
    assert_eq!(<() as CapabilitySet>::NAMES, &[] as &[&str]);
    assert_eq!(
        <(Permission, FsRead, FsWrite, Terminal) as CapabilitySet>::NAMES,
        <(Permission, FsRead, FsWrite, Terminal)>::names().as_slice()
    );
    type Eight = (
        Permission,
        FsRead,
        FsWrite,
        Terminal,
        Permission,
        FsRead,
        FsWrite,
        Terminal,
    );
    assert_eq!(<Eight as CapabilitySet>::NAMES.len(), 8);
    // The tuple impls themselves are unchanged by PLX-78: `CapabilitySet` still
    // describes any 0..=8 tuple of markers, duplicates included. It is the
    // *handle* that must be well formed, which is where the assertion lives.
    assert!(has_duplicate_names(<Eight as CapabilitySet>::NAMES));
}

#[test]
fn well_formed_sets_pay_nothing_for_the_check() {
    // Construction, derivation and gating for every distinct-marker arity the
    // four-marker vocabulary allows. Each `Client::unwired()` here forces
    // `NO_DUPLICATES`, so this test failing to *compile* would be the signal
    // that the check has started rejecting well-formed sets.
    assert!(Client::<()>::callbacks().is_empty());
    let _: Client<()> = Client::unwired();

    let one: Client<(Permission,)> = Client::unwired();
    assert!(matches!(
        one.request_permission(PermissionRequest {
            operation: "x".into(),
            rationale: None
        }),
        Err(CallbackError::NotWired(_))
    ));
    assert_eq!(Client::<(Permission,)>::callbacks().len(), 1);

    let two: Client<(Permission, FsRead)> = Client::default();
    assert!(matches!(
        two.fs_read(FsReadRequest { path: "p".into() }),
        Err(CallbackError::NotWired("fs/read_text_file"))
    ));
    assert_eq!(Client::<(Permission, FsRead)>::callbacks().len(), 2);

    let four: Client<(Permission, FsRead, FsWrite, Terminal)> = Client::unwired();
    assert!(matches!(
        four.terminal_create(TerminalCreateRequest {
            command: "ls".into(),
            args: vec![]
        }),
        Err(CallbackError::NotWired("terminal/create"))
    ));
    assert_eq!(
        Client::<(Permission, FsRead, FsWrite, Terminal)>::capability_names(),
        [
            "session/request_permission",
            "fs/read_text_file",
            "fs/write_text_file",
            "terminal/create",
        ]
    );

    // Forcing the assertion by hand is legal and is a no-op for a good set.
    let () = Client::<(Permission, FsRead, FsWrite, Terminal)>::NO_DUPLICATES;
}

#[test]
fn no_duplicates_is_exactly_the_predicate_the_client_asserts() {
    // The runtime shadow of the compile-time claim: whatever `NO_DUPLICATES`
    // asserts for a `C`, `has_duplicate_names(C::NAMES)` agrees with. The
    // negative half cannot live here — a `C` that fails the assertion cannot be
    // named in a compiling program — so it is
    // `tests/ui/duplicate_capability.rs`.
    for (label, names) in [
        ("()", <() as CapabilitySet>::NAMES),
        ("(Permission,)", <(Permission,) as CapabilitySet>::NAMES),
        (
            "(Permission, FsRead, FsWrite, Terminal)",
            <(Permission, FsRead, FsWrite, Terminal) as CapabilitySet>::NAMES,
        ),
    ] {
        assert!(
            !has_duplicate_names(names),
            "{label} is well formed but reads as duplicated"
        );
    }
}

#[test]
fn payload_types_round_trip() {
    let outcome = PermissionOutcome::Deny {
        reason: Some("policy".into()),
    };
    let v = serde_json::to_value(&outcome).unwrap();
    assert_eq!(v, json!({"outcome": "deny", "reason": "policy"}));
    assert_eq!(
        serde_json::from_value::<PermissionOutcome>(v).unwrap(),
        outcome
    );
    assert_eq!(
        serde_json::to_value(PermissionOutcome::Allow).unwrap(),
        json!({"outcome": "allow"})
    );
}

#[test]
fn debug_shows_the_declared_set_and_the_wiring_state() {
    let c: Client<(Permission, Terminal)> = Client::unwired();
    let s = format!("{c:?}");
    assert!(s.contains("session/request_permission"), "{s}");
    assert!(s.contains("terminal/create"), "{s}");
    assert!(s.contains("wired: false"), "{s}");
}
