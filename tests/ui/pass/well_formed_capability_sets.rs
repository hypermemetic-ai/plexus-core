//! PLX-78: the duplicate check costs a well-formed set nothing.
//!
//! Every distinct-marker set still constructs, still derives its declaration,
//! and still gates its accessors exactly as PLX-77 left it.
//!
//! This fixture also has a second, structural job. `trybuild` runs its cases
//! with `cargo check` unless the suite contains at least one `pass` case, in
//! which case it runs `cargo build`. The duplicate assertion is a
//! post-monomorphization const evaluation — `cargo check` never instantiates a
//! generic function body, so it would never fire, and
//! `tests/ui/duplicate_capability.rs` would capture nothing. Registering this
//! file with `t.pass(..)` is what puts the whole suite in build mode. Deleting
//! it would silently defeat the duplicate golden.

use plexus_core::capability::{
    CapabilitySet, Client, FsRead, FsReadRequest, FsWrite, FsWriteRequest, Permission,
    PermissionRequest, Terminal, TerminalCreateRequest,
};

fn main() {
    // Arity 0.
    let empty: Client<()> = Client::unwired();
    assert!(Client::<()>::callbacks().is_empty());
    assert_eq!(format!("{empty:?}").contains("wired: false"), true);

    // Arity 1, and its accessor is callable.
    let one: Client<(Permission,)> = Client::unwired();
    let _ = one.request_permission(PermissionRequest {
        operation: "write".into(),
        rationale: None,
    });
    assert_eq!(Client::<(Permission,)>::callbacks().len(), 1);

    // Arity 2.
    let two: Client<(Permission, FsRead)> = Client::default();
    let _ = two.fs_read(FsReadRequest {
        path: "/etc/hosts".into(),
    });
    assert_eq!(
        Client::<(Permission, FsRead)>::capability_names(),
        ["session/request_permission", "fs/read_text_file"]
    );

    // Arity 4 — the full ACP `session/prompt` set, every accessor reachable.
    let four: Client<(Permission, FsRead, FsWrite, Terminal)> = Client::unwired();
    let _ = four.request_permission(PermissionRequest {
        operation: "x".into(),
        rationale: None,
    });
    let _ = four.fs_read(FsReadRequest { path: "p".into() });
    let _ = four.fs_write(FsWriteRequest {
        path: "p".into(),
        content: "c".into(),
    });
    let _ = four.terminal_create(TerminalCreateRequest {
        command: "ls".into(),
        args: vec![],
    });
    assert_eq!(
        <(Permission, FsRead, FsWrite, Terminal) as CapabilitySet>::ARITY,
        4
    );
}
