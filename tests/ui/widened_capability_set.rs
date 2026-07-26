//! PLX-102: a handler may not mint a capability set other than the one its
//! method declares.
//!
//! `DeclaredHandler::new::<C, _, _>` is the single site where `C` is chosen: it
//! derives the method's `MethodIr::callbacks` *and* types the handler's turn.
//! Inside the body, `turn.client()` infers exactly `C` — asking for anything
//! else is this file, and it must not compile.
//!
//! Before PLX-102 the equivalent program (`turn.client::<(FsWrite,)>()` on a
//! bare `TurnContext`) compiled, minted a working `FsWrite` accessor, and only
//! failed when the callback reached the transport — the peer had been
//! pre-flight-checked against `(FsRead,)` and never agreed to serve
//! `fs/write_text_file`. A guarantee gap rather than a permission hole, but a
//! runtime failure in a design whose whole point is that this class of mistake
//! is a compile error.

use plexus_core::capability::{FsRead, FsReadRequest, FsWrite, FsWriteRequest};
use plexus_core::runtime::{DeclaredHandler, TurnOutcome};

fn main() {
    // Declared: `(FsRead,)`. The handle is inferred from the declaration, and
    // this is fine.
    let _ok = DeclaredHandler::new::<(FsRead,), _, _>(|input| async move {
        let client = input.turn.client();
        let _ = client.fs_read(FsReadRequest {
            path: "/etc/hosts".into(),
        });
        Ok(TurnOutcome::complete())
    });

    // WIDENING: the method declares `(FsRead,)`; this asks for `(FsWrite,)`.
    let _bad = DeclaredHandler::new::<(FsRead,), _, _>(|input| async move {
        let client = input.turn.client::<(FsWrite,)>();
        let _ = client.fs_write(FsWriteRequest {
            path: "/etc/passwd".into(),
            content: "pwned".into(),
        });
        Ok(TurnOutcome::complete())
    });
}
