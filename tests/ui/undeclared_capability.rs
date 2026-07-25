//! PLX-77 AC3: using a capability that is not in `C` is a COMPILE error.
//!
//! The handle declares only `Permission`. Calling `fs_read` asks for a
//! capability the signature never declared, so there is no such method.

use plexus_core::capability::{Client, FsRead, FsReadRequest, Permission, PermissionRequest};

fn prompt(client: &Client<(Permission,)>) {
    // Declared: this is fine.
    let _ok = client.request_permission(PermissionRequest {
        operation: "write".into(),
        rationale: None,
    });

    // NOT declared: `FsRead` is not in `C`, so this must not compile.
    let _bad = client.fs_read(FsReadRequest {
        path: "/etc/hosts".into(),
    });
}

fn main() {
    // Referenced so an unused-import warning is not what the golden captures.
    let _ = <FsRead as plexus_core::capability::Capability>::NAME;
    prompt(&Client::unwired());
}
