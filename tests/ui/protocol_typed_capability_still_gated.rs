//! PLX-137: `issue_as_async` lets a protocol crate carry its own payload
//! types for a capability's wire name. It must **not** let it reach a
//! capability the method never declared.
//!
//! This is the fixture that keeps the escape hatch from being a hole: the
//! handle declares only `Permission`, and asking for `FsRead` through the
//! protocol-typed accessor has to fail with the *same* `Has<FsRead, _>` bound
//! that `fs_read_async` fails with.

use plexus_core::capability::{Client, FsRead, Permission};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AnyRequest {
    path: String,
}

#[derive(Deserialize)]
struct AnyResponse {
    #[allow(dead_code)]
    content: String,
}

async fn prompt(client: &Client<(Permission,)>) {
    // NOT declared: `FsRead` is not in `C`. Bringing protocol-owned payload
    // types does not change that.
    let _bad: Result<AnyResponse, _> = client
        .issue_as_async::<FsRead, _, _, _>(AnyRequest {
            path: "/etc/hosts".into(),
        })
        .await;
}

fn main() {
    let _ = <FsRead as plexus_core::capability::Capability>::NAME;
    let _ = prompt(&Client::unwired());
}
