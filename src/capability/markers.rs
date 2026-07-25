//! The capability markers and the sealed trait they implement.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ir::{CallbackIr, SchemaRef};

/// Sealing module. `Capability` and `CapabilitySet` both require
/// `sealed::Sealed`, which is private to this crate, so no downstream type can
/// implement either — the capability set is closed by construction, not by
/// documentation.
pub(crate) mod sealed {
    /// Private supertrait. Not nameable outside `plexus-core`.
    pub trait Sealed {}
}

/// A server-to-client callback a client may be able to serve.
///
/// Implemented **only** by the marker types in this module. The trait is sealed
/// (see [`sealed::Sealed`]), so `impl Capability for MyType` outside this crate
/// is a compile error — which is what makes "the handle's type IS the
/// declaration" a guarantee rather than a convention: there is no way to invent
/// a capability the IR does not know about.
pub trait Capability: sealed::Sealed + Copy + Send + Sync + 'static {
    /// Wire name of the server-to-client request, e.g. `"fs/read_text_file"`.
    const NAME: &'static str;

    /// The IR descriptor for this callback: name plus request/response schemas.
    ///
    /// This is the single source of truth. A `Client<C>` derives its declared
    /// [`CallbackIr`] set by calling this for each marker in `C`, so what a
    /// method *declares* and what it *can call* cannot diverge.
    fn descriptor() -> CallbackIr;
}

/// Build a [`SchemaRef`] from a `JsonSchema` type.
///
/// Infallible in practice for every payload type in this module (each is a
/// struct or enum, so `schemars` never yields the empty schema); the
/// `expect` is covered by [`super::tests::every_marker_descriptor_is_valid`].
fn schema_ref<T: JsonSchema>(type_name: &'static str) -> SchemaRef {
    SchemaRef::new(type_name, schemars::schema_for!(T))
        .expect("capability payload types are always representable")
}

// ===========================================================================
// Payload types
// ===========================================================================
//
// These exist so a marker's descriptor carries a *real* resolved schema rather
// than a hand-written JSON blob. They are the minimum shape each callback
// needs; the wire vocabulary for a specific agent protocol is a later build's
// concern (PLX-76), and nothing here dispatches or transports them.

/// What the server is asking permission to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionRequest {
    /// Stable identifier for the operation permission is sought for.
    pub operation: String,
    /// Human-readable explanation shown to whoever decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// The decision the client returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PermissionOutcome {
    /// Permission granted.
    Allow,
    /// Permission refused — feeds [`crate::ir::StopKind::Refused`], not an error.
    Deny {
        /// Why, when the client says.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// Read a text file on the client's filesystem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FsReadRequest {
    /// Path, interpreted by the client.
    pub path: String,
}

/// The file's contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FsReadResponse {
    /// The text that was read.
    pub content: String,
}

/// Write a text file on the client's filesystem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FsWriteRequest {
    /// Path, interpreted by the client.
    pub path: String,
    /// The text to write.
    pub content: String,
}

/// Acknowledgement of a write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FsWriteResponse {
    /// How many bytes the client wrote.
    pub bytes_written: u64,
}

/// Create a terminal on the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TerminalCreateRequest {
    /// The command to run.
    pub command: String,
    /// Its arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// The handle of the terminal the client created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TerminalCreateResponse {
    /// Client-assigned terminal id.
    pub terminal_id: String,
}

// ===========================================================================
// Markers
// ===========================================================================

/// Declares a marker type, seals it, and gives it its [`CallbackIr`].
macro_rules! declare_capability {
    (
        $(#[$meta:meta])*
        $name:ident => $wire:literal, $req:ty as $req_name:literal, $resp:ty as $resp_name:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Capability for $name {
            const NAME: &'static str = $wire;

            fn descriptor() -> CallbackIr {
                CallbackIr::new(
                    $wire,
                    schema_ref::<$req>($req_name),
                    schema_ref::<$resp>($resp_name),
                )
            }
        }
    };
}

declare_capability! {
    /// Ask the client to approve an operation (`session/request_permission`).
    Permission => "session/request_permission",
    PermissionRequest as "PermissionRequest",
    PermissionOutcome as "PermissionOutcome"
}

declare_capability! {
    /// Read a text file through the client (`fs/read_text_file`).
    FsRead => "fs/read_text_file",
    FsReadRequest as "FsReadRequest",
    FsReadResponse as "FsReadResponse"
}

declare_capability! {
    /// Write a text file through the client (`fs/write_text_file`).
    FsWrite => "fs/write_text_file",
    FsWriteRequest as "FsWriteRequest",
    FsWriteResponse as "FsWriteResponse"
}

declare_capability! {
    /// Create a terminal on the client (`terminal/create`).
    Terminal => "terminal/create",
    TerminalCreateRequest as "TerminalCreateRequest",
    TerminalCreateResponse as "TerminalCreateResponse"
}
