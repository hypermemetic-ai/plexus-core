// Guidance system removed during caller-wraps streaming architecture refactor
// pub mod guidance;

pub mod auth;
/// AUTH-5: the `auth` activation and what a service supplies it.
pub mod auth_activation;
pub mod auth_params;
/// AUTH-5: a reference in-memory backend and stores for the `auth` activation.
pub mod auth_memory;
pub mod test_validator;
/// MACRO-20: a hub sees through its activations' static children.
pub mod children;
pub mod context;
// RETURNS-10: canonical schema JSON and the SHA-256/16 hash every schema hash is.
pub mod content_hash;
pub mod credential_envelope;
pub mod dispatch;
/// BIDIR-8 (BIDIR-5's rule): the gate over a duplex call — open, admit,
/// re-verify on the gate's grants generation, answer, audit.
pub mod duplex_gate;
pub mod errors;
pub mod forward_registry;
/// AUTH-2: the grant gate in dispatch, and the task-local reach.
pub mod grant_gate;
pub mod hub_context;
/// RETURNS-40: the IR a service writes of itself — IR 3.0, as synapse builds it.
pub mod ir;
// MACRO-2.B3: the in-process transport for the macro-generated typed client.
pub mod in_process;
/// BIDIR-6: `Input<T>`, the input half of a call.
pub mod input;
/// LOCAL-6: a whole hub, called in memory.
pub mod hub_transport;
pub mod method_enum;
pub mod middleware;
pub mod parent;
pub mod path;
pub mod plexus;
/// DYNAUTH-8: frame logs never carry a credential.
pub mod redact;
/// DYNAUTH-12: tokens a service signs for the peers it forwards calls to.
#[cfg(not(target_arch = "wasm32"))]
pub mod peer_token;
// POLYGLOT-5: the child seam's second implementation — a process or a socket.
// PLEXUS-45: native only. A browser has no processes, and a ws child waits
// for a browser-WebSocket transport (a later ticket); on wasm32 the module
// would compile to a child with no way to reach it.
#[cfg(not(target_arch = "wasm32"))]
pub mod remote_child;
pub mod schema;
// NEST-11: which service a call is routed in.
pub mod service_scope;
/// NEST-15: the service root — a table of peers answered by `peer(name)`.
pub mod service_root;
/// NEST-5: slot types and slot grants.
pub mod slots;
/// NEST-7: the primitive — an activation returns an activation.
pub mod peer;
mod schema_sites;
pub(crate) mod scope_gate;
pub mod streaming;
pub mod types;
/// AUTH-4: the caller's view of a gated hub.
pub mod view;
/// PERF-7: the item path — each item encoded once, straight into the frame
/// its socket writes.
pub mod wire;

// AuthContext + SessionValidator + the sealed Principal / VerifiedUser /
// ServiceIdentity types are re-exported from plexus-auth-core via
// plexus::auth. New code should import directly from plexus_auth_core.
pub use auth::{AuthContext, Principal, ServiceIdentity, SessionValidator, VerifiedUser, Anonymous, CallSite, ForwardDerivation, ForwardPolicy, ForwardPolicyName, IdentityOnly, MethodPath, MethodPathError, PassThrough, ANONYMOUS_NAME, IDENTITY_ONLY_NAME, PASS_THROUGH_NAME};
pub use test_validator::TestSessionValidator;
pub use context::PlexusContext;
pub use in_process::InProcessTransport;
pub use input::{Delivered, Input, InputTable};
pub use hub_transport::HubTransport;
#[cfg(not(target_arch = "wasm32"))]
pub use remote_child::{Backoff, ChildError, ChildMethods, ChildOptions, ChildSpec, ChildStats, Consented, MountTimings, PeerIdentity, RemoteChild};
#[cfg(all(feature = "clap", not(target_arch = "wasm32")))]
pub use remote_child::ChildArgs;
#[deprecated(note = "Use GuidanceErrorType and GuidanceSuggestion from stream events instead")]
pub use errors::{GuidedError, GuidedErrorData, TryRequest};
pub use forward_registry::{ForwardPolicyRegistry, SameService, SAME_SERVICE_NAME};
pub use grant_gate::{current_reach, with_reach, ForbiddenItem};
pub use view::View;
pub use service_scope::WeakService;
pub use service_root::{RootError, ServiceRoot};
pub use peer::{Contract, FindPeer, Interface, ListPeers, Peer, PeerError, PeerRouter, PeerSlot, PeerTransport, RouterPeer, Stamp};
pub use auth_activation::{
    AuthActivation, AuthBackend, AuthClient, AuthEvent, AuthFailure, AuthSetup, LoginAnswer, LoginFlow, MembershipEntry, MembershipStore,
    Provider, ProviderKind, Requirement, RoleStore, Session, SignupAnswer, StoreError, Waiting, SIGNED_IN_GRANTS,
};
pub use auth_memory::{MemoryAuthBackend, MemoryMemberships, MemoryRoles};
// AUTH-2: the grant model, re-exported so an activation needs only plexus-core.
pub use plexus_auth_core::grants::{
    Ceiling, Gate, Grant, GrantSet, Membership, Memberships, Reach, Refusal, Resolve, RoleOrGrant,
    RoleTable, Roles, ScopeRef, ADMIN, CEILING_KEY,
};
#[deprecated(note = "Middleware removed - guidance provided via PlexusStreamEvent::Guidance")]
pub use middleware::{ActivationRegistry, GuidedErrorMiddleware};
pub use path::Provenance;
#[allow(deprecated)]
pub use plexus::{error_item, Activation, ActivationInfo, AuthzDenyReason, ChildCapabilities, ChildRouter, DynamicHub, PlexusError, TransportErrorKind, plexus_error_to_jsonrpc, route_to_child, PLEXUS_NOTIF_METHOD};
// RETURNS-6: the wire's typed call failure, re-exported so server code (and
// the code `#[activation]` emits) names it through plexus-core.
pub use plexus_client::{DenyReason, ParamProblem, RemoteError};
// RETURNS-8: a method's progress vocabulary, named by the code
// `#[plexus_macros::method]` emits (the default `P` of `Progress<T>` is `Note`).
pub use plexus_client::{Note, Progress};
pub use crate::types::Handle;
pub use schema::{
    AuthPosture, Cardinality, ChildHashes, ChildSummary, DeprecationInfo, MethodExample, MethodRole,
    MethodSchema, ParamSchema, PluginHashes, PluginSchema, RequiredCredential, Schema,
    Need, SchemaParams, SchemaProperty, SchemaResult, SchemaType, ViewKind, JSON_TYPES,
    X_PLEXUS_VALUES,
};
pub use types::{PlexusStreamItem, StreamMetadata};
pub use wire::Shared;
pub use method_enum::MethodEnumSchema;
pub use streaming::{PlexusStream, wrap_stream, error_stream, done_stream, progress_stream};
// RETURNS-8: one wrapper per signature form (`wrap_stream` is the plain-T stream's).
pub use streaming::{wrap_one, wrap_one_result, wrap_result_stream, wrap_progress_stream, wrap_result_progress_stream};
// Note: Method enum is auto-generated by hub_macro and exported from plexus module
pub use dispatch::{HubDispatch, StreamItem, from_dispatch_stream};
pub use crate::request::PlexusRequestField;
pub use hub_context::{HubContext, ParentAware, NoParent};
// NEST-16: a graft that knows its parent.
pub use parent::{NeedsMiss, Notice, Parent, ParentTransport, Upward, UpwardError};
