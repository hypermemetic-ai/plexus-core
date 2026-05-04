//! Authentication primitives — relocated to `plexus-auth-core`.
//!
//! Per AUTHZ-CORE-CRATE-1, the canonical home for the Plexus auth sealed
//! types is now the `plexus-auth-core` crate. plexus-core re-exports them
//! here so existing call sites keep compiling during the deprecation
//! window. New code should import directly from `plexus_auth_core`.
//!
//! See `plans/AUTHZ/AUTHZ-CORE-CRATE-1.md` and AUTHZ-0 for rationale.

pub use plexus_auth_core::{AuthContext, Principal, ServiceIdentity, SessionValidator, VerifiedUser};

// Note on `#[deprecated]`:
//
// We intentionally do NOT mark the `pub use` re-exports above with
// `#[deprecated(...)]`. Doing so would emit a deprecation warning at every
// call site across plexus-trak, plexus-transport, plexus-substrate, and
// roughly two dozen other places — many of which carry `warnings = "deny"`
// at the crate level (e.g. plexus-substrate/Cargo.toml). The sudden flip
// would block builds everywhere. The deprecation hint lives here as a doc
// comment on each module-level item; an `#[deprecated]` attribute will be
// added in the follow-up ticket that also migrates the call sites in
// lockstep. (See plans/AUTHZ/AUTHZ-CORE-CRATE-1-RUN-NOTES.md for the
// detailed reasoning.)

/// Re-export of `plexus_auth_core::AuthContext`.
///
/// **Deprecated:** import directly from `plexus_auth_core::AuthContext`.
/// This re-export exists for backward compatibility during the migration
/// window and will be removed in a future major release.
#[doc(hidden)]
pub fn _deprecation_hint_for_auth_context() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the re-exported AuthContext keeps the public API
    /// callers depend on (constructor, anonymous, role check, tenant).
    /// This is the migration's no-functional-change canary.
    #[test]
    fn reexport_preserves_auth_context_api() {
        let ctx = AuthContext::new(
            "user-1".into(),
            "sess-1".into(),
            vec!["admin".into()],
            serde_json::json!({"tenant_id": "acme"}),
        );

        assert_eq!(ctx.user_id, "user-1");
        assert_eq!(ctx.session_id, "sess-1");
        assert!(ctx.has_role("admin"));
        assert!(!ctx.has_role("guest"));
        assert_eq!(ctx.tenant(), Some("acme".into()));
        assert!(ctx.is_authenticated());

        let anon = AuthContext::anonymous();
        assert!(!anon.is_authenticated());
        assert_eq!(anon.user_id, "anonymous");
    }

    /// SessionValidator trait is callable through the re-export.
    #[tokio::test]
    async fn reexport_preserves_session_validator() {
        struct Stub;
        #[async_trait::async_trait]
        impl SessionValidator for Stub {
            async fn validate(&self, cookie: &str) -> Option<AuthContext> {
                if cookie == "ok" {
                    Some(AuthContext::new(
                        "u".into(),
                        "s".into(),
                        vec![],
                        serde_json::Value::Null,
                    ))
                } else {
                    None
                }
            }
        }

        let v = Stub;
        assert!(v.validate("ok").await.is_some());
        assert!(v.validate("nope").await.is_none());
    }
}
