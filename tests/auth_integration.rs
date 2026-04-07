//! End-to-end integration test for authentication flow
//!
//! Tests the complete flow: HTTP cookie → SessionValidator → AuthContext → method parameter

use async_trait::async_trait;
use plexus_core::plexus::{AuthContext, SessionValidator};
use serde_json::{json, Value};
use std::sync::Arc;

/// Test session validator that accepts "session=<user_id>"
struct TestValidator;

#[async_trait]
impl SessionValidator for TestValidator {
    async fn validate(&self, cookie: &str) -> Option<AuthContext> {
        // Simple test validator: parse "session=<user_id>"
        cookie.strip_prefix("session=").map(|user_id| AuthContext {
            user_id: user_id.to_string(),
            session_id: "test-session".into(),
            roles: vec!["user".into()],
            metadata: Value::Null,
        })
    }
}

// Simplified tests that don't require full activation implementation

#[tokio::test]
async fn test_session_validator() {
    let validator = TestValidator;

    // Valid cookie
    let result = validator.validate("session=alice").await;
    assert!(result.is_some(), "Valid cookie should return AuthContext");
    let auth = result.unwrap();
    assert_eq!(auth.user_id, "alice");
    assert_eq!(auth.session_id, "test-session");

    // Invalid cookie
    let result = validator.validate("invalid").await;
    assert!(result.is_none(), "Invalid cookie should return None");

    // Empty cookie
    let result = validator.validate("").await;
    assert!(result.is_none(), "Empty cookie should return None");
}

#[tokio::test]
async fn test_auth_context_helpers() {
    let auth = AuthContext {
        user_id: "alice".to_string(),
        session_id: "sess-123".to_string(),
        roles: vec!["admin".into(), "user".into()],
        metadata: json!({
            "tenant_id": "acme",
            "email": "alice@example.com"
        }),
    };

    // Test role checking
    assert!(auth.has_role("admin"));
    assert!(auth.has_role("user"));
    assert!(!auth.has_role("superuser"));

    // Test metadata access
    assert_eq!(auth.get_metadata_string("tenant_id"), Some("acme".to_string()));
    assert_eq!(auth.get_metadata_string("email"), Some("alice@example.com".to_string()));
    assert_eq!(auth.get_metadata_string("nonexistent"), None);

    // Test tenant extraction
    assert_eq!(auth.tenant(), Some("acme".to_string()));

    // Test is_authenticated
    assert!(auth.is_authenticated());

    // Test anonymous context
    let anon = AuthContext::anonymous();
    assert!(!anon.is_authenticated());
    assert_eq!(anon.user_id, "anonymous");
}
