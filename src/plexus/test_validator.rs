//! Test SessionValidator for E2E testing without Keycloak
//!
//! This validator accepts simple cookie formats for testing:
//! - Simple: "session=<user_id>"
//! - Advanced: "test_user=<user_id>|tenant=<tenant>|roles=<role1>,<role2>"

use super::auth::{AuthContext, SessionValidator};
use async_trait::async_trait;
use serde_json::json;

/// Test session validator that accepts simple cookie formats
///
/// This validator is intended for E2E testing without requiring Keycloak.
/// It accepts two cookie formats:
///
/// 1. Simple format: `session=<user_id>`
///    - Creates AuthContext with user_id and default tenant/roles
///    - Example: `session=alice` → user_id="alice", tenant="test-tenant", roles=["user"]
///
/// 2. Advanced format: `test_user=<user_id>|tenant=<tenant>|roles=<role1>,<role2>`
///    - Allows specifying tenant and roles for testing multi-tenancy and RBAC
///    - Example: `test_user=bob|tenant=acme|roles=admin,user`
///
/// # Security
///
/// **WARNING**: This validator should NEVER be used in production. It accepts
/// any user_id without verification. Use feature flags or environment variables
/// to ensure it's only available in test/dev builds.
pub struct TestSessionValidator;

impl TestSessionValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TestSessionValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionValidator for TestSessionValidator {
    async fn validate(&self, cookie: &str) -> Option<AuthContext> {
        tracing::debug!("TestSessionValidator validating cookie: {}", cookie);

        // Parse simple format: session=<user_id>
        if let Some(user_id) = cookie.strip_prefix("session=") {
            tracing::info!("Test auth: Simple format - user_id={}", user_id);
            return Some(AuthContext {
                user_id: user_id.to_string(),
                session_id: format!("test-session-{}", user_id),
                roles: vec!["user".to_string()],
                metadata: json!({
                    "tenant_id": "test-tenant",
                    "email": format!("{}@test.com", user_id),
                    "test_mode": true
                }),
            });
        }

        // Parse advanced format: test_user=<user_id>|tenant=<tenant>|roles=<role1>,<role2>
        if let Some(params) = cookie.strip_prefix("test_user=") {
            let parts: Vec<&str> = params.split('|').collect();
            if parts.is_empty() {
                tracing::warn!("Test auth: Invalid advanced format - no user_id");
                return None;
            }

            let user_id = parts[0].to_string();
            let mut tenant = "test-tenant".to_string();
            let mut roles = vec!["user".to_string()];

            // Parse additional parameters
            for part in parts.iter().skip(1) {
                if let Some((key, value)) = part.split_once('=') {
                    match key {
                        "tenant" => tenant = value.to_string(),
                        "roles" => roles = value.split(',').map(|s| s.trim().to_string()).collect(),
                        _ => tracing::warn!("Test auth: Unknown parameter: {}", key),
                    }
                }
            }

            tracing::info!(
                "Test auth: Advanced format - user_id={}, tenant={}, roles={:?}",
                user_id, tenant, roles
            );

            return Some(AuthContext {
                user_id: user_id.clone(),
                session_id: format!("test-session-{}", user_id),
                roles,
                metadata: json!({
                    "tenant_id": tenant,
                    "email": format!("{}@test.com", user_id),
                    "test_mode": true
                }),
            });
        }

        // Cookie doesn't match any format
        tracing::debug!("Test auth: Cookie format not recognized");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_format() {
        let validator = TestSessionValidator::new();

        let result = validator.validate("session=alice").await;
        assert!(result.is_some());

        let auth = result.unwrap();
        assert_eq!(auth.user_id, "alice");
        assert_eq!(auth.session_id, "test-session-alice");
        assert!(auth.has_role("user"));
        assert_eq!(auth.tenant(), Some("test-tenant".to_string()));
        assert!(auth.is_authenticated());
    }

    #[tokio::test]
    async fn test_advanced_format_with_tenant() {
        let validator = TestSessionValidator::new();

        let result = validator.validate("test_user=bob|tenant=acme").await;
        assert!(result.is_some());

        let auth = result.unwrap();
        assert_eq!(auth.user_id, "bob");
        assert_eq!(auth.tenant(), Some("acme".to_string()));
        assert!(auth.has_role("user"));
    }

    #[tokio::test]
    async fn test_advanced_format_with_roles() {
        let validator = TestSessionValidator::new();

        let result = validator.validate("test_user=charlie|roles=admin,editor,user").await;
        assert!(result.is_some());

        let auth = result.unwrap();
        assert_eq!(auth.user_id, "charlie");
        assert!(auth.has_role("admin"));
        assert!(auth.has_role("editor"));
        assert!(auth.has_role("user"));
        assert!(!auth.has_role("superuser"));
    }

    #[tokio::test]
    async fn test_advanced_format_complete() {
        let validator = TestSessionValidator::new();

        let result = validator.validate("test_user=dave|tenant=globex|roles=admin,user").await;
        assert!(result.is_some());

        let auth = result.unwrap();
        assert_eq!(auth.user_id, "dave");
        assert_eq!(auth.tenant(), Some("globex".to_string()));
        assert!(auth.has_role("admin"));
        assert!(auth.has_role("user"));
    }

    #[tokio::test]
    async fn test_invalid_format() {
        let validator = TestSessionValidator::new();

        // Invalid/unknown format
        let result = validator.validate("invalid-cookie").await;
        assert!(result.is_none());

        // Empty
        let result = validator.validate("").await;
        assert!(result.is_none());

        // Garbage
        let result = validator.validate("random=garbage").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_metadata_includes_test_mode() {
        let validator = TestSessionValidator::new();

        let result = validator.validate("session=testuser").await;
        let auth = result.unwrap();

        // test_mode is stored as boolean in metadata
        assert_eq!(auth.metadata.get("test_mode").and_then(|v| v.as_bool()), Some(true));
    }
}
