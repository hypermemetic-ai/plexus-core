//! Authentication context for Plexus RPC

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Per-connection authentication context, populated during WS upgrade.
///
/// This context is extracted from HTTP cookies (or other auth mechanisms) during
/// the WebSocket handshake and attached to the connection. Every RPC call on that
/// connection has access to this context.
///
/// # Multi-tenancy with Keycloak
///
/// When using Keycloak for multi-tenancy, the `AuthContext` typically contains:
/// - `user_id`: Keycloak user ID (sub claim from JWT)
/// - `session_id`: Keycloak session ID
/// - `roles`: User roles within the tenant/realm
/// - `metadata`: Additional JWT claims (realm, tenant ID, custom attributes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// User identifier (e.g., Keycloak sub claim, user UUID)
    pub user_id: String,

    /// Session identifier (e.g., Keycloak session ID)
    pub session_id: String,

    /// User roles (e.g., ["user", "admin"], Keycloak realm roles)
    pub roles: Vec<String>,

    /// Additional metadata (e.g., JWT claims, tenant/realm info, custom attributes)
    /// For Keycloak multi-tenancy, this typically includes:
    /// - `realm`: Keycloak realm name
    /// - `tenant_id`: Organization/tenant identifier
    /// - Any custom claims from the JWT token
    pub metadata: Value,
}

impl AuthContext {
    /// Create a new AuthContext
    pub fn new(user_id: String, session_id: String, roles: Vec<String>, metadata: Value) -> Self {
        Self {
            user_id,
            session_id,
            roles,
            metadata,
        }
    }

    /// Create an anonymous/unauthenticated context
    ///
    /// This can be used as a fallback when methods accept `Option<&AuthContext>`
    /// and no authentication was provided.
    pub fn anonymous() -> Self {
        Self {
            user_id: "anonymous".to_string(),
            session_id: String::new(),
            roles: vec![],
            metadata: Value::Null,
        }
    }

    /// Check if this context represents an authenticated user
    pub fn is_authenticated(&self) -> bool {
        self.user_id != "anonymous" && !self.session_id.is_empty()
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Get a metadata field as a string
    pub fn get_metadata_string(&self, key: &str) -> Option<String> {
        self.metadata.get(key).and_then(|v| v.as_str()).map(String::from)
    }

    /// Get the tenant/realm from metadata (Keycloak multi-tenancy)
    pub fn tenant(&self) -> Option<String> {
        self.get_metadata_string("tenant_id")
            .or_else(|| self.get_metadata_string("realm"))
    }
}

/// Backends implement this trait to validate cookies/tokens during WS upgrade.
///
/// This trait is designed to be object-safe and work with async/await, allowing
/// backends to use any authentication mechanism:
/// - JWT validation (e.g., Keycloak tokens)
/// - Database session lookups
/// - Redis session stores
/// - OAuth token introspection
///
/// # Example: Keycloak JWT Validation
///
/// ```rust,ignore
/// use plexus_core::plexus::{AuthContext, SessionValidator};
/// use async_trait::async_trait;
///
/// struct KeycloakValidator {
///     jwks_client: JwksClient,
///     realm: String,
/// }
///
/// #[async_trait]
/// impl SessionValidator for KeycloakValidator {
///     async fn validate(&self, cookie_value: &str) -> Option<AuthContext> {
///         // Parse JWT from cookie
///         let token = parse_jwt_from_cookie(cookie_value)?;
///
///         // Validate signature and claims
///         let claims = self.jwks_client.verify(&token).await.ok()?;
///
///         // Extract user info and tenant from JWT claims
///         Some(AuthContext {
///             user_id: claims.sub,
///             session_id: claims.sid.unwrap_or_default(),
///             roles: claims.realm_access.roles,
///             metadata: serde_json::json!({
///                 "realm": self.realm,
///                 "tenant_id": claims.get("tenant_id"),
///                 "email": claims.email,
///             }),
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait SessionValidator: Send + Sync + 'static {
    /// Validate a cookie header value and return an AuthContext if valid.
    ///
    /// # Arguments
    ///
    /// * `cookie_value` - The raw Cookie header value (e.g., "session=abc123; path=/")
    ///
    /// # Returns
    ///
    /// - `Some(AuthContext)` if the cookie is valid and represents an authenticated session
    /// - `None` if the cookie is invalid, expired, or represents an anonymous session
    ///
    /// # Implementation Notes
    ///
    /// - This is called during the WebSocket handshake (HTTP upgrade)
    /// - Validation should be fast to avoid blocking the connection
    /// - For JWT: verify signature, check expiration, extract claims
    /// - For session-based auth: lookup session in DB/Redis
    /// - Return None for invalid/expired credentials (connection proceeds as anonymous)
    async fn validate(&self, cookie_value: &str) -> Option<AuthContext>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_creation() {
        let ctx = AuthContext::new(
            "user-123".to_string(),
            "sess-456".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"tenant_id": "acme"}),
        );

        assert_eq!(ctx.user_id, "user-123");
        assert_eq!(ctx.session_id, "sess-456");
        assert!(ctx.has_role("admin"));
        assert!(!ctx.has_role("user"));
        assert_eq!(ctx.tenant(), Some("acme".to_string()));
        assert!(ctx.is_authenticated());
    }

    #[test]
    fn test_auth_context_clone() {
        let ctx = AuthContext::new(
            "alice".to_string(),
            "sess-1".to_string(),
            vec!["admin".to_string()],
            serde_json::json!({"org": "acme"}),
        );

        let cloned = ctx.clone();
        assert_eq!(ctx.user_id, cloned.user_id);
        assert_eq!(ctx.session_id, cloned.session_id);
        assert_eq!(ctx.roles, cloned.roles);
    }

    #[test]
    fn test_anonymous_context() {
        let ctx = AuthContext::anonymous();
        assert_eq!(ctx.user_id, "anonymous");
        assert!(!ctx.is_authenticated());
        assert!(ctx.roles.is_empty());
    }

    #[test]
    fn test_role_checking() {
        let ctx = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec!["user".to_string(), "editor".to_string()],
            Value::Null,
        );

        assert!(ctx.has_role("user"));
        assert!(ctx.has_role("editor"));
        assert!(!ctx.has_role("admin"));
    }

    #[test]
    fn test_metadata_access() {
        let ctx = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({
                "tenant_id": "org-123",
                "realm": "production",
                "email": "user@example.com"
            }),
        );

        assert_eq!(ctx.get_metadata_string("tenant_id"), Some("org-123".to_string()));
        assert_eq!(ctx.get_metadata_string("realm"), Some("production".to_string()));
        assert_eq!(ctx.get_metadata_string("email"), Some("user@example.com".to_string()));
        assert_eq!(ctx.get_metadata_string("nonexistent"), None);
    }

    #[test]
    fn test_tenant_from_metadata() {
        // tenant_id takes precedence
        let ctx1 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"tenant_id": "org-123", "realm": "prod"}),
        );
        assert_eq!(ctx1.tenant(), Some("org-123".to_string()));

        // Falls back to realm if no tenant_id
        let ctx2 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            serde_json::json!({"realm": "prod"}),
        );
        assert_eq!(ctx2.tenant(), Some("prod".to_string()));

        // None if neither present
        let ctx3 = AuthContext::new(
            "user-1".to_string(),
            "sess-1".to_string(),
            vec![],
            Value::Null,
        );
        assert_eq!(ctx3.tenant(), None);
    }
}
