# Authentication Framework

**Status**: Implemented
**Date**: 2026-04-07
**Related**: plexus-transport authentication-transport.md, plexus-macros authentication-codegen.md

## Overview

Plexus provides a flexible authentication framework that validates user sessions during WebSocket handshake and makes authentication context available to RPC methods. The framework is designed to support multiple authentication backends (JWT, session-based, OAuth) while maintaining a consistent API surface.

## Core Components

### AuthContext

`AuthContext` is a per-connection authentication state that travels with every RPC call on an authenticated WebSocket connection.

```rust
pub struct AuthContext {
    pub user_id: String,
    pub session_id: String,
    pub roles: Vec<String>,
    pub metadata: Value,
}
```

**Design decisions:**
- **Immutable after creation**: AuthContext is created during WebSocket upgrade and cannot be modified
- **Clone-friendly**: Implements `Clone` for efficient passing to activation closures
- **Serializable**: Can be sent across process boundaries or stored for audit logging
- **Metadata flexibility**: Generic `serde_json::Value` allows backend-specific claims (tenant IDs, JWT custom claims)

**Key methods:**
- `is_authenticated()`: Distinguishes real users from `anonymous()` fallback
- `has_role(role)`: Simple RBAC check
- `tenant()`: Multi-tenancy support via `tenant_id` or `realm` metadata
- `get_metadata_string(key)`: Access to backend-specific claims

### SessionValidator Trait

Backends implement `SessionValidator` to validate authentication credentials during the HTTP → WebSocket upgrade.

```rust
#[async_trait]
pub trait SessionValidator: Send + Sync + 'static {
    async fn validate(&self, cookie_value: &str) -> Option<AuthContext>;
}
```

**Design decisions:**
- **Object-safe**: Allows dynamic dispatch via `Arc<dyn SessionValidator>`
- **Async**: Supports I/O-bound validation (DB lookups, Redis checks, JWT verification)
- **Cookie-based**: Receives raw `Cookie` header value during WS upgrade
- **Returns Option**: `None` means "invalid/expired" → connection continues as anonymous

**Thread-safety requirements:**
- Must be `Send + Sync + 'static` for use in async WebSocket handlers
- Typically wrapped in `Arc<dyn SessionValidator>` for sharing across connections
- Should be stateless or use interior mutability (e.g., `RwLock` for caches)

## Authentication Backends

### TestSessionValidator (Development/E2E Testing)

A simple validator for testing without Keycloak or production auth infrastructure.

**Cookie formats:**
1. **Simple**: `session=<user_id>` → Creates authenticated context with default tenant
2. **Advanced**: `test_user=<user_id>|tenant=<tenant>|roles=<role1>,<role2>` → Full control over context

**Example:**
```rust
let validator = Arc::new(TestSessionValidator::new());
server.with_session_validator(validator);
```

**Security warning**: TestSessionValidator accepts any user_id without verification. **Never use in production.** Gate with feature flags (`#[cfg(debug_assertions)]`) or environment variables.

**Use cases:**
- Playwright E2E tests (see FormVeritasV2/uscis-web/tests/auth-flow.spec.ts)
- Local development without Keycloak setup
- Integration tests for RBAC-protected methods

### Keycloak JWT Validator (Production)

FormVeritasV2 implements `KeycloakSessionValidator` for production authentication:
- Validates JWT tokens from `access_token` cookie
- Verifies RSA signature using Keycloak's public key
- Extracts claims: `sub` (user_id), `sid` (session_id), `realm_access.roles`, custom `tenant` claim
- Supports multi-tenancy via `tenant_id` claim

See `FormVeritasV2/src/auth/keycloak.rs` and `docs/authentication.md` for details.

### Custom Backends

Implement `SessionValidator` for other auth mechanisms:

**Database session lookup:**
```rust
struct DbSessionValidator {
    pool: PgPool,
}

#[async_trait]
impl SessionValidator for DbSessionValidator {
    async fn validate(&self, cookie: &str) -> Option<AuthContext> {
        let session_id = parse_session_cookie(cookie)?;
        let row = sqlx::query!("SELECT user_id, roles FROM sessions WHERE id = $1", session_id)
            .fetch_optional(&self.pool).await.ok()??;

        Some(AuthContext::new(
            row.user_id,
            session_id,
            serde_json::from_value(row.roles).ok()?,
            serde_json::json!({}),
        ))
    }
}
```

**OAuth token introspection:**
```rust
struct OAuthValidator {
    introspection_url: String,
    client: reqwest::Client,
}

#[async_trait]
impl SessionValidator for OAuthValidator {
    async fn validate(&self, cookie: &str) -> Option<AuthContext> {
        let token = parse_bearer_token(cookie)?;
        let resp = self.client.post(&self.introspection_url)
            .form(&[("token", token)])
            .send().await.ok()?;

        let claims: IntrospectionResponse = resp.json().await.ok()?;
        if !claims.active {
            return None;
        }

        Some(AuthContext::new(
            claims.sub,
            claims.jti.unwrap_or_default(),
            claims.scope.split(' ').map(String::from).collect(),
            serde_json::to_value(claims).ok()?,
        ))
    }
}
```

## Integration with Activation Layer

RPC methods can declare an `auth: &AuthContext` parameter to receive the connection's authentication state:

```rust
#[hub]
trait MyService {
    async fn protected_method(&self, auth: &AuthContext, data: String) -> Result<String>;
}
```

**Code generation** (plexus-macros):
1. Macro detects `auth: &AuthContext` in method signature
2. Generates activation closure that extracts `auth` from connection context
3. Passes `&auth` to method implementation

**Unauthenticated handling**:
- If connection has no `AuthContext` (no validator configured or validation failed), the activation returns `Unauthenticated` error
- For optional auth, use `Option<&AuthContext>` parameter (currently not implemented, but planned)

See `plexus-macros/docs/architecture/authentication-codegen.md` for code generation details.

## Security Model

### Connection-scoped Authentication

Authentication happens **once per WebSocket connection** during the HTTP upgrade:
1. Client sends HTTP upgrade request with `Cookie` header
2. Transport layer extracts cookie, calls `validator.validate()`
3. If valid, `AuthContext` is attached to connection state
4. Every RPC call on that connection has access to the same `AuthContext`

**Implications:**
- Auth checks are **not per-request** (unlike REST APIs)
- If a user's session is revoked server-side, active WebSocket connections remain authenticated until disconnect
- Token expiration should be handled by reconnection logic (client detects expired token, reconnects)

### Anonymous Connections

If no validator is configured or validation returns `None`, the connection proceeds **without** an AuthContext:
- Methods requiring `auth: &AuthContext` will fail with `Unauthenticated` error
- Methods with `Option<&AuthContext>` (future) can handle anonymous users gracefully

**Rationale**: Allows mixed authenticated/unauthenticated services on the same server. Some methods may be public.

### Tenant Isolation

Multi-tenant systems should:
1. Store `tenant_id` in `AuthContext.metadata` (via JWT claims or DB lookup)
2. Methods extract tenant via `auth.tenant()`
3. All DB queries filter by tenant: `WHERE tenant_id = auth.tenant()`

**Example:**
```rust
async fn get_documents(&self, auth: &AuthContext) -> Result<Vec<Document>> {
    let tenant = auth.tenant().ok_or(Error::MissingTenant)?;
    let docs = sqlx::query_as!(Document, "SELECT * FROM documents WHERE tenant_id = $1", tenant)
        .fetch_all(&self.db).await?;
    Ok(docs)
}
```

### Role-Based Access Control (RBAC)

Methods can check roles using `auth.has_role()`:

```rust
async fn admin_action(&self, auth: &AuthContext) -> Result<()> {
    if !auth.has_role("admin") {
        return Err(Error::Forbidden("Admin role required".into()));
    }
    // ... admin logic
}
```

**Recommendation**: For complex permissions, define a `PermissionChecker` struct that wraps `AuthContext` and provides domain-specific authorization methods.

## Thread Safety

All components are designed for concurrent access:

**AuthContext**:
- Immutable after creation → safe to share via `&AuthContext`
- `Clone` is cheap (String and Vec clones, but typically small)

**SessionValidator**:
- Must be `Send + Sync + 'static`
- Typically shared via `Arc<dyn SessionValidator>` across all connections
- Should be stateless or use interior mutability for caches

**Connection state**:
- Each WebSocket connection has its own `AuthContext` (no sharing)
- Activations receive `&AuthContext` via closure capture (immutable borrow)

## Testing Strategy

### Unit Tests

Test `AuthContext` methods:
- Role checking: `has_role()`
- Metadata access: `tenant()`, `get_metadata_string()`
- Serialization/deserialization (for audit logging)

Test `SessionValidator` implementations:
- Valid cookies → `Some(AuthContext)`
- Invalid/expired cookies → `None`
- Edge cases (malformed cookies, missing claims)

### Integration Tests

Test end-to-end authentication flow (see `plexus-core/tests/auth_integration.rs`):
1. Create mock `Hub` with auth-protected methods
2. Connect with valid/invalid cookies
3. Call authenticated methods → verify success/failure
4. Verify tenant isolation (method only sees its tenant's data)

### E2E Tests

Playwright tests with real browser cookies (see `FormVeritasV2/uscis-web/tests/auth-flow.spec.ts`):
1. Set test cookie: `test_user=alice|tenant=acme|roles=admin`
2. Connect WebSocket client
3. Call RPC methods → verify access control
4. Reconnect with different tenant → verify isolation

## Performance Considerations

### Validation Cost

`SessionValidator::validate()` is called **once per connection**:
- JWT validation: ~100-500µs (RSA signature check + JSON parsing)
- DB session lookup: ~1-10ms (depends on DB latency)
- Redis session check: ~1ms (network + lookup)

**Optimization**: Validation is async and off the critical path (happens during HTTP upgrade). Fast validators improve connection establishment time.

### Token Expiration

For JWT-based auth:
- Validation checks token expiration during handshake
- If token expires mid-connection, the WebSocket remains authenticated
- Client should monitor token expiration and reconnect proactively

**Pattern**: Client-side token refresh + reconnection logic:
```typescript
function monitorTokenExpiration() {
  const expiresIn = getTokenExpiresIn();
  setTimeout(() => {
    refreshToken().then(() => ws.reconnect());
  }, expiresIn - 60000); // Reconnect 1 minute before expiry
}
```

### Memory Overhead

Each connection stores:
- `AuthContext`: ~200-500 bytes (depends on metadata size)
- Validator state: Shared via `Arc`, no per-connection cost

For 10,000 concurrent connections: ~2-5 MB of auth context data.

## Future Enhancements

1. **Optional auth parameters**: `Option<&AuthContext>` for methods that handle both authenticated and anonymous users
2. **Middleware hooks**: Pre-method authorization checks via trait-based middleware
3. **Token refresh protocol**: WebSocket subprotocol for refreshing tokens without reconnection
4. **Audit logging**: Built-in hooks for logging authentication events (login, logout, failed attempts)
5. **Rate limiting**: Per-user or per-tenant rate limits using `AuthContext` as key

## Related Documentation

- **Transport layer**: `plexus-transport/docs/architecture/authentication-transport.md` - Cookie extraction, WebSocket upgrade flow
- **Code generation**: `plexus-macros/docs/architecture/authentication-codegen.md` - How `auth` parameters are injected
- **FormVeritasV2**: `docs/authentication.md` - Keycloak JWT validation implementation
- **E2E tests**: `FormVeritasV2/uscis-web/tests/auth-flow.spec.ts` - Playwright test examples

## Migration Guide

### Adding Auth to Existing Services

1. **Implement SessionValidator**:
   ```rust
   struct MyValidator { /* ... */ }
   #[async_trait]
   impl SessionValidator for MyValidator {
       async fn validate(&self, cookie: &str) -> Option<AuthContext> { /* ... */ }
   }
   ```

2. **Configure server**:
   ```rust
   let validator = Arc::new(MyValidator::new());
   server.with_session_validator(validator);
   ```

3. **Add auth to methods**:
   ```rust
   #[hub]
   trait MyService {
       async fn my_method(&self, auth: &AuthContext, data: String) -> Result<String>;
       //                         ^^^^ Add this parameter
   }
   ```

4. **Update tests**:
   - Use `TestSessionValidator` for E2E tests
   - Add integration tests for auth failure cases

### Gradual Rollout

- Start with `Option<&AuthContext>` (when implemented) for backward compatibility
- Migrate to required `&AuthContext` once all clients are updated
- Use feature flags to enable auth per-method or per-hub
