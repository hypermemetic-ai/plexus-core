//! Raw HTTP request context and extraction trait for Plexus request extraction.
//!
//! This module defines:
//! - `RawRequestContext` — the raw HTTP view passed through the dispatch chain
//! - `PlexusRequest` — trait for typed field extraction from `RawRequestContext`
//!
//! Defined here (in plexus-core) so that:
//! - The `Activation` trait can reference `RawRequestContext` without a circular dep
//! - The generated dispatch code can call `PlexusRequest::extract` via `#crate_path::request`

use std::net::SocketAddr;
use crate::plexus::{AuthContext, PlexusError};

/// The raw HTTP context available when extracting a typed request struct.
///
/// This is populated from the HTTP upgrade/connection phase and made available
/// to every `#[derive(PlexusRequest)]` extraction.
pub struct RawRequestContext {
    /// HTTP headers from the request.
    pub headers: http::HeaderMap,

    /// The request URI (used for query-parameter extraction).
    pub uri: http::Uri,

    /// Authenticated user context, if authentication succeeded.
    pub auth: Option<AuthContext>,

    /// Remote peer socket address, if available.
    pub peer: Option<SocketAddr>,
}

/// Trait implemented by `#[derive(PlexusRequest)]` structs.
///
/// A `PlexusRequest` struct is a typed view of an inbound HTTP request, where
/// each field is extracted from a specific part of the raw context (cookie,
/// header, query string, peer address, or auth context).
///
/// # Deriving
///
/// Use the `PlexusRequest` derive macro from `plexus_macros`:
///
/// ```ignore
/// use plexus_macros::PlexusRequest;
///
/// #[derive(PlexusRequest)]
/// struct MyRequest {
///     #[from_cookie("access_token")]
///     auth_token: String,
///
///     #[from_header("origin")]
///     origin: Option<String>,
///
///     #[from_peer]
///     peer_addr: Option<std::net::SocketAddr>,
/// }
/// ```
pub trait PlexusRequest: Sized {
    /// Extract a typed request from the raw HTTP context.
    fn extract(ctx: &RawRequestContext) -> Result<Self, PlexusError>;

    /// Return the JSON Schema for this request type as a `serde_json::Value`.
    ///
    /// The schema includes `x-plexus-source` metadata on each field describing
    /// where the field value is extracted from (cookie, header, peer, etc.).
    ///
    /// The default implementation returns `None`; the `#[derive(PlexusRequest)]`
    /// macro generates a concrete implementation with the full schema.
    fn request_schema() -> Option<serde_json::Value> {
        None
    }
}

/// Trait for newtype field types that carry their own extraction and validation logic.
///
/// Implement this trait on a newtype wrapper to enable `#[derive(PlexusRequest)]`
/// to extract it without an explicit source annotation. The macro generates:
///
/// ```ignore
/// let field_name = FieldType::extract_from_raw(ctx)?;
/// ```
///
/// for fields of any type that implements `PlexusRequestField`.
pub trait PlexusRequestField: Sized {
    /// Extract and validate `Self` from the raw HTTP request context.
    ///
    /// Return `Ok(Self)` on success, or a `PlexusError` (typically
    /// `PlexusError::Unauthenticated`) on validation failure.
    fn extract_from_raw(ctx: &RawRequestContext) -> Result<Self, PlexusError>;
}

/// Parse a named cookie from a raw `Cookie` header value.
///
/// The cookie header value is like `"session=abc; access_token=tok123; other=xyz"`.
/// Returns the value for the first matching key, or `None` if not found.
///
/// This is exported so that the `#[derive(PlexusRequest)]` generated code can call it.
pub fn parse_cookie<'a>(cookie_str: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}
