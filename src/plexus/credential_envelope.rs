//! Dispatch-time credential interception (AUTHZ-CRED-CORE-2).
//!
//! This module contains the plexus-core half of the dispatch-time
//! credential interception described in AUTHZ-CRED-CORE-2. The other half
//! lives in `plexus-auth-core`:
//!
//! - `Credential<T>::Serialize` emits the sentinel `{"$credential": "<id>"}`
//!   inline AND captures the inner value into a thread-local sidecar **when
//!   a `DispatchCaptureGuard` is active** on the current thread.
//! - `DispatchCaptureGuard::install` is the (currently `pub(crate)`)
//!   setter for that thread-local.
//!
//! plexus-core's responsibility is, at every dispatch-time serialization
//! point that produces a wire stream item:
//!
//!   1. Install a fresh dispatch sidecar before serializing.
//!   2. Serialize the body — credentials within emit sentinels inline and
//!      register their values in the sidecar.
//!   3. Drain the sidecar and attach the captured entries to the wire
//!      envelope as a `_credentials` field.
//!   4. Apply cookie projection: for entries whose
//!      `AttachmentSite::Cookie { name }` matches the active transport's
//!      cookie-capable surface, drop the `value` field from the sidecar
//!      entry and record a `Set-Cookie` projection hint that the transport
//!      layer reads.
//!
//! See `plans/AUTHZ/AUTHZ-CRED-CORE-2.md` for the full required-behavior
//! table and `plans/AUTHZ/AUTHZ-CRED-CORE-2-RUN-NOTES.md` for the
//! capture-side blocker.

use std::collections::HashMap;

use plexus_auth_core::{
    AttachmentSite, CapturedCredential, CookieName, CredentialId, CredentialMetadata,
};
use serde::Serialize;
use serde_json::{Map, Value};

/// JSON-side projection of a single sidecar entry as it appears in the
/// `_credentials` map of a wire envelope.
///
/// Field shape mirrors AUTHZ-CRED-S01-output §3: `{ "value": <inner>,
/// "metadata": <CredentialMetadata JSON> }`. When cookie projection has
/// stripped the value, the `value` field is omitted (not `null`). The
/// metadata is always present.
fn captured_to_wire_json(captured: &CapturedCredential, include_value: bool) -> Value {
    let mut obj = Map::new();
    if include_value {
        obj.insert("value".to_string(), captured.value.clone());
    }
    obj.insert(
        "metadata".to_string(),
        serde_json::to_value(&captured.metadata).unwrap_or(Value::Null),
    );
    Value::Object(obj)
}

/// Build the `_credentials` envelope map from a drained sidecar and a set
/// of cookie-capable cookie names that the transport will project.
///
/// Returns `(credentials_map, cookie_hints)` where:
///
///   * `credentials_map` is the JSON value to be written under the
///     `_credentials` envelope key (an object mapping `CredentialId` →
///     `{ value?, metadata }`). Returns `None` when the sidecar is empty
///     so callers can omit the key entirely (wire-format-identical to a
///     non-credential payload).
///   * `cookie_hints` is the list of `(cookie_name, value, metadata)`
///     triples the transport must turn into `Set-Cookie` headers. Empty
///     when no entries qualified.
///
/// "Cookie-capable" is determined by [`CookieProjector`]; see that type
/// for the per-transport policy.
pub(crate) fn build_credentials_envelope(
    captured: HashMap<CredentialId, CapturedCredential>,
    projector: &CookieProjector,
) -> (Option<Value>, Vec<CookieProjectionHint>) {
    if captured.is_empty() {
        return (None, Vec::new());
    }

    // Stable id ordering: we sort by id string so the wire output is
    // deterministic across runs. (The ids themselves are assigned in mint
    // order via plexus-auth-core's atomic counter, so this is also the
    // mint order.)
    let mut entries: Vec<(CredentialId, CapturedCredential)> = captured.into_iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

    let mut wire_map = Map::new();
    let mut hints = Vec::new();

    for (id, cap) in entries {
        let cookie_target: Option<CookieName> = match &cap.metadata.attach_as {
            AttachmentSite::Cookie { name } => Some(name.clone()),
            _ => None,
        };

        let should_project = cookie_target
            .as_ref()
            .is_some_and(|name| projector.projects(name));

        // Cookie projection strips the value from the JSON sidecar entry;
        // metadata stays. Non-cookie attachment sites or
        // non-cookie-capable transports keep the value in the sidecar.
        let include_value = !should_project;
        let wire_entry = captured_to_wire_json(&cap, include_value);

        if should_project {
            // The transport reads the hint and emits the `Set-Cookie`
            // header out-of-band; the JavaScript client sees the JSON
            // envelope with the sentinel + metadata but no `value`.
            hints.push(CookieProjectionHint {
                cookie_name: cookie_target
                    .expect("cookie_target is Some on the should_project branch"),
                cookie_value: cap.value.clone(),
                metadata: cap.metadata.clone(),
            });
        }

        wire_map.insert(id.as_str().to_string(), wire_entry);
    }

    (Some(Value::Object(wire_map)), hints)
}

/// Per-transport policy for which `AttachmentSite::Cookie` credentials
/// should be projected into `Set-Cookie` headers and removed from the
/// JSON sidecar's `value` field.
///
/// HTTP-bearing transports (WS-over-HTTPS upgrade response, MCP-HTTP,
/// REST gateway) own a turn of HTTP that can carry response headers;
/// they should project every cookie-shaped credential.
///
/// Non-HTTP-bearing transports (pure stdio, in-process IPC) have no
/// header surface; they leave the value in the sidecar for the
/// client-side storage in `AUTHZ-CRED-CLI-1` to handle.
///
/// Stored as a small enum (rather than a closure) so it is `Clone` and
/// crosses `Send` boundaries cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieProjector {
    /// Project every cookie-shaped credential. Used by transports that
    /// own an HTTP turn (WS-over-HTTPS, MCP-HTTP, REST gateway).
    All,
    /// Project nothing. Used by transports that have no header surface
    /// (pure stdio, in-process IPC). The cookie value remains in the
    /// JSON sidecar and is handled by the client-side storage layer.
    None,
}

impl CookieProjector {
    /// Whether a credential with `AttachmentSite::Cookie { name }` should
    /// have its value stripped from the sidecar and projected onto a
    /// `Set-Cookie` header.
    pub fn projects(&self, _name: &CookieName) -> bool {
        match self {
            CookieProjector::All => true,
            CookieProjector::None => false,
        }
    }
}

impl Default for CookieProjector {
    /// Default to `None` — pure-stdio is the safer baseline. The
    /// dispatch layer caller chooses `All` when it knows it has an
    /// HTTP-bearing turn.
    fn default() -> Self {
        CookieProjector::None
    }
}

/// Out-of-band projection hint emitted alongside a stream item whose
/// payload contained a cookie-shaped credential. The transport layer
/// reads these hints and turns each one into a `Set-Cookie:
/// <name>=<value>; HttpOnly; Secure; SameSite=None; Path=/;
/// Max-Age=<seconds>` header on the response.
///
/// `Max-Age` is derived from `metadata.expires_at` minus the current
/// time. When `expires_at` is `None` the transport emits no `Max-Age`
/// attribute and the cookie is session-scoped per RFC 6265.
#[derive(Debug, Clone)]
pub struct CookieProjectionHint {
    /// The cookie name from `AttachmentSite::Cookie`.
    pub cookie_name: CookieName,
    /// The raw cookie value. Sensitive — this is the credential.
    pub cookie_value: Value,
    /// The full metadata, in case the transport wants to consult e.g.
    /// `metadata.scheme` or `metadata.expires_at`.
    pub metadata: CredentialMetadata,
}

/// Compute the `Set-Cookie` header string for a single projection hint.
///
/// Format: `<name>=<value>; HttpOnly; Secure; SameSite=None; Path=/[;
/// Max-Age=<seconds>]`.
///
/// The cookie value is serialized as JSON string contents (without
/// surrounding quotes) if the inner JSON is a string; otherwise the
/// JSON-encoded form is used as a fallback (e.g. for AWS-STS-shaped
/// composite values). RFC 6265 §4.1.1 cookie-value grammar limits the
/// character set — values that contain RFC-forbidden characters are
/// percent-encoded by upstream serializers and we do not encode here.
pub fn format_set_cookie_header(hint: &CookieProjectionHint) -> String {
    let value_str = match &hint.cookie_value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };

    let mut out = format!(
        "{}={}; HttpOnly; Secure; SameSite=None; Path=/",
        hint.cookie_name.as_str(),
        value_str
    );

    if let Some(expires_at) = hint.metadata.expires_at {
        let now = chrono::Utc::now();
        let delta = expires_at.signed_duration_since(now);
        let max_age = delta.num_seconds().max(0);
        out.push_str(&format!("; Max-Age={max_age}"));
    }

    out
}

/// Compose a Data stream item's content + captured credentials into the
/// final wire envelope's JSON form.
///
/// This function is the single source of truth for how a stream item's
/// payload + sidecar become a wire envelope:
///
///   1. Serialize the payload (the caller does this in the credential
///      capture scope; see `wrap_stream`).
///   2. Drain the captured sidecar (the caller does this).
///   3. Pass both into this function plus the cookie projector.
///   4. The result is a `Map<String, Value>` that goes verbatim into the
///      `PlexusStreamItem::Data.content` field of the wire item.
///
/// Returns the assembled content map AND any cookie projection hints.
/// The hints flow to the transport via `PlexusStreamItem::Data.cookie_hints`.
///
/// **Wire compatibility:** When `captured` is empty, the returned content
/// is `serialized_payload` unchanged — same map, no `_credentials` key.
/// This means a method that returns a payload with zero `Credential<T>`
/// fields produces a wire-format-identical item to today (additive
/// only).
pub(crate) fn assemble_envelope_content(
    serialized_payload: Value,
    captured: HashMap<CredentialId, CapturedCredential>,
    projector: &CookieProjector,
) -> (Value, Vec<CookieProjectionHint>) {
    let (credentials_map, hints) = build_credentials_envelope(captured, projector);

    let Some(credentials_map) = credentials_map else {
        return (serialized_payload, hints);
    };

    // The payload MAY be any JSON value. The `_credentials` envelope key
    // can only be attached when the payload is an object (the spike's
    // §3 mandates a top-level field). For non-object payloads we emit
    // an object envelope of the form `{"value": <payload>, "_credentials":
    // {...}}` so the wire shape remains deterministic.
    //
    // In practice, every credential-bearing payload IS an object
    // (Credential<T> is a struct field), so the non-object branch is
    // defensive.
    match serialized_payload {
        Value::Object(mut map) => {
            // Per AUTHZ-CRED-CORE-2 §"Wire envelope shape": the
            // `_credentials` key is reserved by the framework. The
            // schema-build validator emits a warning at build time if
            // a backend defines a top-level field named `_credentials`;
            // here at dispatch we just shadow it (the framework's
            // projection wins). The schema-build warning is the user-
            // facing diagnostic.
            map.insert("_credentials".to_string(), credentials_map);
            (Value::Object(map), hints)
        }
        other => {
            let mut wrapper = Map::new();
            wrapper.insert("value".to_string(), other);
            wrapper.insert("_credentials".to_string(), credentials_map);
            (Value::Object(wrapper), hints)
        }
    }
}

/// Serialize `payload` and capture any credentials inside it.
///
/// This is the dispatch-time entry point that `wrap_stream` calls for
/// every stream item. Today (per AUTHZ-CRED-CORE-2-RUN-NOTES.md) it
/// performs the serialization without an installed
/// `DispatchCaptureGuard` because the guard's constructor is currently
/// `pub(crate)` to `plexus-auth-core` and unreachable from this crate.
/// The wire-envelope assembly path that consumes the returned `captured`
/// map is fully implemented; once the plexus-auth-core public exposure
/// lands the body of this function changes to install the guard and
/// drain it.
///
/// The function takes a closure rather than a value so the future
/// guard-wrapped form is a one-line internal change.
pub(crate) fn serialize_with_credential_capture<T: Serialize>(
    payload: &T,
) -> (Value, HashMap<CredentialId, CapturedCredential>) {
    // TODO(AUTHZ-CRED-CORE-2-RUN-NOTES.md §Blocker): once
    // plexus-auth-core exposes a public `run_with_credential_capture`
    // helper (or a `pub` `DispatchCaptureGuard::install` constructor),
    // wrap this serialization in the guard so the sidecar is populated.
    // Today the serialization runs with no toggle active, so credentials
    // serialize as sentinel-only and the captured map is empty.
    let value = serde_json::to_value(payload).unwrap_or(Value::Null);
    (value, HashMap::new())
}

/// Schema-build warning emitted when a method's return-type schema
/// declares a top-level field named `_credentials`. The framework
/// reserves that name for the credential sidecar (AUTHZ-CRED-CORE-2
/// §"Wire envelope shape"). When a backend has such a field, the
/// framework's projection shadows it.
///
/// Implemented as a separate function so the schema-build path can
/// route the diagnostic through `tracing::warn!` without coupling to
/// the schema module's structure.
pub fn warn_on_credentials_field_collision(plugin: &str, method: &str) {
    tracing::warn!(
        target: "plexus_core::credentials",
        plugin = plugin,
        method = method,
        "method's return-type schema declares a top-level `_credentials` \
         field; this name is reserved by the framework's credential \
         sidecar (AUTHZ-CRED-CORE-2) and will be shadowed at dispatch \
         time. Rename the domain field to avoid the collision."
    );
}

/// Inspect a serialized JSON value's top-level keys and emit a
/// schema-build warning if any of them are `_credentials`. Used by the
/// schema constructors (`PluginSchema::leaf`, `::hub`) to surface
/// AUTHZ-CRED-CORE-2 acceptance criterion #8 at build time.
///
/// Returns `true` if a collision was detected (so callers can chain
/// this into a counter or test assertion). The warning is emitted as a
/// side effect either way.
pub fn check_returns_schema_for_credentials_collision(
    plugin: &str,
    method: &str,
    returns_schema: &Value,
) -> bool {
    // The returns schema is a JSON Schema; the "properties" key holds the
    // top-level field map for an object schema. Anything else (a scalar
    // type schema, a `oneOf`, a `$ref`) cannot collide with `_credentials`
    // by construction — there is no top-level field to collide.
    let Some(properties) = returns_schema.get("properties") else {
        return false;
    };
    let Some(props_obj) = properties.as_object() else {
        return false;
    };
    if props_obj.contains_key("_credentials") {
        warn_on_credentials_field_collision(plugin, method);
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Wire-shape unit tests.
//
// These tests cover the envelope-assembly half of the ticket. They use
// directly-constructed `CapturedCredential` values (which is OK — the
// type is `pub` and the field shape is `pub`) to exercise the wire
// envelope path independently of whether the cross-crate capture
// blocker is resolved.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use plexus_auth_core::{
        AttachmentSite, CookieName, CredentialIssuer, CredentialKind, CredentialMetadata,
        CredentialScheme, HeaderName, MethodPath, Origin, Scope,
    };

    fn sample_issuer() -> CredentialIssuer {
        CredentialIssuer::new(
            Origin::new("ws://localhost:4444"),
            MethodPath::try_new("auth.login").unwrap(),
        )
    }

    fn header_metadata() -> CredentialMetadata {
        CredentialMetadata::new(
            CredentialKind::Bearer,
            AttachmentSite::Header {
                name: HeaderName::try_new("authorization").unwrap(),
            },
            Some(CredentialScheme::new("Bearer ")),
            vec![Scope::new("cone.send")],
            None,
            None,
            None,
            sample_issuer(),
        )
    }

    fn cookie_metadata() -> CredentialMetadata {
        CredentialMetadata::new(
            CredentialKind::Cookie,
            AttachmentSite::Cookie {
                name: CookieName::try_new("plexus_session").unwrap(),
            },
            None,
            vec![],
            Some(Utc::now() + Duration::seconds(3600)),
            None,
            None,
            sample_issuer(),
        )
    }

    fn capture(id: &str, value: Value, metadata: CredentialMetadata) -> (CredentialId, CapturedCredential) {
        (
            CredentialId::new(id),
            CapturedCredential { value, metadata },
        )
    }

    #[test]
    fn ac3_zero_credentials_produces_no_envelope_field() {
        // Acceptance criterion 3: a payload with zero Credential<T>
        // fields produces a wire stream item with NO `_credentials` key.
        let payload = json!({ "user": "alice", "ok": true });
        let (content, hints) = assemble_envelope_content(
            payload.clone(),
            HashMap::new(),
            &CookieProjector::All,
        );
        assert_eq!(content, payload, "wire payload unchanged when no credentials");
        assert!(hints.is_empty());
        // And the assembled value has no _credentials key.
        let obj = content.as_object().unwrap();
        assert!(!obj.contains_key("_credentials"));
    }

    #[test]
    fn ac1_single_credential_produces_envelope_with_value_and_metadata() {
        // Acceptance criterion 1: a payload containing one Credential<T>
        // field produces a wire item with the sentinel in the body and a
        // top-level `_credentials` map containing metadata + value for
        // that id.
        let payload = json!({
            "user_id": "alice",
            "session": { "$credential": "cred_0" }
        });
        let mut captured = HashMap::new();
        let (id, cap) = capture(
            "cred_0",
            Value::String("jwt-bytes".into()),
            header_metadata(),
        );
        captured.insert(id, cap);

        let (content, hints) =
            assemble_envelope_content(payload, captured, &CookieProjector::All);
        let obj = content.as_object().expect("content is object");

        // Body sentinel unchanged.
        assert_eq!(
            obj["session"],
            json!({ "$credential": "cred_0" })
        );
        // The _credentials sidecar carries the captured value + metadata.
        let creds = obj.get("_credentials").expect("sidecar present");
        let entry = creds.get("cred_0").expect("cred_0 entry");
        assert_eq!(entry["value"], Value::String("jwt-bytes".into()));
        // Metadata is present and serializable.
        assert!(entry.get("metadata").is_some());
        // Header-attached, not cookie — no projection hint.
        assert!(hints.is_empty());
    }

    #[test]
    fn ac2_multi_credential_produces_one_envelope_with_stable_keys() {
        // Acceptance criterion 2: multiple Credential<T> fields →
        // single sidecar with one entry per credential, identifiers
        // assigned in stable order.
        let payload = json!({
            "access":  { "$credential": "cred_0" },
            "refresh": { "$credential": "cred_1" }
        });
        let mut captured = HashMap::new();
        let (id0, c0) = capture(
            "cred_0",
            Value::String("access-jwt".into()),
            header_metadata(),
        );
        let (id1, c1) = capture(
            "cred_1",
            Value::String("refresh-jwt".into()),
            header_metadata(),
        );
        captured.insert(id0, c0);
        captured.insert(id1, c1);

        let (content, _) =
            assemble_envelope_content(payload, captured, &CookieProjector::All);
        let creds = content.get("_credentials").expect("sidecar");
        assert_eq!(creds.as_object().unwrap().len(), 2);
        // Stable iteration order: keys are sorted ascending → cred_0 < cred_1.
        let keys: Vec<&String> = creds.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["cred_0", "cred_1"]);
        // Each entry has its own value.
        assert_eq!(creds["cred_0"]["value"], Value::String("access-jwt".into()));
        assert_eq!(creds["cred_1"]["value"], Value::String("refresh-jwt".into()));
    }

    #[test]
    fn ac4_cookie_credential_over_http_transport_strips_value_and_emits_hint() {
        // Acceptance criterion 4: AttachmentSite::Cookie over an
        // HTTP-bearing transport → sidecar has no `value`, hints carry
        // the value + cookie name, metadata stays in the sidecar.
        let payload = json!({
            "user": "alice",
            "session": { "$credential": "cred_0" }
        });
        let mut captured = HashMap::new();
        let (id, cap) = capture(
            "cred_0",
            Value::String("opaque-session-id".into()),
            cookie_metadata(),
        );
        captured.insert(id, cap);

        let (content, hints) =
            assemble_envelope_content(payload, captured, &CookieProjector::All);

        // The sidecar entry has metadata but NO value.
        let entry = content.get("_credentials").and_then(|c| c.get("cred_0")).unwrap();
        assert!(entry.get("value").is_none(), "value must be stripped");
        assert!(entry.get("metadata").is_some(), "metadata must remain");

        // Exactly one cookie projection hint, carrying the stripped value.
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].cookie_name.as_str(), "plexus_session");
        assert_eq!(hints[0].cookie_value, Value::String("opaque-session-id".into()));
    }

    #[test]
    fn ac5_cookie_credential_over_stdio_transport_keeps_value_no_hint() {
        // Acceptance criterion 5: same Cookie-attach credential over a
        // non-HTTP-bearing transport → value stays in the sidecar; no
        // cookie hint emitted.
        let payload = json!({
            "user": "alice",
            "session": { "$credential": "cred_0" }
        });
        let mut captured = HashMap::new();
        let (id, cap) = capture(
            "cred_0",
            Value::String("opaque-session-id".into()),
            cookie_metadata(),
        );
        captured.insert(id, cap);

        let (content, hints) =
            assemble_envelope_content(payload, captured, &CookieProjector::None);

        let entry = content.get("_credentials").and_then(|c| c.get("cred_0")).unwrap();
        assert_eq!(entry["value"], Value::String("opaque-session-id".into()));
        assert!(hints.is_empty());
    }

    #[test]
    fn header_kind_attachment_no_projection_either_way() {
        // AttachmentSite::Header → no projection even on an HTTP-bearing
        // transport. (The header attach is the client's job at next-call
        // time, not the server's response-side projection.)
        let payload = json!({
            "user": "alice",
            "auth": { "$credential": "cred_0" }
        });
        let mut captured = HashMap::new();
        let (id, cap) = capture(
            "cred_0",
            Value::String("jwt".into()),
            header_metadata(),
        );
        captured.insert(id, cap);

        let (content, hints) =
            assemble_envelope_content(payload, captured, &CookieProjector::All);

        let entry = content.get("_credentials").and_then(|c| c.get("cred_0")).unwrap();
        assert_eq!(entry["value"], Value::String("jwt".into()));
        assert!(hints.is_empty());
    }

    #[test]
    fn set_cookie_header_format_has_required_attributes() {
        // The format string matches the ticket's exact spec:
        //   Set-Cookie: <name>=<value>; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=<seconds>
        let hint = CookieProjectionHint {
            cookie_name: CookieName::try_new("plexus_session").unwrap(),
            cookie_value: Value::String("abc123".into()),
            metadata: cookie_metadata(),
        };
        let out = format_set_cookie_header(&hint);
        assert!(out.starts_with("plexus_session=abc123"));
        assert!(out.contains("; HttpOnly"));
        assert!(out.contains("; Secure"));
        assert!(out.contains("; SameSite=None"));
        assert!(out.contains("; Path=/"));
        assert!(out.contains("; Max-Age="));
    }

    #[test]
    fn set_cookie_header_omits_max_age_when_no_expiry() {
        let mut meta = cookie_metadata();
        meta.expires_at = None;
        let hint = CookieProjectionHint {
            cookie_name: CookieName::try_new("plexus_session").unwrap(),
            cookie_value: Value::String("abc".into()),
            metadata: meta,
        };
        let out = format_set_cookie_header(&hint);
        assert!(!out.contains("Max-Age"));
    }

    #[test]
    fn ac8_schema_build_warning_fires_on_credentials_field_collision() {
        // Acceptance criterion 8: a return-type schema that declares a
        // top-level field named `_credentials` triggers a schema-build
        // warning. We assert the predicate that the schema constructors
        // call; the tracing-side emission is observable via tracing
        // subscribers in higher-level tests.
        let returns_with_collision = json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "string" },
                "_credentials": { "type": "object" }
            }
        });
        let collided = check_returns_schema_for_credentials_collision(
            "auth",
            "login",
            &returns_with_collision,
        );
        assert!(collided, "collision must be detected");

        let returns_without = json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "string" },
                "session": { "$ref": "#/$defs/Credential" }
            }
        });
        let not_collided = check_returns_schema_for_credentials_collision(
            "auth",
            "login",
            &returns_without,
        );
        assert!(!not_collided, "non-collision must not be detected");
    }

    #[test]
    fn cookie_projector_default_is_safe_none() {
        // Documenting the default: pure-stdio is the safer baseline; the
        // dispatch caller must explicitly opt in to All when it has an
        // HTTP-bearing turn.
        assert_eq!(CookieProjector::default(), CookieProjector::None);
        let name = CookieName::try_new("plexus_session").unwrap();
        assert!(!CookieProjector::None.projects(&name));
        assert!(CookieProjector::All.projects(&name));
    }

    #[test]
    fn non_object_payload_gets_wrapped_when_credentials_present() {
        // Defensive: a payload that's a scalar (rare but legal) — when
        // there are credentials, the envelope wraps it in an object so
        // the `_credentials` field has a place to live.
        let payload = Value::String("scalar-payload".into());
        let mut captured = HashMap::new();
        let (id, cap) = capture("cred_0", Value::String("v".into()), header_metadata());
        captured.insert(id, cap);

        let (content, _) =
            assemble_envelope_content(payload, captured, &CookieProjector::All);
        let obj = content.as_object().expect("wrapped into object");
        assert_eq!(obj["value"], Value::String("scalar-payload".into()));
        assert!(obj.contains_key("_credentials"));
    }

    #[test]
    fn non_object_payload_unchanged_when_no_credentials() {
        // Scalar payload + empty sidecar → unchanged, no wrapper.
        let payload = Value::String("scalar-payload".into());
        let (content, hints) = assemble_envelope_content(
            payload.clone(),
            HashMap::new(),
            &CookieProjector::All,
        );
        assert_eq!(content, payload);
        assert!(hints.is_empty());
    }

    #[test]
    fn serialize_with_credential_capture_returns_empty_until_blocker_resolved() {
        // Documents the current state described in
        // AUTHZ-CRED-CORE-2-RUN-NOTES.md §Blocker: without a public
        // entry point on plexus-auth-core to install a
        // DispatchCaptureGuard, the captured map is always empty.
        // The wire-envelope code is exercised independently by the
        // tests above using directly-constructed CapturedCredential
        // values.
        #[derive(Serialize)]
        struct Simple {
            x: u32,
        }
        let s = Simple { x: 42 };
        let (value, captured) = serialize_with_credential_capture(&s);
        assert_eq!(value, json!({ "x": 42 }));
        assert!(
            captured.is_empty(),
            "captured map is empty until plexus-auth-core exposes the guard publicly"
        );
    }
}
