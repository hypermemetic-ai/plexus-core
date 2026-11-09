//! DYNAUTH-8 (TM-2): a log line never carries a credential.
//!
//! One redactor for every frame-level log: a key that names a credential
//! ([`CREDENTIAL_KEYS`], matched without regard to case, `-` read as `_`)
//! keeps its name and loses its value, which becomes [`REDACTED`]. Two
//! forms:
//!
//! - [`redact_value`] walks a JSON value: every such key's value, whatever
//!   it is (a string, an object, an array), is replaced.
//! - [`redact_str`] reads a line of text — a JSON frame, a frame inside a
//!   log message (`Received request: {…}`), a `Debug` of headers
//!   (`authorization: "Bearer …"`), a query string (`code=…&state=…`) —
//!   and replaces the value after each such key's `:` or `=`: a quoted
//!   string, a bracketed or parenthesized group, or a bare word (`Bearer`
//!   and `Basic` take the word after them too).
//!
//! A JSON-RPC error's `code` is a number and stays one: a number, `true`,
//! `false` and `null` are kept after `code`, and only there.
//!
//! plexus-auth-core's `SensitiveField` registry (AUTHZ-PRIVACY-2) is empty
//! today, so the list here is the one source; when the registry fills, its
//! names join it.

use serde_json::Value;

/// What a credential's value becomes in a log.
pub const REDACTED: &str = "…";

/// The keys whose values never reach a log (DYNAUTH-8: `credential`,
/// `authorization`, `token`, `refresh_token`, `client_secret`, `code`; and
/// the ones a provider or a header spells otherwise).
pub const CREDENTIAL_KEYS: &[&str] = &[
    "credential",
    "credentials",
    "authorization",
    "proxy_authorization",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "code",
    "code_verifier",
    "password",
    "secret",
    "api_key",
    "x_api_key",
    "cookie",
    "set_cookie",
];

/// NEST-21: keys redacted beside [`CREDENTIAL_KEYS`] — the setting
/// `log.redact.keys` ([`crate::plexus::config::settings::LOG_REDACT_KEYS`]),
/// process-wide as the log is. Written lower case, `-` as `_`; it adds to
/// the fixed list and never takes one of them away.
static EXTRA_KEYS: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// NEST-21: set the keys redacted beside [`CREDENTIAL_KEYS`] (replacing the
/// ones set before). The config library calls it when `log.redact.keys`
/// changes.
pub fn set_extra_keys(keys: &[String]) {
    let keys: Vec<String> = keys.iter().map(|k| k.trim().bytes().map(|b| norm(b) as char).collect()).filter(|k: &String| !k.is_empty()).collect();
    *EXTRA_KEYS.write().unwrap_or_else(|p| p.into_inner()) = keys;
}

/// NEST-21: the keys redacted beside [`CREDENTIAL_KEYS`].
pub fn extra_keys() -> Vec<String> {
    EXTRA_KEYS.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Whether `key` names a credential.
pub fn is_credential_key(key: &str) -> bool {
    let k = key.trim();
    let same = |c: &str| c.len() == k.len() && c.bytes().zip(k.bytes()).all(|(a, b)| a == norm(b));
    CREDENTIAL_KEYS.iter().any(|c| same(c)) || EXTRA_KEYS.read().map(|x| x.iter().any(|c| same(c))).unwrap_or(false)
}

fn norm(b: u8) -> u8 {
    match b {
        b'-' => b'_',
        b => b.to_ascii_lowercase(),
    }
}

/// `value` with every credential key's value replaced by [`REDACTED`].
pub fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_credential_key(k) {
                    if !(k.eq_ignore_ascii_case("code") && !matches!(v, Value::String(_) | Value::Object(_) | Value::Array(_))) {
                        *v = Value::String(REDACTED.into());
                    }
                } else {
                    redact_value(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        _ => {}
    }
}

/// `text` with the value after every credential key replaced (see the
/// module's doc for the forms read). Text with no credential key comes back
/// unchanged, and without a copy when it holds none of their first letters.
pub fn redact_str(text: &str) -> std::borrow::Cow<'_, str> {
    let b = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0; // bytes of `text` already in `out`
    let mut i = 0;
    while i < b.len() {
        let Some((key_end, value_start)) = key_at(b, i) else {
            i += 1;
            continue;
        };
        let key = &text[i..key_end];
        let (value_end, keep) = value_at(b, value_start, key.trim_matches('"').eq_ignore_ascii_case("code"));
        if keep || value_end == value_start {
            i = key_end.max(i + 1);
            continue;
        }
        let o = out.get_or_insert_with(|| String::with_capacity(text.len()));
        o.push_str(&text[copied..value_start]);
        o.push('"');
        o.push_str(REDACTED);
        o.push('"');
        copied = value_end;
        i = value_end;
    }
    match out {
        None => std::borrow::Cow::Borrowed(text),
        Some(mut o) => {
            o.push_str(&text[copied..]);
            std::borrow::Cow::Owned(o)
        }
    }
}

fn word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// At `i`, a credential key (quoted or bare, on a word boundary) and its
/// separator: the key's end and where its value starts.
fn key_at(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let quoted = b[i] == b'"';
    let start = if quoted { i + 1 } else { i };
    if !quoted && i > 0 && word_byte(b[i - 1]) {
        return None;
    }
    let mut end = start;
    while end < b.len() && word_byte(b[end]) {
        end += 1;
    }
    if end == start || !is_credential_key(std::str::from_utf8(&b[start..end]).ok()?) {
        return None;
    }
    let mut j = end;
    if quoted {
        if b.get(j) != Some(&b'"') {
            return None;
        }
        j += 1;
    }
    let key_end = j;
    while j < b.len() && b[j] == b' ' {
        j += 1;
    }
    if !matches!(b.get(j), Some(b':') | Some(b'=')) {
        return None;
    }
    j += 1;
    while j < b.len() && b[j] == b' ' {
        j += 1;
    }
    Some((key_end, j))
}

/// The value starting at `i`: its end, and whether it is kept (a scalar
/// after `code`).
fn value_at(b: &[u8], i: usize, code: bool) -> (usize, bool) {
    let Some(&c) = b.get(i) else { return (i, true) };
    match c {
        b'"' | b'\'' => (string_end(b, i), false),
        b'{' | b'[' | b'(' => (group_end(b, i), false),
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b' ' | b',' | b'}' | b']' | b')' | b';' | b'&' | b'\n' | b'\r' | b'\t') {
                // `String("…")`, `Some(…)`: a constructor and its group.
                if matches!(b[j], b'(' | b'{' | b'[') {
                    j = group_end(b, j);
                    break;
                }
                j += 1;
            }
            let word = &b[i..j];
            if code && (word.iter().all(|c| c.is_ascii_digit() || *c == b'-') || matches!(word, b"true" | b"false" | b"null")) {
                return (j, true);
            }
            // `Bearer <token>`, `Basic <token>`: the scheme and the token.
            if (word.eq_ignore_ascii_case(b"bearer") || word.eq_ignore_ascii_case(b"basic")) && b.get(j) == Some(&b' ') {
                let mut k = j + 1;
                while k < b.len() && !matches!(b[k], b' ' | b',' | b'}' | b']' | b')' | b';' | b'&' | b'"' | b'\n' | b'\r' | b'\t') {
                    k += 1;
                }
                return (k, false);
            }
            (j, false)
        }
    }
}

/// The end of the quoted string at `i` (past its closing quote; the text's
/// end when it never closes).
fn string_end(b: &[u8], i: usize) -> usize {
    let q = b[i];
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            c if c == q => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

/// The end of the bracketed group at `i`, strings inside it skipped.
fn group_end(b: &[u8], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    while j < b.len() {
        match b[j] {
            b'"' => {
                j = string_end(b, j);
                continue;
            }
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    b.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "ghu_s3cr3tTokenBytes";

    #[test]
    fn a_value_loses_every_credential() {
        let mut v = json!({
            "jsonrpc": "2.0", "id": 1, "method": "github.call",
            "params": { "repo": "a/b", "credential": { "token": SECRET }, "Authorization": format!("Bearer {SECRET}"),
                        "items": [{ "refresh-token": SECRET }], "client_secret": SECRET },
            "error": { "code": -32601, "message": "x" }
        });
        redact_value(&mut v);
        let s = v.to_string();
        assert!(!s.contains(SECRET), "{s}");
        assert_eq!(v["params"]["repo"], "a/b");
        assert_eq!(v["params"]["credential"], REDACTED);
        assert_eq!(v["error"]["code"], -32601, "a JSON-RPC error code stays");
    }

    #[test]
    fn a_line_loses_every_credential() {
        let lines = [
            format!(r#"Received request: {{"jsonrpc":"2.0","id":3,"method":"g.call","params":{{"credential":"{SECRET}","x":1}}}}"#),
            format!(r#"{{"params": {{"credential": {{"token": "{SECRET}", "kind": "oauth"}}}}}}"#),
            format!(r#"    authorization: "Bearer {SECRET}""#),
            format!("Authorization: Bearer {SECRET}"),
            format!("GET /bridge/callback?code={SECRET}&state=abc"),
            format!(r#"args: Some({{"credential": String("{SECRET}"), "q": String("x")}})"#),
            format!(r#"{{"token":"{SECRET}\"still"}}"#),
            format!("cookie: mgs={SECRET}; other=1"),
        ];
        for l in &lines {
            let r = redact_str(l);
            assert!(!r.contains(SECRET), "{l}\n → {r}");
            assert!(r.contains(REDACTED), "{r}");
        }
        assert!(redact_str(&lines[0]).contains(r#""x":1"#));
        assert!(redact_str(&lines[4]).ends_with("&state=abc"), "{}", redact_str(&lines[4]));
    }

    #[test]
    fn text_without_a_credential_is_unchanged() {
        for l in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#,
            "child gone: the process exited (exit status: 0)",
            r#"{"tokens_used": 5, "codec": "json", "decode": "x", "mytoken": "x"}"#,
            "",
        ] {
            assert!(matches!(redact_str(l), std::borrow::Cow::Borrowed(_)), "{l}");
        }
    }
}
