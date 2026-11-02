//! PERF-9: which encoding a connection speaks — the service offers, the
//! client names the ones it speaks in its order, the service picks the first
//! it offers (spec/13).
//!
//! | where | the client says | the service answers |
//! | -- | -- | -- |
//! | a WebSocket upgrade | `Sec-WebSocket-Protocol: plexus.msgpack, plexus.json` | the `101` names the pick; a refusal is the `101`, then close 4415 `offered: …` |
//! | stdio | its first line, the request `plexus.encoding {encodings: ["msgpack","json"]}` | its first line, the answer `{encoding: "msgpack"}`; then 4-byte length-prefixed frames under msgpack |
//!
//! [`Encodings`] is what a service offers (both by default, until
//! TRANSPORT-21); [`Encodings::pick`] reads a client's ask. The same types
//! serve a client (the hop's [`RemoteChild`](super::RemoteChild)), which
//! asks and reads the answer.

use std::fmt;
use std::str::FromStr;

pub use super::wire::WireEncoding;

/// The close code of a refused encoding (spec/13): private use, after HTTP's 415.
pub const REFUSED_CLOSE_CODE: u16 = 4415;

/// The close code of a text message on a msgpack socket: RFC 6455's 1003.
pub const UNSUPPORTED_DATA_CLOSE_CODE: u16 = 1003;

/// The largest frame, in bytes (spec/09's message cap, 10 MiB).
pub const MAX_FRAME: usize = 10 * 1024 * 1024;

impl WireEncoding {
    /// Every encoding, in the order a client that speaks both asks for them.
    pub const ALL: [WireEncoding; 2] = [WireEncoding::Msgpack, WireEncoding::Json];

    /// Its subprotocol token: `plexus.json`, `plexus.msgpack`.
    pub const fn token(self) -> &'static str {
        match self {
            WireEncoding::Json => "plexus.json",
            WireEncoding::Msgpack => "plexus.msgpack",
        }
    }

    /// Its name, as a flag and stdio's first line spell it: `json`, `msgpack`.
    pub const fn name(self) -> &'static str {
        match self {
            WireEncoding::Json => "json",
            WireEncoding::Msgpack => "msgpack",
        }
    }

    /// The encoding a subprotocol token names.
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.token() == token)
    }

    /// The encoding a name names.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == name)
    }
}

impl fmt::Display for WireEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a service offers: one encoding or both, in its order (the order a
/// refusal lists them in; the client's order picks). Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encodings(Vec<WireEncoding>);

impl Default for Encodings {
    /// Both, msgpack and JSON — the default until TRANSPORT-21.
    fn default() -> Self {
        Encodings::both()
    }
}

/// An offered set that cannot be: none, or a name that is no encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingsError(pub String);

impl fmt::Display for EncodingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EncodingsError {}

impl Encodings {
    /// Both: msgpack and JSON.
    pub fn both() -> Self {
        Encodings(WireEncoding::ALL.to_vec())
    }

    /// One alone.
    pub fn only(encoding: WireEncoding) -> Self {
        Encodings(vec![encoding])
    }

    /// The ones given, in their order (a repeat is dropped); none is an error.
    pub fn new<I: IntoIterator<Item = WireEncoding>>(encodings: I) -> Result<Self, EncodingsError> {
        let mut v = Vec::new();
        for e in encodings {
            if !v.contains(&e) {
                v.push(e);
            }
        }
        if v.is_empty() {
            return Err(EncodingsError("a service offers at least one encoding (json, msgpack)".into()));
        }
        Ok(Encodings(v))
    }

    /// Whether `encoding` is offered.
    pub fn offers(&self, encoding: WireEncoding) -> bool {
        self.0.contains(&encoding)
    }

    /// The offered encodings, in order.
    pub fn as_slice(&self) -> &[WireEncoding] {
        &self.0
    }

    /// The offered tokens, `, `-separated, in order (a refusal's list).
    pub fn tokens(&self) -> String {
        self.0.iter().map(|e| e.token()).collect::<Vec<_>>().join(", ")
    }

    /// The reason a refusal's close carries: `offered: plexus.msgpack, plexus.json`.
    pub fn refusal_reason(&self) -> String {
        format!("offered: {}", self.tokens())
    }

    /// The pick for a client's subprotocol tokens, in its order (every token
    /// of its `Sec-WebSocket-Protocol` headers): the first `plexus.` token the
    /// service offers. A client that names no `plexus.` token asks for
    /// nothing, and gets JSON when it is offered.
    pub fn pick<'a, I: IntoIterator<Item = &'a str>>(&self, tokens: I) -> Pick {
        let ask: Vec<&str> = tokens.into_iter().map(str::trim).filter(|t| t.starts_with("plexus.")).collect();
        if ask.is_empty() {
            return if self.offers(WireEncoding::Json) {
                Pick::Picked { encoding: WireEncoding::Json, protocol: None }
            } else {
                Pick::Refused { protocol: None }
            };
        }
        match ask.iter().find_map(|t| WireEncoding::from_token(t).filter(|e| self.offers(*e))) {
            Some(e) => Pick::Picked { encoding: e, protocol: Some(e.token()) },
            None => Pick::Refused { protocol: Some(ask[0].to_string()) },
        }
    }

    /// The pick for stdio's first line's names, in order (spec/13).
    pub fn pick_names<'a, I: IntoIterator<Item = &'a str>>(&self, names: I) -> Option<WireEncoding> {
        names.into_iter().find_map(|n| WireEncoding::from_name(n.trim()).filter(|e| self.offers(*e)))
    }
}

impl FromStr for Encodings {
    type Err = EncodingsError;

    /// `msgpack,json` (any order; `,` or whitespace between; the
    /// `plexus.` tokens read too).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = Vec::new();
        for part in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|p| !p.is_empty()) {
            let e = WireEncoding::from_name(part)
                .or_else(|| WireEncoding::from_token(part))
                .ok_or_else(|| EncodingsError(format!("`{part}` is no encoding: json, msgpack")))?;
            v.push(e);
        }
        Encodings::new(v)
    }
}

impl fmt::Display for Encodings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.iter().map(|e| e.name()).collect::<Vec<_>>().join(","))
    }
}

/// What an upgrade settles (spec/13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// The socket speaks `encoding`; the `101` names `protocol` (none when
    /// the client asked for nothing).
    Picked { encoding: WireEncoding, protocol: Option<&'static str> },
    /// Nothing the client asked for is offered: the `101` names `protocol`
    /// (the first entry of the ask, so the client completes its handshake),
    /// then the socket is closed 4415 with [`Encodings::refusal_reason`].
    Refused { protocol: Option<String> },
}

/// Every token of a request's `Sec-WebSocket-Protocol` values, in order.
pub fn protocol_tokens<'a, I: IntoIterator<Item = &'a [u8]>>(values: I) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|v| std::str::from_utf8(v).ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// The `Sec-WebSocket-Protocol` value a client that speaks `encodings` (in
/// its order) sends: `plexus.msgpack, plexus.json`.
pub fn ask_header(encodings: &[WireEncoding]) -> String {
    encodings.iter().map(|e| e.token()).collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------
// stdio: the first line
// ---------------------------------------------------------------------------

/// The request stdio's first line is (spec/13).
pub const STDIO_METHOD: &str = "plexus.encoding";

/// A client's first line on stdio, the request naming the encodings it
/// speaks in order: `{"jsonrpc":"2.0","id":0,"method":"plexus.encoding","params":{"encodings":["msgpack","json"]}}`
/// (no newline). A request, so a service from before spec/13 answers it
/// (`-32601`) rather than leaving it unanswered as a notification.
pub fn stdio_ask_line(id: u64, encodings: &[WireEncoding]) -> String {
    let names: Vec<&str> = encodings.iter().map(|e| e.name()).collect();
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": STDIO_METHOD, "params": { "encodings": names } }).to_string()
}

/// Whether `line` is a client's negotiation request and, if so, its `id`
/// and the names it asks for, in order (`encodings` a list, or one name).
pub fn stdio_read_ask(line: &[u8]) -> Option<(serde_json::Value, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    if m.get("method")?.as_str()? != STDIO_METHOD {
        return None;
    }
    let id = m.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let names = match m.get("params").and_then(|p| p.get("encodings")) {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    Some((id, names))
}

/// The service's first line on stdio, answering the request `id`: the pick,
/// or the refusal naming what it offers (no newline).
pub fn stdio_answer_line(id: &serde_json::Value, pick: Option<WireEncoding>, offered: &Encodings) -> String {
    let result = match pick {
        Some(e) => serde_json::json!({ "encoding": e.name() }),
        None => {
            let names: Vec<&str> = offered.as_slice().iter().map(|e| e.name()).collect();
            serde_json::json!({ "encoding": null, "offered": names })
        }
    };
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

/// What a client reads in the service's first line on stdio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdioAnswer {
    /// The service picked this one.
    Picked(WireEncoding),
    /// It offers none of the ask; it names what it offers, and ends.
    Refused(Vec<String>),
    /// Not a pick: a service from before spec/13 (its `-32601` to the
    /// request) — it speaks JSON lines.
    NotAnswered,
}

/// The service's first line, as the client that asked with `id` reads it.
pub fn stdio_read_answer(line: &[u8], id: u64) -> StdioAnswer {
    let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(line) else {
        return StdioAnswer::NotAnswered;
    };
    if m.get("id").and_then(serde_json::Value::as_u64) != Some(id) {
        return StdioAnswer::NotAnswered;
    }
    let Some(result) = m.get("result").and_then(serde_json::Value::as_object) else {
        return StdioAnswer::NotAnswered;
    };
    match result.get("encoding") {
        Some(serde_json::Value::String(s)) => WireEncoding::from_name(s).map_or(StdioAnswer::NotAnswered, StdioAnswer::Picked),
        Some(serde_json::Value::Null) => StdioAnswer::Refused(
            result.get("offered").and_then(|o| o.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
        ),
        _ => StdioAnswer::NotAnswered,
    }
}

/// A msgpack frame on stdio: its 4-byte big-endian length, then the frame.
pub fn stdio_frame(frame: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
}

/// One length-prefixed frame read from `r`: `Ok(None)` at a clean EOF;
/// a frame over `max` is read past and given as `Err(TooBig)` with its size.
pub async fn stdio_read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Option<Result<Vec<u8>, usize>>> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        // Read past it, a block at a time: the next frame starts after it.
        let mut left = n as u64;
        let mut sink = tokio::io::sink();
        let copied = tokio::io::copy(&mut (&mut *r).take(left), &mut sink).await?;
        left -= copied;
        if left > 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "a frame cut short"));
        }
        return Ok(Some(Err(n)));
    }
    let mut frame = vec![0u8; n];
    r.read_exact(&mut frame).await?;
    Ok(Some(Ok(frame)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use WireEncoding::{Json, Msgpack};

    fn offers(e: &[WireEncoding]) -> Encodings {
        Encodings::new(e.iter().copied()).unwrap()
    }

    #[test]
    fn the_matrix() {
        // spec/13: three offers by four asks.
        let asks: [&[&str]; 4] = [&[], &["plexus.json"], &["plexus.msgpack"], &["plexus.msgpack", "plexus.json"]];
        let picked = |e: WireEncoding, echo: bool| Pick::Picked { encoding: e, protocol: echo.then(|| e.token()) };
        let refused = |p: Option<&str>| Pick::Refused { protocol: p.map(str::to_string) };
        let rows: [(Encodings, [Pick; 4]); 3] = [
            (offers(&[Json]), [picked(Json, false), picked(Json, true), refused(Some("plexus.msgpack")), picked(Json, true)]),
            (offers(&[Msgpack]), [refused(None), refused(Some("plexus.json")), picked(Msgpack, true), picked(Msgpack, true)]),
            (Encodings::default(), [picked(Json, false), picked(Json, true), picked(Msgpack, true), picked(Msgpack, true)]),
        ];
        for (offered, want) in rows {
            for (ask, want) in asks.iter().zip(want) {
                assert_eq!(offered.pick(ask.iter().copied()), want, "{offered} × {ask:?}");
            }
        }
    }

    #[test]
    fn the_ask_reads_plexus_tokens_only() {
        let both = Encodings::default();
        assert_eq!(both.pick(["graphql-ws"]), Pick::Picked { encoding: Json, protocol: None }, "a foreign token asks nothing");
        assert_eq!(both.pick(["graphql-ws", "plexus.json"]), Pick::Picked { encoding: Json, protocol: Some("plexus.json") });
        assert_eq!(both.pick(["plexus.cbor"]), Pick::Refused { protocol: Some("plexus.cbor".into()) }, "an unknown encoding is never picked");
        assert_eq!(both.pick(["plexus.cbor", "plexus.msgpack"]), Pick::Picked { encoding: Msgpack, protocol: Some("plexus.msgpack") });
        assert_eq!(protocol_tokens([&b"plexus.msgpack, plexus.json"[..], b" x ,"]), vec!["plexus.msgpack", "plexus.json", "x"]);
    }

    #[test]
    fn offered_sets_read_and_say_themselves() {
        assert_eq!("msgpack,json".parse::<Encodings>().unwrap(), Encodings::both());
        assert_eq!("json".parse::<Encodings>().unwrap(), Encodings::only(Json));
        assert_eq!("json, plexus.msgpack".parse::<Encodings>().unwrap().as_slice(), &[Json, Msgpack]);
        assert!("".parse::<Encodings>().is_err());
        assert!("cbor".parse::<Encodings>().is_err());
        assert_eq!(Encodings::both().refusal_reason(), "offered: plexus.msgpack, plexus.json");
        assert_eq!(Encodings::both().to_string(), "msgpack,json");
    }

    #[test]
    fn stdio_lines() {
        use serde_json::json;
        assert_eq!(stdio_ask_line(0, &[Msgpack, Json]), r#"{"id":0,"jsonrpc":"2.0","method":"plexus.encoding","params":{"encodings":["msgpack","json"]}}"#);
        assert_eq!(stdio_read_ask(br#"{"jsonrpc":"2.0","id":0,"method":"plexus.encoding","params":{"encodings":["msgpack","json"]}}"#), Some((json!(0), vec!["msgpack".into(), "json".into()])));
        assert_eq!(stdio_read_ask(br#"{"jsonrpc":"2.0","id":"a","method":"plexus.encoding","params":{"encodings":"msgpack"}}"#), Some((json!("a"), vec!["msgpack".into()])));
        assert_eq!(stdio_read_ask(br#"{"jsonrpc":"2.0","id":1,"method":"_info"}"#), None);
        assert_eq!(stdio_read_ask(br#"{"plexus.encoding":"msgpack"}"#), None, "not the request");
        assert_eq!(stdio_answer_line(&json!(0), Some(Msgpack), &Encodings::both()), r#"{"id":0,"jsonrpc":"2.0","result":{"encoding":"msgpack"}}"#);
        assert_eq!(stdio_answer_line(&json!(0), None, &Encodings::only(Json)), r#"{"id":0,"jsonrpc":"2.0","result":{"encoding":null,"offered":["json"]}}"#);
        assert_eq!(stdio_read_answer(br#"{"jsonrpc":"2.0","id":0,"result":{"encoding":"msgpack"}}"#, 0), StdioAnswer::Picked(Msgpack));
        assert_eq!(stdio_read_answer(br#"{"jsonrpc":"2.0","id":0,"result":{"encoding":null,"offered":["json"]}}"#, 0), StdioAnswer::Refused(vec!["json".into()]));
        assert_eq!(stdio_read_answer(br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"Method not found"}}"#, 0), StdioAnswer::NotAnswered);
        assert_eq!(stdio_read_answer(br#"{"jsonrpc":"2.0","id":9,"result":{"encoding":"msgpack"}}"#, 0), StdioAnswer::NotAnswered, "another request's answer");
    }

    #[tokio::test]
    async fn stdio_frames_are_length_prefixed_and_a_big_one_is_read_past() {
        let mut bytes = Vec::new();
        stdio_frame(&[0x81, 0xa1, b'a', 0x01], &mut bytes);
        stdio_frame(&[0u8; 100], &mut bytes);
        stdio_frame(&[0x80], &mut bytes);
        let mut r = &bytes[..];
        assert_eq!(stdio_read_frame(&mut r, 64).await.unwrap(), Some(Ok(vec![0x81, 0xa1, b'a', 0x01])));
        assert_eq!(stdio_read_frame(&mut r, 64).await.unwrap(), Some(Err(100)));
        assert_eq!(stdio_read_frame(&mut r, 64).await.unwrap(), Some(Ok(vec![0x80])));
        assert_eq!(stdio_read_frame(&mut r, 64).await.unwrap(), None);
    }
}
