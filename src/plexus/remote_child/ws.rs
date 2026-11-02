//! A child over a WebSocket (feature `child-ws`): dialed with the service's
//! own key proof on the upgrade (spec/00), asking for msgpack, then JSON
//! (spec/13): one msgpack map per binary frame when the child picks msgpack,
//! one JSON-RPC message per text frame otherwise. The key is read from its file at each dial, used to sign, and
//! dropped (`SigningKey` zeroizes): never kept, logged, or put in a frame.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, header::SEC_WEBSOCKET_PROTOCOL, HeaderValue};
use crate::plexus::wire::WireEncoding;
use tokio_tungstenite::tungstenite::Message;

use super::link::{gone, Conn, Shared};

const PROOF_PREFIX: &str = "plexus-key.";
const PROOF_CONTEXT: &str = "plexus-key-login/v1";

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The key file's 32-byte Ed25519 seed (synapse's form: base64 text,
/// standard or url-safe, or the raw bytes). Refused when group or others
/// may read it.
pub(super) fn read_seed(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map_err(|e| format!("the key file {shown}: {e}"))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!("the key file {shown} is readable by others (mode {:o}); a key is kept 0600", mode & 0o777));
        }
    }
    let raw = std::fs::read(path).map_err(|e| format!("the key file {shown}: {e}"))?;
    let text: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let seed: [u8; 32] = engines
        .iter()
        .find_map(|e| e.decode(&text).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
        .or_else(|| <[u8; 32]>::try_from(raw.as_slice()).ok())
        .ok_or_else(|| format!("the key file {shown} holds no 32-byte seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// `key:<64 hex>`: the principal a proof by `key` proves.
pub(super) fn principal_of(key: &SigningKey) -> String {
    let hex: String = key.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("key:{hex}")
}

/// The bearer value `plexus-key.<base64url(JSON)>` (spec/00, IDENTITY-41):
/// `{"v":1,"key","aud","agent","nonce","ts","sig"}` in that order, signed
/// over `plexus-key-login/v1\n<aud>\n<agent>\n<nonce>\n<ts>`.
pub(super) fn key_proof(key: &SigningKey, aud: &str, agent: &str, nonce: &[u8; 32], ts: i64) -> String {
    let nonce = b64url(nonce);
    let sig = key.sign(format!("{PROOF_CONTEXT}\n{aud}\n{agent}\n{nonce}\n{ts}").as_bytes());
    let hex: String = key.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let s = |v: &str| serde_json::to_string(v).unwrap_or_default();
    let body = format!(
        r#"{{"v":1,"key":"{hex}","aud":{},"agent":{},"nonce":"{nonce}","ts":{ts},"sig":"{}"}}"#,
        s(aud),
        s(agent),
        b64url(&sig.to_bytes())
    );
    format!("{PROOF_PREFIX}{}", b64url(body.as_bytes()))
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n
}

/// The upgrade to `url`, asking for `encodings` (none: no
/// `Sec-WebSocket-Protocol`, as before spec/13).
async fn upgrade(
    shared: &Arc<Shared>,
    url: &str,
    encodings: &[WireEncoding],
) -> Result<(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, WireEncoding), tokio_tungstenite::tungstenite::Error> {
    let mut req = url.into_client_request()?;
    if let Some(path) = &shared.opts.key {
        let key = read_seed(path).map_err(|e| tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other(e)))?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let proof = key_proof(&key, url.trim_end_matches('/'), &shared.opts.agent, &nonce(), ts);
        let value = HeaderValue::from_str(&format!("Bearer {proof}")).map_err(|e| tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other(e.to_string())))?;
        req.headers_mut().insert(AUTHORIZATION, value);
    }
    if !encodings.is_empty() {
        let ask = crate::plexus::encoding::ask_header(encodings);
        req.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(&ask).expect("tokens are ASCII"));
    }
    let (socket, resp) = tokio_tungstenite::connect_async(req).await?;
    let picked = resp.headers().get(SEC_WEBSOCKET_PROTOCOL).and_then(|v| v.to_str().ok()).and_then(WireEncoding::from_token).unwrap_or(WireEncoding::Json);
    Ok((socket, picked))
}

pub(super) async fn dial(shared: &Arc<Shared>, url: &str) -> Result<Arc<Conn>, String> {
    use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError, SubProtocolError};
    if url.starts_with("wss://") && !cfg!(feature = "child-wss") {
        return Err("a wss:// child needs plexus-core's `child-wss` feature (TLS)".into());
    }
    let refused = |e: WsError| match e {
        WsError::Http(resp) => format!("the upgrade to {url} was refused: HTTP {}", resp.status()),
        WsError::Io(e) if e.kind() == std::io::ErrorKind::Other => e.to_string(),
        e => format!("dialing {url}: {e}"),
    };
    // PERF-9 (spec/13): ask for the options' encodings. A child from before
    // spec/13 answers the 101 naming none, which tungstenite refuses: it is
    // dialed once more, asking for nothing, and spoken to in JSON.
    let (socket, encoding) = match upgrade(shared, url, &shared.opts.encodings).await {
        Ok(s) => s,
        Err(WsError::Protocol(ProtocolError::SecWebSocketSubProtocolError(SubProtocolError::NoSubProtocol))) => {
            tracing::debug!(target: "plexus::child", child = %shared.name, "{url} names no encoding (before spec/13): JSON");
            upgrade(shared, url, &[]).await.map_err(refused)?
        }
        Err(e) => return Err(refused(e)),
    };
    let (mut sink, mut stream) = socket.split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn = Conn::new(&shared.name, None, encoding, out, shared.opts.buffer, Arc::clone(&shared.counters));
    let writer = Arc::clone(&conn);
    let message = move |frame: Vec<u8>| match encoding {
        WireEncoding::Msgpack => Message::Binary(frame.into()),
        _ => Message::text(String::from_utf8_lossy(&frame).into_owned()),
    };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                first = out_rx.recv() => {
                    let Some(first) = first else { break };
                    let mut ok = sink.feed(message(first)).await.is_ok();
                    while let (true, Ok(more)) = (ok, out_rx.try_recv()) {
                        ok = sink.feed(message(more)).await.is_ok();
                    }
                    if !ok || sink.flush().await.is_err() {
                        break;
                    }
                }
                _ = writer.shutdown.notified() => {
                    let _ = sink.close().await;
                    break;
                }
            }
        }
    });
    let reader = Arc::clone(&conn);
    let weak = Arc::downgrade(shared);
    let url = url.to_string();
    tokio::spawn(async move {
        let why = loop {
            match stream.next().await {
                // spec/13: a text message on a msgpack socket is a protocol error.
                Some(Ok(Message::Text(_))) if reader.encoding == WireEncoding::Msgpack => {
                    break format!("{url} sent a text message on a plexus.msgpack socket");
                }
                Some(Ok(Message::Text(t))) => reader.on_message(t.as_bytes()).await,
                Some(Ok(Message::Binary(b))) if reader.encoding == WireEncoding::Msgpack => match crate::plexus::msgpack::frame_to_json(&b) {
                    Ok(json) => reader.on_message(&json).await,
                    Err(e) => tracing::warn!(target: "plexus::child", child = %reader.name, "an unreadable frame from the child: {e}"),
                },
                Some(Ok(Message::Binary(b))) => reader.on_message(&b).await,
                Some(Ok(Message::Close(f))) => break format!("{url} closed the socket ({})", f.map(|f| f.code.to_string()).unwrap_or_else(|| "no code".into())),
                Some(Ok(_)) => {}
                Some(Err(e)) => break format!("{url}: {e}"),
                None => break format!("{url} closed the socket"),
            }
        };
        reader.shutdown.notify_one();
        gone(&weak, &reader, &why);
    });
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_reads_as_spec_00_says() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let p = key_proof(&key, "ws://127.0.0.1:4480", "menger", &[1u8; 32], 1_793_000_000);
        let body = p.strip_prefix(PROOF_PREFIX).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap();
        let text = String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap();
        let order: Vec<usize> = ["\"v\"", "\"key\"", "\"aud\"", "\"agent\"", "\"nonce\"", "\"ts\"", "\"sig\""].iter().map(|k| text.find(k).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "fields in the wire's order: {text}");
        assert_eq!(json["aud"], "ws://127.0.0.1:4480");
        assert_eq!(format!("key:{}", json["key"].as_str().unwrap()), principal_of(&key));
        // Byte for byte the proof plexus-auth-core's adapter verifies (Ed25519 is deterministic).
        let theirs = plexus_auth_core::adapters::sign_key_proof(&[7u8; 32], "ws://127.0.0.1:4480", "menger", &[1u8; 32], 1_793_000_000);
        assert_eq!(p, theirs);
    }
}
