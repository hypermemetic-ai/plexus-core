//! A child over a WebSocket (feature `child-ws`): dialed with the service's
//! own key proof on the upgrade (spec/00), one JSON-RPC message per text
//! frame. The key is read from its file at each dial, used to sign, and
//! dropped (`SigningKey` zeroizes): never kept, logged, or put in a frame.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};
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

pub(super) async fn dial(shared: &Arc<Shared>, url: &str) -> Result<Arc<Conn>, String> {
    if url.starts_with("wss://") && !cfg!(feature = "child-wss") {
        return Err("a wss:// child needs plexus-core's `child-wss` feature (TLS)".into());
    }
    let mut req = url.into_client_request().map_err(|e| format!("`{url}`: {e}"))?;
    if let Some(path) = &shared.opts.key {
        let key = read_seed(path)?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let proof = key_proof(&key, url.trim_end_matches('/'), &shared.opts.agent, &nonce(), ts);
        let value = HeaderValue::from_str(&format!("Bearer {proof}")).map_err(|e| e.to_string())?;
        req.headers_mut().insert(AUTHORIZATION, value);
    }
    let (socket, _) = tokio_tungstenite::connect_async(req).await.map_err(|e| match e {
        tokio_tungstenite::tungstenite::Error::Http(resp) => format!("the upgrade to {url} was refused: HTTP {}", resp.status()),
        e => format!("dialing {url}: {e}"),
    })?;
    let (mut sink, mut stream) = socket.split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn = Conn::new(&shared.name, None, out, shared.opts.buffer, Arc::clone(&shared.counters));
    let writer = Arc::clone(&conn);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                first = out_rx.recv() => {
                    let Some(first) = first else { break };
                    let mut ok = sink.feed(Message::text(String::from_utf8_lossy(&first).into_owned())).await.is_ok();
                    while let (true, Ok(more)) = (ok, out_rx.try_recv()) {
                        ok = sink.feed(Message::text(String::from_utf8_lossy(&more).into_owned())).await.is_ok();
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
                Some(Ok(Message::Text(t))) => reader.on_message(t.as_bytes()).await,
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
