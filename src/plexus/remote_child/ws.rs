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
use super::spec::{check_ws_url, INSECURE_TRANSPORT};

const PROOF_PREFIX: &str = "plexus-key.";
/// spec/00's one key-proof context — a dial-out signing in to its relay and
/// a mount dialing its child alike (plexus-wire spec/00 has no other).
pub(super) const LOGIN_CONTEXT: &str = super::proven::KEY_PROOF_CONTEXT;

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The key file's 32-byte Ed25519 seed (synapse's form: base64 text,
/// standard or url-safe, or the raw bytes). Refused when group or others
/// may read it.
pub(super) fn read_seed(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    // KEEL-19 (P5): not through a link, the user's own, 0600.
    let raw = crate::plexus::peer_token::read_private(path).map_err(|e| format!("the key file {e}"))?;
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
/// over `<context>\n<aud>\n<agent>\n<nonce>\n<ts>` — `context` spec/00's
/// [`LOGIN_CONTEXT`].
pub(super) fn key_proof(key: &SigningKey, context: &str, aud: &str, agent: &str, nonce: &[u8; 32], ts: i64) -> String {
    let nonce = b64url(nonce);
    let sig = key.sign(format!("{context}\n{aud}\n{agent}\n{nonce}\n{ts}").as_bytes());
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

/// DYNAUTH-8: the TLS a `wss://` child is dialed with — rustls on ring,
/// the webpki roots and `roots` (a PEM file of more), every certificate
/// validated.
#[cfg(feature = "child-wss")]
pub(super) fn tls_config(roots: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = roots {
        let shown = path.display();
        let certs = CertificateDer::pem_file_iter(path)
            .and_then(|it| it.collect::<Result<Vec<_>, _>>())
            .map_err(|e| format!("the TLS roots {shown}: {e}"))?;
        if certs.is_empty() {
            return Err(format!("the TLS roots {shown} hold no certificate"));
        }
        for c in certs {
            store.add(c).map_err(|e| format!("the TLS roots {shown}: {e}"))?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// DYNAUTH-8 (TM-3): sha256 (hex) of the key the far side's certificate
/// holds — its SubjectPublicKeyInfo, so a renewal over the same key keeps it.
#[cfg(feature = "child-wss")]
fn tls_key_of(stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>) -> Option<String> {
    use sha2::Digest;
    let tokio_tungstenite::MaybeTlsStream::Rustls(tls) = stream else { return None };
    let leaf = tls.get_ref().1.peer_certificates()?.first()?;
    let cert = webpki::EndEntityCert::try_from(leaf).ok()?;
    let spki = cert.subject_public_key_info();
    Some(sha2::Sha256::digest(spki.as_ref()).iter().map(|b| format!("{b:02x}")).collect())
}

pub(super) async fn dial(shared: &Arc<Shared>, url: &str) -> Result<Arc<Conn>, String> {
    // KEEL-7: the transport decided before any socket opens or any proof is
    // signed — `ws://` beyond loopback only under `transport.insecure_ws`.
    check_ws_url(url, shared.opts.insecure_ws).map_err(|why| format!("{INSECURE_TRANSPORT}: {why}"))?;
    if url.starts_with("wss://") && !cfg!(feature = "child-wss") {
        return Err("a wss:// child needs plexus-core's `child-wss` feature (TLS)".into());
    }
    let mut req = url.into_client_request().map_err(|e| format!("`{url}`: {e}"))?;
    if let Some(path) = &shared.opts.key {
        let key = read_seed(path)?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let proof = key_proof(&key, LOGIN_CONTEXT, url.trim_end_matches('/'), &shared.opts.agent, &nonce(), ts);
        let value = HeaderValue::from_str(&format!("Bearer {proof}")).map_err(|e| e.to_string())?;
        req.headers_mut().insert(AUTHORIZATION, value);
    }
    // NEST-12: a dial that never answers (a socket accepted and left) is
    // given the mount's one timeout, as its `_info` is.
    #[cfg(feature = "child-wss")]
    let connecting = {
        let tls = match url.starts_with("wss://") {
            true => Some(tokio_tungstenite::Connector::Rustls(tls_config(shared.opts.tls_roots.as_deref())?)),
            false => None,
        };
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, tls)
    };
    #[cfg(not(feature = "child-wss"))]
    let connecting = tokio_tungstenite::connect_async(req);
    let dialed = tokio::time::timeout(shared.opts.timeout, connecting)
        .await
        .map_err(|_| format!("dialing {url}: no answer to the upgrade in {:?}", shared.opts.timeout))?;
    let (socket, _) = dialed.map_err(|e| match e {
        tokio_tungstenite::tungstenite::Error::Http(resp) => format!("the upgrade to {url} was refused: HTTP {}", resp.status()),
        e => format!("dialing {url}: {e}"),
    })?;
    #[cfg(feature = "child-wss")]
    let tls_key = tls_key_of(socket.get_ref());
    let (mut sink, mut stream) = socket.split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn = Conn::new(&shared.name, None, out, shared.opts.buffer, Arc::clone(&shared.counters));
    let _ = conn.up.set(Arc::clone(&shared.upcalls));
    #[cfg(feature = "child-wss")]
    if let Some(k) = tls_key {
        let _ = conn.tls_key.set(k);
    }
    let writer = Arc::clone(&conn);
    // NEST-12: a ping every `ping`; the reader marks the socket down when
    // nothing has come for twice as long.
    let ping = shared.opts.ping;
    let mut ticks = ping.map(|p| tokio::time::interval_at(tokio::time::Instant::now() + p, p));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = async { match ticks.as_mut() { Some(t) => { t.tick().await; } None => std::future::pending::<()>().await } } => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
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
        let silent = ping.map(|p| p * 2);
        let why = loop {
            let next = match silent {
                Some(d) => match tokio::time::timeout(d, stream.next()).await {
                    Ok(n) => n,
                    Err(_) => break format!("{url} answered nothing for {d:?} (pinged every {:?})", d / 2),
                },
                None => stream.next().await,
            };
            match next {
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

// ------------------------------------------------------------------ KEEL-19

use super::proven::KeyedUpgrade;

/// KEEL-19 · serve `activation` as a keyed child on one accepted socket
/// (`stream`, a TCP connection or anything like it): the WebSocket upgrade
/// is taken only with a key proof `upgrade` verifies, and the
/// child is then served ([`super::serve_child_proven`]) on a connection
/// proven as that key,
/// trusting `trusted` (service principals, `key:<hex>`) to act for others.
/// The child's `key` and token verifier (`tokens`) as [`super::ServeChild`]
/// has them. An upgrade without a valid proof is refused (401) and served
/// nothing.
pub async fn serve_child_ws<A, S>(activation: A, stream: S, upgrade: &KeyedUpgrade, trusted: Vec<String>, key: Option<crate::plexus::peer_token::PeerKey>, tokens: Option<Arc<crate::plexus::peer_token::Verifier>>) -> std::io::Result<()>
where
    A: crate::plexus::plexus::Activation + Clone,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let proven = std::sync::Mutex::new(None::<Result<super::Proven, String>>);
    let check = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let bearer = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
        let verdict = upgrade.verify(bearer);
        let ok = verdict.is_ok();
        *proven.lock().unwrap() = Some(verdict);
        if ok {
            Ok(resp)
        } else {
            let mut refused = ErrorResponse::new(Some("a child is dialed with a key proof".into()));
            *refused.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED;
            Err(refused)
        }
    };
    let ws = tokio_tungstenite::accept_hdr_async(stream, check).await;
    let proven = match (proven.lock().unwrap().take(), ws) {
        (Some(Ok(p)), Ok(ws)) => (p, ws),
        (Some(Err(why)), _) => return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why)),
        (_, Err(e)) => return Err(std::io::Error::other(e.to_string())),
        (None, Ok(_)) => return Err(std::io::Error::other("no upgrade was checked")),
    };
    let (principal, ws) = proven;
    let (mut sink, mut source) = ws.split();
    let (mut in_w, in_r) = tokio::io::duplex(1 << 20);
    let (out_w, out_r) = tokio::io::duplex(1 << 20);
    let pump_in = async move {
        while let Some(Ok(m)) = source.next().await {
            match m {
                Message::Text(t) => {
                    if in_w.write_all(t.as_bytes()).await.is_err() || in_w.write_all(b"\n").await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };
    let pump_out = async move {
        let mut lines = tokio::io::BufReader::new(out_r).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if sink.send(Message::text(l)).await.is_err() {
                break;
            }
        }
    };
    let (_, _, served) = tokio::join!(pump_in, pump_out, super::serve_child_proven(activation, in_r, out_w, principal, trusted, key, tokens));
    served
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_reads_as_spec_00_says() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let p = key_proof(&key, LOGIN_CONTEXT, "ws://127.0.0.1:4480", "menger", &[1u8; 32], 1_793_000_000);
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
