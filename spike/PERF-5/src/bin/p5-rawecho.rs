//! The ceilings with no Plexus on the path: a WebSocket server that answers
//! each call frame with pre-built frames — the same bytes plexus sends (the
//! answer, one `data` item, `done`), or for `bench.count` N pre-built data
//! frames then `done`. Two stacks: `fastwebsockets` and `tokio-tungstenite`.
//! No JSON is parsed: the id is scanned, the subscription is the id.

use clap::Parser;
use futures::{SinkExt, StreamExt};
use memchr::memmem;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 4479)]
    port: u16,
    /// fastwebsockets | tungstenite
    #[arg(long, default_value = "fastwebsockets")]
    stack: String,
    #[arg(long, default_value = "multi")]
    rt: String,
    #[arg(long, default_value_t = 4)]
    workers: usize,
}

fn id_of(p: &[u8]) -> &[u8] {
    let at = memmem::find(p, b"\"id\":").map(|i| i + 5).unwrap_or(0);
    let end = at + p[at..].iter().position(|&c| c == b',' || c == b'}').unwrap_or(0);
    &p[at..end]
}

/// (to, size) of a bench.count call, if it is one.
fn count_of(p: &[u8]) -> Option<(u64, usize)> {
    memmem::find(p, b"bench.count")?;
    let num = |k: &[u8]| -> u64 {
        let at = memmem::find(p, k).unwrap() + k.len();
        p[at..].iter().take_while(|c| c.is_ascii_digit()).fold(0, |n, &c| n * 10 + (c - b'0') as u64)
    };
    Some((num(b"\"to\":"), num(b"\"size\":") as usize))
}

fn answer(id: &[u8]) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{},"result":{}}}"#, String::from_utf8_lossy(id), String::from_utf8_lossy(id)).into_bytes()
}
fn data_health(sub: &[u8]) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","method":"perf5.call","params":{{"subscription":{},"result":{{"type":"data","metadata":{{"provenance":["bench"],"plexus_hash":"190a802f261e2c6f","timestamp":1793259270}},"content_type":"bench.once","content":{{"ticket_count":1518,"type":"health","unix_now":1793258669,"version":"0.6.2"}}}}}}}}"#, String::from_utf8_lossy(sub)).into_bytes()
}
fn data_item(sub: &[u8], n: u64, size: usize) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","method":"perf5.call","params":{{"subscription":{},"result":{{"type":"data","metadata":{{"provenance":["bench"],"plexus_hash":"190a802f261e2c6f","timestamp":1793259270}},"content_type":"bench.count","content":{{"n":{n},"pad":"{}","type":"item"}}}}}}}}"#, String::from_utf8_lossy(sub), "x".repeat(size)).into_bytes()
}
fn done(sub: &[u8]) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","method":"perf5.call","params":{{"subscription":{},"result":{{"type":"done","metadata":{{"provenance":["bench"],"plexus_hash":"190a802f261e2c6f","timestamp":1793259270}}}}}}}}"#, String::from_utf8_lossy(sub)).into_bytes()
}

/// The frames a call is answered with. A stream's items are built once per
/// call (outside the send loop's measure: the ceiling is the socket's).
fn replies(p: &[u8]) -> Vec<Vec<u8>> {
    let id = id_of(p).to_vec();
    let mut out = vec![answer(&id)];
    match count_of(p) {
        Some((to, size)) => {
            let one = data_item(&id, 4242, size);
            for _ in 0..to {
                out.push(one.clone());
            }
        }
        None => out.push(data_health(&id)),
    }
    out.push(done(&id));
    out
}

async fn fws(port: u16) -> anyhow::Result<()> {
    use fastwebsockets::{upgrade, Frame, OpCode, Payload};
    use http_body_util::Empty;
    use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request, Response};
    let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("listening ws://127.0.0.1:{port} pid {} stack fastwebsockets", std::process::id());
    loop {
        let (s, _) = l.accept().await?;
        s.set_nodelay(true)?;
        tokio::spawn(async move {
            let svc = service_fn(|mut req: Request<Incoming>| async move {
                let (resp, fut) = upgrade::upgrade(&mut req)?;
                tokio::spawn(async move {
                    let mut ws = fastwebsockets::FragmentCollector::new(fut.await.unwrap());
                    while let Ok(f) = ws.read_frame().await {
                        match f.opcode {
                            OpCode::Close => break,
                            OpCode::Text => {
                                let rs = replies(&f.payload);
                                for r in rs {
                                    if ws.write_frame(Frame::text(Payload::Owned(r))).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                });
                Ok::<Response<Empty<bytes::Bytes>>, fastwebsockets::WebSocketError>(resp)
            });
            let _ = http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).with_upgrades().await;
        });
    }
}

async fn tung(port: u16) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::Message;
    let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("listening ws://127.0.0.1:{port} pid {} stack tungstenite", std::process::id());
    loop {
        let (s, _) = l.accept().await?;
        s.set_nodelay(true)?;
        tokio::spawn(async move {
            let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else { return };
            while let Some(Ok(m)) = ws.next().await {
                if let Message::Text(t) = m {
                    let rs = replies(t.as_bytes());
                    let n = rs.len();
                    for (i, r) in rs.into_iter().enumerate() {
                        let msg = Message::Text(String::from_utf8(r).unwrap().into());
                        // feed, flushing at the end of a call's frames and every 64 (tungstenite batches writes)
                        let res = if i + 1 == n || i % 64 == 63 { ws.send(msg).await } else { ws.feed(msg).await };
                        if res.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let rt = match a.rt.as_str() {
        "current" => tokio::runtime::Builder::new_current_thread().enable_all().build()?,
        _ => tokio::runtime::Builder::new_multi_thread().worker_threads(a.workers).enable_all().build()?,
    };
    rt.block_on(async move {
        match a.stack.as_str() {
            "tungstenite" => tung(a.port).await,
            _ => fws(a.port).await,
        }
    })
}
