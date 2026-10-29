//! A raw WebSocket client: blocking std sockets, pre-built frames, no JSON
//! parse on the hot path — so the client's cost never hides the server's.
//! The writer is one OS thread sending on the open-loop schedule; the
//! reader is another, timing each call's `done` against its intended time.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use memchr::memmem;

use crate::hist::Lat;
use crate::openloop::Schedule;

// ---------------------------------------------------------------- frames

/// A client text frame, FIN set, masked with a zero key (RFC 6455 allows any
/// key; zero makes the mask a no-op, so a frame is built once and patched).
pub fn client_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 14);
    header(&mut f, 0x1, payload.len(), true);
    f.extend_from_slice(payload);
    f
}

/// A server frame (unmasked) — for tests and the raw echo ceilings.
pub fn server_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 10);
    header(&mut f, 0x1, payload.len(), false);
    f.extend_from_slice(payload);
    f
}

fn header(f: &mut Vec<u8>, op: u8, len: usize, masked: bool) {
    f.push(0x80 | op);
    let m = if masked { 0x80 } else { 0 };
    if len < 126 {
        f.push(m | len as u8);
    } else if len <= 0xffff {
        f.push(m | 126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(m | 127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if masked {
        f.extend_from_slice(&[0, 0, 0, 0]);
    }
}

/// Server → client frames out of a byte stream. Counts every byte fed.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    start: usize,
    bytes_in: u64,
    frames: u64,
}

impl FrameReader {
    pub fn feed(&mut self, b: &[u8]) {
        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 1 << 20 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(b);
        self.bytes_in += b.len() as u64;
    }
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
    pub fn frames(&self) -> u64 {
        self.frames
    }
    /// (opcode, payload) of the next whole frame. Server frames are unmasked;
    /// a masked one is unmasked in place.
    pub fn next_frame(&mut self) -> Option<(u8, &[u8])> {
        let b = &self.buf[self.start..];
        if b.len() < 2 {
            return None;
        }
        let op = b[0] & 0x0f;
        let masked = b[1] & 0x80 != 0;
        let (len, mut at) = match b[1] & 0x7f {
            126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
            127 if b.len() >= 10 => (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10),
            126 | 127 => return None,
            n => (n as usize, 2),
        };
        let mask = if masked {
            if b.len() < at + 4 {
                return None;
            }
            let m = [b[at], b[at + 1], b[at + 2], b[at + 3]];
            at += 4;
            Some(m)
        } else {
            None
        };
        if b.len() < at + len {
            return None;
        }
        let s = self.start + at;
        self.start = s + len;
        self.frames += 1;
        if let Some(m) = mask {
            for (i, x) in self.buf[s..s + len].iter_mut().enumerate() {
                *x ^= m[i & 3];
            }
        }
        Some((op, &self.buf[s..s + len]))
    }
}

// ---------------------------------------------------------------- messages

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Data,
    Done,
    Error,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// `{"id":N,"result":SUB}` — a call's subscription named.
    Answer { id: u64, sub: Vec<u8> },
    /// `{"params":{"subscription":SUB,"result":{"type":KIND,…}}}`.
    Item { sub: Vec<u8>, kind: Kind },
    /// An error answer to the call itself (counts as its end).
    CallError { id: u64 },
    /// An error the server could not tie to a call (`"id":null`: a frame it
    /// could not read) — the harness is wrong; stop.
    Fatal(String),
    Other,
}

fn token_after(b: &[u8], key: &[u8]) -> Option<(usize, usize)> {
    let at = memmem::find(b, key)? + key.len();
    let end = at + b[at..].iter().position(|&c| c == b',' || c == b'}')?;
    Some((at, end))
}

fn num(b: &[u8]) -> u64 {
    b.iter().filter(|c| c.is_ascii_digit()).fold(0u64, |n, &c| n.wrapping_mul(10).wrapping_add((c - b'0') as u64))
}

/// Classify a server frame by scanning, not parsing. An item's kind is the
/// `"type"` that opens its `result` object (serde writes the tag first), so
/// a `content` holding `"type":"done"` is not mistaken for the end.
pub fn classify(b: &[u8]) -> Msg {
    if let Some((s, e)) = token_after(b, b"\"subscription\":") {
        let sub = b[s..e].to_vec();
        let kind = match memmem::find(&b[e..], b"\"result\":{\"type\":\"") {
            Some(k) => {
                let t = &b[e + k + 18..];
                if t.starts_with(b"data\"") {
                    Kind::Data
                } else if t.starts_with(b"done\"") {
                    Kind::Done
                } else if t.starts_with(b"error\"") {
                    Kind::Error
                } else {
                    Kind::Other
                }
            }
            None => Kind::Other,
        };
        return Msg::Item { sub, kind };
    }
    if memmem::find(b, b"\"id\":null").is_some() {
        return Msg::Fatal(String::from_utf8_lossy(b).into_owned());
    }
    if let Some((s, e)) = token_after(b, b"\"id\":") {
        let id = num(&b[s..e]).wrapping_sub(CallFrame::BASE);
        if let Some((rs, re)) = token_after(b, b"\"result\":") {
            return Msg::Answer { id, sub: b[rs..re].to_vec() };
        }
        if memmem::find(b, b"\"error\":").is_some() {
            return Msg::CallError { id };
        }
    }
    Msg::Other
}

// ---------------------------------------------------------------- connect

pub struct Conn {
    pub write: Arc<Mutex<TcpStream>>,
    pub read: TcpStream,
    pub leftover: Vec<u8>,
}

/// Upgrade over a plain TCP socket (TCP_NODELAY), `headers` added verbatim.
pub fn connect(url: &str, headers: &[(String, String)]) -> anyhow::Result<Conn> {
    let rest = url.strip_prefix("ws://").ok_or_else(|| anyhow::anyhow!("ws:// only"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut s = TcpStream::connect(hostport)?;
    s.set_nodelay(true)?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        let n = s.read(&mut chunk)?;
        anyhow::ensure!(n > 0, "closed during the upgrade");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = memmem::find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    anyhow::ensure!(head.starts_with("HTTP/1.1 101"), "upgrade refused: {}", head.lines().next().unwrap_or(""));
    let leftover = buf[end..].to_vec();
    let w = s.try_clone()?;
    Ok(Conn { write: Arc::new(Mutex::new(w)), read: s, leftover })
}

/// A call frame with a fixed-width id (20 digits) patched in place per call.
pub struct CallFrame {
    frame: Vec<u8>,
    id_at: usize,
}

impl CallFrame {
    pub fn new(method: &str, params: &str) -> Self {
        let payload = format!(r#"{{"jsonrpc":"2.0","id":{},"method":"{method}","params":{params}}}"#, Self::BASE);
        let f = client_text_frame(payload.as_bytes());
        let id_at = f.len() - payload.len() + payload.find(&Self::BASE.to_string()).unwrap();
        CallFrame { frame: f, id_at }
    }
    /// Ids on the wire are BASE + n: twenty digits, no leading zero (JSON
    /// forbids one), patched in place.
    pub const BASE: u64 = 10_000_000_000_000_000_000;
    pub fn id_of(wire: u64) -> u64 {
        wire - Self::BASE
    }
    pub fn with_id(&mut self, id: u64) -> &[u8] {
        let digits = (Self::BASE + id).to_string();
        self.frame[self.id_at..self.id_at + 20].copy_from_slice(digits.as_bytes());
        &self.frame
    }
}

fn pong(write: &Arc<Mutex<TcpStream>>, payload: &[u8]) {
    let mut f = Vec::with_capacity(payload.len() + 6);
    header(&mut f, 0xA, payload.len(), true);
    f.extend_from_slice(payload);
    let _ = write.lock().unwrap().write_all(&f);
}

// ---------------------------------------------------------------- runs

#[derive(Debug, Clone, serde::Serialize)]
pub struct CallRun {
    #[serde(skip)]
    pub latencies_us: Vec<f64>,
    pub summary: crate::hist::Summary,
    /// How late the client itself sent, against the schedule.
    pub send_lateness: crate::hist::Summary,
    pub calls: u64,
    pub wall_s: f64,
    pub calls_per_s: f64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub frames_in: u64,
    pub errors: u64,
}

/// `n` calls on one socket at `rate`/s, open loop, after `warm` sequential
/// warm-up calls. Latency is from each call's intended send time to its
/// `done` (or its error).
pub async fn open_loop_calls(
    url: &str,
    headers: &[(String, String)],
    call_method: &str,
    params: &str,
    n: u64,
    rate: f64,
    warm: u64,
) -> anyhow::Result<CallRun> {
    let (url, headers, call_method, params) = (url.to_string(), headers.to_vec(), call_method.to_string(), params.to_string());
    tokio::task::spawn_blocking(move || open_loop_calls_blocking(&url, &headers, &call_method, &params, n, rate, warm)).await?
}

pub fn open_loop_calls_blocking(
    url: &str,
    headers: &[(String, String)],
    call_method: &str,
    params: &str,
    n: u64,
    rate: f64,
    warm: u64,
) -> anyhow::Result<CallRun> {
    let mut conn = connect(url, headers)?;
    let mut reader = FrameReader::default();
    reader.feed(&std::mem::take(&mut conn.leftover));
    let mut frame = CallFrame::new(call_method, params);
    // warm-up, sequential
    let mut read_buf = vec![0u8; 1 << 16];
    for i in 0..warm {
        conn.write.lock().unwrap().write_all(frame.with_id(1_000_000_000 + i))?;
        wait_done(&mut conn.read, &mut reader, &mut read_buf, &conn.write)?;
    }
    let bytes_in0 = reader.bytes_in();
    let frames_in0 = reader.frames();
    let t0 = Instant::now() + Duration::from_millis(5);
    let sched = Schedule::new(t0, rate);
    let sent: Arc<Vec<std::sync::atomic::AtomicU64>> = Arc::new((0..n).map(|_| std::sync::atomic::AtomicU64::new(0)).collect());
    let w = conn.write.clone();
    let sent_w = sent.clone();
    let writer = std::thread::spawn(move || -> anyhow::Result<(u64, Lat)> {
        let mut late = Lat::new();
        let mut out = 0u64;
        for i in 0..n {
            let at = sched.intended(i);
            loop {
                let now = Instant::now();
                if now >= at {
                    break;
                }
                if at - now > Duration::from_millis(2) {
                    std::thread::sleep(at - now - Duration::from_millis(1));
                } else {
                    std::hint::spin_loop();
                }
            }
            let f = frame.with_id(i);
            let now = Instant::now();
            late.record(now - at);
            sent_w[i as usize].store((now - t0).as_nanos() as u64 + 1, std::sync::atomic::Ordering::Relaxed);
            w.lock().unwrap().write_all(f)?;
            out += f.len() as u64;
        }
        Ok((out, late))
    });
    let mut subs: HashMap<Vec<u8>, u64> = HashMap::with_capacity(n as usize);
    let mut lat = Lat::new();
    let mut lats = Vec::with_capacity(n as usize);
    let mut finished = 0u64;
    let mut errors = 0u64;
    let mut last = t0;
    'outer: while finished < n {
        let k = conn.read.read(&mut read_buf)?;
        anyhow::ensure!(k > 0, "server closed after {finished} of {n}");
        reader.feed(&read_buf[..k]);
        while let Some((op, p)) = reader.next_frame() {
            match op {
                0x9 => {
                    let p = p.to_vec();
                    pong(&conn.write, &p);
                    continue;
                }
                0x8 => anyhow::bail!("server closed the socket after {finished} of {n}"),
                _ => {}
            }
            let done_id = match classify(p) {
                Msg::Answer { id, sub } => {
                    subs.insert(sub, id);
                    None
                }
                Msg::Item { sub, kind: Kind::Done } => subs.remove(&sub),
                Msg::Item { sub, kind: Kind::Error } => {
                    errors += 1;
                    subs.remove(&sub)
                }
                Msg::CallError { id } => {
                    errors += 1;
                    Some(id)
                }
                Msg::Fatal(f) => anyhow::bail!("the server could not read a call: {f}"),
                _ => None,
            };
            if let Some(id) = done_id {
                if id >= n {
                    continue;
                }
                let now = Instant::now();
                let us = (now - sched.intended(id)).as_nanos() as f64 / 1000.0;
                lat.record_us(us);
                lats.push(us);
                finished += 1;
                last = now;
                if finished == n {
                    break 'outer;
                }
            }
        }
    }
    let (bytes_out, late) = writer.join().unwrap()?;
    let wall = (last - t0).as_secs_f64();
    Ok(CallRun {
        latencies_us: lats,
        summary: lat.summary(),
        send_lateness: late.summary(),
        calls: n,
        wall_s: wall,
        calls_per_s: n as f64 / wall,
        bytes_out,
        bytes_in: reader.bytes_in() - bytes_in0,
        frames_in: reader.frames() - frames_in0,
        errors,
    })
}

fn wait_done(read: &mut TcpStream, reader: &mut FrameReader, buf: &mut [u8], write: &Arc<Mutex<TcpStream>>) -> anyhow::Result<u64> {
    let mut items = 0;
    loop {
        while let Some((op, p)) = reader.next_frame() {
            if op == 0x9 {
                let p = p.to_vec();
                pong(write, &p);
                continue;
            }
            match classify(p) {
                Msg::Item { kind: Kind::Error, .. } | Msg::CallError { .. } => anyhow::bail!("the call failed: {}", String::from_utf8_lossy(p)),
                Msg::Fatal(f) => anyhow::bail!("the server could not read a call: {f}"),
                Msg::Item { kind: Kind::Done, .. } => return Ok(items),
                Msg::Item { kind: Kind::Data, .. } => items += 1,
                _ => {}
            }
        }
        let k = read.read(buf)?;
        anyhow::ensure!(k > 0, "server closed");
        reader.feed(&buf[..k]);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SeqRun {
    pub summary: crate::hist::Summary,
    pub calls_per_s: f64,
}

/// Sequential calls on one socket (POLYGLOT-13's shape: one in flight).
pub fn sequential_calls(url: &str, headers: &[(String, String)], call_method: &str, params: &str, n: u64, warm: u64) -> anyhow::Result<SeqRun> {
    let mut conn = connect(url, headers)?;
    let mut reader = FrameReader::default();
    reader.feed(&std::mem::take(&mut conn.leftover));
    let mut frame = CallFrame::new(call_method, params);
    let mut buf = vec![0u8; 1 << 16];
    let mut lat = Lat::new();
    let t0 = Instant::now();
    for i in 0..(warm + n) {
        let s = Instant::now();
        conn.write.lock().unwrap().write_all(frame.with_id(i))?;
        wait_done(&mut conn.read, &mut reader, &mut buf, &conn.write)?;
        if i >= warm {
            lat.record(s.elapsed());
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    Ok(SeqRun { summary: lat.summary(), calls_per_s: (warm + n) as f64 / wall })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamRun {
    pub items: u64,
    pub secs: f64,
    pub items_per_s: f64,
    pub bytes_in: u64,
    pub frames_in: u64,
    pub wire_bytes_per_item: f64,
}

/// One streaming call, timed from the call frame written to its `done`.
pub fn one_stream(url: &str, headers: &[(String, String)], call_method: &str, params: &str, warm: u64, runs: u64) -> anyhow::Result<Vec<StreamRun>> {
    let mut conn = connect(url, headers)?;
    let mut reader = FrameReader::default();
    reader.feed(&std::mem::take(&mut conn.leftover));
    let mut frame = CallFrame::new(call_method, params);
    let mut buf = vec![0u8; 1 << 20];
    let mut out = Vec::new();
    for i in 0..(warm + runs) {
        let b0 = reader.bytes_in();
        let f0 = reader.frames();
        let s = Instant::now();
        conn.write.lock().unwrap().write_all(frame.with_id(i))?;
        let items = wait_done(&mut conn.read, &mut reader, &mut buf, &conn.write)?;
        let secs = s.elapsed().as_secs_f64();
        if i >= warm {
            let bytes = reader.bytes_in() - b0;
            out.push(StreamRun {
                items,
                secs,
                items_per_s: items as f64 / secs,
                bytes_in: bytes,
                frames_in: reader.frames() - f0,
                wire_bytes_per_item: bytes as f64 / items.max(1) as f64,
            });
        }
    }
    Ok(out)
}

/// Run the given blocking closure while also exposing a reusable connection.
pub mod testing {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A WebSocket server that answers each call in order — the answer, one
    /// data item, done — and stalls once, before answering call `stall_at`.
    pub async fn stalling_server(stall: Duration, stall_at: u64) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut buf = vec![0u8; 1 << 16];
            let mut head = Vec::new();
            loop {
                let n = s.read(&mut buf).await.unwrap();
                head.extend_from_slice(&buf[..n]);
                if memmem::find(&head, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
            let mut r = FrameReader::default();
            let mut seen = 0u64;
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                r.feed(&buf[..n]);
                let mut out = Vec::new();
                let mut stall_now = false;
                while let Some((_, p)) = r.next_frame() {
                    let Some((a, e)) = token_after(p, b"\"id\":") else { continue };
                    let id = num(&p[a..e]);
                    if seen == stall_at {
                        stall_now = true;
                    }
                    seen += 1;
                    let sub = id + 1;
                    out.push((id, sub, stall_now));
                }
                for (id, sub, stall_now) in out {
                    if stall_now {
                        tokio::time::sleep(stall).await;
                    }
                    let mut w = Vec::new();
                    w.extend(server_text_frame(format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{sub}}}"#).as_bytes()));
                    w.extend(server_text_frame(format!(r#"{{"jsonrpc":"2.0","method":"bench.call","params":{{"subscription":{sub},"result":{{"type":"data","content":{{}}}}}}}}"#).as_bytes()));
                    w.extend(server_text_frame(format!(r#"{{"jsonrpc":"2.0","method":"bench.call","params":{{"subscription":{sub},"result":{{"type":"done"}}}}}}"#).as_bytes()));
                    if s.write_all(&w).await.is_err() {
                        return;
                    }
                }
            }
        });
        addr
    }
}

/// One socket for control calls (stats): a call, its data items' payloads.
pub struct Session {
    conn: Conn,
    reader: FrameReader,
    buf: Vec<u8>,
    next: u64,
}

impl Session {
    pub fn open(url: &str, headers: &[(String, String)]) -> anyhow::Result<Self> {
        let mut conn = connect(url, headers)?;
        let mut reader = FrameReader::default();
        reader.feed(&std::mem::take(&mut conn.leftover));
        Ok(Session { conn, reader, buf: vec![0u8; 1 << 16], next: 1 })
    }
    /// The `result` objects of a call's items, parsed.
    pub fn call(&mut self, call_method: &str, params: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut f = CallFrame::new(call_method, params);
        self.next += 1;
        self.conn.write.lock().unwrap().write_all(f.with_id(self.next))?;
        let mut out = Vec::new();
        loop {
            while let Some((op, p)) = self.reader.next_frame() {
                if op != 1 {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_slice(p)?;
                if let Some(item) = v.pointer("/params/result") {
                    let t = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    out.push(item.clone());
                    if t == "done" || t == "error" {
                        return Ok(out);
                    }
                } else if v.get("error").is_some() {
                    out.push(v);
                    return Ok(out);
                }
            }
            let k = self.conn.read.read(&mut self.buf)?;
            anyhow::ensure!(k > 0, "server closed");
            self.reader.feed(&self.buf[..k]);
        }
    }
}
