//! PERF-5's client: one JSON line per run on stdout.
//!
//!   p5-client seq    --url U [--method bench.once] [--n 5000]
//!   p5-client open   --url U --rate 2000 [--conns 1] [--n 10000]
//!   p5-client max    --url U --conns 64 --inflight 8 --secs 3
//!   p5-client stream --url U --to 10000 --size 64 --server-pid P
//!   p5-client allocs --url U --server-pid P     (per call, per item; needs --count-allocs on the server)

use std::io::Write;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use perf5::{echo, hist::Lat, procstat, rawws};
use serde_json::json;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, global = true, default_value = "ws://127.0.0.1:4478/")]
    url: String,
    /// the call method (`{service}.call`)
    #[arg(long, global = true, default_value = "perf5.call")]
    call: String,
    #[arg(long, global = true, default_value = "bench.once")]
    method: String,
    /// the method's params (JSON)
    #[arg(long, global = true, default_value = "{}")]
    params: String,
    /// `Authorization: Bearer` value; `key:NAME` proves ~/.plexus/keys/NAME.key; `none`
    #[arg(long, global = true, default_value = "bench")]
    bearer: String,
    #[arg(long, global = true, default_value = "")]
    label: String,
}

#[derive(Subcommand)]
enum Cmd {
    Seq { #[arg(long, default_value_t = 5000)] n: u64, #[arg(long, default_value_t = 200)] warm: u64 },
    Open { #[arg(long, default_value_t = 2000.0)] rate: f64, #[arg(long, default_value_t = 1)] conns: u64, #[arg(long, default_value_t = 10000)] n: u64, #[arg(long, default_value_t = 200)] warm: u64 },
    Max { #[arg(long, default_value_t = 1)] conns: u64, #[arg(long, default_value_t = 1)] inflight: u64, #[arg(long, default_value_t = 3.0)] secs: f64, #[arg(long)] server_pid: Option<u32> },
    Stream { #[arg(long, default_value_t = 10000)] to: u64, #[arg(long, default_value_t = 64)] size: u64, #[arg(long, default_value_t = 2)] warm: u64, #[arg(long)] server_pid: Option<u32> },
    Allocs { #[arg(long)] server_pid: Option<u32>, #[arg(long, default_value_t = 2000)] n: u64 },
}

fn headers(a: &Args) -> anyhow::Result<Vec<(String, String)>> {
    if a.bearer == "none" {
        return Ok(vec![]);
    }
    if let Some(name) = a.bearer.strip_prefix("key:") {
        let aud = a.url.trim_end_matches('/').to_string();
        return Ok(vec![("Authorization".into(), format!("Bearer {}", keyproof::proof(name, &aud)?))]);
    }
    Ok(vec![("Authorization".into(), format!("Bearer {}", a.bearer))])
}

mod keyproof {
    //! spec/00 §Key proof, as the kit's keyproof.py does it. The seed is read,
    //! used to sign, and dropped — never printed.
    use base64::Engine;
    pub fn proof(name: &str, aud: &str) -> anyhow::Result<String> {
        let path = std::path::PathBuf::from(std::env::var("HOME")?).join(".plexus/keys").join(format!("{name}.key"));
        let raw = std::fs::read(&path)?;
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        let b64 = base64::engine::general_purpose::STANDARD;
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let seed: [u8; 32] = b64
            .decode(&text)
            .ok()
            .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(&text).ok())
            .or_else(|| url.decode(text.trim_end_matches('=')).ok())
            .or_else(|| (raw.len() == 32).then(|| raw.clone()))
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("{}: not a 32-byte seed", path.display()))?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let nonce: [u8; 32] = rand::random();
        let n = url.encode(nonce);
        let msg = format!("plexus-key-login/v1\n{aud}\n{name}\n{n}\n{ts}");
        use ed25519_dalek::Signer;
        let sig = sk.sign(msg.as_bytes());
        let body = format!(
            r#"{{"v":1,"key":"{}","aud":"{aud}","agent":"{name}","nonce":"{n}","ts":{ts},"sig":"{}"}}"#,
            sk.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
            url.encode(sig.to_bytes())
        );
        Ok(format!("plexus-key.{}", url.encode(body)))
    }
}

fn params_of(a: &Args) -> String {
    format!(r#"{{"method":"{}","params":{}}}"#, a.method, a.params)
}

fn stats(s: &mut rawws::Session, call: &str) -> anyhow::Result<serde_json::Value> {
    let items = s.call(call, r#"{"method":"bench.stats","params":{}}"#)?;
    Ok(items.first().and_then(|i| i.get("content")).cloned().unwrap_or_default())
}

fn delta(a: &serde_json::Value, b: &serde_json::Value, k: &str) -> f64 {
    b[k].as_f64().unwrap_or(0.0) - a[k].as_f64().unwrap_or(0.0)
}

fn proc_json(d: &procstat::Proc, per: f64) -> serde_json::Value {
    let t = procstat::ticks_per_s() as f64;
    json!({
        "syscr_per": d.syscr as f64 / per, "syscw_per": d.syscw as f64 / per,
        "wchar_per": d.wchar as f64 / per, "rchar_per": d.rchar as f64 / per,
        "user_us_per": d.utime_ticks as f64 / t * 1e6 / per, "sys_us_per": d.stime_ticks as f64 / t * 1e6 / per,
        "cpu_us_per": d.cpu_ns as f64 / 1000.0 / per, "vol_cs_per": d.vol_cs as f64 / per, "invol_cs_per": d.invol_cs as f64 / per, "threads": d.threads,
    })
}

fn emit(mut v: serde_json::Value, a: &Args, scenario: &str) {
    v["scenario"] = json!(scenario);
    v["label"] = json!(a.label);
    v["url"] = json!(a.url);
    v["unix"] = json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    v["loadavg"] = json!(std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" "));
    println!("{v}");
    std::io::stdout().flush().ok();
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let h = headers(&a)?;
    let _ = echo::BENCH_PRINCIPAL;
    match &a.cmd {
        Cmd::Seq { n, warm } => {
            let r = rawws::sequential_calls(&a.url, &h, &a.call, &params_of(&a), *n, *warm)?;
            emit(json!({"summary": r.summary, "calls_per_s": r.calls_per_s, "n": n}), &a, "call.one_item.seq");
        }
        Cmd::Open { rate, conns, n, warm } => {
            let per = *n / conns;
            let mut ths = Vec::new();
            for _ in 0..*conns {
                let (url, h, call, p) = (a.url.clone(), h.clone(), a.call.clone(), params_of(&a));
                let r = rate / *conns as f64;
                let w = *warm;
                ths.push(std::thread::spawn(move || rawws::open_loop_calls_blocking(&url, &h, &call, &p, per, r, w)));
            }
            let mut lat = Lat::new();
            let (mut late_p99, mut errors, mut bytes_in, mut frames_in, mut bytes_out, mut wall) = (0f64, 0, 0, 0, 0, 0f64);
            for t in ths {
                let r = t.join().unwrap()?;
                for us in &r.latencies_us {
                    lat.record_us(*us);
                }
                late_p99 = late_p99.max(r.send_lateness.p99_us);
                errors += r.errors;
                bytes_in += r.bytes_in;
                bytes_out += r.bytes_out;
                frames_in += r.frames_in;
                wall = f64::max(wall, r.wall_s);
            }
            let calls = per * conns;
            emit(json!({"summary": lat.summary(), "rate": rate, "conns": conns, "calls": calls, "achieved_per_s": calls as f64 / wall,
                "send_lateness_p99_us": late_p99, "errors": errors, "bytes_in_per_call": bytes_in as f64 / calls as f64,
                "bytes_out_per_call": bytes_out as f64 / calls as f64, "frames_in_per_call": frames_in as f64 / calls as f64}), &a, "call.one_item.open");
        }
        Cmd::Max { conns, inflight, secs, server_pid } => {
            let p0 = server_pid.map(procstat::read).transpose()?;
            let stop = Instant::now() + Duration::from_secs_f64(*secs);
            let mut ths = Vec::new();
            for _ in 0..*conns {
                let (url, h, call, p, k) = (a.url.clone(), h.clone(), a.call.clone(), params_of(&a), *inflight);
                ths.push(std::thread::spawn(move || closed_loop(&url, &h, &call, &p, k, stop)));
            }
            let mut total = 0u64;
            let mut lat = Lat::new();
            for t in ths {
                let (n, l) = t.join().unwrap()?;
                total += n;
                for us in l {
                    lat.record_us(us);
                }
            }
            let mut v = json!({"conns": conns, "inflight": inflight, "calls": total, "calls_per_s": total as f64 / secs, "summary": lat.summary()});
            if let (Some(pid), Some(p0)) = (server_pid, p0) {
                v["server"] = proc_json(&(procstat::read(*pid)? - p0), total as f64);
            }
            emit(v, &a, "call.one_item.max");
        }
        Cmd::Stream { to, size, warm, server_pid } => {
            let p = format!(r#"{{"method":"bench.count","params":{{"to":{to},"size":{size}}}}}"#);
            rawws::one_stream(&a.url, &h, &a.call, &p, *warm, 0)?;
            let mut ctl = rawws::Session::open(&a.url, &h)?;
            let s_base0 = stats(&mut ctl, &a.call)?;
            let s_base1 = stats(&mut ctl, &a.call)?;
            for run in 0..3 {
                let s0 = stats(&mut ctl, &a.call)?;
                let p0 = server_pid.map(procstat::read).transpose()?;
                let r = rawws::one_stream(&a.url, &h, &a.call, &p, 0, 1)?.remove(0);
                let pd = server_pid.map(|pid| procstat::read(pid).map(|p1| p1 - p0.unwrap())).transpose()?;
                let s1 = stats(&mut ctl, &a.call)?;
                let items = r.items as f64;
                let stats_cost = delta(&s_base0, &s_base1, "allocs");
                let stats_bytes = delta(&s_base0, &s_base1, "bytes");
                let mut v = json!({"run": run, "to": to, "size": size, "items_per_s": r.items_per_s, "secs": r.secs, "items": r.items,
                    "wire_bytes_per_item": r.wire_bytes_per_item, "frames_per_item": r.frames_in as f64 / items,
                    "allocs_per_item": (delta(&s0, &s1, "allocs") - stats_cost) / items,
                    "alloc_bytes_per_item": (delta(&s0, &s1, "bytes") - stats_bytes) / items,
                    "spawned_tasks": delta(&s0, &s1, "spawned_tasks") - delta(&s_base0, &s_base1, "spawned_tasks")});
                if let Some(d) = pd {
                    v["server"] = proc_json(&d, items);
                }
                emit(v, &a, &format!("stream.10k.{size}B"));
            }
        }
        Cmd::Allocs { server_pid, n } => {
            let mut ctl = rawws::Session::open(&a.url, &h)?;
            let p = params_of(&a);
            let mut s = rawws::Session::open(&a.url, &h)?;
            for _ in 0..200 {
                s.call(&a.call, &p)?;
            }
            let b0 = stats(&mut ctl, &a.call)?;
            let b1 = stats(&mut ctl, &a.call)?;
            for run in 0..3 {
                let s0 = stats(&mut ctl, &a.call)?;
                let p0 = server_pid.map(procstat::read).transpose()?;
                for _ in 0..*n {
                    s.call(&a.call, &p)?;
                }
                let pd = server_pid.map(|pid| procstat::read(pid).map(|p1| p1 - p0.unwrap())).transpose()?;
                let s1 = stats(&mut ctl, &a.call)?;
                let per = *n as f64;
                let mut v = json!({"run": run, "method": a.method, "calls": n,
                    "allocs_per_call": (delta(&s0, &s1, "allocs") - delta(&b0, &b1, "allocs")) / per,
                    "alloc_bytes_per_call": (delta(&s0, &s1, "bytes") - delta(&b0, &b1, "bytes")) / per,
                    "spawned_tasks_per_call": (delta(&s0, &s1, "spawned_tasks") - delta(&b0, &b1, "spawned_tasks")) / per});
                if let Some(d) = pd {
                    v["server"] = proc_json(&d, per);
                }
                emit(v, &a, "call.one_item.allocs");
            }
        }
    }
    Ok(())
}

/// One socket, `k` calls kept in flight until `stop`.
fn closed_loop(url: &str, h: &[(String, String)], call: &str, p: &str, k: u64, stop: Instant) -> anyhow::Result<(u64, Vec<f64>)> {
    use std::collections::HashMap;
    use std::io::Read;
    let mut conn = rawws::connect(url, h)?;
    let mut reader = rawws::FrameReader::default();
    reader.feed(&std::mem::take(&mut conn.leftover));
    let mut frame = rawws::CallFrame::new(call, p);
    let mut buf = vec![0u8; 1 << 16];
    let mut started: HashMap<u64, Instant> = HashMap::new();
    let mut subs: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut next = 0u64;
    let mut done = 0u64;
    let mut lats = Vec::new();
    let send = |id: u64, frame: &mut rawws::CallFrame, conn: &rawws::Conn| -> anyhow::Result<()> {
        conn.write.lock().unwrap().write_all(frame.with_id(id))?;
        Ok(())
    };
    for _ in 0..k {
        started.insert(next, Instant::now());
        send(next, &mut frame, &conn)?;
        next += 1;
    }
    while !started.is_empty() {
        let n = conn.read.read(&mut buf)?;
        anyhow::ensure!(n > 0, "closed");
        reader.feed(&buf[..n]);
        let mut finished = Vec::new();
        while let Some((op, pl)) = reader.next_frame() {
            if op != 1 {
                continue;
            }
            match rawws::classify(pl) {
                rawws::Msg::Answer { id, sub } => {
                    subs.insert(sub, id);
                }
                rawws::Msg::Item { sub, kind: rawws::Kind::Done } => {
                    if let Some(id) = subs.remove(&sub) {
                        finished.push(id);
                    }
                }
                rawws::Msg::CallError { .. } | rawws::Msg::Fatal(_) | rawws::Msg::Item { kind: rawws::Kind::Error, .. } => anyhow::bail!("a call failed: {}", String::from_utf8_lossy(pl)),
                _ => {}
            }
        }
        for id in finished {
            if let Some(t) = started.remove(&id) {
                lats.push(t.elapsed().as_nanos() as f64 / 1000.0);
                done += 1;
            }
            if Instant::now() < stop {
                started.insert(next, Instant::now());
                send(next, &mut frame, &conn)?;
                next += 1;
            }
        }
    }
    Ok((done, lats))
}
