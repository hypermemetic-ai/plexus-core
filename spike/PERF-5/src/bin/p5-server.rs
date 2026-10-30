//! PERF-5's echo service on a port. SIGUSR1 starts the in-process sampler
//! (pprof, SIGPROF at --hz), SIGUSR2 stops it and writes
//! `<prefix>.svg`, `<prefix>.folded` and `<prefix>.shares.json`.

use clap::Parser;
use perf5::{alloc, echo, layers};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 4478)]
    port: u16,
    /// multi | current | percore (PERF-17 E4: a current-thread runtime per
    /// worker, each pinned to a core and accepting on the same port with
    /// SO_REUSEPORT)
    #[arg(long, default_value = "multi")]
    rt: String,
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// the grant gate on every call (menger's way) or none
    #[arg(long, default_value = "on")]
    gate: String,
    #[arg(long)]
    count_allocs: bool,
    #[arg(long, default_value = "flame/server")]
    flame_prefix: String,
    #[arg(long, default_value_t = 1999)]
    hz: i32,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    alloc::enable(a.count_allocs);
    if a.rt == "percore" {
        return percore(&a);
    }
    let rt = match a.rt.as_str() {
        "current" => tokio::runtime::Builder::new_current_thread().enable_all().build()?,
        _ => tokio::runtime::Builder::new_multi_thread().worker_threads(a.workers).enable_all().build()?,
    };
    rt.block_on(async move {
        let gated = a.gate == "on";
        let svc = if gated { echo::gated_service() } else { echo::plain_service() };
        let (handle, addr) = echo::serve(svc, a.port, gated).await?;
        println!("listening ws://{addr} pid {} rt {} gate {} alloc {}", std::process::id(), a.rt, a.gate, alloc::INNER);
        use tokio::signal::unix::{signal, SignalKind};
        let mut u1 = signal(SignalKind::user_defined1())?;
        let mut u2 = signal(SignalKind::user_defined2())?;
        let mut term = signal(SignalKind::terminate())?;
        let mut guard: Option<pprof::ProfilerGuard<'static>> = None;
        let mut prefix_n = 0;
        loop {
            tokio::select! {
                _ = u1.recv() => {
                    guard = Some(pprof::ProfilerGuardBuilder::default().frequency(a.hz).build()?);
                    eprintln!("sampling at {} Hz", a.hz);
                }
                _ = u2.recv() => {
                    if let Some(g) = guard.take() {
                        let report = g.report().build()?;
                        let prefix = if prefix_n == 0 { a.flame_prefix.clone() } else { format!("{}.{prefix_n}", a.flame_prefix) };
                        prefix_n += 1;
                        write_report(&report, &prefix)?;
                        eprintln!("wrote {prefix}.svg");
                    }
                }
                _ = term.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        handle.stop().ok();
        anyhow::Ok(())
    })
}

fn write_report(report: &pprof::Report, prefix: &str) -> anyhow::Result<()> {
    if let Some(dir) = std::path::Path::new(prefix).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut folded = String::new();
    for (frames, count) in report.data.iter() {
        let mut names: Vec<String> = Vec::new();
        // pprof's frames are innermost first; folded stacks are root first.
        for f in frames.frames.iter().rev() {
            for sym in f.iter().rev() {
                names.push(sym.name().replace(';', ":"));
            }
        }
        folded.push_str(&format!("{};{} {}\n", frames.thread_name.replace(';', ":"), names.join(";"), count));
    }
    std::fs::write(format!("{prefix}.folded"), &folded)?;
    let f = std::fs::File::create(format!("{prefix}.svg"))?;
    let mut opts = pprof::flamegraph::Options::default();
    opts.title = prefix.rsplit('/').next().unwrap_or(prefix).to_string();
    report.flamegraph_with_options(f, &mut opts)?;
    let s = layers::shares(&folded, |_| true);
    let out = serde_json::json!({"samples": s.samples, "layer_pct": s.pct(), "leaf_pct": s.leaf_pct(), "by_layer": s.by_layer});
    std::fs::write(format!("{prefix}.shares.json"), serde_json::to_string_pretty(&out)?)?;
    Ok(())
}

/// PERF-17 E4: `--rt percore` — `--workers` current-thread runtimes, each on
/// its own thread pinned to one of the process's CPUs, each serving the same
/// service on the same port through SO_REUSEPORT (plexus-transport's
/// PERF17_REUSEPORT). The kernel spreads connections across them by hash.
fn percore(a: &Args) -> anyhow::Result<()> {
    std::env::set_var("PERF17_REUSEPORT", "1");
    let gated = a.gate == "on";
    let svc = if gated { echo::gated_service() } else { echo::plain_service() };
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    let (tx, rx) = std::sync::mpsc::channel();
    for w in 0..a.workers {
        let (svc, port, tx) = (svc.clone(), a.port, tx.clone());
        let core = cores.get(w % cores.len().max(1)).copied();
        std::thread::spawn(move || {
            if let Some(c) = core {
                core_affinity::set_for_current(c);
            }
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let (_handle, addr) = echo::serve(svc, port, gated).await.unwrap();
                tx.send(addr).unwrap();
                std::future::pending::<()>().await;
            });
        });
    }
    let addr = rx.recv()?;
    for _ in 1..a.workers {
        rx.recv()?;
    }
    println!("listening ws://{addr} pid {} rt percore x{} gate {} alloc {}", std::process::id(), a.workers, a.gate, alloc::INNER);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
        anyhow::Ok(())
    })?;
    std::process::exit(0)
}
