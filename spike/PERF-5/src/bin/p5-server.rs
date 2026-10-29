//! PERF-5's echo service on a port. SIGUSR1 starts the in-process sampler
//! (pprof, SIGPROF at --hz), SIGUSR2 stops it and writes
//! `<prefix>.svg`, `<prefix>.folded` and `<prefix>.shares.json`.

use clap::Parser;
use perf5::{alloc, echo, layers};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 4478)]
    port: u16,
    /// multi | current
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
    let rt = match a.rt.as_str() {
        "current" => tokio::runtime::Builder::new_current_thread().enable_all().build()?,
        _ => tokio::runtime::Builder::new_multi_thread().worker_threads(a.workers).enable_all().build()?,
    };
    rt.block_on(async move {
        let gated = a.gate == "on";
        let svc = if gated { echo::gated_service() } else { echo::plain_service() };
        let (handle, addr) = echo::serve(svc, a.port, gated).await?;
        println!("listening ws://{addr} pid {} rt {} gate {}", std::process::id(), a.rt, a.gate);
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
