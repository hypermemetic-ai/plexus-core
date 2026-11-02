//! POLYGLOT-6 — plexus-core held to the wire's conformance kit
//! (`plexus-wire/conformance`, written from `plexus-wire/spec/`, nothing read
//! from here): a `DynamicHub` serving the kit's reference echo — the
//! activation taken by path from `plexus-wire/reference/echo-rs`, the sibling
//! checkout — on a WebSocket under `key`, and `run.py run --role service`
//! against it, with what plexus-core does not pass yet listed in
//! `plexus-wire/conformance/expect/plexus-core.txt`, each line naming its gap.
//!
//! POLYGLOT-5 — the second half: the same run against a service mounting the
//! reference echo as a child (`echo-rs --stdio`, through `RemoteChild`), where
//! the kit's `hop.*` tests apply; `expect/plexus-core-child.txt`. The child
//! is `PLEXUS_ECHO_RS` when that names a program, else built from the
//! sibling checkout (its own workspace) into this target's scratch.
//!
//! `python3`, cargo or the plexus-wire checkout missing fails, naming it —
//! never a silent skip.

#[path = "../../plexus-wire/reference/echo-rs/src/echo.rs"]
mod echo;
#[path = "../../plexus-wire/reference/echo-rs/src/service.rs"]
mod service;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use plexus_core::plexus::{ChildOptions, ChildSpec, RemoteChild};
use plexus_core::DynamicHub;

fn wire() -> PathBuf {
    let p = std::env::var_os("PLEXUS_WIRE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-wire"));
    assert!(p.join("conformance/run.py").exists(), "the conformance kit is not at {} (a plexus-wire checkout beside plexus-core, or PLEXUS_WIRE)", p.display());
    p
}

fn kit(args: &[&str]) -> (bool, String) {
    let out = Command::new("python3")
        .arg("-I")
        .arg(wire().join("conformance/run.py"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("python3 (the conformance kit's interpreter) did not run: {e}"));
    (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

/// The kit's two keys, `admin.key` and `viewer.key`, made fresh in a
/// temporary directory, and the principal each proves as.
fn keygen() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (ok, keys) = kit(&["keygen", dir.path().to_str().unwrap(), "admin", "viewer"]);
    assert!(ok, "{keys}");
    let principal = |n: &str| keys.lines().find_map(|l| l.strip_prefix(&format!("{n} "))).unwrap().to_string();
    let (admin, viewer) = (principal("admin"), principal("viewer"));
    (dir, admin, viewer)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// What the service is served with — the deployment `--role service` is told of.
fn serve_opts(port: u16, admin: &str, viewer: &str) -> service::Serve {
    service::Serve {
        port,
        grants: vec![(admin.to_string(), "admin".into()), (viewer.to_string(), "viewer".into())],
        origins: vec!["http://127.0.0.1:1".into()],
        max_per_principal: Some(8),
        resource: Some(format!("http://127.0.0.1:{port}")),
        ..Default::default()
    }
}

/// `run --role service` against the service `serving` listens with on
/// `port`, held to `conformance/expect/<expect>`; the service stopped after.
async fn kit_against(port: u16, serving: tokio::task::JoinHandle<anyhow::Result<()>>, keys: &Path, expect: &str) -> (bool, String) {
    let t0 = Instant::now();
    while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10) && !serving.is_finished(), "the service did not listen on {port}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let key = |n: &str| keys.join(format!("{n}.key")).to_str().unwrap().to_string();
    let expect = wire().join("conformance/expect").join(expect);
    let url = format!("ws://127.0.0.1:{port}");
    let mut args: Vec<String> = [
        "run", "--role", "service", "--url", &url, "--key", &key("admin"), "--viewer-key", &key("viewer"),
        "--max-calls", "0", "--idle-secs", "0", "--max-per-principal", "8", "--origin-allowed", "http://127.0.0.1:1",
        "--expect-fail", expect.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // PERF-9: every case in JSON and in msgpack, once the kit beside this
    // checkout knows spec/13 (plexus-wire's main does with the release that
    // carries msgpack; before it, the kit's JSON run alone).
    if wire().join("spec/13-encodings.md").is_file() {
        args.extend(["--encoding".to_string(), "json,msgpack".to_string()]);
    }
    let out = tokio::task::spawn_blocking(move || kit(&args.iter().map(String::as_str).collect::<Vec<_>>())).await.unwrap();
    serving.abort();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn kit_green_on_service() {
    let (dir, admin, viewer) = keygen();
    let port = free_port();
    let serving = tokio::spawn(service::serve(serve_opts(port, &admin, &viewer)));
    let (ok, out) = kit_against(port, serving, dir.path(), "plexus-core.txt").await;
    println!("{out}");
    assert!(ok, "the conformance kit is not green on plexus-core's DynamicHub:\n{out}");
}

/// plexus-wire's reference echo as a program: `PLEXUS_ECHO_RS` when it names
/// one, else `reference/echo-rs` built (debug, its own workspace) into
/// `CARGO_TARGET_TMPDIR/echo-rs`.
fn echo_rs() -> PathBuf {
    if let Some(p) = std::env::var_os("PLEXUS_ECHO_RS") {
        let p = PathBuf::from(p);
        assert!(p.is_file(), "PLEXUS_ECHO_RS names no program: {}", p.display());
        return p;
    }
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("echo-rs");
    let out = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--bin", "echo-rs", "--manifest-path"])
        .arg(wire().join("reference/echo-rs/Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .output()
        .unwrap_or_else(|e| panic!("cargo (to build plexus-wire's reference/echo-rs) did not run: {e}"));
    assert!(out.status.success(), "plexus-wire's reference/echo-rs did not build:\n{}", String::from_utf8_lossy(&out.stderr));
    target.join("debug/echo-rs")
}

#[tokio::test(flavor = "multi_thread")]
async fn kit_green_through_child() {
    let program = echo_rs();
    let (dir, admin, viewer) = keygen();
    let spec = ChildSpec::Stdio { name: "echo".into(), argv: vec![program.to_string_lossy().into_owned(), "--stdio".into()] };
    let child = RemoteChild::connect(spec, ChildOptions::for_service(service::NS))
        .await
        .unwrap_or_else(|e| panic!("{} --stdio did not mount as a child: {e}", program.display()));
    let port = free_port();
    let mounted = DynamicHub::new(service::NS).register(child.clone());
    let serving = tokio::spawn(service::serve_over(mounted, serve_opts(port, &admin, &viewer)));
    let (ok, out) = kit_against(port, serving, dir.path(), "plexus-core-child.txt").await;
    println!("{out}");
    println!("the child, as the seam saw it: {:?}", child.stats());
    assert!(ok, "the conformance kit is not green through a child (plexus-wire's echo-rs --stdio, mounted by RemoteChild):\n{out}");
}
