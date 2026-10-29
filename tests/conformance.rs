//! POLYGLOT-6 — plexus-core held to the wire's conformance kit
//! (`plexus-wire/conformance`, written from `plexus-wire/spec/`, nothing read
//! from here): a `DynamicHub` serving the kit's reference echo — the
//! activation taken by path from `plexus-wire/reference/echo-rs`, the sibling
//! checkout — on a WebSocket under `key`, and `run.py run --role service`
//! against it, with what plexus-core does not pass yet listed in
//! `plexus-wire/conformance/expect/plexus-core.txt`, each line naming its gap.
//!
//! `python3` or the plexus-wire checkout missing fails, naming it — never a
//! silent skip. (The second half — the same run through a hub mounting
//! `echo-rs --stdio` as a child — lands with POLYGLOT-5's `RemoteChild`.)

#[path = "../../plexus-wire/reference/echo-rs/src/echo.rs"]
mod echo;
#[path = "../../plexus-wire/reference/echo-rs/src/service.rs"]
mod service;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

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

#[tokio::test(flavor = "multi_thread")]
async fn kit_green_on_service() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, keys) = kit(&["keygen", dir.path().to_str().unwrap(), "admin", "viewer"]);
    assert!(ok, "{keys}");
    let principal = |n: &str| keys.lines().find_map(|l| l.strip_prefix(&format!("{n} "))).unwrap().to_string();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let serving = tokio::spawn(service::serve(service::Serve {
        port,
        grants: vec![(principal("admin"), "admin".into()), (principal("viewer"), "viewer".into())],
        origins: vec!["http://127.0.0.1:1".into()],
        max_per_principal: Some(8),
        resource: Some(format!("http://127.0.0.1:{port}")),
        ..Default::default()
    }));
    let t0 = Instant::now();
    while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10) && !serving.is_finished(), "the service did not listen on {port}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let key = |n: &str| dir.path().join(format!("{n}.key")).to_str().unwrap().to_string();
    let expect = wire().join("conformance/expect/plexus-core.txt");
    let url = format!("ws://127.0.0.1:{port}");
    let args: Vec<String> = [
        "run", "--role", "service", "--url", &url, "--key", &key("admin"), "--viewer-key", &key("viewer"),
        "--max-calls", "0", "--idle-secs", "0", "--max-per-principal", "8", "--origin-allowed", "http://127.0.0.1:1",
        "--expect-fail", expect.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (ok, out) = tokio::task::spawn_blocking(move || kit(&args.iter().map(String::as_str).collect::<Vec<_>>())).await.unwrap();
    println!("{out}");
    serving.abort();
    assert!(ok, "the conformance kit is not green on plexus-core's DynamicHub:\n{out}");
}
