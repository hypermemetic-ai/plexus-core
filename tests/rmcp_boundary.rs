//! TRANSPORT-23: `scripts/check-rmcp.sh` fails on any rmcp in plexus-core's
//! tree, whatever the feature set, so one coming back fails `cargo test`.

use std::process::Command;

#[test]
fn plexus_core_carries_no_rmcp() {
    let root = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("bash")
        .arg(format!("{root}/scripts/check-rmcp.sh"))
        .current_dir(root)
        .output()
        .expect("run scripts/check-rmcp.sh");
    assert!(
        out.status.success(),
        "scripts/check-rmcp.sh failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
