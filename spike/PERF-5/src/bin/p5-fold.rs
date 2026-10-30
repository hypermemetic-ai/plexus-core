//! Re-read folded stacks into layer shares: `p5-fold flame/*.folded`
//! writes each `<name>.shares.json` beside it and prints a line each.
fn main() -> anyhow::Result<()> {
    for path in std::env::args().skip(1) {
        let folded = std::fs::read_to_string(&path)?;
        let s = perf5::layers::shares(&folded, |_| true);
        let out = serde_json::json!({"samples": s.samples, "layer_pct": s.pct(), "leaf_pct": s.leaf_pct(), "by_layer": s.by_layer});
        std::fs::write(path.replace(".folded", ".shares.json"), serde_json::to_string_pretty(&out)?)?;
        println!("{path}: {}", serde_json::json!({"samples": s.samples, "layer_pct": s.pct(), "leaf_pct": s.leaf_pct()}));
    }
    Ok(())
}
