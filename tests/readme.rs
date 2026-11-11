//! The code in README.md and docs/ is the code the tests run.
//!
//! A fenced block is named by the comment above it,
//! `<!-- tests/readme_example.rs -->`: its lines stand together in that
//! file, at any indentation. A named block that differs from its file fails
//! this test; so does a file that is gone, and a `rust` block that names no
//! file.

use std::fs;
use std::path::Path;

const PAGES: &[&str] = &["README.md", "docs/activations.md", "docs/service-root.md", "docs/gate.md", "docs/keyed-peers.md"];

/// The lines without their common indentation and trailing spaces.
fn dedented(lines: &[&str]) -> Vec<String> {
    let indent = lines.iter().filter(|l| !l.trim().is_empty()).map(|l| l.len() - l.trim_start().len()).min().unwrap_or(0);
    lines.iter().map(|l| l.get(indent..).unwrap_or("").trim_end().to_string()).collect()
}

/// What is wrong with `page`'s blocks, and how many it checked.
fn check(root: &Path, page: &str, wrong: &mut Vec<String>) -> usize {
    let text = fs::read_to_string(root.join(page)).unwrap_or_else(|e| panic!("{page}: {e}"));
    let lines: Vec<&str> = text.lines().collect();
    let (mut above, mut index, mut checked) = ("", 0, 0);
    while index < lines.len() {
        let line = lines[index];
        if let Some(language) = line.strip_prefix("```") {
            let close = (index + 1..lines.len())
                .find(|&i| lines[i].starts_with("```"))
                .unwrap_or_else(|| panic!("{page}:{}: the block is not closed", index + 1));
            let source = above.strip_prefix("<!-- ").and_then(|rest| rest.strip_suffix(" -->"));
            match source {
                Some(source) => {
                    let file = fs::read_to_string(root.join(source)).unwrap_or_else(|e| panic!("{page}:{}: {source}: {e}", index + 1));
                    let file: Vec<&str> = file.lines().collect();
                    let quoted = dedented(&lines[index + 1..close]);
                    if quoted.is_empty() || !file.windows(quoted.len()).any(|window| dedented(window) == quoted) {
                        wrong.push(format!("{page}:{}: not what {source} says", index + 1));
                    }
                    checked += 1;
                }
                None if language.trim() == "rust" => wrong.push(format!("{page}:{}: the block names no file in a comment above it", index + 1)),
                None => {}
            }
            index = close;
            above = "";
        } else if !line.trim().is_empty() {
            above = line;
        }
        index += 1;
    }
    checked
}

#[test]
fn every_named_block_is_its_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut wrong = Vec::new();
    let checked: usize = PAGES.iter().map(|page| check(root, page, &mut wrong)).sum();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(checked, 3, "README.md's example, and one each in docs/activations.md and docs/service-root.md");
}
