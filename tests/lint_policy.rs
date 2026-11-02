//! Lint suppression policy, checked.
//!
//! `#[allow]` is not allowed anywhere: `clippy::allow_attributes` is denied for the workspace, and
//! this test repeats the check for files clippy does not compile in a given run. `#[expect]` is
//! allowed in test code only, with a reason, because it states a violation that is knowingly
//! present and is itself an error once the violation goes away (`unfulfilled_lint_expectations`).
//! Clippy has no lint that forbids `#[expect]` in production code, so this is where that rule lives.
//!
//! Test code is a file under a `tests/` directory, the `libra-test-harness` crate, the fuzz targets, or
//! whatever follows the first `#[cfg(test)]` in a source file. The workspace puts its test module at the end of the
//! file, and a production item after one would be a layout problem in its own right.
//!
//! The lint levels themselves live in the root manifest and reach a crate only when its manifest
//! inherits them, so every member is checked to do so.

mod workspace_sources;

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};
use toml::{Table, Value};

/// The crate that exists only to support tests.
const TEST_SUPPORT_CRATE: &str = "libra-test-harness";

/// The directory of the fuzz targets, which are test code throughout.
const FUZZ_DIRECTORY: &str = "fuzz";

/// What a line suppresses a lint with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suppression {
    Allow,
    Expect,
}

/// Which kind of suppression a line holds, if any. Comments do not count.
fn suppression_on(line: &str) -> Option<Suppression> {
    let code = line.trim_start();
    if code.starts_with("//") {
        return None;
    }

    ["#[allow(", "#![allow(", "#[cfg_attr(", "#![cfg_attr("]
        .iter()
        .any(|marker| code.starts_with(marker) && code.contains("allow("))
        .then_some(Suppression::Allow)
        .or_else(|| {
            ["#[expect(", "#![expect("]
                .iter()
                .any(|marker| code.starts_with(marker))
                .then_some(Suppression::Expect)
        })
}

/// The violations in one file's text, as `line: reason`. `is_test_file` exempts `#[expect]` for the
/// whole file; otherwise it is exempt after the first `#[cfg(test)]`.
fn violations(text: &str, is_test_file: bool) -> Vec<String> {
    let mut in_tests = is_test_file;
    let mut found = Vec::new();

    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            in_tests = true;
        }

        match suppression_on(line) {
            Some(Suppression::Allow) => found.push(format!(
                "{}: `#[allow]` is not allowed; satisfy the lint, or use `#[expect]` in test code",
                index + 1
            )),
            Some(Suppression::Expect) if !in_tests => found.push(format!("{}: `#[expect]` is not allowed in production code; satisfy the lint", index + 1)),
            Some(Suppression::Expect) | None => {}
        }
    }

    found
}

/// Whether a file is test code as a whole.
fn is_test_file(path: &Path) -> bool {
    path.components().any(|component| {
        let part = component.as_os_str();
        part == "tests" || part == TEST_SUPPORT_CRATE || part == FUZZ_DIRECTORY
    })
}

#[test]
fn no_lint_is_suppressed_where_it_must_not_be() -> io::Result<()> {
    let root = workspace_sources::root();
    let files = workspace_sources::all()?;

    let mut offences = Vec::new();
    for file in &files {
        // This file spells the markers it searches for, which is not a suppression.
        if file.ends_with("tests/lint_policy.rs") {
            continue;
        }
        let relative = file.strip_prefix(root).unwrap_or(file);
        for violation in violations(&fs::read_to_string(file)?, is_test_file(relative)) {
            offences.push(format!("{}:{violation}", relative.display()));
        }
    }

    assert!(offences.is_empty(), "lint suppression policy violated:\n{}", offences.join("\n"));
    assert!(!files.is_empty(), "no sources were found, so nothing was checked");

    Ok(())
}

/// The manifest of every workspace member: the root package and each crate under `crates/`.
fn member_manifests() -> io::Result<Vec<PathBuf>> {
    let root = workspace_sources::root();
    let mut manifests = vec![root.join("Cargo.toml")];
    for entry in fs::read_dir(root.join("crates"))? {
        let manifest = entry?.path().join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }

    Ok(manifests)
}

/// Whether a manifest takes its lint levels from the workspace (`[lints] workspace = true`).
fn inherits_workspace_lints(manifest: &str) -> bool {
    manifest
        .parse::<Table>()
        .is_ok_and(|table| matches!(table.get("lints").and_then(|lints| lints.get("workspace")), Some(Value::Boolean(true))))
}

#[test]
fn every_member_inherits_the_workspace_lints() -> io::Result<()> {
    let root = workspace_sources::root();
    let manifests = member_manifests()?;

    let mut offences = Vec::new();
    for manifest in &manifests {
        if !inherits_workspace_lints(&fs::read_to_string(manifest)?) {
            offences.push(manifest.strip_prefix(root).unwrap_or(manifest).display().to_string());
        }
    }

    assert!(offences.is_empty(), "these manifests lack `[lints] workspace = true`:\n{}", offences.join("\n"));
    assert!(manifests.len() > 1, "no crate manifests were found, so nothing was checked");

    Ok(())
}

#[test]
fn only_an_explicit_workspace_inheritance_counts() {
    assert!(inherits_workspace_lints("[lints]\nworkspace = true\n"));
    assert!(!inherits_workspace_lints("[package]\nname = \"x\"\n"));
    assert!(!inherits_workspace_lints("[lints]\nworkspace = false\n"));
    assert!(!inherits_workspace_lints("[lints.rust]\nunsafe_code = \"allow\"\n"));
}

#[test]
fn allow_is_a_violation_everywhere() {
    for text in [
        "#[allow(dead_code, reason = \"x\")]\nfn f() {}",
        "#![allow(clippy::pedantic, reason = \"x\")]",
        "    #[allow(unused)]",
    ] {
        assert_eq!(violations(text, false).len(), 1, "{text}");
        assert_eq!(violations(text, true).len(), 1, "{text} in a test file");
    }
}

#[test]
fn expect_is_a_violation_in_production_and_fine_in_tests() {
    let expect = "#[expect(clippy::unwrap_used, reason = \"x\")]\nfn f() {}";

    assert_eq!(violations(expect, false).len(), 1);
    assert_eq!(violations(expect, true), [] as [String; 0]);
    assert_eq!(
        violations(&format!("fn g() {{}}\n#[cfg(test)]\nmod tests {{\n{expect}\n}}"), false),
        [] as [String; 0]
    );
    assert_eq!(violations(&format!("{expect}\n#[cfg(test)]\nmod tests {{}}"), false).len(), 1);
}

#[test]
fn a_comment_that_mentions_a_suppression_is_not_one() {
    assert_eq!(violations("// #[allow(dead_code)] was removed", false), [] as [String; 0]);
    assert_eq!(violations("/// use `#[expect]` instead", false), [] as [String; 0]);
}
