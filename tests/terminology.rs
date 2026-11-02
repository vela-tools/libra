//! The policy vocabulary, checked.
//!
//! Each concept of the policy language has one word, used the same way in identifiers, doc
//! comments and comments: a policy's effect is `allow` or `deny`, the outcome of evaluating a
//! request is a decision, enforcement on the request is narrowing, and enforcement on the response
//! is filtering. The words listed in [`RETIRED`] named those concepts too, and a second word for one
//! concept is how two layers come to mean different things by it.
//!
//! String literals are not checked: a wire format Libra does not own (an OAuth `grant_type`, an
//! identity provider's setting) keeps its own spelling, and a test may spell a retired word to
//! show that it is refused.

mod workspace_sources;

use std::{fs, io};

/// The retired words and the word that replaced each.
const RETIRED: [(&str, &str); 5] = [
    ("verdict", "decision, or visibility for a per-item outcome"),
    ("permit", "allow"),
    ("grant", "allow, or restriction for what an allow is limited to"),
    ("clamp", "narrow"),
    ("redact", "filter"),
];

/// A line with its string literals removed, lowercased.
///
/// Raw strings are not recognised; none of them holds a retired word.
fn without_literals(line: &str) -> String {
    let mut kept = String::with_capacity(line.len());
    let mut in_literal = false;
    let mut escaped = false;

    for character in line.chars() {
        match (in_literal, escaped, character) {
            (true, true, _) => escaped = false,
            (true, false, '\\') => escaped = true,
            (true, false, '"') | (false, _, '"') => in_literal = !in_literal,
            (true, false, _) => {}
            (false, _, other) => kept.extend(other.to_lowercase()),
        }
    }

    kept
}

/// The retired words in one file's text, as `line: word (use replacement)`.
fn offences(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .flat_map(|(index, line)| {
            let code = without_literals(line);
            RETIRED
                .iter()
                .filter(move |(word, _)| code.contains(word))
                .map(move |(word, replacement)| format!("{}: '{word}' (use {replacement})", index + 1))
        })
        .collect()
}

#[test]
fn no_retired_word_names_a_policy_concept() -> io::Result<()> {
    let root = workspace_sources::root();
    let files = workspace_sources::all()?;

    let mut found = Vec::new();
    for file in &files {
        // This file lists the retired words in order to look for them.
        if file.ends_with("tests/terminology.rs") {
            continue;
        }
        let relative = file.strip_prefix(root).unwrap_or(file);
        for offence in offences(&fs::read_to_string(file)?) {
            found.push(format!("{}:{offence}", relative.display()));
        }
    }

    assert!(found.is_empty(), "retired policy vocabulary in use:\n{}", found.join("\n"));
    assert!(!files.is_empty(), "no sources were found, so nothing was checked");

    Ok(())
}

#[test]
fn a_retired_word_is_found_inside_an_identifier_and_a_comment() {
    assert_eq!(offences("enum PublicAccess { NotPermitted }").len(), 1);
    assert_eq!(offences("fn clamp_window() {}").len(), 1);
    assert_eq!(offences("// the verdict of the scope check").len(), 1);
}

#[test]
fn a_retired_word_inside_a_string_literal_is_not_an_offence() {
    assert_eq!(offences(r#"let body = "grant_type=password";"#), [] as [String; 0]);
    assert_eq!(offences(r#"assert!(parse("effect = \"permit\"").is_err());"#), [] as [String; 0]);
}

#[test]
fn the_current_vocabulary_is_not_an_offence() {
    assert_eq!(offences("fn narrow_window(restriction: &TimeRestriction) -> Visibility {}"), [] as [String; 0]);
}
