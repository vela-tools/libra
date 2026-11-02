//! The configuration file `libra config init` writes: every key at its built-in default.
//!
//! A file with the defaults spelled out is the starting point an operator edits, so it has to be
//! exactly the defaults. The tests below load it and compare it with the defaults the sections
//! declare, key by key, so a default changed in one place and not the other fails here.

/// The template, as TOML text with comments.
pub const TEMPLATE: &str = include_str!("template.toml");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::PendingConfig;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;
    use toml::{Table, Value};

    /// The configuration, serialized, without the broker every test layers under it.
    fn serialized(text: &str) -> Table {
        let pending = PendingConfig::from_toml_with_broker(text).expect("the text should load over a broker");
        let mut table = Table::try_from(pending.config()).expect("a loaded configuration should serialize");
        table.remove("broker");
        table
    }

    /// Every key path in a table, tables included, as dotted names.
    fn paths(table: &Table, prefix: &str, into: &mut BTreeSet<String>) {
        for (key, value) in table {
            let path = format!("{prefix}{key}");
            if let Value::Table(inner) = value {
                paths(inner, &format!("{path}."), into);
            }
            into.insert(path);
        }
    }

    #[test]
    fn the_template_holds_exactly_the_built_in_defaults() {
        assert_eq!(serialized(TEMPLATE), serialized(""));
    }

    #[test]
    fn the_template_writes_out_every_key_that_has_a_default() {
        let written: Table = toml::from_str(TEMPLATE).expect("the template should be TOML");
        let (mut expected, mut found) = (BTreeSet::new(), BTreeSet::new());
        paths(&serialized(""), "", &mut expected);
        paths(&written, "", &mut found);

        assert_eq!(found, expected);
    }

    #[test]
    fn the_template_names_no_broker_so_it_does_not_start_as_written() {
        assert!(PendingConfig::from_toml(TEMPLATE).is_err());
    }

    #[test]
    fn the_template_reads_as_every_section_this_build_defines() {
        let pending = PendingConfig::from_toml_with_broker(TEMPLATE).expect("the template should load over a broker");

        assert!(pending.finish().is_ok());
    }

    #[test]
    fn the_commented_jwt_section_loads_once_uncommented() {
        let section = TEMPLATE
            .lines()
            .skip_while(|line| *line != "# [jwt]")
            .take_while(|line| line.starts_with("# "))
            .filter_map(|line| line.strip_prefix("# "))
            .collect::<Vec<_>>()
            .join("\n");
        let pending = PendingConfig::from_toml_with_broker(&section).expect("the uncommented section should load");

        assert!(section.starts_with("[jwt]"), "{section}");
        assert!(pending.config().jwt.is_some());
    }
}
