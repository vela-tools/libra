//! `[representation]`: how strictly a request's response representation is read.
//!
//! Resolving a representation is not the same as refusing one. Libra reads every request's
//! `Accept`, `options` and `format` so the layers below know what shape the answer will take, and
//! by default a request whose answer cannot be decided is still forwarded: the broker behind Libra
//! has its own opinion about an unsatisfiable `Accept` or a contradictory `options`, and that
//! opinion is the one a deployment already depends on. Both keys here let an operator move the
//! refusal to the gateway instead.

use serde::{Deserialize, Serialize};

/// What to do with an `Accept` header naming nothing Libra can produce.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UnsatisfiableAccept {
    /// Send the request on and let the broker answer it. The default, because it is what Libra
    /// did before it read the header at all.
    #[default]
    Forward,
    /// Answer 406 without reaching the broker.
    Refuse,
}

/// What to do with `options` and `format` parameters that cannot be read as one shape.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ContradictoryOptions {
    /// Send the request on and let the broker resolve it. The default.
    #[default]
    Forward,
    /// Answer 400 without reaching the broker.
    Refuse,
}

/// How strictly the response representation is resolved.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct RepresentationStrictness {
    /// What to do when every media type Libra can produce is unmatched or refused outright.
    pub unsatisfiable_accept: UnsatisfiableAccept,

    /// What to do when `options` names two shapes, `format` disagrees with `options`, a token is
    /// misspelled, or the query cannot be read at all.
    pub contradictory_options: ContradictoryOptions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn both_keys_default_to_forwarding_to_the_broker() {
        // Wiring the representation layer in must not change what a deployment sees. Anything
        // other than forwarding here would make reading the header a behaviour change.
        let strictness = RepresentationStrictness::default();

        assert_eq!(strictness.unsatisfiable_accept, UnsatisfiableAccept::Forward);
        assert_eq!(strictness.contradictory_options, ContradictoryOptions::Forward);
    }

    #[test]
    fn the_values_are_spelled_in_kebab_case() {
        assert_eq!(
            serde_json::to_string(&UnsatisfiableAccept::Refuse).expect("the value should render"),
            "\"refuse\""
        );
        assert_eq!(
            serde_json::to_string(&ContradictoryOptions::Forward).expect("the value should render"),
            "\"forward\""
        );
    }
}
