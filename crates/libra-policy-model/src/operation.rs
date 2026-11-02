//! The coarse operation a policy is written in terms of.

use libra_ngsi_ld_operation::operation::Mode;
use serde::{Deserialize, Serialize};

/// What a policy condition matches a request's effect on state against.
///
/// Deliberately coarser than [`libra_ngsi_ld_operation::resource::Resource`]: a policy says "may read" and
/// "may write", and the mapping from an NGSI-LD request to one of those is
/// `libra-ngsi-ld-operation`'s job, made once per request rather than restated per policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    /// The request only observes state.
    Read,
    /// The request may change state.
    Write,
}

impl From<Mode> for Operation {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Read => Self::Read,
            Mode::Write => Self::Write,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_classified_request_maps_onto_the_policy_vocabulary() {
        assert_eq!(Operation::from(Mode::Read), Operation::Read);
        assert_eq!(Operation::from(Mode::Write), Operation::Write);
    }
}
