//! The members of an entity a projection may name besides its attributes.
//!
//! `pick` and `omit` take "an Entity member (`id`, `type`, `scope`) or a projected Attribute name"
//! (NGSI-LD clause 4.21 and the `pick`/`omit` rows of clause 6.4.3.2). The three members are what a
//! response document uses to say what an entity is, and a projection that removes one leaves a
//! reader of the answer unable to tell.

use strum::{Display, EnumIter, EnumString, IntoStaticStr};

/// An entity member a projection may name that is not an attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum EntityMember {
    /// `id`, the entity identifier.
    Id,
    /// `type`, the entity type or types.
    Type,
    /// `scope`, the entity scope or scopes (clause 4.18).
    Scope,
}

impl EntityMember {
    /// The member as a projection spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    #[test]
    fn every_member_is_spelled_the_way_the_specification_spells_it() {
        assert_eq!(EntityMember::iter().map(EntityMember::as_str).collect::<Vec<_>>(), ["id", "type", "scope"]);
    }

    #[test]
    fn a_member_reads_back_from_its_spelling_and_nothing_else() {
        assert_eq!(EntityMember::from_str("type"), Ok(EntityMember::Type));
        assert!(EntityMember::from_str("Type").is_err(), "projection names are case-sensitive");
        assert!(EntityMember::from_str("speed").is_err());
    }
}
