//! Which members of an NGSI-LD document are attributes and which are its shape.
//!
//! This distinction decides whether a policy that names `location` does anything. Exempting a list
//! of "core attributes" (`id`, `type`, `@context`, but also `location`, `createdAt`, `modifiedAt`,
//! `observationSpace`, `operationSpace`, `instanceId`) from the policy would let a policy written
//! to hide a device's position load cleanly, report itself as in force, and do nothing at all.
//!
//! The correct line is narrower. `id`, `type` and `@context` are not attributes: they are how a
//! document says what it is, and removing them produces something no client can read. Everything
//! else, `location` included, is an attribute, and a policy that names one means it.

/// The members that are document structure rather than data.
///
/// Deliberately three. Adding a fourth is adding a name no policy can ever restrict, so it needs a
/// reason that is about the shape of the document and not about how useful the value is.
pub const STRUCTURAL_MEMBERS: [&str; 3] = ["id", "type", "@context"];

/// Whether `member` is document structure rather than an attribute.
#[must_use]
pub fn is_structural(member: &str) -> bool {
    STRUCTURAL_MEMBERS.contains(&member)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_members_that_say_what_a_document_is_are_structural() {
        assert!(is_structural("id"));
        assert!(is_structural("type"));
        assert!(is_structural("@context"));
    }

    #[test]
    fn location_is_an_attribute_and_a_policy_may_hide_it() {
        // `location` is an attribute like any other, so a geo-privacy policy that names it takes effect.
        assert!(!is_structural("location"));
    }

    #[test]
    fn the_system_timestamps_are_attributes_too() {
        // `createdAt` and `modifiedAt` say when a reading was taken, which is exactly what a
        // policy limiting temporal detail is trying to withhold.
        assert!(!is_structural("createdAt"));
        assert!(!is_structural("modifiedAt"));
        assert!(!is_structural("observedAt"));
        assert!(!is_structural("observationSpace"));
        assert!(!is_structural("operationSpace"));
        assert!(!is_structural("instanceId"));
        assert!(!is_structural("scope"));
    }
}
