//! Whether a reader of context source registrations is shown what a source needs to be reached.
//!
//! A registration's `contextSourceInfo` (NGSI-LD clause 5.2.9) holds the key-value pairs the broker
//! sends to the source on every request it forwards there (clause 4.3.6.5), which is where a source's
//! credentials go. Allowing registration reads is much weaker than allowing writes, and a reader who
//! could not have written a registration is not shown what one carries for its source.

/// What a registration read may show of each registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationDisclosure {
    /// The caller may also write registrations, and sees them whole.
    Whole,
    /// The caller may not write registrations, and sees them without `contextSourceInfo`.
    WithoutSourceInfo,
}
