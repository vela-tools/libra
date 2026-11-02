//! Where in a request or an answer a restricted member was looked for.

use derive_more::Display;
use libra_ngsi_ld_operation::resource::ResourceId;

/// The place a missing or unreadable member was found in, phrased for the caller.
///
/// A refusal names the place so the caller can find what to fix; each variant renders as the words
/// the refusal reads.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum Location {
    /// The body of a write that carries one entity.
    #[display("the payload")]
    Payload,

    /// One entity of a batch write body.
    #[display("entity {index} of the batch")]
    BatchEntity {
        /// The entity's position in the batch, counted from zero.
        index: usize,
    },

    /// An entity, or a registration, the broker holds, as a pre-flight answered for it.
    #[display("entity '{id}'")]
    Stored {
        /// The identifier the request addressed.
        id: ResourceId,
    },

    /// The body of a batch query or a subscription.
    #[display("the Query body")]
    QueryBody,

    /// An entity of an answer, queried or linked, being judged on the way back.
    #[display("a linked entity")]
    LinkedEntity,

    /// The body of a context source registration write.
    #[display("the registration")]
    Registration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn every_location_renders_as_the_words_a_refusal_reads() {
        assert_eq!(Location::Payload.to_string(), "the payload");
        assert_eq!(Location::BatchEntity { index: 3 }.to_string(), "entity 3 of the batch");
        assert_eq!(
            Location::Stored {
                id: ResourceId::new("urn:ngsi-ld:Vehicle:1")
            }
            .to_string(),
            "entity 'urn:ngsi-ld:Vehicle:1'"
        );
        assert_eq!(Location::QueryBody.to_string(), "the Query body");
        assert_eq!(Location::LinkedEntity.to_string(), "a linked entity");
        assert_eq!(Location::Registration.to_string(), "the registration");
    }
}
