//! Classifies a request's NGSI-LD operation once, and places it where every layer below reads it.
//!
//! Authorization weighs the operation, the representation and linked-entity layers choose where to
//! read selectors by it, and every enforcement layer branches on it. Each classifying the method and
//! path for itself is how two layers come to disagree about one request, so the classification is
//! made here and [`Operation`](libra_ngsi_ld_operation::operation::Operation) is read from the request
//! extensions below. A request that is not an NGSI-LD operation is refused here: nothing below
//! has a rule for it, and nothing unclassifiable is forwarded to the broker.

pub mod classified;
pub mod layer;
