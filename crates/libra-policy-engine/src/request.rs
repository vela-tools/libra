//! Everything an authorization decision is made from.
//!
//! Assembled once, by the layer that has the request, and then read. Nothing here is derived
//! again during evaluation; in particular, no name is expanded here, because expansion happens
//! once per request and evaluating against a second expansion is how two parts of the proxy come
//! to disagree about what a name meant.

use jiff::Timestamp;
use libra_jsonld_term_expansion::name::ExpandedIri;
use libra_policy_model::{
    identity::{GroupName, IdentityName, RoleName, TenantSelector},
    operation::Operation,
    query::CompiledQuerySelector,
    resource_family::ResourceFamily,
};

/// The request, as the policy vocabulary sees it.
#[derive(Debug, Clone, Copy)]
pub struct EvaluationRequest<'a> {
    /// The caller's name for policy matching, or `None` for an unauthenticated request.
    ///
    /// An account's name, which for a JWT caller is its `sub`, or a principal's name. A principal is
    /// propagated downstream by its URN rather than its name, so the two differ for a principal,
    /// and a policy is written in terms of the name an operator chose.
    pub name: Option<&'a IdentityName>,

    /// The groups the caller belongs to.
    pub groups: &'a [GroupName],

    /// The roles the caller holds.
    pub roles: &'a [RoleName],

    /// The tenant the request is for.
    pub tenant: &'a TenantSelector,

    /// Whether the request reads or writes.
    pub operation: Operation,

    /// The family of the resource the request addresses.
    pub resource: ResourceFamily,

    /// The entity types the request names, already expanded.
    pub entity_types: RequestedTypes<'a>,

    /// The request's query, canonicalised.
    pub query: Option<&'a CompiledQuerySelector>,

    /// The instant the decision is made at.
    ///
    /// Passed in rather than read here, so a decision is reproducible and a test does not have to
    /// wait for a clock.
    pub now: Timestamp,
}

/// What a request says about the entity types it touches.
///
/// "Unbounded" is not the same as "names a type that matches nothing", and the two effects need
/// opposite answers to it: see [`crate::matching::matches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedTypes<'a> {
    /// The request does not bound the types it touches to the ones its query string names. Either
    /// it names none there (a read by id, a batch body, a create body, a subscription) or it asks
    /// for Linked Entity Retrieval (NGSI-LD 4.5.23), which also returns whatever entities the
    /// matched ones link to. The types it touches are whatever the broker holds.
    Unbounded,
    /// Every type the request's selection expression names, whichever connective joined them, and
    /// the only types its answer can hold.
    Named(&'a [ExpandedIri]),
}
