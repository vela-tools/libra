//! Every operation of the NGSI-LD HTTP binding, and what each column of the matrix expects of it.

use crate::columns::RestrictionKind;
use libra_ngsi_ld_operation::{
    operation::Operation,
    resource::{BatchAction, Resource},
};
use reqwest::{Method, StatusCode};
use std::collections::BTreeSet;

/// What the proxy does with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Sent to the broker, and the broker's answer returned.
    Forwarded,
    /// Answered at the gateway with this status; the broker never saw the request.
    Refused(StatusCode),
    /// Sent to the broker, and its answer replaced with this status.
    Withheld(StatusCode),
}

const F: Outcome = Outcome::Forwarded;
const FORBIDDEN: Outcome = Outcome::Refused(StatusCode::FORBIDDEN);

/// What a route expects under each restriction.
///
/// A struct literal without a rest pattern in every row, so a restriction kind added here is not
/// compiled until every route says what it expects under it.
#[derive(Debug, Clone, Copy)]
pub struct Restricted {
    pub scope: Outcome,
    pub entity_type: Outcome,
    pub time: Outcome,
    pub attribute: Outcome,
    pub aggregation: Outcome,
}

impl Restricted {
    /// The outcome expected under `kind`.
    pub const fn under(&self, kind: RestrictionKind) -> Outcome {
        match kind {
            RestrictionKind::Scope => self.scope,
            RestrictionKind::EntityType => self.entity_type,
            RestrictionKind::Time => self.time,
            RestrictionKind::Attribute => self.attribute,
            RestrictionKind::Aggregation => self.aggregation,
        }
    }
}

/// One operation of the HTTP binding, as the matrix sends it.
pub struct Route {
    /// The clause of ETSI GS CIM 009 v1.9.1 that binds the method to the resource.
    pub clause: &'static str,
    pub method: Method,
    /// Path and query. `{recent}` is replaced with an instant an hour before the request.
    pub target: &'static str,
    /// The request body and its media type, if the operation takes one. `{recent}` is replaced as
    /// in the target.
    pub body: Option<Payload>,
    /// What the stand-in broker answers, to this request and to any pre-flight read it causes.
    pub answer: &'static str,
    /// What an unrestricted allow over every resource family does with it.
    pub allowed: Outcome,
    pub restricted: Restricted,
}

/// A request body.
#[derive(Debug, Clone, Copy)]
pub struct Payload {
    pub media_type: &'static str,
    pub text: &'static str,
}

/// A body sent as `application/json`.
const fn json(text: &'static str) -> Payload {
    Payload {
        media_type: "application/json",
        text,
    }
}

impl Route {
    /// The path the broker is sent, without the query a narrowing layer may rewrite.
    pub fn path(&self) -> &'static str {
        self.target.split_once('?').map_or(self.target, |(path, _)| path)
    }
}

const ENTITY: &str = r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Allowed/a","speed":{"type":"Property","value":1}}"#;
const ENTITIES: &str = r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Allowed/a","speed":{"type":"Property","value":1}}]"#;
const FRAGMENT: &str = r#"{"speed":{"type":"Property","value":1}}"#;
const ATTRIBUTE_VALUE: &str = r#"{"type":"Property","value":1}"#;
const ENTITY_IDS: &str = r#"["urn:ngsi-ld:Vehicle:1"]"#;
const QUERY: &str = r#"{"type":"Query","entities":[{"type":"Vehicle"}]}"#;
const TEMPORAL_ENTITY: &str =
    r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Allowed/a","speed":[{"type":"Property","value":1,"observedAt":"{recent}"}]}"#;
const TEMPORAL_ENTITIES: &str =
    r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Allowed/a","speed":[{"type":"Property","value":1,"observedAt":"2026-01-01T00:00:00Z"}]}]"#;
const TEMPORAL_ANSWER: &str =
    r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Allowed/a","speed":[{"type":"Property","value":1,"observedAt":"2026-01-01T00:00:00Z"}]}"#;
const TEMPORAL_FRAGMENT: &str = r#"{"speed":[{"type":"Property","value":1,"observedAt":"{recent}"}]}"#;
const TEMPORAL_QUERY: &str = r#"{"type":"Query","entities":[{"type":"Vehicle"}],"temporalQ":{"timerel":"after","timeAt":"{recent}"}}"#;
const SUBSCRIPTION: &str =
    r#"{"id":"urn:ngsi-ld:Subscription:1","type":"Subscription","entities":[{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://notify.test"}}}"#;
const SUBSCRIPTIONS: &str =
    r#"[{"id":"urn:ngsi-ld:Subscription:1","type":"Subscription","entities":[{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://notify.test"}}}]"#;
const SUBSCRIPTION_PATCH: &str = r#"{"notification":{"endpoint":{"uri":"http://notify.test"}}}"#;
const REGISTRATION: &str = r#"{"id":"urn:ngsi-ld:ContextSourceRegistration:1","type":"ContextSourceRegistration","information":[{"entities":[{"type":"Vehicle"}]}],"scope":"/Allowed/a","endpoint":"http://source.test"}"#;
const REGISTRATIONS: &str = r#"[{"id":"urn:ngsi-ld:ContextSourceRegistration:1","type":"ContextSourceRegistration","information":[{"entities":[{"type":"Vehicle"}]}],"scope":"/Allowed/a","endpoint":"http://source.test"}]"#;
const REGISTRATION_PATCH: &str = r#"{"endpoint":"http://source.test"}"#;
const CSOURCE_SUBSCRIPTION: &str =
    r#"{"id":"urn:ngsi-ld:Subscription:2","type":"Subscription","entities":[{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://notify.test"}}}"#;
const CSOURCE_SUBSCRIPTIONS: &str =
    r#"[{"id":"urn:ngsi-ld:Subscription:2","type":"Subscription","entities":[{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://notify.test"}}}]"#;
const TYPE_LIST: &str = r#"{"id":"urn:ngsi-ld:EntityTypeList:1","type":"EntityTypeList","typeList":["Vehicle"]}"#;
const TYPE_INFO: &str = r#"{"id":"https://uri.etsi.org/ngsi-ld/default-context/Vehicle","type":"EntityTypeInfo","typeName":"Vehicle","entityCount":1,"attributeDetails":[{"id":"https://uri.etsi.org/ngsi-ld/default-context/speed","type":"Attribute","attributeName":"speed","attributeTypes":["Property"]}]}"#;
const ATTRIBUTE_LIST: &str = r#"{"id":"urn:ngsi-ld:AttributeList:1","type":"AttributeList","attributeList":["speed"]}"#;
const ATTRIBUTE: &str =
    r#"{"id":"https://uri.etsi.org/ngsi-ld/default-context/speed","type":"Attribute","attributeName":"speed","attributeCount":1,"typeNames":["Vehicle"]}"#;
const CONTEXT: &str = r#"{"@context":{"speed":"https://example.test/speed"}}"#;
const OBJECT: &str = "{}";
const LIST: &str = "[]";

/// Expands to a [`Restricted`] with every restriction named.
macro_rules! restricted {
    (scope: $scope:expr, entity_type: $entity_type:expr, time: $time:expr, attribute: $attribute:expr, aggregation: $aggregation:expr $(,)?) => {
        Restricted {
            scope: $scope,
            entity_type: $entity_type,
            time: $time,
            attribute: $attribute,
            aggregation: $aggregation,
        }
    };
}

/// Every route forwarded under every restriction.
const OPEN: Restricted = restricted!(scope: F, entity_type: F, time: F, attribute: F, aggregation: F);

const fn route(clause: &'static str, method: Method, target: &'static str, body: Option<Payload>, answer: &'static str, restricted: Restricted) -> Route {
    Route {
        clause,
        method,
        target,
        body,
        answer,
        allowed: F,
        restricted,
    }
}

/// Every operation clause 6 of ETSI GS CIM 009 v1.9.1 binds, then one path it does not.
#[expect(clippy::too_many_lines, reason = "one row per operation of the binding reads best as one table")]
pub fn all() -> Vec<Route> {
    vec![
        route(
            "6.4.3.1",
            Method::POST,
            "/ngsi-ld/v1/entities",
            Some(json(ENTITY)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.4.3.2",
            Method::GET,
            "/ngsi-ld/v1/entities?type=Vehicle",
            None,
            ENTITIES,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.4.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/entities?type=Vehicle",
            None,
            ENTITIES,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.5.3.1",
            Method::GET,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            None,
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.5.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            None,
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.5.3.3",
            Method::PUT,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            Some(json(ENTITY)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.5.3.4",
            Method::PATCH,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            Some(json(FRAGMENT)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.6.3.1",
            Method::POST,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs",
            Some(json(FRAGMENT)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.6.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs",
            Some(json(FRAGMENT)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.7.3.1",
            Method::PATCH,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
            Some(json(ATTRIBUTE_VALUE)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.7.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
            None,
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.7.3.3",
            Method::PUT,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
            Some(json(ATTRIBUTE_VALUE)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.8.3.1",
            Method::POST,
            "/ngsi-ld/v1/csourceRegistrations",
            Some(json(REGISTRATION)),
            OBJECT,
            OPEN,
        ),
        route(
            "6.8.3.2",
            Method::GET,
            "/ngsi-ld/v1/csourceRegistrations?type=Vehicle",
            None,
            REGISTRATIONS,
            OPEN,
        ),
        route(
            "6.9.3.1",
            Method::GET,
            "/ngsi-ld/v1/csourceRegistrations/urn:ngsi-ld:ContextSourceRegistration:1",
            None,
            REGISTRATION,
            OPEN,
        ),
        route(
            "6.9.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/csourceRegistrations/urn:ngsi-ld:ContextSourceRegistration:1",
            Some(json(REGISTRATION_PATCH)),
            REGISTRATION,
            OPEN,
        ),
        route(
            "6.9.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/csourceRegistrations/urn:ngsi-ld:ContextSourceRegistration:1",
            None,
            REGISTRATION,
            OPEN,
        ),
        route(
            "6.10.3.1",
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            Some(json(SUBSCRIPTION)),
            OBJECT,
            restricted!(scope: F, entity_type: F, time: F, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.10.3.2",
            Method::GET,
            "/ngsi-ld/v1/subscriptions",
            None,
            SUBSCRIPTIONS,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.11.3.1",
            Method::GET,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            None,
            SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.11.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            Some(json(SUBSCRIPTION_PATCH)),
            SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.11.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            None,
            SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.12.3.1",
            Method::POST,
            "/ngsi-ld/v1/csourceSubscriptions",
            Some(json(CSOURCE_SUBSCRIPTION)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.12.3.2",
            Method::GET,
            "/ngsi-ld/v1/csourceSubscriptions",
            None,
            CSOURCE_SUBSCRIPTIONS,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.13.3.1",
            Method::GET,
            "/ngsi-ld/v1/csourceSubscriptions/urn:ngsi-ld:Subscription:2",
            None,
            CSOURCE_SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.13.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/csourceSubscriptions/urn:ngsi-ld:Subscription:2",
            Some(json(SUBSCRIPTION_PATCH)),
            CSOURCE_SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.13.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/csourceSubscriptions/urn:ngsi-ld:Subscription:2",
            None,
            CSOURCE_SUBSCRIPTION,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.14.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/create",
            Some(json(ENTITIES)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.15.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(json(ENTITIES)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.16.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/update",
            Some(json(ENTITIES)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.17.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            Some(json(ENTITY_IDS)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.18.3.1",
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            Some(json(TEMPORAL_ENTITY)),
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.18.3.2",
            Method::GET,
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt={recent}",
            None,
            TEMPORAL_ENTITIES,
            restricted!(scope: F, entity_type: F, time: F, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.19.3.1",
            Method::GET,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1",
            None,
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: F, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.19.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1",
            None,
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.20.3.1",
            Method::POST,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs",
            Some(json(TEMPORAL_FRAGMENT)),
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.21.3.1",
            Method::DELETE,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
            None,
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.22.3.1",
            Method::PATCH,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/speed/urn:ngsi-ld:Instance:1",
            Some(json(TEMPORAL_FRAGMENT)),
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.22.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/speed/urn:ngsi-ld:Instance:1",
            None,
            TEMPORAL_ANSWER,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.23.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/query",
            Some(json(QUERY)),
            ENTITIES,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: FORBIDDEN),
        ),
        route(
            "6.24.3.1",
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            Some(json(TEMPORAL_QUERY)),
            TEMPORAL_ENTITIES,
            restricted!(scope: F, entity_type: F, time: F, attribute: F, aggregation: FORBIDDEN),
        ),
        route("6.25.3.1", Method::GET, "/ngsi-ld/v1/types", None, TYPE_LIST, OPEN),
        route("6.26.3.1", Method::GET, "/ngsi-ld/v1/types/Vehicle", None, TYPE_INFO, OPEN),
        route("6.27.3.1", Method::GET, "/ngsi-ld/v1/attributes", None, ATTRIBUTE_LIST, OPEN),
        route("6.28.3.1", Method::GET, "/ngsi-ld/v1/attributes/speed", None, ATTRIBUTE, OPEN),
        route(
            "6.29.3.1",
            Method::POST,
            "/ngsi-ld/v1/jsonldContexts",
            Some(Payload {
                media_type: "application/ld+json",
                text: CONTEXT,
            }),
            OBJECT,
            OPEN,
        ),
        route("6.29.3.2", Method::GET, "/ngsi-ld/v1/jsonldContexts", None, LIST, OPEN),
        route("6.30.3.1", Method::GET, "/ngsi-ld/v1/jsonldContexts/urn:ngsi-ld:Context:1", None, CONTEXT, OPEN),
        route(
            "6.30.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/jsonldContexts/urn:ngsi-ld:Context:1",
            None,
            OBJECT,
            OPEN,
        ),
        route(
            "6.31.3.1",
            Method::POST,
            "/ngsi-ld/v1/entityOperations/merge",
            Some(json(ENTITIES)),
            ENTITY,
            restricted!(scope: F, entity_type: F, time: FORBIDDEN, attribute: F, aggregation: F),
        ),
        route(
            "6.32.3.1",
            Method::GET,
            "/ngsi-ld/v1/entityMaps/urn:ngsi-ld:EntityMap:1",
            None,
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.32.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/entityMaps/urn:ngsi-ld:EntityMap:1",
            Some(json(OBJECT)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.32.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/entityMaps/urn:ngsi-ld:EntityMap:1",
            None,
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route("6.33.3.1", Method::GET, "/ngsi-ld/v1/info/sourceIdentity", None, OBJECT, OPEN),
        route(
            "6.34.3.1",
            Method::GET,
            "/ngsi-ld/v1/entityMaps",
            None,
            LIST,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.34.3.2",
            Method::POST,
            "/ngsi-ld/v1/entityMaps",
            Some(json(QUERY)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.35.3.1",
            Method::GET,
            "/ngsi-ld/v1/temporal/entityMaps",
            None,
            LIST,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.35.3.2",
            Method::POST,
            "/ngsi-ld/v1/temporal/entityMaps",
            Some(json(TEMPORAL_QUERY)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: F, attribute: FORBIDDEN, aggregation: F),
        ),
        route(
            "6.36.3.1",
            Method::POST,
            "/ngsi-ld/v1/snapshots",
            Some(json(OBJECT)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.36.3.2",
            Method::DELETE,
            "/ngsi-ld/v1/snapshots",
            None,
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.37.3.1",
            Method::GET,
            "/ngsi-ld/v1/snapshots/urn:ngsi-ld:Snapshot:1",
            None,
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.37.3.2",
            Method::PATCH,
            "/ngsi-ld/v1/snapshots/urn:ngsi-ld:Snapshot:1",
            Some(json(OBJECT)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.37.3.3",
            Method::DELETE,
            "/ngsi-ld/v1/snapshots/urn:ngsi-ld:Snapshot:1",
            None,
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        route(
            "6.38.3.1",
            Method::POST,
            "/ngsi-ld/v1/snapshots/urn:ngsi-ld:Snapshot:1/clone",
            Some(json(OBJECT)),
            OBJECT,
            restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        ),
        // A path the binding does not name is one no policy was written about.
        Route {
            clause: "none",
            method: Method::GET,
            target: "/ngsi-ld/v1/somethingNew",
            body: None,
            answer: OBJECT,
            allowed: FORBIDDEN,
            restricted: restricted!(scope: FORBIDDEN, entity_type: FORBIDDEN, time: FORBIDDEN, attribute: FORBIDDEN, aggregation: FORBIDDEN),
        },
    ]
}

/// The number of resources [`resource_ordinal`] tells apart.
const RESOURCES: usize = 36;

/// A number per resource Libra names, with each batch action counted as its own resource.
///
/// Exhaustive, so a resource added to the classification does not compile here until it is given a
/// number, and the coverage test fails until a route reaches it.
const fn resource_ordinal(resource: &Resource) -> usize {
    match resource {
        Resource::Entities => 0,
        Resource::Entity { .. } => 1,
        Resource::EntityAttributes { .. } => 2,
        Resource::EntityAttribute { .. } => 3,
        Resource::EntityBatch { action: BatchAction::Create } => 4,
        Resource::EntityBatch { action: BatchAction::Update } => 5,
        Resource::EntityBatch { action: BatchAction::Upsert } => 6,
        Resource::EntityBatch { action: BatchAction::Delete } => 7,
        Resource::EntityBatch { action: BatchAction::Merge } => 8,
        Resource::EntityBatch { action: BatchAction::Query } => 9,
        Resource::TemporalEntities => 10,
        Resource::TemporalEntity { .. } => 11,
        Resource::TemporalEntityAttributes { .. } => 12,
        Resource::TemporalEntityAttribute { .. } => 13,
        Resource::TemporalEntityAttributeInstance { .. } => 14,
        Resource::TemporalBatchQuery => 15,
        Resource::Subscriptions => 16,
        Resource::Subscription { .. } => 17,
        Resource::ContextSourceRegistrations => 18,
        Resource::ContextSourceRegistration { .. } => 19,
        Resource::ContextSourceSubscriptions => 20,
        Resource::ContextSourceSubscription { .. } => 21,
        Resource::EntityTypes => 22,
        Resource::EntityType { .. } => 23,
        Resource::Attributes => 24,
        Resource::Attribute { .. } => 25,
        Resource::EntityMaps => 26,
        Resource::EntityMap { .. } => 27,
        Resource::JsonLdContexts => 28,
        Resource::JsonLdContext { .. } => 29,
        Resource::TemporalEntityMaps => 30,
        Resource::Snapshots => 31,
        Resource::Snapshot { .. } => 32,
        Resource::SnapshotClone { .. } => 33,
        Resource::SourceIdentity => 34,
        Resource::Unrecognised => 35,
    }
}

#[test]
fn the_routes_reach_every_resource_libra_names() {
    let reached: BTreeSet<usize> = all()
        .iter()
        .map(|route| match Operation::classify(&route.method, route.target) {
            Ok(Some(operation)) => resource_ordinal(&operation.resource),
            other => panic!("{} {} {}: {other:?}", route.clause, route.method, route.target),
        })
        .collect();

    assert_eq!(reached, (0..RESOURCES).collect::<BTreeSet<_>>());
}

#[test]
fn no_operation_is_listed_twice() {
    let routes = all();
    let operations: BTreeSet<(&str, &str, &str)> = routes.iter().map(|route| (route.clause, route.method.as_str(), route.path())).collect();

    assert_eq!(operations.len(), routes.len());
}
