//! The header that points a request at a stored entity map.

use http::{HeaderMap, HeaderName};

/// `NGSILD-EntityMap` (NGSI-LD tables 6.4.3.2-2, 6.4.3.3-2 and 6.5.3.1-2).
///
/// When present, the broker determines the entities a query, a purge or a retrieval is about from
/// the entity map the header names rather than from the request's own filters. An entity map is a
/// list of entity identifiers built by an earlier query, so a request carrying one reaches whatever
/// entities that query matched, whoever ran it and under whatever restriction.
pub const ENTITY_MAP_HEADER: HeaderName = HeaderName::from_static("ngsild-entitymap");

/// Whether a request names an entity map, in any number of `NGSILD-EntityMap` values.
#[must_use]
pub fn names_entity_map(headers: &HeaderMap) -> bool {
    headers.contains_key(ENTITY_MAP_HEADER)
}

#[cfg(test)]
mod tests {
    use crate::entity_map::names_entity_map;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn the_header_is_found_whatever_its_case() {
        let mut headers = HeaderMap::new();
        headers.insert("NGSILD-EntityMap", HeaderValue::from_static("urn:ngsi-ld:EntityMap:1"));

        assert!(names_entity_map(&headers));
    }

    #[test]
    fn a_request_without_the_header_names_no_entity_map() {
        assert!(!names_entity_map(&HeaderMap::new()));
    }
}
