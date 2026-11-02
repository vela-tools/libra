//! Reading the parsed query from the request extensions, and writing a narrowed one back.

use axum::http::{Extensions, request::Parts, uri::InvalidUri};
use libra_ngsi_ld_query::parameters::QueryParameters;
use thiserror::Error;

/// The request reached a layer that reads its query without one parsed above.
///
/// A wiring error rather than anything about the request: the query layer runs above every reader,
/// and judging a request by a second parse is the disagreement it exists to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the request's query was not parsed before it was read")]
pub struct Unparsed;

/// The query parameters parsed above, as narrowed by every layer between there and here.
///
/// # Errors
///
/// Returns [`Unparsed`] when the extension is absent.
pub fn parameters(extensions: &Extensions) -> Result<&QueryParameters, Unparsed> {
    extensions.get::<QueryParameters>().ok_or(Unparsed)
}

/// Replaces the request's query with `parameters`, in its target and in its extensions together.
///
/// Writing one without the other would leave the layers below reading a query the broker is not
/// sent, which is the disagreement parsing once exists to stop.
///
/// # Errors
///
/// Returns the [`InvalidUri`] the path and the rendered query make together. The URI is left as it
/// was, and so are the stored parameters.
pub fn replace_query(parts: &mut Parts, parameters: QueryParameters) -> Result<(), InvalidUri> {
    parts.uri = parameters.uri_at(parts.uri.path())?;
    parts.extensions.insert(parameters);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request};
    use libra_ngsi_ld_query::parameter_name::ParameterName;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_absent_query_is_a_wiring_error() {
        assert_eq!(parameters(&Extensions::new()), Err(Unparsed));
    }

    #[test]
    fn a_rewrite_changes_the_target_and_the_stored_parameters_together() {
        let (mut parts, _) = Request::builder()
            .uri("/ngsi-ld/v1/entities?type=Vehicle")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let mut narrowed = QueryParameters::parse("type=Vehicle").unwrap();
        narrowed.set(ParameterName::SCOPE_Q, "/Madrid");

        replace_query(&mut parts, narrowed.clone()).unwrap();

        assert_eq!(parts.uri, "/ngsi-ld/v1/entities?scopeQ=%2FMadrid&type=Vehicle");
        assert_eq!(parameters(&parts.extensions), Ok(&narrowed));
        assert_eq!(QueryParameters::parse(parts.uri.query().unwrap()).as_ref(), Ok(&narrowed));
    }
}
