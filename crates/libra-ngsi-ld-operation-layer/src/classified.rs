//! Reading the classified operation from the request extensions.

use axum::http::Extensions;
use libra_ngsi_ld_operation::operation::Operation;
use thiserror::Error;

/// The request reached a layer that reads its operation without one classified above.
///
/// A wiring error rather than anything about the request: the operation layer runs above every
/// reader, and judging a request by a second classification is the disagreement it exists to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the request's operation was not classified before it was read")]
pub struct Unclassified;

/// The operation classified above.
///
/// # Errors
///
/// Returns [`Unclassified`] when the extension is absent.
pub fn operation(extensions: &Extensions) -> Result<&Operation, Unclassified> {
    extensions.get::<Operation>().ok_or(Unclassified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_absent_operation_is_a_wiring_error() {
        assert_eq!(operation(&Extensions::new()), Err(Unclassified));
    }

    #[test]
    fn the_stored_operation_is_the_one_read() {
        let stored = Operation::classify(&Method::GET, "/ngsi-ld/v1/entities").unwrap().unwrap();
        let mut extensions = Extensions::new();
        extensions.insert(stored.clone());

        assert_eq!(operation(&extensions), Ok(&stored));
    }
}
