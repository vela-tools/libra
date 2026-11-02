//! Turning the `[cors]` section into a layer, or into an error that says what is wrong with it.
//!
//! tower-http asserts, while the router is being built, that a credentialed policy names its
//! origins, headers and methods rather than using a wildcard, and it silently drops an entry that
//! does not parse. Both are wrong for a security policy: the first is a panic at startup, the
//! second is a policy that quietly allows less, or in the origin case something other than what the
//! operator wrote. Every entry is checked here and a bad one stops startup with its name.

use libra_config::{
    allow_list::AllowList,
    cors::{Cors, CorsEnabled},
};
use std::time::Duration;
use thiserror::Error;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};

/// A `[cors]` section that cannot be turned into a policy.
///
/// An entry that does not parse never gets this far: `libra-config` refuses it where the file is
/// read, naming the key.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CorsError {
    /// Credentials were allowed alongside a wildcard.
    ///
    /// Browsers refuse a credentialed response whose policy is a wildcard, and tower-http panics
    /// rather than build one.
    #[error("cors.allow-credentials cannot be combined with a '*' in cors.{list}; name the entries")]
    CredentialsWithWildcard {
        /// Which list held the wildcard.
        list: &'static str,
    },
}

/// Builds the CORS layer the configuration asks for, or `None` when CORS is off.
///
/// # Errors
///
/// Returns [`CorsError`] for credentials combined with a wildcard.
pub fn layer(config: &Cors) -> Result<Option<CorsLayer>, CorsError> {
    match config.enabled {
        CorsEnabled::False => Ok(None),
        CorsEnabled::Permissive => Ok(Some(CorsLayer::very_permissive())),
        CorsEnabled::True => configured(config).map(Some),
    }
}

/// Builds a layer from the explicit lists of the `[cors]` section.
fn configured(config: &Cors) -> Result<CorsLayer, CorsError> {
    if config.allow_credentials {
        for (list, wildcard) in [
            ("allow-origins", matches!(config.allow_origins, AllowList::Any)),
            ("allow-methods", matches!(config.allow_methods, AllowList::Any)),
            ("allow-headers", matches!(config.allow_headers, AllowList::Any)),
            ("expose-headers", matches!(config.expose_headers, AllowList::Any)),
        ] {
            if wildcard {
                return Err(CorsError::CredentialsWithWildcard { list });
            }
        }
    }

    // tower-http's policies own their entries, and the configuration is only borrowed.
    let origins = match &config.allow_origins {
        AllowList::Any => AllowOrigin::any(),
        AllowList::Only(origins) => AllowOrigin::list(origins.iter().cloned()),
    };
    let methods = match &config.allow_methods {
        AllowList::Any => AllowMethods::any(),
        AllowList::Only(methods) => AllowMethods::list(methods.iter().cloned()),
    };
    let allowed_headers = match &config.allow_headers {
        AllowList::Any => AllowHeaders::any(),
        AllowList::Only(names) => AllowHeaders::list(names.iter().cloned()),
    };

    // Without exposed headers a browser cannot read `Link` or `NGSILD-Results-Count` off a
    // response, which NGSI-LD clients need for paging and for finding a context.
    let exposed_headers = match &config.expose_headers {
        AllowList::Any => ExposeHeaders::any(),
        AllowList::Only(names) => ExposeHeaders::list(names.iter().cloned()),
    };

    Ok(CorsLayer::new()
        .allow_credentials(config.allow_credentials)
        .max_age(Duration::from_secs(config.max_age_seconds))
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(allowed_headers)
        .expose_headers(exposed_headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{HeaderName, HeaderValue, Request},
        routing::get,
    };
    use pretty_assertions::assert_eq;
    use tower::ServiceExt;

    fn configured_section() -> Cors {
        Cors {
            enabled: CorsEnabled::True,
            allow_origins: AllowList::Only(vec![HeaderValue::from_static("https://app.example.test")]),
            expose_headers: AllowList::Only(vec![HeaderName::from_static("link"), HeaderName::from_static("ngsild-results-count")]),
            ..Cors::default()
        }
    }

    #[test]
    fn cors_is_off_unless_the_operator_turns_it_on() {
        assert_eq!(Cors::default().enabled, CorsEnabled::False);
        assert!(layer(&Cors::default()).unwrap().is_none());
    }

    #[test]
    fn credentials_with_a_wildcard_is_an_error_rather_than_a_panic() {
        // The defaults for origins and headers are wildcards, so turning credentials on without
        // naming them would panic while the router was built.
        let section = Cors {
            enabled: CorsEnabled::True,
            allow_credentials: true,
            ..Cors::default()
        };

        assert_eq!(layer(&section).unwrap_err(), CorsError::CredentialsWithWildcard { list: "allow-origins" });
    }

    #[tokio::test]
    async fn exposed_headers_reach_the_browser() {
        let cors = layer(&configured_section()).unwrap().expect("configured CORS builds a layer");
        let app = Router::new().route("/", get(|| async { "ok" })).layer(cors);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("origin", "https://app.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "https://app.example.test");
        assert_eq!(response.headers().get("access-control-expose-headers").unwrap(), "link,ngsild-results-count");
    }
}
