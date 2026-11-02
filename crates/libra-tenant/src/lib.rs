//! Resolving the tenant a request is for.
//!
//! The tenant decides which data a request is about, so getting it wrong is not a routing mistake
//! but an authorization one. Three things follow from that, and this crate exists to hold all
//! three in one place: the header is read exactly once, its value is checked before anything
//! carries it, and a request that names no tenant is a distinct outcome rather than a request that
//! names the empty one.

use http::{HeaderMap, HeaderName};
use libra_config::multitenancy::{MissingTenantHeaderPolicy, Multitenancy};
use libra_policy_model::{
    error::ValueError,
    identity::{TenantId, TenantSelector},
};
use strum::Display;
use thiserror::Error;

/// The header a request names its tenant in.
pub const TENANT_HEADER: HeaderName = HeaderName::from_static("ngsild-tenant");

/// The tenant a request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tenant {
    /// The request named no tenant, so it is for the broker's unnamed default.
    Untenanted,
    /// The request named a tenant.
    Named(TenantId),
}

impl Tenant {
    /// The form a policy condition is matched against.
    #[must_use]
    pub fn as_selector(&self) -> TenantSelector {
        match self {
            Self::Untenanted => TenantSelector::Untenanted,
            // The selector owns its id so a policy condition can outlive the request's tenant.
            Self::Named(tenant) => TenantSelector::Named(tenant.clone()),
        }
    }

    /// Whether the request named no tenant.
    #[must_use]
    pub const fn is_untenanted(&self) -> bool {
        matches!(self, Self::Untenanted)
    }
}

/// The tenant header could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TenantError {
    /// The header appeared more than once.
    ///
    /// Refused rather than resolved. Implementations disagree about which copy wins (the first,
    /// the last, or a concatenation) and Libra forwards the request unchanged, so a second copy
    /// is a way to show the proxy one tenant and the broker another.
    #[error("the NGSILD-Tenant header appears more than once")]
    Repeated,

    /// The header's bytes are not printable ASCII.
    #[error("the NGSILD-Tenant header is not printable ASCII")]
    NotText,

    /// The header's value is not a usable tenant name.
    #[error("the NGSILD-Tenant header is not a usable tenant: {source}")]
    Unusable {
        /// What was wrong with it.
        #[source]
        source: ValueError,
    },

    /// The request named no tenant and the deployment requires one.
    #[error("the NGSILD-Tenant header is required")]
    Required,
}

/// Marks a request that may proceed without an authenticated caller.
///
/// Inserted into the request extensions only for a request that named no tenant under a deployment
/// that allows public access. A request naming a tenant never carries it, whatever the
/// configuration says.
#[derive(Debug, Clone, Copy)]
pub struct PublicAccessAllowed;

/// Whether the request may proceed without an authenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum PublicAccess {
    /// The deployment allows public access and this request named no tenant, so no caller is needed.
    Allowed,
    /// The request proceeds only with an authenticated caller.
    NotAllowed,
}

/// What resolving the tenant decided about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The tenant the request is for.
    pub tenant: Tenant,

    /// Whether the request may proceed without an authenticated caller.
    ///
    /// Only ever [`PublicAccess::Allowed`] for a request that named no tenant under a deployment
    /// that allows public access. A request that names a tenant always requires authentication,
    /// whatever the policy.
    pub public_access: PublicAccess,
}

/// Reads the tenant a request is for.
///
/// # Errors
///
/// Returns [`TenantError`] if the header repeats, is unreadable, is not a usable tenant name, or
/// is absent under a deployment that requires it.
pub fn resolve(headers: &HeaderMap, config: &Multitenancy) -> Result<Resolution, TenantError> {
    let mut values = headers.get_all(&TENANT_HEADER).into_iter();

    let Some(raw) = values.next() else {
        return resolve_absent(config.policy);
    };

    // Read before anything else is decided: two copies mean the proxy and the broker may not be
    // talking about the same tenant, and no reading of that is safe.
    if values.next().is_some() {
        return Err(TenantError::Repeated);
    }

    let text = raw.to_str().map_err(|_| TenantError::NotText)?;
    let tenant = TenantId::new(text).map_err(|source| TenantError::Unusable { source })?;

    Ok(Resolution {
        tenant: Tenant::Named(tenant),
        // A request that named a tenant is asking for someone's data by name, so it authenticates
        // whatever the missing-header policy says.
        public_access: PublicAccess::NotAllowed,
    })
}

/// What to do about a request that named no tenant.
const fn resolve_absent(policy: MissingTenantHeaderPolicy) -> Result<Resolution, TenantError> {
    match policy {
        MissingTenantHeaderPolicy::RequireHeader => Err(TenantError::Required),
        MissingTenantHeaderPolicy::Authenticate => Ok(Resolution {
            tenant: Tenant::Untenanted,
            public_access: PublicAccess::NotAllowed,
        }),
        MissingTenantHeaderPolicy::AllowPublic => Ok(Resolution {
            tenant: Tenant::Untenanted,
            public_access: PublicAccess::Allowed,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use pretty_assertions::assert_eq;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();

        for value in values {
            headers.append(TENANT_HEADER, HeaderValue::from_str(value).expect("a header value"));
        }

        headers
    }

    fn config(policy: MissingTenantHeaderPolicy) -> Multitenancy {
        Multitenancy { policy }
    }

    #[test]
    fn a_named_tenant_is_read_once_and_checked() {
        let resolution = resolve(&headers(&["acme"]), &config(MissingTenantHeaderPolicy::AllowPublic)).expect("the tenant should resolve");

        assert_eq!(resolution.tenant, Tenant::Named(TenantId::new("acme").unwrap()));
        assert_eq!(
            resolution.public_access,
            PublicAccess::NotAllowed,
            "naming a tenant always requires authentication"
        );
    }

    #[test]
    fn a_repeated_header_is_refused_rather_than_resolved() {
        // The proxy forwards the request unchanged, so a broker that reads the last value would
        // serve a tenant the proxy never authorized.
        assert_eq!(
            resolve(&headers(&["acme", "other"]), &config(MissingTenantHeaderPolicy::AllowPublic)),
            Err(TenantError::Repeated)
        );
    }

    #[test]
    fn an_empty_tenant_is_not_the_same_thing_as_no_tenant() {
        // Both must not collapse to the empty string, or a policy written for untenanted requests would
        // also match a caller who sent an empty header.
        let empty = resolve(&headers(&[""]), &config(MissingTenantHeaderPolicy::RequireHeader));
        let absent = resolve(&headers(&[]), &config(MissingTenantHeaderPolicy::RequireHeader));

        assert!(matches!(empty, Err(TenantError::Unusable { .. })));
        assert_eq!(absent, Err(TenantError::Required));
    }

    #[test]
    fn a_tenant_carrying_a_separator_is_refused() {
        // The value reaches a cache key, a per-tenant counter, and the identity header sent to the
        // broker. Each of those splits on a different character.
        for hostile in ["a:b", "a/b", "a b", "a,b"] {
            let refused = resolve(&headers(&[hostile]), &config(MissingTenantHeaderPolicy::AllowPublic));

            assert!(matches!(refused, Err(TenantError::Unusable { .. })), "{hostile:?} must be refused");
        }
    }

    #[test]
    fn a_missing_header_follows_the_configured_policy() {
        let absent = headers(&[]);

        assert_eq!(resolve(&absent, &config(MissingTenantHeaderPolicy::RequireHeader)), Err(TenantError::Required));

        let authenticate = resolve(&absent, &config(MissingTenantHeaderPolicy::Authenticate)).expect("it should resolve");
        assert_eq!(authenticate.tenant, Tenant::Untenanted);
        assert_eq!(authenticate.public_access, PublicAccess::NotAllowed);

        let public = resolve(&absent, &config(MissingTenantHeaderPolicy::AllowPublic)).expect("it should resolve");
        assert_eq!(public.tenant, Tenant::Untenanted);
        assert_eq!(public.public_access, PublicAccess::Allowed);
    }

    #[test]
    fn public_access_is_never_allowed_for_a_request_that_names_a_tenant() {
        // Whatever the missing-header policy says, it is about a *missing* header.
        for policy in [
            MissingTenantHeaderPolicy::AllowPublic,
            MissingTenantHeaderPolicy::Authenticate,
            MissingTenantHeaderPolicy::RequireHeader,
        ] {
            let resolution = resolve(&headers(&["acme"]), &config(policy)).expect("the tenant should resolve");

            assert_eq!(resolution.public_access, PublicAccess::NotAllowed, "{policy:?}");
        }
    }

    #[test]
    fn the_resolved_tenant_is_what_a_policy_matches_against() {
        let named = resolve(&headers(&["acme"]), &config(MissingTenantHeaderPolicy::AllowPublic)).unwrap();
        let absent = resolve(&headers(&[]), &config(MissingTenantHeaderPolicy::AllowPublic)).unwrap();

        assert_eq!(named.tenant.as_selector(), TenantSelector::Named(TenantId::new("acme").unwrap()));
        assert_eq!(absent.tenant.as_selector(), TenantSelector::Untenanted);
    }
}
