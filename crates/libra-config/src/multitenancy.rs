//! `[multitenancy]`: what to do with a request that carries no tenant header.

use serde::{Deserialize, Serialize};

/// Policy for handling requests missing the `NGSILD-Tenant` header.
///
/// The default authenticates: a request without the header reaches the default tenant only with a
/// credential. Allowing it through anonymously has to be written down, because a policy that names no
/// users, groups or roles then matches a caller nobody identified.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MissingTenantHeaderPolicy {
    /// Fail the request with 401 Unauthorized.
    RequireHeader,
    /// Serve the default tenant, to an authenticated caller only.
    #[default]
    Authenticate,
    /// Serve the default tenant to anyone, an anonymous caller included.
    AllowPublic,
}

/// Multi-tenancy configuration.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Multitenancy {
    /// Policy to apply when the tenant header is missing.
    pub policy: MissingTenantHeaderPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_request_without_a_tenant_header_must_authenticate_by_default() {
        assert_eq!(Multitenancy::default().policy, MissingTenantHeaderPolicy::Authenticate);
    }
}
