//! `[management-api]`: who may reach the privileged endpoints.

use libra_policy_model::identity::{ClientId, GroupName, PrincipalName, RoleName, Username};
use serde::{Deserialize, Serialize};

/// Who a management endpoint answers a read for. A write always needs a privileged caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementAccess {
    /// Only a caller named in one of the `admin-*` lists.
    #[default]
    Privileged,
    /// Any caller Libra authenticates. An anonymous caller never reaches a management endpoint.
    Authenticated,
}

/// Access control for management endpoints.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct ManagementApi {
    /// Accounts allowed to perform privileged management operations, matched against the account
    /// name (what a policy's `users` names, a token's `sub`) and nothing else.
    ///
    /// It is deliberately not matched against the client. The client id is chosen by whoever
    /// registered the client, so an identity provider holding a client named `admin` would hand
    /// management access to every token that client ever issued. Clients are named separately, in
    /// [`ManagementApi::admin_clients`].
    pub admin_users: Vec<Username>,
    /// Principals whose API keys are privileged, matched against the principal's name and nothing
    /// else. A principal and an account of the same name are different callers.
    pub admin_principals: Vec<PrincipalName>,
    /// OAuth clients whose tokens are privileged, matched against the token's `client_id` claim.
    ///
    /// Empty by default: allowing a whole client management access covers every subject it issues
    /// a token to, so it has to be asked for by name rather than fallen into.
    pub admin_clients: Vec<ClientId>,
    /// Groups allowed to perform privileged management operations.
    pub admin_groups: Vec<GroupName>,
    /// Roles allowed to perform privileged management operations, each matched by its exact name.
    pub admin_roles: Vec<RoleName>,
    /// Who may read the metrics endpoint.
    ///
    /// Privileged by default: the metrics carry tenant names, request volumes and error rates, and
    /// with `authenticated` any caller Libra authenticates can read them.
    pub metrics_access: ManagementAccess,
    /// Who may read the build-info endpoint.
    ///
    /// Privileged by default, like the metrics. The payload is the exact version and commit of the
    /// running gateway, which is precisely what decides whether a known vulnerability applies to
    /// it, and unlike the metrics there is no routine reason for a caller to want it.
    pub info_access: ManagementAccess,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn admin_clients_loads_under_its_kebab_case_name() {
        let section: ManagementApi = serde_json::from_str(r#"{"admin-clients": ["policy-writer"]}"#).unwrap();

        assert_eq!(section.admin_clients, [ClientId::new("policy-writer").unwrap()]);
    }

    #[test]
    fn a_name_the_identity_model_refuses_is_a_configuration_error() {
        // A group or role containing the header separator could never match a token, because the
        // token side refuses it too, so accepting it would be a rule that silently never fires.
        assert!(serde_json::from_str::<ManagementApi>(r#"{"admin-groups": ["ops,admins"]}"#).is_err());
        assert!(serde_json::from_str::<ManagementApi>(r#"{"admin-roles": [""]}"#).is_err());
        assert!(serde_json::from_str::<ManagementApi>(r#"{"admin-users": ["alice"], "admin-roles": ["ngsi-client:admin"]}"#).is_ok());
    }

    #[test]
    fn both_endpoints_start_privileged() {
        // An omitted key must not be read as a request to publish the running commit, or to let
        // every caller Libra authenticates read request volumes and tenant names.
        let omitted: ManagementApi = serde_json::from_str("{}").unwrap();

        assert_eq!(omitted.info_access, ManagementAccess::Privileged);
        assert_eq!(omitted.metrics_access, ManagementAccess::Privileged);
        assert_eq!(ManagementApi::default().info_access, ManagementAccess::Privileged);
        assert_eq!(ManagementApi::default().metrics_access, ManagementAccess::Privileged);
    }

    #[test]
    fn access_is_written_in_kebab_case_and_nothing_else_is_read() {
        let opened: ManagementApi = serde_json::from_str(r#"{"metrics-access": "authenticated"}"#).unwrap();

        assert_eq!(opened.metrics_access, ManagementAccess::Authenticated);
        assert_eq!(opened.info_access, ManagementAccess::Privileged);
        for refused in [
            r#"{"metrics-access": "open"}"#,
            r#"{"metrics-access": false}"#,
            r#"{"metrics-requires-privileged": false}"#,
        ] {
            assert!(serde_json::from_str::<ManagementApi>(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn nobody_is_privileged_by_default() {
        // A well-known default username is a privileged account at every identity provider that has
        // a user of that name, or lets anyone register one. Empty fails closed: the gated endpoints refuse
        // everyone until the operator names who may use them.
        let defaults = ManagementApi::default();

        assert_eq!(defaults.admin_users, [] as [_; 0]);
        assert_eq!(defaults.admin_clients, [] as [_; 0]);
        assert_eq!(defaults.admin_groups, [] as [_; 0]);
        assert_eq!(defaults.admin_roles, [] as [_; 0]);
    }

    #[test]
    fn no_client_is_privileged_by_default() {
        // Management access follows the account name only: a client that happens to be named `admin`
        // confers nothing. Client privilege is opt-in and starts empty.
        assert_eq!(ManagementApi::default().admin_clients, [] as [_; 0]);
    }
}
