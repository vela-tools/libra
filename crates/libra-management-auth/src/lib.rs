//! Decides whether a caller may use the management endpoints.
//!
//! Only the decision lives here. There is no Tower layer and no token validation: by the time
//! anything in this crate runs, a token has already been accepted and turned into a set of names.
//! Keeping the decision separate from the plumbing means it can be tested exhaustively without an
//! identity provider, a key set or a running server, and it means the rule is written down in
//! exactly one place.
//!
//! # One set of names, one gate per endpoint group
//!
//! The five `admin-*` lists say who is privileged, and that answer is the same everywhere. Whether
//! privilege is *demanded* for a read is not: the build info and the metrics are different
//! disclosures, so [`PrivilegeSettings::for_build_info`] and [`PrivilegeSettings::for_metrics`] read
//! their own key and produce their own settings, and any other group of routes is gated through
//! [`PrivilegeSettings::for_group`] with a [`ManagementAccess`] its own owner decides. Sharing one
//! value between them would let a deployment set one key, watch the startup log report it, and be
//! gated by another endpoint's key instead. A write always needs a privileged caller.
//!
//! [`ManagementApi::metrics_access`] defaults to privileged. Set to `authenticated`, **any caller
//! Libra authenticates** (every account the identity provider vouches for, every principal holding
//! an API key) can scrape the metrics, which carry tenant names, request volumes and error rates.
//! An operator who scrapes with an ordinary credential sets it on purpose.
//!
//! # Every name is matched exactly
//!
//! A role, a group, a client and a name are each compared with the list for their own kind, whole
//! and as written. Nothing strips or adds a prefix, so `ngsi-client:admin` and `admin` are two
//! different roles.

use derive_more::Display;
use http::Method;
use libra_config::management_api::{ManagementAccess, ManagementApi};
use libra_policy_model::identity::{ClientId, GroupName, PrincipalName, RoleName, Subject, Username};
use std::collections::HashSet;
use thiserror::Error;

/// How a caller names itself, for the refusal it is told.
///
/// Never written to the log: a name is a personal identifier, and the log names a caller by the
/// fingerprint of their credential instead.
///
/// Never matched against an admin list: only [`Caller::username`] and [`Caller::client_id`] are.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum CallerName {
    /// The caller's login name.
    #[display("{_0}")]
    User(Username),
    /// The Libra principal the caller's API key belongs to.
    #[display("principal {_0}")]
    Principal(PrincipalName),
    /// The caller's opaque subject identifier, for a token with no username.
    #[display("{_0}")]
    Subject(Subject),
    /// The OAuth client, for a token with neither a username nor a subject.
    #[display("{_0}")]
    Client(ClientId),
    /// The token named nobody at all.
    #[display("anonymous")]
    Anonymous,
}

/// The caller was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManagementAuthError {
    /// The endpoint is gated and this caller does not hold management privilege.
    #[error("caller '{caller}' is not a privileged management identity")]
    NotPrivileged {
        /// How the caller named itself, for the refusal and nothing else.
        caller: CallerName,
    },
}

/// The names a decision is made about.
///
/// Borrowed rather than owned, and a plain struct rather than a trait, so that this crate does not
/// have to know how claims are modelled. Whoever holds the validated token fills this in; the five
/// name spaces stay separate because they are assigned by different people.
#[derive(Debug, Clone, Copy)]
pub struct Caller<'a> {
    /// The account name: what a policy's `users` names, a token's `sub`.
    pub username: Option<&'a Username>,
    /// The Libra principal, for a caller holding an API key. Matched against `admin_principals`
    /// only, never against `admin_users`.
    pub principal: Option<&'a PrincipalName>,
    /// The `sub` claim. Used to name the caller in a refusal, never to match an admin list: an
    /// opaque identifier is not something an operator can write down in a configuration file.
    pub subject: Option<&'a Subject>,
    /// The OAuth client the credential was issued to, the `client_id` claim of a token.
    pub client_id: Option<&'a ClientId>,
    /// The caller's groups.
    pub groups: &'a [GroupName],
    /// The caller's roles.
    pub roles: &'a [RoleName],
}

impl<'a> Caller<'a> {
    /// A caller with no groups and no roles.
    #[must_use]
    pub const fn new(username: Option<&'a Username>, subject: Option<&'a Subject>, client_id: Option<&'a ClientId>) -> Self {
        Self {
            username,
            principal: None,
            subject,
            client_id,
            groups: &[],
            roles: &[],
        }
    }

    /// The best available name for this caller, for the refusal it is told.
    #[must_use]
    pub fn identity(&self) -> CallerName {
        // Owned because the name is carried by the refusal, which outlives the borrowed claims;
        // it is built only on the path that refuses.
        match (self.principal, self.username, self.subject, self.client_id) {
            (Some(principal), _, _, _) => CallerName::Principal(principal.clone()), // the caller name outlives the borrowed identity
            (None, Some(username), _, _) => CallerName::User(username.clone()),     // as above
            (None, None, Some(subject), _) => CallerName::Subject(subject.clone()), // as above
            (None, None, None, Some(client)) => CallerName::Client(client.clone()), // as above
            (None, None, None, None) => CallerName::Anonymous,
        }
    }
}

/// Who counts as privileged, and whether a read needs it. A write always does.
#[derive(Debug, Clone)]
pub struct PrivilegeSettings {
    admin_users: HashSet<Username>,
    admin_principals: HashSet<PrincipalName>,
    admin_clients: HashSet<ClientId>,
    admin_groups: HashSet<GroupName>,
    admin_roles: HashSet<RoleName>,
    read: ManagementAccess,
}

impl PrivilegeSettings {
    /// Settings for a group of routes whose owner decides who may read.
    ///
    /// The names of who is privileged come from `config`, because that answer is the same for every
    /// group. Writes always need a privileged caller: there is no way to ask for a group an
    /// unprivileged caller can write to.
    #[must_use]
    pub fn for_group(config: &ManagementApi, read: ManagementAccess) -> Self {
        // The settings own their names; the configuration is borrowed.
        Self {
            admin_users: config.admin_users.iter().cloned().collect(),
            admin_principals: config.admin_principals.iter().cloned().collect(),
            admin_clients: config.admin_clients.iter().cloned().collect(),
            admin_groups: config.admin_groups.iter().cloned().collect(),
            admin_roles: config.admin_roles.iter().cloned().collect(),
            read,
        }
    }

    /// Settings for the build-info endpoint, which follows [`ManagementApi::info_access`] and
    /// nothing else.
    #[must_use]
    pub fn for_build_info(config: &ManagementApi) -> Self {
        Self::for_group(config, config.info_access)
    }

    /// Settings for the metrics endpoint, which follows [`ManagementApi::metrics_access`] and
    /// nothing else.
    ///
    /// The endpoint answers only `GET`, and every other method needs privilege, so a method added
    /// later is refused rather than open.
    #[must_use]
    pub fn for_metrics(config: &ManagementApi) -> Self {
        Self::for_group(config, config.metrics_access)
    }

    /// Whether any identity at all can be privileged under these settings.
    ///
    /// False when all five lists are empty, which means no caller passes a gated endpoint.
    #[must_use]
    pub fn admits_anyone(&self) -> bool {
        !(self.admin_users.is_empty()
            && self.admin_principals.is_empty()
            && self.admin_clients.is_empty()
            && self.admin_groups.is_empty()
            && self.admin_roles.is_empty())
    }

    /// Whether this caller holds management privilege.
    ///
    /// Each list is matched against exactly one name. `admin_users` is matched against the account
    /// name alone: matching it against the client as well would let an identity provider holding a
    /// client named `admin` give management access to every token that client issued. A client that
    /// really is privileged is named in `admin_clients` instead.
    #[must_use]
    pub fn is_privileged(&self, caller: &Caller<'_>) -> bool {
        let by_user = caller.username.is_some_and(|username| self.admin_users.contains(username));
        let by_principal = caller.principal.is_some_and(|principal| self.admin_principals.contains(principal));
        let by_client = caller.client_id.is_some_and(|client| self.admin_clients.contains(client));
        let by_group = caller.groups.iter().any(|group| self.admin_groups.contains(group));
        let by_role = caller.roles.iter().any(|role| self.admin_roles.contains(role));

        by_user || by_principal || by_client || by_group || by_role
    }

    /// Whether a request using this method needs a privileged caller.
    ///
    /// `GET`, `HEAD` and `OPTIONS` are reads and follow the read access; everything else is treated
    /// as a write and always needs privilege. An unknown method falls on the write side on purpose:
    /// a verb this code does not recognise is not a verb it can promise is safe.
    #[must_use]
    pub const fn privilege_required(&self, method: &Method) -> bool {
        match (is_read(method), self.read) {
            (true, ManagementAccess::Authenticated) => false,
            (true, ManagementAccess::Privileged) | (false, ManagementAccess::Privileged | ManagementAccess::Authenticated) => true,
        }
    }

    /// Decides whether this caller may make this request.
    ///
    /// # Errors
    ///
    /// Returns [`ManagementAuthError::NotPrivileged`] when the endpoint is gated for this method
    /// and the caller holds none of the configured names.
    pub fn authorize(&self, method: &Method, caller: &Caller<'_>) -> Result<(), ManagementAuthError> {
        if !self.privilege_required(method) || self.is_privileged(caller) {
            return Ok(());
        }

        Err(ManagementAuthError::NotPrivileged { caller: caller.identity() })
    }
}

/// Whether a method only observes state.
const fn is_read(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn user(name: &str) -> Username {
        Username::new(name).unwrap()
    }

    fn subject(name: &str) -> Subject {
        Subject::new(name).unwrap()
    }

    fn client(name: &str) -> ClientId {
        ClientId::new(name).unwrap()
    }

    fn users(items: &[&str]) -> Vec<Username> {
        items.iter().map(|item| user(item)).collect()
    }

    fn clients(items: &[&str]) -> Vec<ClientId> {
        items.iter().map(|item| client(item)).collect()
    }

    fn groups(items: &[&str]) -> Vec<GroupName> {
        items.iter().map(|item| GroupName::new(*item).unwrap()).collect()
    }

    fn roles(items: &[&str]) -> Vec<RoleName> {
        items.iter().map(|item| RoleName::new(*item).unwrap()).collect()
    }

    fn settings(admin_users: &[&str], admin_clients: &[&str], admin_groups: &[&str], admin_roles: &[&str]) -> PrivilegeSettings {
        let config = ManagementApi {
            admin_users: users(admin_users),
            admin_clients: clients(admin_clients),
            admin_groups: groups(admin_groups),
            admin_roles: roles(admin_roles),
            ..ManagementApi::default()
        };

        PrivilegeSettings::for_group(&config, ManagementAccess::Privileged)
    }

    fn admins(read: ManagementAccess) -> PrivilegeSettings {
        let config = ManagementApi {
            admin_users: users(&["admin"]),
            ..ManagementApi::default()
        };

        PrivilegeSettings::for_group(&config, read)
    }

    fn caller<'a>(username: &'a Username, subject: &'a Subject, groups: &'a [GroupName], roles: &'a [RoleName]) -> Caller<'a> {
        Caller {
            username: Some(username),
            principal: None,
            subject: Some(subject),
            client_id: None,
            groups,
            roles,
        }
    }

    #[test]
    fn a_client_named_admin_does_not_make_every_token_it_issues_privileged() {
        // `admin_users` is matched against the username alone, not the subject or the client. The client
        // id is set by whoever registers the client, so an identity provider holding a client called
        // `admin` must not hand management access to every token that client ever issued.
        let settings = settings(&["admin"], &[], &[], &[]);
        let caller = Caller {
            username: Some(&user("mallory")),
            principal: None,
            subject: Some(&subject("uuid")),
            client_id: Some(&client("admin")),
            groups: &[],
            roles: &[],
        };

        assert!(!settings.is_privileged(&caller), "the client id must not be matched against admin_users");
    }

    #[test]
    fn a_client_is_privileged_only_when_it_is_named_in_admin_clients() {
        let caller = Caller {
            username: None,
            principal: None,
            subject: Some(&subject("uuid")),
            client_id: Some(&client("policy-writer")),
            groups: &[],
            roles: &[],
        };

        assert!(!settings(&[], &[], &[], &[]).is_privileged(&caller));
        assert!(settings(&[], &["policy-writer"], &[], &[]).is_privileged(&caller));
    }

    #[test]
    fn admin_users_matches_the_account_name_and_not_the_subject_field() {
        // The account name is what a policy's `users` names. The subject field is for the log line,
        // and for a principal it is a URN no operator writes down.
        let caller = Caller {
            username: Some(&user("alice")),
            principal: None,
            subject: Some(&subject("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")),
            client_id: None,
            groups: &[],
            roles: &[],
        };

        assert!(settings(&["alice"], &[], &[], &[]).is_privileged(&caller));
        assert!(!settings(&["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"], &[], &[], &[]).is_privileged(&caller));
    }

    #[test]
    fn a_role_does_not_satisfy_an_entry_that_merely_ends_with_it() {
        // `admin` is not `ngsi-client:admin`: a role is compared whole, so no role can pass for
        // another by sharing a word with it.
        let held = roles(&["admin"]);
        let (alice, uuid) = (user("alice"), subject("uuid"));
        let caller = caller(&alice, &uuid, &[], &held);

        assert!(!settings(&[], &[], &[], &["ngsi-client:admin"]).is_privileged(&caller));
        assert!(settings(&[], &[], &[], &["admin"]).is_privileged(&caller));
    }

    #[test]
    fn a_role_does_not_satisfy_an_entry_that_is_a_part_of_it() {
        let held = roles(&["ngsi-client:admin"]);
        let (alice, uuid) = (user("alice"), subject("uuid"));
        let caller = caller(&alice, &uuid, &[], &held);

        assert!(!settings(&[], &[], &[], &["admin"]).is_privileged(&caller));
        assert!(settings(&[], &[], &[], &["ngsi-client:admin"]).is_privileged(&caller));
    }

    #[test]
    fn empty_admin_lists_make_nobody_privileged() {
        let held_groups = groups(&["/ops", "/everyone"]);
        let held_roles = roles(&["libra-admin", "ngsi-client:admin"]);
        let caller = Caller {
            username: Some(&user("admin")),
            principal: None,
            subject: Some(&subject("uuid")),
            client_id: Some(&client("admin")),
            groups: &held_groups,
            roles: &held_roles,
        };
        let settings = settings(&[], &[], &[], &[]);

        assert!(!settings.admits_anyone());
        assert!(
            !settings.is_privileged(&caller),
            "with no admin names configured, nothing may pass a gated endpoint"
        );
        assert_eq!(
            settings.authorize(&Method::POST, &caller),
            Err(ManagementAuthError::NotPrivileged {
                caller: CallerName::User(user("admin"))
            })
        );
    }

    #[test]
    fn a_group_confers_privilege() {
        let held = groups(&["/ops"]);
        let (alice, uuid) = (user("alice"), subject("uuid"));
        let caller = caller(&alice, &uuid, &held, &[]);

        assert!(settings(&[], &[], &["/ops"], &[]).is_privileged(&caller));
        assert!(!settings(&[], &[], &["/ops-readonly"], &[]).is_privileged(&caller));
    }

    #[test]
    fn an_unnamed_caller_is_never_privileged() {
        let caller = Caller::new(None, None, None);

        assert!(!settings(&["admin"], &["admin"], &["/ops"], &["admin"]).is_privileged(&caller));
        assert_eq!(caller.identity(), CallerName::Anonymous);
    }

    #[test]
    fn a_caller_is_named_by_its_username_then_its_subject_then_its_client() {
        let (alice, uuid, gateway) = (user("alice"), subject("uuid"), client("gateway"));

        // Cloned because each `Caller` borrows the names until the end of its assertion.
        assert_eq!(
            Caller::new(Some(&alice), Some(&uuid), Some(&gateway)).identity(),
            CallerName::User(alice.clone())
        );
        assert_eq!(Caller::new(None, Some(&uuid), Some(&gateway)).identity(), CallerName::Subject(uuid.clone()));
        assert_eq!(Caller::new(None, None, Some(&gateway)).identity(), CallerName::Client(gateway));
        assert_eq!(CallerName::Anonymous.to_string(), "anonymous");
        assert_eq!(CallerName::User(alice).to_string(), "alice");
    }

    #[test]
    fn reads_follow_the_read_access() {
        let gated = admins(ManagementAccess::Privileged);
        let open = admins(ManagementAccess::Authenticated);

        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(gated.privilege_required(&method), "{method} needs privilege when reads are privileged");
            assert!(!open.privilege_required(&method), "{method} is open to the authenticated");
        }
    }

    #[test]
    fn a_write_needs_privilege_whatever_the_read_access() {
        // No group can be asked for that lets an unprivileged caller write.
        for read in [ManagementAccess::Privileged, ManagementAccess::Authenticated] {
            for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::CONNECT] {
                assert!(admins(read).privilege_required(&method), "{method} under {read:?}");
            }
        }
    }

    #[test]
    fn each_endpoint_group_reads_its_own_gate() {
        // Each endpoint group reads its own key: sharing one settings value would parse the other group's
        // key, report it at startup, and never consult it, so a deployment could turn one gate on and be
        // gated by the other key.
        let config = ManagementApi {
            admin_users: users(&["ops-lead"]),
            metrics_access: ManagementAccess::Privileged,
            info_access: ManagementAccess::Authenticated,
            ..ManagementApi::default()
        };

        assert!(
            PrivilegeSettings::for_metrics(&config).privilege_required(&Method::GET),
            "metrics must follow metrics-access"
        );
        assert!(
            !PrivilegeSettings::for_build_info(&config).privilege_required(&Method::GET),
            "build info must follow info-access"
        );
    }

    #[test]
    fn an_ungated_endpoint_lets_an_unprivileged_caller_through() {
        let settings = admins(ManagementAccess::Authenticated);
        let (alice, uuid) = (user("alice"), subject("uuid"));
        let caller = caller(&alice, &uuid, &[], &[]);

        assert_eq!(settings.authorize(&Method::GET, &caller), Ok(()));
        assert!(settings.authorize(&Method::POST, &caller).is_err());
    }

    #[test]
    fn the_configuration_lists_reach_the_matching_claim() {
        let config = ManagementApi {
            admin_users: users(&["ops-lead"]),
            admin_principals: Vec::new(),
            admin_clients: clients(&["policy-writer"]),
            admin_groups: groups(&["/ops"]),
            admin_roles: roles(&["ngsi-client:policy-admin"]),
            metrics_access: ManagementAccess::Privileged,
            info_access: ManagementAccess::Privileged,
        };
        let settings = PrivilegeSettings::for_group(&config, ManagementAccess::Authenticated);
        let (ops_lead, policy_writer) = (user("ops-lead"), client("policy-writer"));
        let (writer_as_user, lead_as_client) = (user("policy-writer"), client("ops-lead"));

        assert!(settings.admits_anyone());
        assert!(settings.is_privileged(&Caller::new(Some(&ops_lead), None, None)));
        assert!(settings.is_privileged(&Caller::new(None, None, Some(&policy_writer))));
        assert!(
            !settings.is_privileged(&Caller::new(Some(&writer_as_user), None, None)),
            "a client name must not work as a username"
        );
        assert!(
            !settings.is_privileged(&Caller::new(None, None, Some(&lead_as_client))),
            "a username must not work as a client name"
        );
    }

    #[test]
    fn admin_principals_matches_a_principal_and_never_an_account_of_the_same_name() {
        let ingest = PrincipalName::new("ingest").unwrap();
        let ingest_account = user("ingest");
        let config = ManagementApi {
            admin_principals: vec![ingest.clone()], // the configuration owns its list; the test keeps the name to compare
            ..ManagementApi::default()
        };
        let only_principals = PrivilegeSettings::for_group(&config, ManagementAccess::Privileged);

        let principal = Caller {
            principal: Some(&ingest),
            ..Caller::new(None, None, None)
        };
        let account = Caller::new(Some(&ingest_account), None, None);

        assert!(only_principals.is_privileged(&principal));
        assert!(!only_principals.is_privileged(&account));
        assert!(
            !settings(&["ingest"], &[], &[], &[]).is_privileged(&principal),
            "admin-users does not name principals"
        );
        assert_eq!(principal.identity(), CallerName::Principal(ingest));
    }
}
