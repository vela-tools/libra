//! The names a policy matches a caller by.
//!
//! These are not NGSI-LD terms and never become IRIs: a username means what the identity provider
//! says it means, and there is no context that could redefine it. They are newtypes anyway, so a
//! group cannot be compared with a role by accident, and so the values that end up in cache keys,
//! log lines and propagated headers are checked once, here, rather than nowhere.

use crate::{
    error::{IdentityError, ValueError},
    principal_id::PrincipalId,
};
use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Longest identity name Libra will carry, in characters.
///
/// Identity names reach cache keys and per-tenant counters, so an unbounded one is unbounded
/// memory in a map an unauthenticated caller can add rows to. Counted in characters, as the
/// refusal and the documentation state it, so a name in a script outside ASCII gets the same
/// length as one inside it; a character is at most four bytes, which keeps the bound.
const MAX_IDENTITY_LENGTH: usize = 256;

/// Longest tenant name Libra will carry. Shorter than an identity: a tenant is an operator's own
/// label, and it appears in more derived keys than anything else.
const MAX_TENANT_LENGTH: usize = 128;

/// Builds a validated identity newtype constrained by length, printability and a set of forbidden
/// separator characters.
macro_rules! identity_name {
    ($name:ident, $kind:literal, $forbidden:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, derive_more::Display, Serialize, Deserialize)]
        #[display("{_0}")]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Checks and wraps a name.
            ///
            /// # Errors
            ///
            /// Returns an [`IdentityError`] if the name is empty, longer than 256 characters, contains a
            /// control character, or contains a character forbidden for this kind of name.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();

                let reason = if value.is_empty() {
                    Some("it is empty")
                } else if value.chars().count() > MAX_IDENTITY_LENGTH {
                    Some("it is longer than 256 characters")
                } else if value.chars().any(char::is_control) {
                    // A control character in a name reaches a log line and a propagated header.
                    Some("it contains a control character")
                } else if value.chars().any(|character| $forbidden.contains(&character)) {
                    // A name that holds the separator of the header it is joined into becomes two
                    // names at the broker: a group `ops,admins` would be read as `ops` and `admins`.
                    Some("it contains a comma, which separates the names in a propagated header")
                } else {
                    None
                };

                match reason {
                    Some(reason) => Err(IdentityError { kind: $kind, reason }),
                    None => Ok(Self(value)),
                }
            }

            /// The name as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }
    };
}

identity_name!(Username, "username", [] as [char; 0], "A caller, as the identity provider names them.");
identity_name!(
    Subject,
    "subject",
    [] as [char; 0],
    "The stable identifier of a caller: a token's `sub` claim, or a principal's URN."
);
identity_name!(
    ClientId,
    "client id",
    [','],
    "An OAuth client, as the identity provider identifies it.\n\nA comma is refused because an authenticator may name a role after the client that assigned it\n(`{client}:{role}`), and a role name is joined into a comma-separated header."
);
identity_name!(
    EmailAddress,
    "email address",
    [] as [char; 0],
    "A caller's email address as the identity provider asserts it.\n\nOnly checked to be safe to carry into a log line or a header: it is not parsed as an RFC 5322 address,\nbecause Libra never routes mail and an identity provider is free to hold addresses a parser rejects."
);
identity_name!(GroupName, "group", [','], "A group the caller belongs to.");
identity_name!(
    PrincipalName,
    "principal name",
    [] as [char; 0],
    "A principal: a machine identity Libra itself defines, which API keys authenticate as.\n\nA namespace of its own, apart from [`Username`]: a policy that names a user is about an account an\nidentity provider vouches for, and a principal of the same name is not that account."
);
identity_name!(
    RoleName,
    "role",
    [','],
    "A role the caller holds, matched by its exact name.\n\nA comma is refused because the roles a caller holds are joined into a comma-separated header."
);

impl From<Subject> for Username {
    /// A caller with no username is named by their subject, which satisfies every constraint a
    /// username has.
    fn from(subject: Subject) -> Self {
        Self(subject.0)
    }
}

impl From<PrincipalId> for Subject {
    /// A principal is identified downstream by `urn:libra:principal:<ulid>`. The id outlives the
    /// name, so a principal removed and created again under the same name is a different subject,
    /// and the URN cannot be mistaken for an identity provider's own subject identifier.
    fn from(id: PrincipalId) -> Self {
        Self(id.urn())
    }
}

/// A tenant, as an operator names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, derive_more::Display)]
#[display("{_0}")]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// Checks and wraps a tenant name.
    ///
    /// The character set is deliberately narrow. A tenant name is copied into cache keys, into
    /// per-tenant counters, and into the identity headers sent to the broker; every separator it
    /// is allowed to contain is a place where one of those consumers can split it differently from
    /// the others.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Tenant`] if the name is empty, longer than 128 characters, or
    /// contains anything outside `A-Z`, `a-z`, `0-9`, `-`, `.`, `_` and `~`.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        let reason = if value.is_empty() {
            // An empty tenant is the ambiguity this type exists to remove: it is not the same
            // thing as a request that carried no tenant at all, and nothing downstream could tell
            // the two apart once both had become the empty string.
            Some("it is empty; a request with no tenant is written as \"*untenanted\"")
        } else if value.len() > MAX_TENANT_LENGTH {
            Some("it is longer than 128 characters")
        } else if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~'))
        {
            Some("it contains a character outside A-Z a-z 0-9 - . _ ~")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(ValueError::Tenant { value, reason }),
            None => Ok(Self(value)),
        }
    }

    /// The tenant as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TenantId> for String {
    fn from(tenant: TenantId) -> Self {
        tenant.0
    }
}

/// The name a policy matches a caller by, in the namespace it belongs to.
///
/// Two namespaces, never compared with each other: `users` in a policy matches only accounts and
/// `principals` matches only principals, so a principal created with the name of an account, or an
/// account registered with the name of a principal, is not the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
pub enum IdentityName {
    /// An account an identity provider authenticated.
    #[display("{_0}")]
    Account(Username),
    /// A principal Libra defines, authenticated by one of its API keys.
    #[display("principal {_0}")]
    Principal(PrincipalName),
}

/// The caller, as the policy vocabulary sees them.
///
/// Assembled by whatever authenticated the request and read by whatever evaluates it, so the
/// engine never sees a token, a claim set, or an identity provider's idea of a name. The
/// separation is what lets the policy model stay free of how identity happens to be established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyIdentity {
    /// The name a policy matches on, or `None` for an unauthenticated request.
    pub name: Option<IdentityName>,

    /// The groups the caller belongs to.
    ///
    /// A credential carrying a group that is not a usable [`GroupName`] is refused by the
    /// authenticator that reads it, rather than the name dropped: dropping it would hand the policy
    /// engine a caller holding less than the credential says, and the deny that follows would look
    /// like a policy bug.
    pub groups: Vec<GroupName>,

    /// The roles the caller holds, each matched by its exact name.
    ///
    /// Unusable names are refused, for the same reason as `groups`.
    pub roles: Vec<RoleName>,
}

impl PolicyIdentity {
    /// The identity of a request nobody authenticated.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            name: None,
            groups: Vec::new(),
            roles: Vec::new(),
        }
    }

    /// Whether the request was authenticated.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.name.is_some()
    }
}

/// The kind of caller a policy applies to: one nobody authenticated, or one somebody did.
///
/// A policy that names no identity matches every caller, so without this an allow written for
/// anonymous access under `allow-public` also matches every authenticated caller, and a restriction
/// it carries narrows them too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallerKind {
    /// A request that carried no credential.
    Anonymous,
    /// A request authenticated by a JWT or an API key.
    Authenticated,
}

impl CallerKind {
    /// Whether a caller of this kind can also be named by an identity condition (`users`,
    /// `principals`, `groups` or `roles`). An anonymous caller has no name, groups or roles.
    #[must_use]
    pub const fn can_carry_identity(self) -> bool {
        matches!(self, Self::Authenticated)
    }

    /// Whether a caller is of this kind.
    #[must_use]
    pub const fn admits(self, authenticated: bool) -> bool {
        match self {
            Self::Anonymous => !authenticated,
            Self::Authenticated => authenticated,
        }
    }
}

/// The literal a policy writes to match a request that carried no tenant.
///
/// `*` cannot appear in a [`TenantId`], so this can never collide with a real tenant name.
pub const UNTENANTED: &str = "*untenanted";

/// One entry of a policy's tenant list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TenantSelector {
    /// Matches a request that carried no tenant at all.
    Untenanted,
    /// Matches one named tenant.
    Named(TenantId),
}

impl TenantSelector {
    /// Reads a selector from its written form.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Tenant`] if the value is neither [`UNTENANTED`] nor a valid tenant.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value == UNTENANTED {
            return Ok(Self::Untenanted);
        }

        TenantId::new(value).map(Self::Named)
    }
}

impl Display for TenantSelector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Untenanted => formatter.write_str(UNTENANTED),
            Self::Named(tenant) => formatter.write_str(tenant.as_str()),
        }
    }
}

impl TryFrom<String> for TenantSelector {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<TenantSelector> for String {
    fn from(selector: TenantSelector) -> Self {
        selector.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_group_or_role_cannot_hold_the_separator_of_the_header_it_is_joined_into() {
        assert!(GroupName::new("ops,admins").is_err());
        assert!(RoleName::new("x,fleet-admin").is_err());
        assert!(GroupName::new("ops-admins").is_ok());
        assert!(RoleName::new("client:role").is_ok(), "a colon is an ordinary character in a role");
        assert!(Username::new("smith, jo").is_ok(), "a username is never joined into a list");
        assert!(ClientId::new("a,b").is_err(), "a client id may name a role, which is joined into a list");
        assert!(Subject::new("9f1c-uuid").is_ok());
        assert!(EmailAddress::new("alice@example.invalid").is_ok());
        assert!(EmailAddress::new("").is_err());
    }

    #[test]
    fn a_name_is_checked_when_it_is_read_not_when_it_is_used() {
        assert!(Username::new("alice").is_ok());
        assert!(Username::new("").is_err());
        assert!(Username::new("a\nb").is_err(), "a newline in a name reaches a log line");
        assert!(Username::new("x".repeat(257)).is_err());
    }

    #[test]
    fn the_length_limit_counts_characters_not_bytes() {
        assert!(GroupName::new("ž".repeat(256)).is_ok(), "256 two-byte characters are 256 characters");
        assert!(GroupName::new("ž".repeat(257)).is_err());
    }

    #[test]
    fn a_subject_names_an_account_and_a_principal_id_names_a_subject() {
        let subject = Subject::new("9f1c-uuid").unwrap();
        assert_eq!(Username::from(subject).as_str(), "9f1c-uuid");

        let principal = PrincipalId::from_parts(1_700_000_000_000, 7);
        assert_eq!(Subject::from(principal).as_str(), format!("urn:libra:principal:{principal}"));
    }

    #[test]
    fn a_role_is_its_exact_name() {
        // A role named after a client and the bare role of the same name are different roles, and
        // a policy that asked for one must not be satisfied by the other.
        assert_ne!(RoleName::new("ngsi-client:admin").unwrap(), RoleName::new("admin").unwrap());
    }

    #[test]
    fn a_tenant_may_not_contain_a_separator_that_something_downstream_would_split_on() {
        assert!(TenantId::new("acme").is_ok());
        assert!(TenantId::new("acme-eu.1_x~2").is_ok());

        // Each of these reaches a cache key, a counter key, or the identity header sent to the
        // broker, and each of those splits on a different one of them.
        for hostile in ["a:b", "a/b", "a b", "a,b", "a\u{0}b", "a\nb"] {
            assert!(TenantId::new(hostile).is_err(), "{hostile:?} must not be a tenant");
        }
    }

    #[test]
    fn an_empty_tenant_is_not_the_same_thing_as_no_tenant() {
        // An empty header value and an absent header must not both collapse to "": otherwise a policy
        // written for untenanted requests would also match a caller who sent an empty tenant, and vice
        // versa.
        assert!(TenantId::new("").is_err());
        assert_eq!(TenantSelector::parse(UNTENANTED).unwrap(), TenantSelector::Untenanted);
    }

    #[test]
    fn the_untenanted_literal_cannot_collide_with_a_real_tenant() {
        // `*` is outside the tenant character set, so no tenant can be named the literal.
        assert!(TenantId::new(UNTENANTED).is_err());
    }

    #[test]
    fn a_tenant_is_written_back_exactly_as_it_was_read() {
        // A tenant is copied into cache keys and the identity headers sent to the broker, so the
        // written form has to be the name itself and not some other spelling of it.
        let tenant = TenantId::new("acme-eu").unwrap();

        assert_eq!(tenant.as_str(), "acme-eu");
        assert_eq!(String::from(tenant), "acme-eu");
        assert_eq!(String::from(TenantSelector::Untenanted), UNTENANTED);
        assert_eq!(String::from(TenantSelector::Named(TenantId::new("acme").unwrap())), "acme");
    }

    #[test]
    fn each_kind_of_caller_admits_only_its_own_kind() {
        assert!(CallerKind::Anonymous.admits(false));
        assert!(!CallerKind::Anonymous.admits(true));
        assert!(CallerKind::Authenticated.admits(true));
        assert!(!CallerKind::Authenticated.admits(false));
    }

    #[test]
    fn only_a_named_caller_is_authenticated() {
        assert!(!PolicyIdentity::anonymous().is_authenticated());

        let caller = PolicyIdentity {
            name: Some(IdentityName::Account(Username::new("alice").unwrap())),
            ..PolicyIdentity::anonymous()
        };

        assert!(caller.is_authenticated());
    }

    #[test]
    fn a_tenant_list_round_trips_through_a_policy_file() {
        #[derive(Deserialize)]
        struct Wrapper {
            tenants: Vec<TenantSelector>,
        }

        let wrapper: Wrapper = toml::from_str(r#"tenants = ["acme", "*untenanted"]"#).unwrap();

        assert_eq!(
            wrapper.tenants,
            vec![TenantSelector::Named(TenantId::new("acme").unwrap()), TenantSelector::Untenanted]
        );
    }
}
