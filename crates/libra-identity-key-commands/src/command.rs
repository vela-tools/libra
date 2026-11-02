//! The command line, and running it against a key store.

use crate::{error::CommandError, key, lifetime::Lifetime, principal};
use clap::{Args, Subcommand};
use jiff::Timestamp;
use libra_identity_api_key::key_id::KeyId;
use libra_identity_key_store::store::ApiKeyStore;
use libra_policy_model::{
    error::IdentityError,
    identity::{GroupName, PrincipalName, RoleName},
};
use std::{io::Write, path::Path};

/// A key store administration command.
#[derive(Debug, Clone, Subcommand)]
pub enum AdminCommand {
    /// Issue, revoke and list API keys.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Create, remove and list the principals keys belong to.
    #[command(subcommand)]
    Principal(PrincipalCommand),
}

/// `libra key`.
#[derive(Debug, Clone, Subcommand)]
pub enum KeyCommand {
    /// Issue a key for a principal. The key is printed once and never stored.
    Create(CreateKey),
    /// Revoke a key from the next request on.
    Revoke {
        /// The key's id, as `libra key list` shows it.
        id: KeyId,
    },
    /// List every key, without its secret.
    List,
}

/// `libra key create`.
#[derive(Debug, Clone, Args)]
pub struct CreateKey {
    /// The principal the key authenticates as.
    #[arg(long, value_parser = principal_name)]
    pub principal: PrincipalName,
    /// When the key stops being accepted.
    #[command(flatten)]
    pub expiry: Expiry,
}

/// When a key expires: exactly one of the two forms.
#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
pub struct Expiry {
    /// An RFC 3339 time, such as 2027-01-31T00:00:00Z.
    #[arg(long)]
    pub expires_at: Option<Timestamp>,
    /// A duration from now, such as 90d or P30D. Days count as 24 hours.
    #[arg(long)]
    pub expires_in: Option<Lifetime>,
}

/// `libra principal`.
#[derive(Debug, Clone, Subcommand)]
pub enum PrincipalCommand {
    /// Create a principal.
    Create {
        /// Its name, which a policy's `principals` condition matches.
        #[arg(value_parser = principal_name)]
        name: PrincipalName,
        /// A group it belongs to. Repeat for several.
        #[arg(long = "group", value_parser = group)]
        groups: Vec<GroupName>,
        /// A role it holds. Repeat for several.
        #[arg(long = "role", value_parser = role)]
        roles: Vec<RoleName>,
    },
    /// Remove a principal and every key it holds.
    Remove {
        /// Its name.
        #[arg(value_parser = principal_name)]
        name: PrincipalName,
    },
    /// List every principal.
    List,
}

fn principal_name(text: &str) -> Result<PrincipalName, IdentityError> {
    PrincipalName::new(text)
}

fn group(text: &str) -> Result<GroupName, IdentityError> {
    GroupName::new(text)
}

fn role(text: &str) -> Result<RoleName, IdentityError> {
    RoleName::new(text)
}

impl Expiry {
    /// The expiry as a time, measured from `now` when it was given as a duration.
    fn at(&self, now: Timestamp) -> Result<Timestamp, CommandError> {
        let expires_at = match (self.expires_at, self.expires_in) {
            (Some(at), _) => at,
            (None, Some(lifetime)) => now.checked_add(lifetime.duration()).map_err(|_| CommandError::ExpiryOutOfRange)?,
            (None, None) => return Err(CommandError::NoExpiry),
        };

        if expires_at <= now {
            return Err(CommandError::ExpiryNotInFuture { expires_at });
        }

        Ok(expires_at)
    }
}

/// Runs a command against the configured key store, `None` when the configuration has no
/// `[key-store]`, writing what it reports to `out`.
///
/// # Errors
///
/// Returns [`CommandError`] if no key store is configured or the command fails.
pub async fn run(command: AdminCommand, store_path: Option<&Path>, out: &mut impl Write) -> Result<(), CommandError> {
    let store_path = store_path.ok_or(CommandError::NoKeyStore)?;
    let store = ApiKeyStore::open(store_path).await?;
    let now = Timestamp::now();

    let outcome = match command {
        AdminCommand::Key(KeyCommand::Create(create)) => {
            let expires_at = create.expiry.at(now)?;
            key::create(&store, create.principal, expires_at, now, out).await
        }
        AdminCommand::Key(KeyCommand::Revoke { id }) => key::revoke(&store, id, now, out).await,
        AdminCommand::Key(KeyCommand::List) => key::list(&store, now, out).await,
        AdminCommand::Principal(PrincipalCommand::Create { name, groups, roles }) => principal::create(&store, name, groups, roles, now, out).await,
        AdminCommand::Principal(PrincipalCommand::Remove { name }) => principal::remove(&store, &name, out).await,
        AdminCommand::Principal(PrincipalCommand::List) => principal::list(&store, out).await,
    };

    store.close().await;

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use libra_identity_api_key_authenticator::ApiKeyAuthenticator;
    use libra_identity_authenticator::{authenticator::Authenticator, bearer_token::BearerToken};
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// The commands as a binary mounts them.
    #[derive(Debug, Parser)]
    struct Cli {
        #[command(subcommand)]
        command: AdminCommand,
    }

    fn parse(arguments: &[&str]) -> Result<AdminCommand, clap::Error> {
        Cli::try_parse_from(["libra"].iter().chain(arguments)).map(|cli| cli.command)
    }

    struct Fixture {
        _directory: TempDir,
        store_path: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = TempDir::new().unwrap();
        let store_path = directory.path().join("keys.db");
        Fixture {
            _directory: directory,
            store_path,
        }
    }

    async fn execute(fixture: &Fixture, arguments: &[&str]) -> Result<String, CommandError> {
        let mut out = Vec::new();
        run(parse(arguments).unwrap(), Some(&fixture.store_path), &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn an_expiry_is_required_in_exactly_one_form() {
        assert!(parse(&["key", "create", "--principal", "ingest", "--expires-in", "90d"]).is_ok());
        assert!(parse(&["key", "create", "--principal", "ingest", "--expires-at", "2030-01-01T00:00:00Z"]).is_ok());
        assert!(parse(&["key", "create", "--principal", "ingest"]).is_err());
        assert!(
            parse(&[
                "key",
                "create",
                "--principal",
                "ingest",
                "--expires-in",
                "90d",
                "--expires-at",
                "2030-01-01T00:00:00Z"
            ])
            .is_err()
        );
    }

    #[test]
    fn a_lifetime_that_is_not_a_positive_fixed_duration_is_refused() {
        for lifetime in ["0s", "-1d", "P1M", "soon"] {
            assert!(
                parse(&["key", "create", "--principal", "ingest", "--expires-in", lifetime]).is_err(),
                "{lifetime}"
            );
        }
    }

    #[test]
    fn names_are_checked_as_they_are_read() {
        assert!(parse(&["principal", "create", "ingest", "--group", "fleet,ops"]).is_err());
        assert!(parse(&["key", "revoke", "not-an-id"]).is_err());
    }

    #[tokio::test]
    async fn a_command_without_a_key_store_says_so() {
        let mut out = Vec::new();
        let outcome = run(parse(&["key", "list"]).unwrap(), None, &mut out).await;

        assert!(matches!(outcome, Err(CommandError::NoKeyStore)));
    }

    #[tokio::test]
    async fn principals_are_created_listed_and_removed_with_their_keys() {
        let fixture = fixture();

        let created = execute(&fixture, &["principal", "create", "ingest", "--group", "fleet", "--role", "writer"])
            .await
            .unwrap();
        assert!(created.starts_with("created principal ingest\turn:libra:principal:"), "{created}");
        assert!(created.ends_with("\tgroups=fleet\troles=writer\n"), "{created}");

        execute(&fixture, &["principal", "create", "audit"]).await.unwrap();
        let listed = execute(&fixture, &["principal", "list"]).await.unwrap();
        let names: Vec<&str> = listed.lines().filter_map(|line| line.split('\t').next()).collect();
        assert_eq!(names, ["audit", "ingest"]);
        assert!(listed.contains("\tgroups=-\troles=-"));

        execute(&fixture, &["key", "create", "--principal", "ingest", "--expires-in", "1d"])
            .await
            .unwrap();
        assert_eq!(
            execute(&fixture, &["principal", "remove", "ingest"]).await.unwrap(),
            "removed principal ingest and its 1 keys\n"
        );
        assert!(execute(&fixture, &["principal", "list"]).await.unwrap().starts_with("audit\t"));
    }

    #[tokio::test]
    async fn a_created_key_is_printed_once_authenticates_and_stops_when_revoked() {
        let fixture = fixture();
        execute(&fixture, &["principal", "create", "ingest", "--group", "fleet"]).await.unwrap();

        let printed = execute(&fixture, &["key", "create", "--principal", "ingest", "--expires-in", "90d"])
            .await
            .unwrap();
        let key = printed.lines().next().and_then(|line| line.strip_prefix("key:       ")).unwrap().to_owned();
        let id = printed.lines().nth(1).and_then(|line| line.strip_prefix("id:        ")).unwrap().to_owned();

        let store = ApiKeyStore::open(&fixture.store_path).await.unwrap();
        let authenticator = ApiKeyAuthenticator::new(store);
        let authenticated = authenticator.authenticate(BearerToken::from(key.as_str())).await.unwrap();
        assert_eq!(authenticated.identity.groups, vec![GroupName::new("fleet").unwrap()]);

        let listed = execute(&fixture, &["key", "list"]).await.unwrap();
        assert!(listed.contains(&id) && listed.contains("\tactive"));
        assert!(!listed.contains(&key), "a listing never shows a key");

        assert_eq!(execute(&fixture, &["key", "revoke", &id]).await.unwrap(), format!("revoked key {id}\n"));
        assert!(authenticator.authenticate(BearerToken::from(key.as_str())).await.is_err());
        assert!(execute(&fixture, &["key", "list"]).await.unwrap().contains("\trevoked"));
    }

    #[tokio::test]
    async fn a_key_for_an_unknown_principal_or_with_a_past_expiry_is_refused() {
        let fixture = fixture();

        assert!(matches!(
            execute(&fixture, &["key", "create", "--principal", "nobody", "--expires-in", "1d"]).await,
            Err(CommandError::Store(_))
        ));

        execute(&fixture, &["principal", "create", "ingest"]).await.unwrap();
        assert!(matches!(
            execute(&fixture, &["key", "create", "--principal", "ingest", "--expires-at", "2000-01-01T00:00:00Z"]).await,
            Err(CommandError::ExpiryNotInFuture { .. })
        ));
    }
}
