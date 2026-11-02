//! Principals: the named machine identities keys belong to.

use crate::{error::StoreError, store::ApiKeyStore, timestamp::to_stored};
use jiff::Timestamp;
use libra_policy_model::{
    error::IdentityError,
    identity::{GroupName, IdentityName, PolicyIdentity, PrincipalName, RoleName},
    principal_id::PrincipalId,
};
use sqlx::{Sqlite, SqliteConnection, error::DatabaseError};

/// A principal about to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipal {
    /// The name policies match it by.
    pub name: PrincipalName,
    /// The groups it belongs to.
    pub groups: Vec<GroupName>,
    /// The roles it holds.
    pub roles: Vec<RoleName>,
}

/// A named machine identity with the groups and roles policies match it by.
///
/// A principal has no tenants and no permissions of its own: what it may do is what the policies
/// that match its name, groups and roles allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Assigned at creation and never reused, so a principal created again under a removed one's
    /// name is a different principal downstream.
    pub id: PrincipalId,
    /// The name policies match it by.
    pub name: PrincipalName,
    /// The groups it belongs to.
    pub groups: Vec<GroupName>,
    /// The roles it holds.
    pub roles: Vec<RoleName>,
}

impl Principal {
    /// The principal in the policy vocabulary.
    #[must_use]
    pub fn identity(self) -> PolicyIdentity {
        PolicyIdentity {
            name: Some(IdentityName::Principal(self.name)),
            groups: self.groups,
            roles: self.roles,
        }
    }
}

/// How many keys were removed with a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovedKeys(pub u64);

impl ApiKeyStore {
    /// Creates a principal, assigning it a fresh id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::PrincipalExists`] if the name is taken.
    pub async fn create_principal(&self, principal: NewPrincipal, now: Timestamp) -> Result<Principal, StoreError> {
        let id = generate_id(now)?;
        let mut transaction = self.pool().begin().await?;

        let inserted = sqlx::query("INSERT INTO principals (id, name, created_at) VALUES ($1, $2, $3)")
            .bind(id.to_bytes().as_slice())
            .bind(principal.name.as_str())
            .bind(to_stored(now))
            .execute(&mut *transaction)
            .await;

        if let Err(error) = inserted {
            return Err(if error.as_database_error().is_some_and(DatabaseError::is_unique_violation) {
                StoreError::PrincipalExists { name: principal.name }
            } else {
                StoreError::Database(error)
            });
        }

        for group in &principal.groups {
            sqlx::query("INSERT OR IGNORE INTO principal_groups (principal, name) VALUES ($1, $2)")
                .bind(id.to_bytes().as_slice())
                .bind(group.as_str())
                .execute(&mut *transaction)
                .await?;
        }

        for role in &principal.roles {
            sqlx::query("INSERT OR IGNORE INTO principal_roles (principal, name) VALUES ($1, $2)")
                .bind(id.to_bytes().as_slice())
                .bind(role.as_str())
                .execute(&mut *transaction)
                .await?;
        }

        transaction.commit().await?;

        let NewPrincipal { name, groups, roles } = principal;
        Ok(Principal { id, name, groups, roles })
    }

    /// Removes a principal, and with it every key it holds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownPrincipal`] if there is no such principal.
    pub async fn remove_principal(&self, name: &PrincipalName) -> Result<RemovedKeys, StoreError> {
        let mut transaction = self.pool().begin().await?;

        let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE principal = (SELECT id FROM principals WHERE name = $1)")
            .bind(name.as_str())
            .fetch_one(&mut *transaction)
            .await?;

        let removed = sqlx::query("DELETE FROM principals WHERE name = $1")
            .bind(name.as_str())
            .execute(&mut *transaction)
            .await?;

        if removed.rows_affected() == 0 {
            // Owned by the error, which outlives the borrowed name.
            return Err(StoreError::UnknownPrincipal { name: name.clone() });
        }

        transaction.commit().await?;

        Ok(RemovedKeys(u64::try_from(keys).map_err(|_| StoreError::CorruptRow {
            reason: "a key count is negative",
        })?))
    }

    /// Every principal, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read or holds a value Libra did not write.
    pub async fn principals(&self) -> Result<Vec<Principal>, StoreError> {
        let mut connection = self.pool().acquire().await?;

        let ids: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM principals ORDER BY name")
            .fetch_all(&mut *connection)
            .await?;

        let mut principals = Vec::with_capacity(ids.len());
        for id in ids {
            principals.push(read_principal(&mut connection, stored_id(&id)?).await?);
        }

        Ok(principals)
    }
}

/// A fresh principal id for a principal created at `now`.
fn generate_id(now: Timestamp) -> Result<PrincipalId, StoreError> {
    let created_ms = u64::try_from(now.as_millisecond()).map_err(|_| StoreError::ClockBeforeEpoch)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random[6..]).map_err(StoreError::RandomSource)?;

    Ok(PrincipalId::from_parts(created_ms, u128::from_be_bytes(random)))
}

/// A principal id as stored.
pub(crate) fn stored_id(bytes: &[u8]) -> Result<PrincipalId, StoreError> {
    <[u8; 16]>::try_from(bytes).map(PrincipalId::from_bytes).map_err(|_| StoreError::CorruptRow {
        reason: "a principal id is not 16 bytes",
    })
}

/// Reads one principal by id, with its groups and roles.
pub(crate) async fn read_principal(connection: &mut SqliteConnection, id: PrincipalId) -> Result<Principal, StoreError> {
    let name: String = sqlx::query_scalar("SELECT name FROM principals WHERE id = $1")
        .bind(id.to_bytes().as_slice())
        .fetch_one(&mut *connection)
        .await?;
    let name = PrincipalName::new(name).map_err(|_| StoreError::CorruptRow {
        reason: "a principal name is not usable",
    })?;

    let groups = names(
        connection,
        "SELECT name FROM principal_groups WHERE principal = $1 ORDER BY name",
        id,
        GroupName::new,
    )
    .await?;
    let roles = names(
        connection,
        "SELECT name FROM principal_roles WHERE principal = $1 ORDER BY name",
        id,
        RoleName::new,
    )
    .await?;

    Ok(Principal { id, name, groups, roles })
}

/// Reads a list of names through the newtype that checks them.
async fn names<T>(
    connection: &mut SqliteConnection,
    query: &'static str,
    principal: PrincipalId,
    check: impl Fn(String) -> Result<T, IdentityError>,
) -> Result<Vec<T>, StoreError> {
    let written: Vec<String> = sqlx::query_scalar::<Sqlite, String>(query)
        .bind(principal.to_bytes().as_slice())
        .fetch_all(&mut *connection)
        .await?;

    written
        .into_iter()
        .map(|name| {
            check(name).map_err(|_| StoreError::CorruptRow {
                reason: "a group or role name is not usable",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_store::store;
    use pretty_assertions::assert_eq;

    fn ingest() -> NewPrincipal {
        NewPrincipal {
            name: PrincipalName::new("ingest").unwrap(),
            groups: vec![GroupName::new("fleet").unwrap(), GroupName::new("ops").unwrap()],
            roles: vec![RoleName::new("writer").unwrap()],
        }
    }

    #[tokio::test]
    async fn a_principal_is_listed_with_its_id_groups_and_roles_and_resolves_to_an_identity() {
        let (_directory, store) = store().await;
        let created = store.create_principal(ingest(), Timestamp::UNIX_EPOCH).await.unwrap();

        assert_eq!(store.principals().await.unwrap(), vec![created.clone()]);

        let identity = created.identity();
        assert_eq!(identity.name, Some(IdentityName::Principal(PrincipalName::new("ingest").unwrap())));
        assert_eq!(identity.groups.len(), 2);
        assert_eq!(identity.roles, vec![RoleName::new("writer").unwrap()]);
    }

    #[tokio::test]
    async fn a_name_cannot_be_taken_twice() {
        let (_directory, store) = store().await;
        store.create_principal(ingest(), Timestamp::UNIX_EPOCH).await.unwrap();

        assert!(matches!(
            store.create_principal(ingest(), Timestamp::UNIX_EPOCH).await,
            Err(StoreError::PrincipalExists { .. })
        ));
    }

    #[tokio::test]
    async fn a_principal_created_again_under_a_removed_name_has_a_new_id() {
        let (_directory, store) = store().await;
        let first = store.create_principal(ingest(), Timestamp::UNIX_EPOCH).await.unwrap();
        store.remove_principal(&first.name).await.unwrap();

        let second = store.create_principal(ingest(), Timestamp::UNIX_EPOCH).await.unwrap();

        assert_ne!(first.id, second.id);
    }

    #[tokio::test]
    async fn removing_an_unknown_principal_is_refused() {
        let (_directory, store) = store().await;

        assert!(matches!(
            store.remove_principal(&PrincipalName::new("nobody").unwrap()).await,
            Err(StoreError::UnknownPrincipal { .. })
        ));
    }
}
