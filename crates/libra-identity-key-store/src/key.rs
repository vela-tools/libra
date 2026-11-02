//! API keys, as the store keeps them: an id, a verifier and a lifetime.

use crate::{
    error::StoreError,
    principal::{Principal, read_principal, stored_id},
    store::ApiKeyStore,
    timestamp::{from_stored, to_stored},
};
use jiff::Timestamp;
use libra_identity_api_key::{key_id::KeyId, verifier::Verifier};
use libra_policy_model::identity::PrincipalName;
use sqlx::FromRow;

/// A key about to be stored.
#[derive(Debug, Clone)]
pub struct NewKey {
    /// The key's id.
    pub id: KeyId,
    /// The principal the key authenticates as.
    pub principal: PrincipalName,
    /// What the store keeps in place of the secret.
    pub verifier: Verifier,
    /// When it was issued.
    pub created_at: Timestamp,
    /// When it stops being accepted.
    pub expires_at: Timestamp,
}

/// A key as listed: everything but its verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The key's id.
    pub id: KeyId,
    /// The principal the key authenticates as.
    pub principal: PrincipalName,
    /// When it was issued.
    pub created_at: Timestamp,
    /// When it stops being accepted.
    pub expires_at: Timestamp,
    /// When it was revoked, if it was.
    pub revoked_at: Option<Timestamp>,
}

/// Where a key stands at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub enum KeyStatus {
    /// Accepted.
    #[display("active")]
    Active,
    /// Past its expiry.
    #[display("expired")]
    Expired,
    /// Revoked.
    #[display("revoked")]
    Revoked,
}

impl KeyRecord {
    /// Where the key stands at `now`. Revocation is reported over expiry.
    #[must_use]
    pub fn status(&self, now: Timestamp) -> KeyStatus {
        match self.revoked_at {
            Some(_) => KeyStatus::Revoked,
            None if self.expires_at <= now => KeyStatus::Expired,
            None => KeyStatus::Active,
        }
    }
}

/// What a request carrying a key is judged against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// The verifier the presented secret must match.
    pub verifier: Verifier,
    /// When the key stops being accepted.
    pub expires_at: Timestamp,
    /// When it was revoked, if it was.
    pub revoked_at: Option<Timestamp>,
    /// The principal it authenticates as.
    pub principal: Principal,
}

/// A row of `api_keys`, before its values are checked.
#[derive(FromRow)]
struct KeyRow {
    id: Vec<u8>,
    principal_id: Vec<u8>,
    principal: String,
    verifier: Vec<u8>,
    created_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
}

impl KeyRow {
    fn id(&self) -> Result<KeyId, StoreError> {
        <[u8; 16]>::try_from(self.id.as_slice())
            .map(KeyId::from_bytes)
            .map_err(|_| StoreError::CorruptRow {
                reason: "a key id is not 16 bytes",
            })
    }

    fn verifier(&self) -> Result<Verifier, StoreError> {
        <[u8; 32]>::try_from(self.verifier.as_slice())
            .map(Verifier::from_bytes)
            .map_err(|_| StoreError::CorruptRow {
                reason: "a verifier is not 32 bytes",
            })
    }

    fn principal(&self) -> Result<PrincipalName, StoreError> {
        // Owned by the record that outlives the row.
        PrincipalName::new(self.principal.clone()).map_err(|_| StoreError::CorruptRow {
            reason: "a principal name is not usable",
        })
    }

    fn revoked_at(&self) -> Result<Option<Timestamp>, StoreError> {
        self.revoked_at.map(from_stored).transpose()
    }
}

impl ApiKeyStore {
    /// Stores a key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownPrincipal`] if the principal does not exist.
    pub async fn insert_key(&self, key: &NewKey) -> Result<(), StoreError> {
        // Inserted from a select by name, so a key for a principal that does not exist inserts
        // nothing rather than inserting a row nothing can resolve.
        let inserted =
            sqlx::query("INSERT INTO api_keys (id, principal, verifier, created_at, expires_at) SELECT $1, id, $3, $4, $5 FROM principals WHERE name = $2")
                .bind(key.id.to_bytes().as_slice())
                .bind(key.principal.as_str())
                .bind(key.verifier.as_bytes().as_slice())
                .bind(to_stored(key.created_at))
                .bind(to_stored(key.expires_at))
                .execute(self.pool())
                .await?;

        if inserted.rows_affected() == 0 {
            return Err(StoreError::UnknownPrincipal {
                // Owned by the error, which outlives the borrowed key.
                name: key.principal.clone(),
            });
        }

        Ok(())
    }

    /// Revokes a key from `now` on.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownKey`] if there is no such key and
    /// [`StoreError::AlreadyRevoked`] if it is revoked already.
    pub async fn revoke_key(&self, id: KeyId, now: Timestamp) -> Result<(), StoreError> {
        let mut transaction = self.pool().begin().await?;

        let revoked: Option<Option<i64>> = sqlx::query_scalar("SELECT revoked_at FROM api_keys WHERE id = $1")
            .bind(id.to_bytes().as_slice())
            .fetch_optional(&mut *transaction)
            .await?;

        match revoked {
            None => return Err(StoreError::UnknownKey { id }),
            Some(Some(_)) => return Err(StoreError::AlreadyRevoked { id }),
            Some(None) => {}
        }

        sqlx::query("UPDATE api_keys SET revoked_at = $1 WHERE id = $2")
            .bind(to_stored(now))
            .bind(id.to_bytes().as_slice())
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;

        Ok(())
    }

    /// Every key, ordered by id, which is the order they were issued in.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read or holds a row Libra did not write.
    pub async fn keys(&self) -> Result<Vec<KeyRecord>, StoreError> {
        let rows: Vec<KeyRow> = sqlx::query_as(
            "SELECT k.id, k.principal AS principal_id, p.name AS principal, k.verifier, k.created_at, k.expires_at, k.revoked_at FROM api_keys k JOIN principals p ON p.id = k.principal ORDER BY k.id",
        )
            .fetch_all(self.pool())
            .await?;

        rows.iter()
            .map(|row| {
                Ok(KeyRecord {
                    id: row.id()?,
                    principal: row.principal()?,
                    created_at: from_stored(row.created_at)?,
                    expires_at: from_stored(row.expires_at)?,
                    revoked_at: row.revoked_at()?,
                })
            })
            .collect()
    }

    /// The key with this id and the principal it belongs to, read in one transaction so the two
    /// cannot come from either side of a concurrent change.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read or holds a row Libra did not write.
    pub async fn lookup(&self, id: &KeyId) -> Result<Option<StoredKey>, StoreError> {
        let mut transaction = self.pool().begin().await?;

        let row: Option<KeyRow> = sqlx::query_as(
            "SELECT k.id, k.principal AS principal_id, p.name AS principal, k.verifier, k.created_at, k.expires_at, k.revoked_at FROM api_keys k JOIN principals p ON p.id = k.principal WHERE k.id = $1",
        )
            .bind(id.to_bytes().as_slice())
            .fetch_optional(&mut *transaction)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let principal = read_principal(&mut transaction, stored_id(&row.principal_id)?).await?;
        let stored = StoredKey {
            verifier: row.verifier()?,
            expires_at: from_stored(row.expires_at)?,
            revoked_at: row.revoked_at()?,
            principal,
        };

        transaction.commit().await?;

        Ok(Some(stored))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{principal::NewPrincipal, test_store::store};
    use jiff::SignedDuration;
    use libra_policy_model::identity::GroupName;
    use pretty_assertions::assert_eq;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn ingest() -> NewPrincipal {
        NewPrincipal {
            name: PrincipalName::new("ingest").unwrap(),
            groups: vec![GroupName::new("fleet").unwrap()],
            roles: Vec::new(),
        }
    }

    fn new_key(random: u128) -> NewKey {
        NewKey {
            id: KeyId::from_parts(1_000, random),
            principal: PrincipalName::new("ingest").unwrap(),
            verifier: Verifier::from_bytes([u8::try_from(random).unwrap(); 32]),
            created_at: at(1),
            expires_at: at(100),
        }
    }

    #[tokio::test]
    async fn a_key_for_a_principal_that_does_not_exist_is_refused() {
        let (_directory, store) = store().await;

        assert!(matches!(store.insert_key(&new_key(1)).await, Err(StoreError::UnknownPrincipal { .. })));
    }

    #[tokio::test]
    async fn a_stored_key_is_found_by_its_id_with_its_principal() {
        let (_directory, store) = store().await;
        let created = store.create_principal(ingest(), at(0)).await.unwrap();
        store.insert_key(&new_key(1)).await.unwrap();

        let found = store.lookup(&new_key(1).id).await.unwrap().unwrap();

        assert_eq!(found.verifier, new_key(1).verifier);
        assert_eq!(found.expires_at, at(100));
        assert_eq!(found.revoked_at, None);
        assert_eq!(found.principal, created);
        assert_eq!(store.lookup(&new_key(2).id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_key_is_revoked_once() {
        let (_directory, store) = store().await;
        store.create_principal(ingest(), at(0)).await.unwrap();
        store.insert_key(&new_key(1)).await.unwrap();

        store.revoke_key(new_key(1).id, at(50)).await.unwrap();

        assert_eq!(store.lookup(&new_key(1).id).await.unwrap().unwrap().revoked_at, Some(at(50)));
        assert!(matches!(store.revoke_key(new_key(1).id, at(60)).await, Err(StoreError::AlreadyRevoked { .. })));
        assert!(matches!(store.revoke_key(new_key(2).id, at(60)).await, Err(StoreError::UnknownKey { .. })));
    }

    #[tokio::test]
    async fn every_key_is_listed_in_the_order_it_was_issued_with_its_status() {
        let (_directory, store) = store().await;
        store.create_principal(ingest(), at(0)).await.unwrap();
        for random in [3, 1, 2] {
            store.insert_key(&new_key(random)).await.unwrap();
        }
        store.revoke_key(new_key(2).id, at(10)).await.unwrap();

        let listed = store.keys().await.unwrap();

        assert_eq!(
            listed.iter().map(|key| key.id).collect::<Vec<_>>(),
            vec![new_key(1).id, new_key(2).id, new_key(3).id]
        );
        assert_eq!(listed[0].status(at(50)), KeyStatus::Active);
        assert_eq!(listed[1].status(at(50)), KeyStatus::Revoked);
        assert_eq!(listed[0].status(at(100)), KeyStatus::Expired);
        assert_eq!(listed[0].status(at(100) - SignedDuration::from_secs(1)), KeyStatus::Active);
    }

    #[tokio::test]
    async fn removing_a_principal_removes_its_keys() {
        let (_directory, store) = store().await;
        store.create_principal(ingest(), at(0)).await.unwrap();
        store.insert_key(&new_key(1)).await.unwrap();
        store.insert_key(&new_key(2)).await.unwrap();

        let removed = store.remove_principal(&PrincipalName::new("ingest").unwrap()).await.unwrap();

        assert_eq!(removed.0, 2);
        assert_eq!(store.lookup(&new_key(1).id).await.unwrap(), None);
        assert_eq!(store.keys().await.unwrap(), [] as [_; 0]);
        assert_eq!(store.principals().await.unwrap(), [] as [_; 0]);
    }
}
