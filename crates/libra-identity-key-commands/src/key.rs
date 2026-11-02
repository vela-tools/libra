//! `libra key create | revoke | list`.

use crate::error::CommandError;
use jiff::Timestamp;
use libra_identity_api_key::{api_key::ApiKey, key_id::KeyId};
use libra_identity_key_store::{key::NewKey, store::ApiKeyStore};
use libra_policy_model::identity::PrincipalName;
use secrecy::ExposeSecret;
use std::io::Write;
use tracing::info;

/// Issues a key and prints it, the only time it is ever shown.
pub async fn create(store: &ApiKeyStore, principal: PrincipalName, expires_at: Timestamp, now: Timestamp, out: &mut impl Write) -> Result<(), CommandError> {
    let key = ApiKey::generate(now)?;

    store
        .insert_key(&NewKey {
            id: *key.id(),
            // Kept for the log line and the output below.
            principal: principal.clone(),
            verifier: key.verifier(),
            created_at: now,
            expires_at,
        })
        .await?;

    // The id and the principal are logged so the issue is on record; the key itself never is.
    info!(key = %key.id(), principal = %principal, expires_at = %expires_at, "issued an API key");

    writeln!(out, "key:       {}", key.reveal().expose_secret())?;
    writeln!(out, "id:        {}", key.id())?;
    writeln!(out, "principal: {principal}")?;
    writeln!(out, "expires:   {expires_at}")?;
    writeln!(out, "This is the only time the key is shown. Store it now: only its verifier is kept.")?;

    Ok(())
}

/// Revokes a key.
pub async fn revoke(store: &ApiKeyStore, id: KeyId, now: Timestamp, out: &mut impl Write) -> Result<(), CommandError> {
    store.revoke_key(id, now).await?;

    info!(key = %id, "revoked an API key");
    writeln!(out, "revoked key {id}")?;

    Ok(())
}

/// Lists every key, without its secret.
pub async fn list(store: &ApiKeyStore, now: Timestamp, out: &mut impl Write) -> Result<(), CommandError> {
    writeln!(out, "id\tprincipal\tcreated\texpires\tstatus")?;
    for key in store.keys().await? {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            key.id,
            key.principal,
            key.created_at,
            key.expires_at,
            key.status(now)
        )?;
    }

    Ok(())
}
