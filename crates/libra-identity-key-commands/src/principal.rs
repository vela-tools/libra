//! `libra principal create | remove | list`.

use crate::error::CommandError;
use jiff::Timestamp;
use libra_identity_key_store::{
    principal::{NewPrincipal, Principal},
    store::ApiKeyStore,
};
use libra_policy_model::identity::{GroupName, PrincipalName, RoleName};
use std::io::Write;
use tracing::info;

/// Creates a principal.
pub async fn create(
    store: &ApiKeyStore,
    name: PrincipalName,
    groups: Vec<GroupName>,
    roles: Vec<RoleName>,
    now: Timestamp,
    out: &mut impl Write,
) -> Result<(), CommandError> {
    let principal = store.create_principal(NewPrincipal { name, groups, roles }, now).await?;

    info!(principal = %principal.name, id = %principal.id, "created a principal");
    writeln!(out, "created principal {}", describe(&principal))?;

    Ok(())
}

/// Removes a principal and its keys.
pub async fn remove(store: &ApiKeyStore, name: &PrincipalName, out: &mut impl Write) -> Result<(), CommandError> {
    let removed = store.remove_principal(name).await?;

    info!(principal = %name, keys = removed.0, "removed a principal and its keys");
    writeln!(out, "removed principal {name} and its {} keys", removed.0)?;

    Ok(())
}

/// Lists every principal.
pub async fn list(store: &ApiKeyStore, out: &mut impl Write) -> Result<(), CommandError> {
    for principal in store.principals().await? {
        writeln!(out, "{}", describe(&principal))?;
    }

    Ok(())
}

/// A principal on one line: its name, the URN it is known by downstream, its groups and roles.
fn describe(principal: &Principal) -> String {
    let join = |names: Vec<&str>| if names.is_empty() { "-".to_owned() } else { names.join(",") };

    format!(
        "{}\t{}\tgroups={}\troles={}",
        principal.name,
        principal.id.urn(),
        join(principal.groups.iter().map(GroupName::as_str).collect()),
        join(principal.roles.iter().map(RoleName::as_str).collect())
    )
}
