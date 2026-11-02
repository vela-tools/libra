//! Starting the proxy: build what has to succeed, then serve.

use crate::{
    extensions::Extensions,
    server::{self, ServeError},
    startup::{self, StartupError},
};
use libra_config::Config;
use tracing::warn;

/// Anything that stops the proxy, before or after it is serving.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// Something that had to succeed before serving did not.
    #[error(transparent)]
    Startup(#[from] StartupError),

    /// The proxy could not be built or served.
    #[error(transparent)]
    Serve(#[from] ServeError),
}

/// Builds the services, loads the policies, and serves until the process is asked to stop.
///
/// A policy carrying a key that is no restriction stops the process here rather than loading and
/// being ignored: a restriction that is silently dropped has turned a policy into an unrestricted
/// allow.
///
/// # Errors
///
/// Returns [`RunError`] if startup fails or serving stops with an error.
pub async fn run(config: &Config, extensions: Extensions) -> Result<(), RunError> {
    let Extensions {
        authenticators,
        layers,
        management_routes,
    } = extensions;

    let (request_path, background) = startup::build(config, authenticators).await?;
    // A handle to the store and a copy of the lease, so the lease is released however serving ends.
    let leased = background.key_store.clone();

    let served = server::serve(config, &request_path, &background, layers, management_routes).await;

    if let Some(leased) = leased
        && let Err(error) = leased.store.release_lease(leased.lease).await
    {
        // Not fatal: the lease goes stale on its own, and a replacement waits that long at most.
        warn!(error = %error, "the key store's lease could not be released");
    }

    served?;

    Ok(())
}
