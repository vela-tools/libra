//! Everything a Libra binary does between its first line and serving, so that two binaries that
//! differ only in what they add to the proxy share one copy of it.
//!
//! A binary supplies a function that accepts the configuration and says what it adds. Loading, the
//! logging, the report of how the configuration was found, the management access-control report and
//! the way a startup failure is printed are the same for every binary and live here. An
//! administrative command, such as issuing an API key, goes through the same loading and logging
//! with [`administer`] instead of serving.

use crate::{
    extensions::Extensions,
    run::{RunError, run},
};
use libra_build_info::BuildInfo;
use libra_config::{Config, ConfigError, Loaded, pending::PendingConfig, source::ConfigSource};
use libra_logging::{LoggerGuard, LoggingError};
use libra_management_auth::PrivilegeSettings;
use std::{error::Error, future::Future, process::ExitCode};
use thiserror::Error;
use tracing::{info, warn};

/// Anything that stops a binary before it has done what it was started for.
#[derive(Debug, Error)]
pub enum LaunchError<E: Error + 'static, R: Error + 'static> {
    /// The configuration could not be read.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The binary could not accept the configuration or work out what it adds.
    #[error(transparent)]
    Assemble(E),

    /// Logging could not start.
    #[error(transparent)]
    Logging(#[from] LoggingError),

    /// The proxy or the command failed.
    #[error(transparent)]
    Run(R),
}

/// Loads the configuration, starts logging, serves, and reports how it ended.
///
/// `assemble` receives the configuration with only the sections every build reads extracted. A
/// binary that adds to the proxy claims its own sections from it before calling
/// [`PendingConfig::finish`], which is where a section nothing reads is refused.
pub async fn launch<E, F>(name: &str, assemble: F) -> ExitCode
where
    E: Error + 'static,
    F: FnOnce(PendingConfig) -> Result<(Extensions, Loaded), E>,
{
    report(name, start(assemble).await)
}

/// Loads the configuration exactly as [`launch`] does, starts logging, and runs `command` instead
/// of serving.
///
/// The configuration is assembled the same way, so a command sees the file the proxy would see and
/// refuses the same unclaimed sections.
pub async fn administer<E, F, R, C, Fut>(name: &str, assemble: F, command: C) -> ExitCode
where
    E: Error + 'static,
    F: FnOnce(PendingConfig) -> Result<(Extensions, Loaded), E>,
    R: Error + 'static,
    C: FnOnce(Config) -> Fut,
    Fut: Future<Output = Result<(), R>>,
{
    let outcome = async {
        let (_extensions, loaded, _logger_guard) = prepare(assemble)?;
        command(loaded.config).await.map_err(LaunchError::Run)
    };

    report(name, outcome.await)
}

/// Prints a failure with its causes, which may happen before logging exists, and turns the outcome
/// into the process's exit code.
fn report<E: Error + 'static, R: Error + 'static>(name: &str, outcome: Result<(), LaunchError<E, R>>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{name}: {error}");
            let mut source = Error::source(&error);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// Loads and assembles the configuration and starts logging.
///
/// The guard flushes the file appender when dropped, so the caller keeps it for as long as it runs.
fn prepare<E, R, F>(assemble: F) -> Result<(Extensions, Loaded, LoggerGuard), LaunchError<E, R>>
where
    E: Error + 'static,
    R: Error + 'static,
    F: FnOnce(PendingConfig) -> Result<(Extensions, Loaded), E>,
{
    // Configuration first, and fail fast: everything below is shaped by it, including the
    // security posture. Logging is not up yet, so the resolved source is reported afterwards
    // rather than printed here.
    let (extensions, loaded) = assemble(Config::load()?).map_err(LaunchError::Assemble)?;

    let logger_guard = libra_logging::init(&loaded.config.logging)?;

    match &loaded.source {
        ConfigSource::Explicit(path) => info!(path = %path.display(), "loaded configuration from LIBRA__CONFIG_FILE"),
        ConfigSource::Discovered(path) => info!(path = %path.display(), "loaded configuration"),
        ConfigSource::Missing(path) => warn!(path = %path.display(), "configuration file is missing"),
        ConfigSource::None => info!("no configuration file found; running on built-in defaults and LIBRA__* environment variables"),
    }

    Ok((extensions, loaded, logger_guard))
}

async fn start<E, F>(assemble: F) -> Result<(), LaunchError<E, RunError>>
where
    E: Error + 'static,
    F: FnOnce(PendingConfig) -> Result<(Extensions, Loaded), E>,
{
    // The guard flushes the file appender on the way out, so it has to outlive everything.
    let (extensions, loaded, _logger_guard) = prepare(assemble)?;

    let build = BuildInfo::new();
    info!(version = build.version, commit = build.commit, "starting Libra");

    // Surface the effective management-API access control, so a configuration that did not load
    // the way the operator expected is visible immediately rather than at the first request.
    let management = &loaded.config.management_api;
    info!(
        admin_users = ?management.admin_users,
        admin_principals = ?management.admin_principals,
        admin_clients = ?management.admin_clients,
        admin_groups = ?management.admin_groups,
        admin_roles = ?management.admin_roles,
        metrics_access = ?management.metrics_access,
        info_access = ?management.info_access,
        "management API access control configured"
    );
    if !PrivilegeSettings::for_build_info(management).admits_anyone() {
        // Not an error: a deployment that exposes no management endpoint to anyone is a valid one.
        // But it is the default, and an operator who expected to reach the metrics or the build
        // information should learn why they cannot at startup, not from a 403.
        warn!(
            "no management caller is privileged; the gated management endpoints will refuse everyone. Set [management-api] admin-users, admin-principals, admin-clients, admin-groups or admin-roles"
        );
    }

    run(&loaded.config, extensions).await.map_err(LaunchError::Run)?;

    Ok(())
}
