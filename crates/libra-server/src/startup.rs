//! Everything that has to succeed before Libra serves a request.
//!
//! All of it happens here, at startup, and any failure stops the process. That is the point: a
//! JWKS that cannot be fetched, a context that cannot be resolved, a policy that names something
//! meaningless, a key store another instance holds: every one of those would otherwise be
//! discovered on a request, where the only available answers are to refuse everything or to allow
//! something nobody checked.

use jiff::Timestamp;
use libra_audit::credential::FingerprintKey;
use libra_config::{Config, jwt::Jwt};
use libra_identity_api_key_authenticator::ApiKeyAuthenticator;
use libra_identity_authenticator::{authenticator::Authenticator, authenticators::Authenticators};
use libra_identity_jwks::{KeyStore, error::KeyStoreError};
use libra_identity_jwt::{TokenValidator, ValidationSettings, authenticator::JwtAuthenticator};
use libra_identity_key_store::{
    error::StoreError,
    lease::{InstanceId, Lease, LeaseError},
    store::ApiKeyStore,
};
use libra_jsonld_context::{error::ContextError, resolver::ContextResolver};
use libra_policy_store::{error::PolicyStoreError, store::PolicyStore};
use std::{path::Path, sync::Arc, time::Duration};
use tracing::info;

/// What a request is judged with, built once: how its names resolve, which policies decide it, and
/// who its caller is.
pub struct RequestPath {
    /// Resolves the JSON-LD context of each request, and of each policy file.
    pub resolver: Arc<ContextResolver>,
    /// The compiled policy set.
    pub store: Arc<PolicyStore>,
    /// How a presented credential becomes a caller.
    pub authentication: CallerAuthentication,
}

/// How a presented credential becomes a caller, the same on the proxied path and at the management
/// gate.
#[derive(Clone)]
pub struct CallerAuthentication {
    /// Turns a presented credential into a caller.
    pub authenticators: Arc<Authenticators>,
    /// The audit key for credential fingerprints, absent when the deployment configured none.
    pub fingerprint: Option<FingerprintKey>,
}

/// What runs beside serving rather than on a request.
pub struct Background {
    /// The JWT signing keys the refresh task renews and the readiness probe checks, absent when the
    /// deployment accepts no JWT.
    pub signing_keys: Option<SigningKeys>,
    /// The API key store and the lease this instance keeps on it, absent when none is configured.
    pub key_store: Option<LeasedKeyStore>,
}

/// The JWT signing keys, and how often they are fetched again.
#[derive(Clone)]
pub struct SigningKeys {
    /// The key set, kept for the readiness probe and the refresh task.
    pub keys: KeyStore,
    /// How long a fetched key set is used before it is fetched again.
    pub refresh_period: Duration,
}

/// An API key store this instance holds the lease on.
#[derive(Debug, Clone)]
pub struct LeasedKeyStore {
    /// The store.
    pub store: ApiKeyStore,
    /// The lease, renewed while serving and released on the way out.
    pub lease: Lease,
}

/// Anything that stops Libra before it is serving.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The JSON-LD configuration is unusable, or the core context is not.
    #[error(transparent)]
    Context(#[from] ContextError),

    /// The signing keys could not be fetched.
    ///
    /// Fatal rather than deferred: without keys every token would be refused, so a process that
    /// started anyway would be a process that refuses everything while reporting itself healthy.
    #[error(transparent)]
    Keys(#[from] KeyStoreError),

    /// The policy set would not load.
    #[error(transparent)]
    Policies(#[from] PolicyStoreError),

    /// The API key store could not be opened.
    #[error(transparent)]
    ApiKeys(#[from] StoreError),

    /// The API key store's lease is held by another instance, or could not be claimed.
    #[error(transparent)]
    Lease(#[from] LeaseError),

    /// Nothing in this deployment accepts a credential.
    ///
    /// Every bearer credential would be refused, which is a misconfiguration rather than a
    /// deployment: a gateway that authenticates nobody is not one anybody meant to start.
    #[error("no credential would be accepted: configure [jwt], [key-store], or both")]
    NoAuthenticator,
}

/// Builds what the request path reads and what runs beside it. `extra` are the authenticators the
/// binary adds, after the JWT authenticator and the API key authenticator, each present when its
/// section is.
///
/// # Errors
///
/// Returns [`StartupError`] if any of it cannot be built. Every variant is fatal.
pub async fn build(config: &Config, extra: Vec<Arc<dyn Authenticator>>) -> Result<(RequestPath, Background), StartupError> {
    // The core context is processed here, so a broken one stops the process rather than
    // failing every request once Libra is serving.
    let resolver = Arc::new(ContextResolver::new(&config.jsonld)?);
    info!(
        allow_remote = config.jsonld.allow_remote,
        allowed_contexts = ?config.jsonld.allowed_contexts,
        "JSON-LD context resolution ready"
    );

    let store = Arc::new(PolicyStore::from_config(&config.authz, &resolver).await?);
    let snapshot = store.snapshot();
    info!(
        policies = snapshot.len(),
        default_effect = ?snapshot.default_effect(),
        directory = %store.directory().display(),
        "authorization policies loaded"
    );

    let mut authenticators: Vec<Arc<dyn Authenticator>> = Vec::new();

    let signing_keys = match &config.jwt {
        Some(jwt) => {
            let (keys, authenticator) = jwt_authenticator(jwt).await?;
            authenticators.push(Arc::new(authenticator));
            Some(keys)
        }
        None => None,
    };

    let key_store = match config.key_store.enabled_path() {
        Some(path) => {
            let leased = open_key_store(path).await?;
            authenticators.push(Arc::new(ApiKeyAuthenticator::new(leased.store.clone()))); // a handle to the shared pool
            Some(leased)
        }
        None => None,
    };

    authenticators.extend(extra);
    let authenticators = Authenticators::new(authenticators);
    if authenticators.is_empty() {
        return Err(StartupError::NoAuthenticator);
    }

    let fingerprint = config.audit.token_fingerprint_key.as_ref().map(|secret| FingerprintKey::new(secret.bytes()));
    if fingerprint.is_some() {
        // The key is a deliberate decision to record a digest of every credential, and
        // rotating it breaks correlation with the records before the rotation.
        info!("credential fingerprints are on: rotating the audit key breaks correlation with earlier records");
    }

    let request_path = RequestPath {
        resolver,
        store,
        authentication: CallerAuthentication {
            authenticators: Arc::new(authenticators),
            fingerprint,
        },
    };

    Ok((request_path, Background { signing_keys, key_store }))
}

/// Fetches the signing keys `[jwt]` names and builds the authenticator that verifies tokens with
/// them.
async fn jwt_authenticator(jwt: &Jwt) -> Result<(SigningKeys, JwtAuthenticator), StartupError> {
    let keys = KeyStore::new(jwt.jwks_url.clone()).await?; // the key store owns its address, the configuration is borrowed
    info!(url = %jwt.jwks_url, issuer = %jwt.issuer, audience = %jwt.audience, "JWTs are accepted; signing keys loaded");

    let validator = TokenValidator::new(keys.clone(), &ValidationSettings::from(jwt)); // a shared handle to the key set, which the background keeps for the health probe and refresh task
    let signing_keys = SigningKeys {
        keys,
        refresh_period: Duration::from_secs(jwt.jwks_cache_duration),
    };

    Ok((signing_keys, JwtAuthenticator::new(validator)))
}

/// Opens the API key store and claims its lease for this instance.
async fn open_key_store(path: &Path) -> Result<LeasedKeyStore, StartupError> {
    let store = ApiKeyStore::open(path).await?;

    let now = Timestamp::now();
    let lease = store.claim_lease(InstanceId::generate(now)?, now).await?;
    info!(path = %path.display(), instance = %lease.holder(), "API keys are accepted; this instance holds the key store's lease");

    Ok(LeasedKeyStore { store, lease })
}
