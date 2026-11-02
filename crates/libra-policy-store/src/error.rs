//! Why a policy set could not be loaded.
//!
//! Every variant stops the process. There is no partial load: a policy set that is half in force
//! is a policy set nobody has reviewed, and the half that is missing is always the half that would
//! have refused something.

use libra_jsonld_context::error::ContextError;
use libra_policy_model::{error::CompileError, policy::PolicyId};
use std::{io, path::PathBuf};
use thiserror::Error;
use toml::de::Error as TomlError;

/// A policy set could not be loaded.
#[derive(Debug, Error)]
pub enum PolicyStoreError {
    /// The configured policy directory is not a directory.
    #[error("the policy directory '{path}' does not exist or is not a directory")]
    NotADirectory {
        /// What was configured.
        path: PathBuf,
    },

    /// A policy file could not be read.
    #[error("could not read '{path}'")]
    Unreadable {
        /// The file.
        path: PathBuf,
        /// What the filesystem said.
        #[source]
        source: io::Error,
    },

    /// A policy file is not valid TOML, or does not fit the schema.
    #[error("could not parse '{path}'")]
    Malformed {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        #[source]
        source: TomlError,
    },

    /// A policy file declares a context that could not be resolved.
    ///
    /// Fatal rather than skipped: without the context the file's terms have no meaning, and a
    /// policy whose terms have no meaning cannot be said to allow or refuse anything.
    #[error("could not resolve the context declared by '{path}'")]
    Context {
        /// The file.
        path: PathBuf,
        /// What resolution said.
        #[source]
        source: ContextError,
    },

    /// A policy's terms could not be compiled against its declared context, or it carries a
    /// restriction that nothing claims or that its kind refuses.
    ///
    /// The unclaimed case is the refusal that makes one policy format safe to share between builds.
    /// A build that loaded the policy would answer the request while silently ignoring the
    /// restriction, which turns the policy into a permission, in a build the operator believes is
    /// enforcing it.
    #[error("in '{path}': {source}")]
    Compile {
        /// The file.
        path: PathBuf,
        /// What compilation said.
        #[source]
        source: CompileError,
    },

    /// Two policies share an identifier.
    ///
    /// Which one applies would depend on the order the directory happened to be read in.
    #[error("policy '{id}' is defined in both '{first}' and '{second}'")]
    DuplicateId {
        /// The repeated identifier.
        id: PolicyId,
        /// Where it was seen first.
        first: PathBuf,
        /// Where it was seen again.
        second: PathBuf,
    },

    /// A policy can never apply, or can never allow anything.
    ///
    /// An empty condition list, or a window whose start is after its end. Both read as a policy and
    /// enforce as nothing, which is the shape of a policy someone believes is in force.
    #[error("policy '{id}' in '{path}' can never apply; it has an empty condition list or an impossible window")]
    Unsatisfiable {
        /// The policy.
        id: PolicyId,
        /// The file.
        path: PathBuf,
    },
}
