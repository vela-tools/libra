//! What the fuzz targets share: the contexts and services a parser needs around it.
//!
//! A target exercises one parser on hostile input. Whatever that parser is handed besides the input
//! (the core context, a context resolver, a runtime, a key set endpoint, a token validator) is built once per process here, so every input
//! is judged by the same surroundings and an execution costs the parser, not its setup.
//!
//! Setup that fails stops the process: a harness that cannot be built has nothing to fuzz, and
//! continuing would report inputs as passing that were never run.
#![expect(clippy::expect_used, reason = "setup that fails has to stop the process, and the message says which part failed")]

pub mod context_resolver;
pub mod core_context;
pub mod jwks_endpoint;
pub mod runtime;
pub mod token_validator;
