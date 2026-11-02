//! A policy file, read and compiled against the core context.
//!
//! The contexts a file declares are not fetched: the target compiles against the core context
//! alone, which is what a file that declares none is compiled against.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_policy_model::policy::PolicyFile;
use toml::from_str;

fuzz_target!(|source: &str| {
    let Ok(file) = from_str::<PolicyFile>(source) else {
        return;
    };

    for policy in &file.policy {
        if policy.is_satisfiable() {
            let _ = policy.compile(core_context::resolved());
        }
    }
});
