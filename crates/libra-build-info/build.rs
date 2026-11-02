//! Emits the build-time constants Libra reports through `--version` and its info endpoint.
//!
//! shadow-rs does not fail without git metadata: it emits an empty commit. The build refuses that
//! instead, so no binary ships that cannot say which commit it came from. A container build needs
//! `.git` in its context for this reason.

use shadow_rs::{SHORT_COMMIT, SdResult, ShadowBuilder};

fn main() -> SdResult<()> {
    let shadow = ShadowBuilder::builder().build()?;
    if shadow.map.get(SHORT_COMMIT).is_none_or(|commit| commit.v.is_empty()) {
        return Err("no git commit found: build from a git checkout, with `.git` in the build context".into());
    }
    Ok(())
}
