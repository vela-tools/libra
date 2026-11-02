//! Whether a document must carry the member a restriction judges.

use serde::{Deserialize, Serialize};

/// Whether a document must carry the member a restriction judges, such as an entity's scope or its
/// type, or may leave it out.
///
/// A restriction cannot judge a member that is absent, so this is what decides what absence means.
/// Written `required` or `optional` in a policy file; the default is `required`, because an
/// unlabelled write is refused rather than let through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberOnWrite {
    /// A document without the member is refused.
    #[default]
    Required,
    /// A document without the member is accepted, and judged by what it does carry.
    Optional,
}
