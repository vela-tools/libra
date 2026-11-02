//! A configuration that has been read but not yet accepted.
//!
//! Loading splits the configuration in two. What [`Config`] defines is extracted at once. Every
//! other top-level section is held aside until a crate claims it with [`PendingConfig::take_section`],
//! and [`PendingConfig::finish`] refuses to produce a [`Loaded`] while any is left. That is the
//! property `deny_unknown_fields` gave when every section was defined here: a section nobody reads
//! is a startup error, not a section that quietly does nothing.

use crate::{
    Config,
    ConfigError,
    Loaded,
    section::{ConfigSection, SectionName},
    source::ConfigSource,
};
use figment2::{
    Figment,
    Profile,
    Provider,
    providers::{Format, Serialized, Toml},
    value::Dict,
};
use serde_aux::serde_introspection::serde_introspect;
use std::collections::BTreeSet;

/// A configuration whose own sections are read and whose other sections are waiting to be claimed.
#[derive(Debug)]
pub struct PendingConfig {
    config: Config,
    source: ConfigSource,
    /// The field names [`Config`]'s `Deserialize` implementation reads, which are its sections as the
    /// file spells them. A crate cannot claim one, so an extension cannot shadow `[authz]`.
    reserved: BTreeSet<&'static str>,
    unclaimed: Dict,
    claimed: BTreeSet<SectionName>,
}

impl PendingConfig {
    /// Splits a merged figment into the sections `Config` defines and everything else.
    ///
    /// The names `Config` defines are the field names its `Deserialize` implementation reads, so
    /// adding a section to `Config` cannot leave this stale. They are not read from the serialized
    /// defaults: an optional section has no default, and would be mistaken for one nobody reads.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Extract`] if the figment cannot be read or a defined section does not
    /// fit its type.
    pub(crate) fn from_figment(figment: &Figment, source: ConfigSource) -> Result<Self, ConfigError> {
        let reserved: BTreeSet<&'static str> = serde_introspect::<Config>().iter().copied().collect();

        let merged = figment
            .data()
            .map_err(|error| ConfigError::Extract(Box::new(error)))?
            .remove(&Profile::Default)
            .unwrap_or_default();
        let (defined, unclaimed): (Dict, Dict) = merged.into_iter().partition(|(name, _)| reserved.contains(name.as_str()));

        let config: Config = Figment::from(Serialized::defaults(defined))
            .extract()
            .map_err(|error| ConfigError::Extract(Box::new(error)))?;

        config.validate()?;

        Ok(Self {
            config,
            source,
            reserved,
            unclaimed,
            claimed: BTreeSet::new(),
        })
    }

    /// Reads a configuration from TOML text alone, over the defaults each section declares, the way
    /// a file is read.
    ///
    /// The environment is not consulted, so the result depends on the text and nothing else. That
    /// is what makes it the way to check a file, such as the one an image ships, against the schema
    /// that will read it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Extract`] if the text is not TOML or a defined section does not fit.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let figment = Figment::from(Toml::string(text));

        Self::from_figment(&figment, ConfigSource::None)
    }

    /// The sections every build reads.
    ///
    /// Available before [`PendingConfig::finish`] because a crate building its own layers needs
    /// values from them.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Claims one extension section, layering the file and the environment over `S::default()`.
    ///
    /// A section the file never mentions is `S::default()`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ReservedSection`] if `S` names a section [`Config`] defines,
    /// [`ConfigError::SectionClaimedTwice`] if it was already claimed, and
    /// [`ConfigError::Extract`] if the section does not fit `S`, including a key `S` does not know.
    pub fn take_section<S: ConfigSection>(&mut self) -> Result<S, ConfigError> {
        let name = S::NAME;

        if self.reserved.contains(name.as_str()) {
            return Err(ConfigError::ReservedSection { name });
        }
        if !self.claimed.insert(S::NAME) {
            return Err(ConfigError::SectionClaimedTwice { name });
        }

        let layered = match self.unclaimed.remove(name.as_str()) {
            Some(written) => Figment::from(Serialized::default(name.as_str(), S::default())).merge(Serialized::default(name.as_str(), written)),
            None => Figment::from(Serialized::default(name.as_str(), S::default())),
        };

        layered.extract_inner(name.as_str()).map_err(|error| ConfigError::Extract(Box::new(error)))
    }

    /// Accepts the configuration, if every section in it was read by someone.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::UnclaimedSections`] naming every section nothing claimed, so an
    /// operator can fix the file in one pass.
    pub fn finish(self) -> Result<Loaded, ConfigError> {
        if self.unclaimed.is_empty() {
            return Ok(Loaded {
                config: self.config,
                source: self.source,
            });
        }

        Err(ConfigError::UnclaimedSections {
            names: self.unclaimed.into_keys().collect(),
        })
    }
}

/// The smallest configuration that loads, which is a broker and nothing else.
#[cfg(test)]
const BROKER: &str = "[broker]\nurl = \"http://broker.test:9090\"";

#[cfg(test)]
impl PendingConfig {
    /// Reads TOML text over [`BROKER`], so a test about another section need not name the broker
    /// every configuration requires. A `[broker] url` in the text takes precedence.
    pub(crate) fn from_toml_with_broker(text: &str) -> Result<Self, ConfigError> {
        let figment = Figment::from(Toml::string(BROKER)).merge(Toml::string(text));

        Self::from_figment(&figment, ConfigSource::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};

    /// A section some other crate would own.
    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct CacheLike {
        enabled: bool,
        max_entries: u64,
    }

    impl Default for CacheLike {
        fn default() -> Self {
            Self {
                enabled: true,
                max_entries: 100,
            }
        }
    }

    impl ConfigSection for CacheLike {
        const NAME: SectionName = SectionName::from_static("cache-like");
    }

    /// A second section, so a test can say two are claimed independently.
    #[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct Other {
        level: u8,
    }

    impl ConfigSection for Other {
        const NAME: SectionName = SectionName::from_static("other");
    }

    /// A section that reuses a name `Config` already defines.
    #[derive(Debug, Default, Deserialize, Serialize)]
    struct Shadow {}

    impl ConfigSection for Shadow {
        const NAME: SectionName = SectionName::from_static("authz");
    }

    fn pending(source: &str) -> PendingConfig {
        PendingConfig::from_toml_with_broker(source).unwrap()
    }

    fn unclaimed(result: Result<Loaded, ConfigError>) -> Vec<String> {
        match result {
            Err(ConfigError::UnclaimedSections { names }) => names,
            other => panic!("expected unclaimed sections, got {other:?}"),
        }
    }

    #[test]
    fn a_section_nothing_claims_fails_finish_and_is_named() {
        let pending = pending("[cache-like]\nenabled = false");

        assert_eq!(unclaimed(pending.finish()), ["cache-like"]);
    }

    #[test]
    fn a_misspelled_section_fails_finish_while_the_real_one_loads_from_defaults() {
        let mut pending = pending("[cache-lik]\nenabled = false");

        assert_eq!(pending.take_section::<CacheLike>().unwrap(), CacheLike::default());
        assert_eq!(unclaimed(pending.finish()), ["cache-lik"]);
    }

    #[test]
    fn a_mistyped_key_inside_a_claimed_section_is_an_error() {
        let mut pending = pending("[cache-like]\nmax_entries = 5");

        assert!(matches!(pending.take_section::<CacheLike>(), Err(ConfigError::Extract(..))));
    }

    #[test]
    fn a_claimed_section_layers_its_defaults_under_the_file() {
        let mut pending = pending("[cache-like]\nmax-entries = 25");

        assert_eq!(
            pending.take_section::<CacheLike>().unwrap(),
            CacheLike {
                enabled: true,
                max_entries: 25
            }
        );
        assert!(pending.finish().is_ok());
    }

    #[test]
    fn a_claimed_section_the_file_never_mentions_is_its_defaults() {
        let mut pending = pending("");

        assert_eq!(pending.take_section::<CacheLike>().unwrap(), CacheLike::default());
        assert!(pending.finish().is_ok());
    }

    #[test]
    fn every_unclaimed_section_is_named_at_once() {
        let pending = pending("[cache-like]\nenabled = false\n\n[other]\nlevel = 1");

        assert_eq!(unclaimed(pending.finish()), ["cache-like", "other"]);
    }

    #[test]
    fn two_sections_are_claimed_independently() {
        let mut pending = pending("[cache-like]\nenabled = false\n\n[other]\nlevel = 3");

        assert!(!pending.take_section::<CacheLike>().unwrap().enabled);
        assert_eq!(pending.take_section::<Other>().unwrap(), Other { level: 3 });
        assert!(pending.finish().is_ok());
    }

    #[test]
    fn a_section_defined_by_config_is_never_offered_as_an_extension() {
        let mut pending = pending("[authz]\ndefault-effect = \"allow\"");

        assert!(matches!(pending.take_section::<Shadow>(), Err(ConfigError::ReservedSection { .. })));
        assert!(pending.finish().is_ok(), "a defined section is read by Config, so nothing is left over");
    }

    #[test]
    fn a_section_cannot_be_claimed_twice() {
        let mut pending = pending("");

        assert!(pending.take_section::<CacheLike>().is_ok());
        assert!(matches!(pending.take_section::<CacheLike>(), Err(ConfigError::SectionClaimedTwice { .. })));
    }

    #[test]
    fn the_sections_config_defines_are_not_extension_candidates() {
        let pending = pending("[libra]\nport = 9999\n\n[management-api]\nadmin-users = [\"ops\"]");

        assert_eq!(pending.config().libra.port, 9999);
        assert!(pending.finish().is_ok());
    }

    #[test]
    fn every_section_config_defines_is_reserved_including_the_optional_ones() {
        let pending = pending("");

        for name in ["libra", "broker", "jwt", "key-store", "management-api", "representation"] {
            assert!(pending.reserved.contains(name), "{name} is a section Config defines");
        }
        assert!(!pending.reserved.contains("key_store"), "names are reserved as the file spells them");
    }

    #[test]
    fn an_optional_section_cannot_be_claimed_by_an_extension() {
        // An absent optional section is still a name Config defines, so an extension cannot claim
        // `[jwt]` and shadow it.
        #[derive(Debug, Default, Deserialize, Serialize)]
        struct ShadowJwt {}

        impl ConfigSection for ShadowJwt {
            const NAME: SectionName = SectionName::from_static("jwt");
        }

        assert!(matches!(pending("").take_section::<ShadowJwt>(), Err(ConfigError::ReservedSection { .. })));
    }

    #[test]
    fn a_key_misspelled_inside_a_defined_section_is_still_an_error() {
        assert!(matches!(
            PendingConfig::from_toml_with_broker("[libra]\nprot = 1"),
            Err(ConfigError::Extract(..))
        ));
    }
}
