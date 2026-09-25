use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::{
    Config, ConfigError, PartialConfig, UseSystemConfig,
    load::files::{Files, Filesystem},
    tree::{ConfigMerger, Setting},
};

mod files;

/// Where `use-system-config = true` reads its fragments from.
const DEFAULT_SYSTEM_CONFIG: &str = "/usr/lib/ntpd-rs/system-config";

impl Config {
    /// Load the configuration from `path`, layered on top of the system
    /// configuration fragments it asks for, if any.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::load_from(&Filesystem, path.as_ref())
    }

    fn load_from(files: &impl Files, main_path: &Path) -> Result<Self, ConfigError> {
        let main = parse::<PartialConfig>(files, main_path)?;

        let mut merger = ConfigMerger::new();

        for fragment in system_fragments(files, &main.use_system_config)? {
            let partial = parse::<PartialConfig>(files, &fragment)?;

            // this setting is what sent the loader looking for fragments, so
            // the documents it found cannot be the ones to answer it
            if !partial.use_system_config.is_unset() {
                return Err(ConfigError::DirectiveNotAllowed { path: fragment });
            }

            merger.add_system(fragment, partial)?;
        }

        merger.add_main(main_path.to_path_buf(), main)?;
        merger.apply_defaults();

        let (config, _provenance) = merger.finish()?;

        Ok(config)
    }
}

fn parse<T: DeserializeOwned>(files: &impl Files, path: &Path) -> Result<T, ConfigError> {
    let contents = files
        .read(path)
        .map_err(|cause| ConfigError::CouldNotRead {
            path: path.to_path_buf(),
            cause,
        })?;

    toml::from_str(&contents).map_err(|cause| ConfigError::CouldNotParse {
        path: path.to_path_buf(),
        cause,
    })
}

/// The directory to read fragments from, and whether the configuration named
/// it: a directory that was asked for and is missing is a mistake, whereas the
/// default one can be missing.
fn fragment_directory(setting: &Setting<UseSystemConfig>) -> Option<(PathBuf, bool)> {
    match setting.get()? {
        UseSystemConfig::Enabled(false) => None,
        UseSystemConfig::Enabled(true) => Some((PathBuf::from(DEFAULT_SYSTEM_CONFIG), false)),
        UseSystemConfig::Directory(path) => Some((path.clone(), true)),
    }
}

fn system_fragments(
    files: &impl Files,
    setting: &Setting<UseSystemConfig>,
) -> Result<Vec<PathBuf>, ConfigError> {
    let Some((directory, named)) = fragment_directory(setting) else {
        // use-system-config is not set, or set explicitly to false
        return Ok(Vec::new());
    };

    let entries = match files.list(&directory) {
        Ok(entries) => entries,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound && !named => {
            return Ok(Vec::new());
        }
        Err(cause) => {
            return Err(ConfigError::CouldNotRead {
                path: directory,
                cause,
            });
        }
    };

    // only read toml files in the directory
    let mut fragments: Vec<_> = entries
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect();

    // fragments don't need to be merged deterministically, but it helps for
    // error messages and debugging to ensure we do
    fragments.sort();

    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigError, LogLevel, ServerSourceConfig, SourceConfig, load::files::Memory};

    fn load(documents: Memory) -> Result<Config, ConfigError> {
        Config::load_from(&documents, Path::new("/etc/ntp.toml"))
    }

    #[test]
    fn fragments_contribute_to_the_configuration() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'")
            .document(
                "/etc/ntp.d/10-logging.toml",
                "observability.log-level = 'warn'",
            )
            .document(
                "/etc/ntp.d/20-sources.toml",
                "[[sources]]\nmode = 'server'\nurl = 'example.com'",
            )
            // only TOML documents are read
            .document("/etc/ntp.d/README.md", "not a configuration");

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Warn);
        assert_eq!(
            config.sources,
            vec![SourceConfig::Server(ServerSourceConfig {
                url: "example.com".to_owned(),
                ntp_version: 4,
            })]
        );
    }

    #[test]
    fn the_main_config_overrides_a_fragment() {
        let documents = Memory::new()
            .document(
                "/etc/ntp.toml",
                "use-system-config = '/etc/ntp.d'\nobservability.log-level = 'debug'",
            )
            .document(
                "/etc/ntp.d/10-logging.toml",
                "observability.log-level = 'warn'",
            );

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Debug);
    }

    #[test]
    fn a_fragment_may_not_steer_the_loader() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'")
            .document("/etc/ntp.d/10-logging.toml", "use-system-config = true");

        let error = load(documents).unwrap_err();

        let ConfigError::DirectiveNotAllowed { path } = error else {
            panic!("expected a rejected directive, got {error:?}");
        };
        assert_eq!(path, PathBuf::from("/etc/ntp.d/10-logging.toml"));
    }

    #[test]
    fn the_default_directory_is_read_when_enabled() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = true")
            .document(
                "/usr/lib/ntpd-rs/system-config/10-logging.toml",
                "observability.log-level = 'warn'",
            );

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Warn);
    }

    #[test]
    fn an_unset_setting_means_no_system_configuration() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "")
            // the same fragment the setting would have reached
            .document(
                "/usr/lib/ntpd-rs/system-config/10-logging.toml",
                "observability.log-level = 'warn'",
            );

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Info);
    }

    #[test]
    fn the_system_config_setting_is_part_of_the_configuration() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'")
            .directory("/etc/ntp.d");

        let config = load(documents).unwrap();

        assert_eq!(
            config.use_system_config,
            UseSystemConfig::Directory("/etc/ntp.d".into())
        );

        // and it takes its default like any other setting
        let unset = Memory::new().document("/etc/ntp.toml", "");
        assert_eq!(
            load(unset).unwrap().use_system_config,
            UseSystemConfig::Enabled(false)
        );
    }

    #[test]
    fn an_empty_fragment_directory_is_not_an_error() {
        let documents = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'")
            .directory("/etc/ntp.d");

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Info);
    }

    #[test]
    fn a_named_directory_that_is_missing_is_an_error() {
        let documents = Memory::new().document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'");

        let error = load(documents).unwrap_err();

        let ConfigError::CouldNotRead { path, .. } = error else {
            panic!("expected a read failure, got {error:?}");
        };
        assert_eq!(path, PathBuf::from("/etc/ntp.d"));
    }

    #[test]
    fn errors_describe_themselves() {
        let missing_value = Memory::new().document(
            "/etc/ntp.toml",
            "[[sources]]\nmode = 'server'\nntp-version = 5",
        );
        assert_eq!(
            load(missing_value).unwrap_err().to_string(),
            "`sources[0].url` is required, but was never set"
        );

        let unreadable = Memory::new();
        assert_eq!(
            load(unreadable).unwrap_err().to_string(),
            "could not read `/etc/ntp.toml`: no such document"
        );

        let set_in_fragment = Memory::new()
            .document("/etc/ntp.toml", "use-system-config = '/etc/ntp.d'")
            .document("/etc/ntp.d/10-logging.toml", "use-system-config = true");
        assert_eq!(
            load(set_in_fragment).unwrap_err().to_string(),
            "`/etc/ntp.d/10-logging.toml` sets `use-system-config`, \
             which only the main configuration may do"
        );
    }

    /// Assert that a document is rejected while parsing, by a complaint that
    /// points at `offender`.
    fn rejects(document: &str, offender: &str) {
        let documents = Memory::new().document("/etc/ntp.toml", document);
        let error = load(documents).unwrap_err();

        assert!(
            matches!(error, ConfigError::CouldNotParse { .. }),
            "expected {document:?} to be rejected while parsing, got {error:?}"
        );
        assert!(
            error.to_string().contains(offender),
            "the complaint about {document:?} does not mention `{offender}`: {error}"
        );
    }

    #[test]
    fn an_unknown_key_is_rejected_wherever_it_appears() {
        rejects("log-levle = 'warn'", "log-levle");
        rejects("[observability]\nlog-levle = 'warn'", "log-levle");
        rejects(
            "[[sources]]\nmode = 'server'\nurl = 'a'\nurll = 'b'",
            "urll",
        );
        rejects("[[sources]]\nmode = 'nonsense'", "nonsense");
    }

    #[test]
    fn the_default_directory_need_not_exist() {
        let documents = Memory::new().document("/etc/ntp.toml", "use-system-config = true");

        let config = load(documents).unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Info);
    }
}
