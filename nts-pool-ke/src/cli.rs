use crate::daemon_tracing::LogLevel;
use std::path::PathBuf;
use std::str::FromStr;

const USAGE_MSG: &str = "\
usage: nts-pool-ke [-c PATH] [-l LOG_LEVEL]
       nts-pool-ke -h
       nts-pool-ke -v";

const DESCRIPTOR: &str = "ntp-daemon - synchronize system time";

const HELP_MSG: &str = "Options:
  -c, --config=PATH             change the config .toml file
  -l, --log-level=LOG_LEVEL     change the log level
  -h, --help                    display this help text
  -v, --version                 display version information";

pub fn long_help_message() -> String {
    format!("{DESCRIPTOR}\n\n{USAGE_MSG}\n\n{HELP_MSG}")
}

#[derive(Debug, Default)]
pub(crate) struct NtsPoolKeOptions {
    /// Path of the configuration file
    pub config: Option<PathBuf>,
    /// Level for messages to display in logs
    pub log_level: Option<LogLevel>,
    help: bool,
    version: bool,
    pub action: NtsPoolKeAction,
}

pub enum CliArg {
    Flag(String),
    Argument(String, String),
    Rest(Vec<String>),
}

impl CliArg {
    pub fn normalize_arguments<I>(
        takes_argument: &[&str],
        takes_argument_short: &[char],
        iter: I,
    ) -> Result<Vec<Self>, String>
    where
        I: IntoIterator<Item = String>,
    {
        // the first argument is the nts-pool-ke command - so we can skip it
        let mut arg_iter = iter.into_iter().skip(1);
        let mut processed = vec![];
        let mut rest = vec![];

        while let Some(arg) = arg_iter.next() {
            match arg.as_str() {
                "--" => {
                    rest.extend(arg_iter);
                    break;
                }
                long_arg if long_arg.starts_with("--") => {
                    // --config=/path/to/config.toml
                    let invalid = Err(format!("invalid option: '{long_arg}'"));

                    if let Some((key, value)) = long_arg.split_once('=') {
                        if takes_argument.contains(&key) {
                            processed.push(CliArg::Argument(key.to_string(), value.to_string()));
                        } else {
                            invalid?;
                        }
                    } else if takes_argument.contains(&long_arg) {
                        if let Some(next) = arg_iter.next() {
                            processed.push(CliArg::Argument(long_arg.to_string(), next));
                        } else {
                            Err(format!("'{}' expects an argument", &long_arg))?;
                        }
                    } else {
                        processed.push(CliArg::Flag(arg));
                    }
                }
                short_arg if short_arg.starts_with('-') => {
                    // split combined shorthand options
                    for (n, char) in short_arg.trim_start_matches('-').chars().enumerate() {
                        let flag = format!("-{char}");
                        // convert option argument to separate segment
                        if takes_argument_short.contains(&char) {
                            let rest = short_arg[(n + 2)..].trim().to_string();
                            // assignment syntax is not accepted for shorthand arguments
                            if rest.starts_with('=') {
                                Err("invalid option '='")?;
                            }
                            if !rest.is_empty() {
                                processed.push(CliArg::Argument(flag, rest));
                            } else if let Some(next) = arg_iter.next() {
                                processed.push(CliArg::Argument(flag, next));
                            } else if char == 'h' {
                                // short version of --help has no arguments
                                processed.push(CliArg::Flag(flag));
                            } else {
                                Err(format!("'-{char}' expects an argument"))?;
                            }
                            break;
                        }

                        processed.push(CliArg::Flag(flag));
                    }
                }
                _argument => rest.push(arg),
            }
        }

        if !rest.is_empty() {
            processed.push(CliArg::Rest(rest));
        }

        Ok(processed)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum NtsPoolKeAction {
    #[default]
    Help,
    Version,
    Run,
}

impl NtsPoolKeOptions {
    const TAKES_ARGUMENT: &'static [&'static str] = &["--config", "--log-level"];
    const TAKES_ARGUMENT_SHORT: &'static [char] = &['c', 'l'];

    /// parse an iterator over command line arguments
    pub fn try_parse_from<I, T>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str> + Clone,
    {
        let mut options = NtsPoolKeOptions::default();
        let arg_iter = CliArg::normalize_arguments(
            Self::TAKES_ARGUMENT,
            Self::TAKES_ARGUMENT_SHORT,
            iter.into_iter().map(|x| x.as_ref().to_string()),
        )?
        .into_iter()
        .peekable();

        for arg in arg_iter {
            match arg {
                CliArg::Flag(flag) => match flag.as_str() {
                    "-h" | "--help" => {
                        options.help = true;
                    }
                    "-v" | "--version" => {
                        options.version = true;
                    }
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Argument(option, value) => match option.as_str() {
                    "-c" | "--config" => {
                        options.config = Some(PathBuf::from(value));
                    }
                    "-l" | "--log-level" => match LogLevel::from_str(&value) {
                        Ok(level) => options.log_level = Some(level),
                        Err(_) => return Err("invalid log level".into()),
                    },
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Rest(_rest) => { /* do nothing, drop remaining arguments */ }
            }
        }

        options.resolve_action();
        // nothing to validate at the moment

        Ok(options)
    }

    /// from the arguments resolve which action should be performed
    fn resolve_action(&mut self) {
        if self.help {
            self.action = NtsPoolKeAction::Help;
        } else if self.version {
            self.action = NtsPoolKeAction::Version;
        } else {
            self.action = NtsPoolKeAction::Run;
        }
    }
}
