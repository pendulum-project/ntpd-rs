use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::Deserialize;
use tracing::metadata::LevelFilter;

#[derive(Debug, Default, Copy, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    Trace = 0,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    Debug = 1,
    /// The "info" level.
    ///
    /// Designates useful information.
    #[default]
    Info = 2,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    Warn = 3,
    /// The "error" level.
    ///
    /// Designates very serious errors.
    Error = 4,
}

pub struct UnknownLogLevel;

impl FromStr for LogLevel {
    type Err = UnknownLogLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(UnknownLogLevel),
        }
    }
}

impl From<LogLevel> for tracing::Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        LevelFilter::from_level(value.into())
    }
}

struct ReloadableMakeWriter {
    file: Arc<Mutex<std::fs::File>>,
}

struct ReloadableWriter<'a> {
    writer: MutexGuard<'a, std::fs::File>,
}

impl std::io::Write for ReloadableWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        self.writer.write_vectored(bufs)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(buf)
    }

    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        self.writer.write_fmt(args)
    }
}

pub struct LogReloadTaskStarter {
    path: PathBuf,
    file_handle: Arc<Mutex<std::fs::File>>,
}

impl ReloadableMakeWriter {
    // Note, making one of these leaks
    fn new(path: PathBuf) -> Result<(Self, LogReloadTaskStarter), std::io::Error> {
        let file = std::fs::File::create(&path)?;
        let file = Arc::new(Mutex::new(file));
        let file_handle = file.clone();
        Ok((Self { file }, LogReloadTaskStarter { path, file_handle }))
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ReloadableMakeWriter {
    type Writer = ReloadableWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        ReloadableWriter {
            writer: self.file.lock().unwrap(),
        }
    }
}

impl LogReloadTaskStarter {
    pub fn start(self) {
        tokio::spawn(async move {
            let Ok(mut stream) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                tracing::error!("Could not listen for hangup signal, logrotation may malfunction.");
                return;
            };

            loop {
                stream.recv().await;
                let new_file = match std::fs::File::create(&self.path) {
                    Ok(new_file) => new_file,
                    Err(e) => {
                        tracing::error!(
                            "Could not reopen log file, continuing with old handle: {e}"
                        );
                        continue;
                    }
                };
                *self.file_handle.lock().unwrap() = new_file;
            }
        });
    }
}

pub fn tracing_init(
    level: impl Into<LevelFilter>,
    log_path: Option<PathBuf>,
    ansi_colors: bool,
) -> (
    Box<dyn tracing::Subscriber + Send + Sync + 'static>,
    Option<LogReloadTaskStarter>,
) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(ansi_colors);
    if let Some(path) = log_path {
        let (writer, task_starter) = match ReloadableMakeWriter::new(path.clone()) {
            Ok(writer) => writer,
            Err(e) => {
                tracing::error!("Could not open logfile {}, exiting: {e}", path.display());
                std::process::exit(70);
            }
        };
        (
            Box::new(builder.with_writer(writer).finish()),
            Some(task_starter),
        )
    } else {
        (Box::new(builder.finish()), None)
    }
}
