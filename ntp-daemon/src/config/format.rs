use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;
use tracing::Subscriber;
use tracing_subscriber::{
    field::RecordFields,
    fmt::{
        format::{
            Compact, DefaultFields, Format, Full, Json, JsonFields, Pretty, PrettyFields, Writer,
        },
        FormatEvent, FormatFields,
    },
    registry::LookupSpan,
};

#[derive(Debug, Clone)]
pub enum LogFormat {
    Full(Format<Full>),
    Compact(Format<Compact>),
    Pretty(Format<Pretty>),
    Json(Format<Json>),
}

impl LogFormat {
    pub fn get_format_fields(&self) -> LogFormatFields {
        match self {
            LogFormat::Json(_) => LogFormatFields::Json(JsonFields::default()),
            LogFormat::Pretty(_) => LogFormatFields::Pretty(PrettyFields::default()),
            _ => LogFormatFields::Default(DefaultFields::default()),
        }
    }
}

impl<'de> Deserialize<'de> for LogFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: String = Deserialize::deserialize(deserializer)?;
        LogFormat::from_str(&data).map_err(serde::de::Error::custom)
    }
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Full(Default::default())
    }
}

#[derive(Error, Debug)]
#[error("Invalid log format, must be one of full, compact, pretty, json")]
pub struct InvalidLogFormat;

impl FromStr for LogFormat {
    type Err = InvalidLogFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(LogFormat::Full(Default::default())),
            "compact" => Ok(LogFormat::Compact(Format::default().compact())),
            "pretty" => Ok(LogFormat::Pretty(Format::default().pretty())),
            "json" => Ok(LogFormat::Json(Format::default().json().with_ansi(false))),
            _ => Err(InvalidLogFormat),
        }
    }
}

impl<S, N> FormatEvent<S, N> for LogFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        match self {
            LogFormat::Full(f) => f.format_event(ctx, writer, event),
            LogFormat::Compact(f) => f.format_event(ctx, writer, event),
            LogFormat::Pretty(f) => f.format_event(ctx, writer, event),
            LogFormat::Json(f) => f.format_event(ctx, writer, event),
        }
    }
}

pub enum LogFormatFields {
    Json(JsonFields),
    Pretty(PrettyFields),
    Default(DefaultFields),
}

impl<'a> FormatFields<'a> for LogFormatFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'a>, fields: R) -> std::fmt::Result {
        match self {
            LogFormatFields::Json(f) => f.format_fields(writer, fields),
            LogFormatFields::Pretty(f) => f.format_fields(writer, fields),
            LogFormatFields::Default(f) => f.format_fields(writer, fields),
        }
    }
}
