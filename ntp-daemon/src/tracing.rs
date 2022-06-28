use crate::config::{
    format::{LogFormat, LogFormatFields},
    Config,
};
use tracing::info;
use tracing_subscriber::{filter::Filtered, EnvFilter, Registry};

#[cfg(feature = "sentry")]
type GuardType = Option<sentry::ClientInitGuard>;
#[cfg(not(feature = "sentry"))]
type GuardType = ();

pub type ReloadHandle = tracing_subscriber::reload::Handle<
    Filtered<
        tracing_subscriber::fmt::Layer<Registry, LogFormatFields, LogFormat>,
        EnvFilter,
        Registry,
    >,
    Registry,
>;

pub struct TracingState {
    pub guard: GuardType,
    pub reload_handle: ReloadHandle,
}

/// Setup tracing. Since we know the settings of some subscribers only once
/// the full configuration has been loaded, this returns an FnOnce to complete
/// setup when the config is available.
pub fn init(
    filter: EnvFilter,
    format: LogFormat,
) -> impl FnOnce(&mut Config, bool, bool) -> Result<TracingState, tracing_subscriber::reload::Error>
{
    // Setup a tracing subscriber with the bare minimum for now, so that errors
    // in loading the configuration can be properly logged.
    use tracing_subscriber::prelude::*;
    let layer = tracing_subscriber::fmt::layer()
        .fmt_fields(format.get_format_fields())
        .event_format(format)
        .with_filter(filter);
    let (fmt_layer, fmt_handle) = tracing_subscriber::reload::Layer::new(layer);

    let registry = tracing_subscriber::registry().with(fmt_layer);

    #[cfg(feature = "sentry")]
    let (sentry_handle, registry) = {
        let (sentry_layer, sentry_handle) = tracing_subscriber::reload::Layer::new(None);
        (sentry_handle, registry.with(sentry_layer))
    };

    registry.init();

    // Final setup needs the full configuration
    move |config, has_log_override, has_format_override| -> _ {
        #[cfg(not(feature = "sentry"))]
        let guard = ();

        #[cfg(feature = "sentry")]
        let guard = if let Some(dsn) = config.sentry.dsn.take() {
            let guard = sentry::init((
                dsn,
                sentry::ClientOptions {
                    traces_sample_rate: config.sentry.sample_rate,
                    ..sentry::ClientOptions::default()
                },
            ));

            sentry_handle.modify(|l| *l = Some(sentry_tracing::layer()))?;

            Some(guard)
        } else {
            None
        };

        if has_format_override {
            info!("Log format override from command line arguments is active");
        } else {
            fmt_handle.modify(|l| {
                *l.inner_mut() = tracing_subscriber::fmt::layer()
                    .fmt_fields(config.log_format.get_format_fields())
                    .event_format(config.log_format.clone());
            })?;
        }

        if let Some(log_filter) = config.log_filter.take() {
            if has_log_override {
                info!("Log filter override from command line arguments is active");
            } else {
                fmt_handle.modify(|l| *l.filter_mut() = log_filter)?;
            }
        }

        let state = TracingState {
            guard,
            reload_handle: fmt_handle,
        };

        Ok(state)
    }
}
