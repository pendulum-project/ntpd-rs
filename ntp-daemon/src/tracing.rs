use crate::config::Config;
use tracing::info;
use tracing_subscriber::{
    filter::Filtered,
    fmt::format::{DefaultFields, Format, Full},
    EnvFilter, Registry,
};

pub type ReloadHandle = tracing_subscriber::reload::Handle<
    Filtered<
        tracing_subscriber::fmt::Layer<Registry, DefaultFields, Format<Full>>,
        EnvFilter,
        Registry,
    >,
    Registry,
>;

pub struct TracingState {
    pub reload_handle: ReloadHandle,
}

/// Setup tracing. Since we know the settings of some subscribers only once
/// the full configuration has been loaded, this returns an `FnOnce` to complete
/// setup when the config is available.
pub fn init(
    filter: EnvFilter,
) -> impl FnOnce(&mut Config, bool) -> Result<TracingState, tracing_subscriber::reload::Error> {
    // Setup a tracing subscriber with the bare minimum for now, so that errors
    // in loading the configuration can be properly logged.
    use tracing_subscriber::prelude::*;
    let layer = tracing_subscriber::fmt::layer()
        .fmt_fields(DefaultFields::default())
        .event_format(Format::<Full>::default())
        .with_filter(filter);
    let (fmt_layer, fmt_handle) = tracing_subscriber::reload::Layer::new(layer);

    let registry = tracing_subscriber::registry().with(fmt_layer);
    registry.init();

    // Final setup needs the full configuration
    #[allow(clippy::let_unit_value)]
    move |config, has_log_override| -> _ {
        if let Some(log_filter) = config.log_filter.take() {
            if has_log_override {
                info!("Log filter override from command line arguments is active");
            } else {
                fmt_handle.modify(|l| *l.filter_mut() = log_filter)?;
            }
        }

        let state = TracingState {
            reload_handle: fmt_handle,
        };

        Ok(state)
    }
}
