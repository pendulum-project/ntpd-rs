use tracing::Subscriber;
use tracing_subscriber::{reload, EnvFilter, Registry};

type FormatLayer<S> =
    tracing_subscriber::filter::Filtered<tracing_subscriber::fmt::Layer<S>, EnvFilter, S>;
type TracingFilterHandle = reload::Handle<FormatLayer<Registry>, Registry>;

fn init_fmt_layer<S>(
    filter: EnvFilter,
) -> (
    reload::Layer<FormatLayer<S>, S>,
    reload::Handle<FormatLayer<S>, S>,
)
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    use tracing_subscriber::prelude::*;

    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(filter);
    tracing_subscriber::reload::Layer::new(fmt_layer)
}

#[cfg(feature = "sentry")]
pub fn init(filter: EnvFilter) -> (sentry::ClientInitGuard, TracingFilterHandle) {
    use tracing_subscriber::prelude::*;

    let guard = sentry::init(sentry::ClientOptions {
        // Set this a to lower value in production
        traces_sample_rate: 1.0,
        ..sentry::ClientOptions::default()
    });

    let (fmt_layer, reload_handle) = init_fmt_layer(filter);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(sentry_tracing::layer())
        .init();

    (guard, reload_handle)
}

#[cfg(not(feature = "sentry"))]
pub fn init(filter: EnvFilter) -> ((), TracingFilterHandle) {
    use tracing_subscriber::prelude::*;

    let (fmt_layer, reload_handle) = init_fmt_layer(filter);

    tracing_subscriber::registry().with(fmt_layer).init();

    ((), reload_handle)
}
