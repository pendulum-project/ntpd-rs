#![forbid(unsafe_code)]

use ntp_metrics_exporter::Metrics;
use serde_json::json;
use thiserror::Error;

use std::{net::SocketAddr, path::PathBuf};

use axum::{
    handler::Handler,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{AppendHeaders, IntoResponse},
    routing::get,
    Json, Router,
};
use clap::Parser;
use ntp_daemon::{Config, ObservableState};

#[derive(Parser)]
#[command(version = "0.2.0", about = "Serve ntpd-rs openmetrics via http")]
struct Cli {
    /// Which configuration file to read the socket paths from
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path of the observation socket
    #[arg(short, long)]
    observation_socket: Option<PathBuf>,

    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1:9975")]
    listen_socket: SocketAddr,
}

#[derive(Debug, Error)]
enum ServeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for ServeError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": 500,
            })),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::from_args(cli.config, vec![], vec![]).await;

    if let Err(ref e) = config {
        println!("Warning: Unable to load configuration file: {}", e);
    }

    let config = config.unwrap_or_default();

    let observation_socket_path = match cli.observation_socket {
        Some(path) => path,
        None => match config.observe.path {
            Some(path) => path,
            None => "/run/ntpd-rs/observe".into(),
        },
    };

    let app = Router::new()
        .route(
            "/metrics",
            get(|| async {
                let mut stream = tokio::net::UnixStream::connect(observation_socket_path).await?;
                let mut msg = Vec::with_capacity(16 * 1024);
                let output: ObservableState =
                    ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;
                let metrics = Metrics::default();
                metrics.fill(&output);
                let registry = metrics.registry();
                let mut buf = vec![];
                prometheus_client::encoding::text::encode(&mut buf, &registry)?;
                Ok::<_, ServeError>((
                    HeaderMap::from_iter([(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain"),
                    )]),
                    buf,
                ))
            }),
        )
        .route(
            "/",
            get(|| async {
                (
                    StatusCode::FOUND,
                    AppendHeaders([(axum::http::header::LOCATION, "/metrics")]),
                )
            }),
        )
        .fallback(
            (|| async {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": 404,
                    })),
                )
            })
            .into_service(),
        );

    axum::Server::bind(&cli.listen_socket)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
