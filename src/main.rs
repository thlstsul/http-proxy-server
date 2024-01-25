#![windows_subsystem = "windows"]
use std::sync::Arc;

use ca::CA;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper_util::rt::TokioIo;
use time::{macros::format_description, UtcOffset};
use tokio::net::TcpListener;
use tracing::{error, info, Level};
use tracing_subscriber::fmt::time::OffsetTime;

use crate::config::Config;
use crate::proxy::Proxy;

mod ca;
mod client;
mod config;
mod proxy;
mod util;

#[tokio::main]
async fn main() {
    let file_appender = tracing_appender::rolling::never(".", "proxy.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let offset = UtcOffset::current_local_offset().expect("should get local offset!");
    let timer = OffsetTime::new(
        offset,
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
    );
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_timer(timer)
        .with_ansi(false)
        .with_max_level(Level::INFO)
        .init();

    let config = Arc::new(Config::load().await.unwrap());
    let root_ca = Arc::new(
        CA::load_or_create(
            config.root_ca_cert_path.as_path(),
            config.root_ca_key_path.as_path(),
        )
        .await
        .unwrap(),
    );

    let listener = TcpListener::bind(config.local_addr().unwrap())
        .await
        .unwrap();
    info!("Listening on http://{}", listener.local_addr().unwrap());

    loop {
        let (stream, _) = listener.accept().await.unwrap();

        let config = config.clone();
        let root_ca = root_ca.clone();

        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = ServerBuilder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, Proxy::new(config, root_ca))
                .with_upgrades()
                .await
            {
                error!("Failed to serve connection: {:?}", err);
            }
        });
    }
}
