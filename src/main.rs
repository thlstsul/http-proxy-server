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
    let offset = UtcOffset::current_local_offset().expect("Should get local offset!");
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

    let config = Arc::new(Config::load().await.expect("Failed to load config"));
    let root_ca = Arc::new(
        CA::load_or_create(
            config.root_ca_cert_path.as_path(),
            config.root_ca_key_path.as_path(),
        )
        .await
        .expect("Failed to load root CA"),
    );

    let addr = config.local_addr().expect("Parse config address failed");
    let listener = TcpListener::bind(addr)
        .await
        .expect("Create listener failed");
    info!("Listening on http://{}", listener.local_addr().unwrap());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
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
                        error!("Failed to serve connection: {err:?}");
                    }
                });
            }
            Err(err) => error!("Failed to accept: {err:?}"),
        }
    }
}
