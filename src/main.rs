#![windows_subsystem = "windows"]

use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper_util::rt::TokioIo;
use time::{macros::format_description, UtcOffset};
use tokio::net::TcpListener;
use tracing::{error, info, Level};
use tracing_subscriber::fmt::time::OffsetTime;

use crate::adapter::HyperAdapter;
use crate::proxy::Proxy;
use crate::state::State;

mod adapter;
mod ca;
mod client;
mod config;
mod proxy;
mod state;
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

    let state = State::new().await.expect("State init failed");

    let addr = state.local_addr().expect("Parse config address failed");
    let listener = TcpListener::bind(addr)
        .await
        .expect("Create listener failed");
    info!("Listening on http://{}", listener.local_addr().unwrap());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                let io = TokioIo::new(stream);

                tokio::task::spawn(async move {
                    if let Err(err) = ServerBuilder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(io, Proxy.hyper(|req| (state, req)))
                        .with_upgrades()
                        .await
                    {
                        error!("Failed to serve connection: {err}");
                    }
                });
            }
            Err(err) => error!("Failed to accept: {err}"),
        }
    }
}
