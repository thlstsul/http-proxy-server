#![allow(clippy::manual_async_fn)]

use std::pin::Pin;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use motore::{service, Service};
use tokio::io;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::adapter::HyperAdapter;
use crate::client::HttpClient;
use crate::state::State;
use crate::util::{self, create_ssl_connection, host_addr};

#[derive(Clone)]
pub struct Proxy;

#[service]
impl Service<State, Request<IncomingBody>> for Proxy {
    async fn call(
        &self,
        state: &mut State,
        req: Request<IncomingBody>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if Method::CONNECT == req.method() {
            let state = state.clone();
            // https
            tokio::task::spawn(async move {
                let _ = upgrade_https(req, state)
                    .await
                    .inspect_err(|e| error!("upgrade https fail: {e}"));
            });

            Ok(Response::new(util::empty()))
        } else {
            // http
            if let Some((addr, host)) = host_addr(req.uri()) {
                let client = HttpClient::new(addr, host, false);
                client.call(state, req).await
            } else {
                let mut resp = Response::new(util::full("HTTP must be to socket address"));
                *resp.status_mut() = StatusCode::NOT_ACCEPTABLE;
                Ok(resp)
            }
        }
    }
}

async fn upgrade_https(req: Request<IncomingBody>, state: State) -> Result<()> {
    let (addr, host) = host_addr(req.uri()).ok_or(anyhow!("CONNECT must be to socket address"))?;
    let upgraded = hyper::upgrade::on(req).await?;
    let mut upgraded = TokioIo::new(upgraded);

    if state.is_proxy(&host) {
        let mut input = state.wrap_ssl_stream(upgraded, host.clone())?;
        Pin::new(&mut input).accept().await?;

        debug!("accept success");

        let sni = state.get_sni(&host);

        if state.is_parse() {
            // use hyper parse http
            let input = TokioIo::new(input);
            ServerBuilder::new()
                .serve_connection(
                    input,
                    HttpClient::new(addr, host, true).hyper(|req| (state, req)),
                )
                .without_shutdown()
                .await?;
        } else {
            let mut output = create_ssl_connection(&addr, sni).await?;

            debug!("connect success");

            let (from_client, from_server) =
                io::copy_bidirectional(&mut input, &mut output).await?;
            info!("client wrote {from_client} bytes and received {from_server} bytes");
        }
    } else {
        // Connect to remote server
        let mut server = TcpStream::connect(addr).await?;

        // Proxying data
        let (from_client, from_server) = io::copy_bidirectional(&mut upgraded, &mut server).await?;
        info!("client wrote {from_client} bytes and received {from_server} bytes");
    }
    Ok(())
}
