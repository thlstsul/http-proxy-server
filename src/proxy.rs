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
use crate::state::{ClientState, State};
use crate::util::{self, create_ssl_connection, host_addr};

#[derive(Clone)]
pub struct Proxy<C> {
    client: C,
}

impl<C> Proxy<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

#[service]
impl<C> Service<State, Request<IncomingBody>> for Proxy<C>
where
    C: Service<
            ClientState,
            Request<IncomingBody>,
            Response = Response<BoxBody<Bytes, hyper::Error>>,
            Error = hyper::Error,
        > + Clone
        + Sync
        + Send
        + Unpin
        + 'static,
{
    async fn call(
        &self,
        state: &mut State,
        req: Request<IncomingBody>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if Method::CONNECT == req.method() {
            let state = state.clone();
            let client = self.client.clone();
            // https
            tokio::task::spawn(async move {
                let _ = upgrade_https(req, state, client)
                    .await
                    .inspect_err(|e| error!("upgrade https fail: {e}"));
            });

            Ok(Response::new(util::empty()))
        } else {
            // http
            if let Some((addr, host)) = host_addr(req.uri()) {
                let mut state = ClientState {
                    addr,
                    sni: host,
                    is_secure: false,
                    parse: state.is_parse(),
                };
                self.client.call(&mut state, req).await
            } else {
                let mut resp = Response::new(util::full("HTTP must be to socket address"));
                *resp.status_mut() = StatusCode::NOT_ACCEPTABLE;
                Ok(resp)
            }
        }
    }
}

async fn upgrade_https<C>(req: Request<IncomingBody>, state: State, client: C) -> Result<()>
where
    C: Service<
            ClientState,
            Request<IncomingBody>,
            Response = Response<BoxBody<Bytes, hyper::Error>>,
            Error = hyper::Error,
        > + Clone
        + Sync
        + Send
        + Unpin
        + 'static,
{
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
            let state = ClientState {
                addr,
                sni: sni.to_owned(),
                is_secure: true,
                parse: true,
            };
            ServerBuilder::new()
                .serve_connection(input, client.hyper(|req| (state, req)))
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
