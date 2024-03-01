use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
use tokio::io;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::{debug, error, info, instrument};

use crate::ca::CA;
use crate::client::{http_request, HttpsClient, PrintReq, PrintResp};
use crate::config::Config;
use crate::util::{self, get_signed_cert, get_ssl_connection, host_addr};

pub struct Proxy {
    config: Arc<Config>,
    root_ca: Arc<CA>,
}

impl Proxy {
    pub fn new(config: Arc<Config>, root_ca: Arc<CA>) -> Self {
        Self { config, root_ca }
    }
}

impl Service<Request<IncomingBody>> for Proxy {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        let config = self.config.clone();
        let root_ca = self.root_ca.clone();
        let res = async move {
            if let Some((addr, host)) = host_addr(req.uri()) {
                if Method::CONNECT == req.method() {
                    // https
                    tokio::task::spawn(async move {
                        let result = upgrade_https(req, host, addr, config, root_ca).await;
                        if let Err(e) = result {
                            error!("upgrade https fail: {e}");
                        }
                    });

                    Ok(Response::new(util::empty()))
                } else {
                    // http
                    match TcpStream::connect(addr).await {
                        Ok(stream) => {
                            let resp =
                                http_request(req, stream, Some(PrintReq), Some(PrintResp)).await?;
                            Ok(resp.map(|b| b.boxed()))
                        }
                        Err(e) => {
                            error!("connect http failed: {e}");
                            let mut resp = Response::new(util::full("connect http failed"));
                            *resp.status_mut() = StatusCode::NOT_ACCEPTABLE;
                            Ok(resp)
                        }
                    }
                }
            } else {
                error!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(util::full("CONNECT must be to a socket address"));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                Ok(resp)
            }
        };

        Box::pin(res)
    }
}

async fn upgrade_https(
    req: Request<IncomingBody>,
    host: String,
    addr: String,
    config: Arc<Config>,
    root_ca: Arc<CA>,
) -> Result<()> {
    let upgraded = hyper::upgrade::on(req).await?;
    let mut upgraded = TokioIo::new(upgraded);

    if config.is_proxy(&host) {
        let signed_ca = get_signed_cert(host.clone(), &root_ca)?;
        transform_tunnel(upgraded, addr, host, &signed_ca, &config.sni, config.parse).await
    } else {
        // Connect to remote server
        let mut server = TcpStream::connect(addr).await?;

        // Proxying data
        let (from_client, from_server) = io::copy_bidirectional(&mut upgraded, &mut server).await?;
        info!("client wrote {from_client} bytes and received {from_server} bytes");

        Ok(())
    }
}

#[instrument]
async fn transform_tunnel(
    upgraded: TokioIo<Upgraded>,
    addr: String,
    host: String,
    signed_ca: &CA,
    sni: &str,
    parse: bool,
) -> Result<()> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate(&signed_ca.cert)?;
    builder.set_private_key(&signed_ca.key)?;
    let acceptor = builder.build();

    let server_ssl = Ssl::new(acceptor.context())?;
    let mut input = SslStream::new(server_ssl, upgraded)?;
    Pin::new(&mut input).accept().await?;

    debug!("accept success");

    let sni = if sni.is_empty() { &host } else { sni };

    if parse {
        // use hyper parse http
        let input = TokioIo::new(input);
        ServerBuilder::new()
            .serve_connection(
                input,
                HttpsClient {
                    addr,
                    sni: sni.to_owned(),
                },
            )
            .without_shutdown()
            .await?;
    } else {
        let mut output = get_ssl_connection(&addr, sni).await?;

        debug!("connect success");

        let (from_client, from_server) = io::copy_bidirectional(&mut input, &mut output).await?;
        info!("client wrote {from_client} bytes and received {from_server} bytes");
    }

    Ok(())
}
