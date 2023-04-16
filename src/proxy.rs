use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use cached::{cached_result, Cached, SizedCache};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode, Uri};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use tokio::io;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::{debug, error, info, instrument};

use crate::ca::CA;
use crate::config::Config;

cached_result! {
    SIGNED_CA: SizedCache<String, CA> = SizedCache::with_size(50);
    fn get_cached_cert(host: String) -> Result<CA, String> = {
        let mut cache = SIGNED_CA.lock().map_err(|e| e.to_string())?;
        cache.cache_get(&host).cloned().ok_or("had not cache".to_string())
    }
}

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

    fn call(&mut self, req: Request<IncomingBody>) -> Self::Future {
        Box::pin(proxy(req, self.config.clone(), self.root_ca.clone()))
    }
}

struct HttpsClient {
    addr: String,
    sni: String,
}

impl Service<Request<IncomingBody>> for HttpsClient {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, req: Request<IncomingBody>) -> Self::Future {
        Box::pin(https_request(req, self.addr.clone(), self.sni.clone()))
    }
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    config: Arc<Config>,
    root_ca: Arc<CA>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if Method::CONNECT == req.method() {
        if let Some((addr, host)) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let result = if config.is_proxy(&host) {
                            let signed_ca = get_signed_cert(host.clone(), &root_ca);

                            match signed_ca {
                                Ok(signed_ca) => {
                                    transform_tunnel(
                                        upgraded,
                                        addr,
                                        host,
                                        &signed_ca,
                                        &config.sni,
                                        config.parse,
                                    )
                                    .await
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            direct_tunnel(upgraded, addr).await
                        };

                        if let Err(e) = result {
                            error!("server io error: {}", e);
                        };
                    }
                    Err(e) => error!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect(addr).await.unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(stream)
            .await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        let resp = sender.send_request(req).await?;
        Ok(resp.map(|b| b.boxed()))
    }
}

#[instrument]
async fn transform_tunnel(
    upgraded: Upgraded,
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
        hyper::server::conn::http1::Builder::new()
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
        let mut output = get_ssl_connection(addr, sni).await?;

        debug!("connect success");

        tokio::io::copy_bidirectional(&mut input, &mut output).await?;
    }

    Ok(())
}

async fn https_request(
    req: Request<hyper::body::Incoming>,
    addr: String,
    sni: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let output = get_ssl_connection(addr, &sni).await.unwrap();

    debug!("connect success");

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(output)
        .await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    let resp = sender.send_request(req).await?;
    Ok(resp.map(|b| b.boxed()))
}

async fn get_ssl_connection(addr: String, sni: &str) -> Result<SslStream<TcpStream>> {
    let output = TcpStream::connect(addr).await?;
    let mut client_ssl = SslConnector::builder(SslMethod::tls())?
        .build()
        .configure()?
        .verify_hostname(false)
        .into_ssl(sni)?;
    // TODO 客户端校验证书（store: Microsoft.pem）
    client_ssl.set_verify(SslVerifyMode::NONE);
    let mut output = SslStream::new(client_ssl, output)?;
    Pin::new(&mut output)
        .connect()
        .await
        .map_err(|e| anyhow!("ssl客户端连接异常:{}", e))?;
    Ok(output)
}

async fn direct_tunnel(mut upgraded: Upgraded, addr: String) -> Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

    // Proxying data
    let (from_client, from_server) = io::copy_bidirectional(&mut upgraded, &mut server).await?;

    info!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

fn get_signed_cert(host: String, root_ca: &CA) -> Result<CA> {
    match get_cached_cert(host.clone()) {
        Ok(ca) => Ok(ca),
        Err(_) => match root_ca.sign(host.clone()) {
            Ok(ca) => match SIGNED_CA.lock() {
                Ok(mut cache) => {
                    cache.cache_set(host, ca.clone());
                    Ok(ca)
                }
                Err(e) => Err(anyhow!("{}", e)),
            },
            Err(e) => Err(anyhow!("{}", e)),
        },
    }
}

fn host_addr(uri: &Uri) -> Option<(String, String)> {
    uri.authority()
        .map(|auth| auth.to_string())
        .zip(uri.host().map(|host| host.to_string()))
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::test]
async fn test() {
    let stream = TcpStream::connect("bing.com:443").await.unwrap();

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(stream)
        .await
        .unwrap();
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    println!("client conn success");
    let req = Request::builder()
        .uri("/")
        .method("GET")
        .header(hyper::header::HOST, "bing.com")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    println!("client request success: {:?}", resp);
}
