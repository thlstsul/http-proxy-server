use std::pin::Pin;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::uri::Scheme;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::Uri;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

pub async fn create_ssl_connection(addr: &str, sni: &str) -> Result<SslStream<TcpStream>> {
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

pub fn host_addr(uri: &Uri) -> Option<(String, String)> {
    uri.authority()
        .map(|auth| {
            let mut addr = auth.to_string();
            if Some(&Scheme::HTTP) == uri.scheme() && uri.port().is_none() {
                // for TcpStream connect
                addr = format!("{addr}:80");
            }
            addr
        })
        .zip(uri.host().map(|host| host.to_string()))
}

pub fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
