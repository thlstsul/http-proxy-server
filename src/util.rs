use std::pin::Pin;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use cached::{cached_result, Cached, SizedCache};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::Uri;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::ca::CA;

cached_result! {
    SIGNED_CA: SizedCache<String, CA> = SizedCache::with_size(50);
    fn get_cached_cert(host: String) -> Result<CA, String> = {
        let mut cache = SIGNED_CA.lock().map_err(|e| e.to_string())?;
        cache.cache_get(&host).cloned().ok_or("had not cache".to_string())
    }
}

pub async fn get_ssl_connection(addr: String, sni: &str) -> Result<SslStream<TcpStream>> {
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

pub fn get_signed_cert(host: String, root_ca: &CA) -> Result<CA> {
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

pub fn host_addr(uri: &Uri) -> Option<(String, String)> {
    uri.authority()
        .map(|auth| auth.to_string())
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
