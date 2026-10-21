use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::uri::Scheme;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::Uri;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// TODO 客户端校验证书（store: Microsoft.pem）
/// 暂时跳过所有服务端证书校验（与原 openssl verify_hostname(false)/NONE 行为一致）
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

pub async fn create_ssl_connection(addr: &str, sni: &str) -> Result<TlsStream<TcpStream>> {
    let output = TcpStream::connect(addr).await?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(sni.to_owned())?;
    let output = connector
        .connect(name, output)
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
