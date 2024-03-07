use anyhow::{anyhow, Result};
use cached::{cached_result, Cached, SizedCache};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
use std::{net::SocketAddr, sync::Arc};
use tokio_openssl::SslStream;

use crate::{ca::CA, config::Config};

cached_result! {
    SIGNED_CA: SizedCache<String, CA> = SizedCache::with_size(50);
    fn get_cached_cert(host: String) -> Result<CA, String> = {
        let mut cache = SIGNED_CA.lock().map_err(|e| e.to_string())?;
        cache.cache_get(&host).cloned().ok_or("had not cache".to_string())
    }
}

#[derive(Clone)]
pub struct ClientState {
    pub addr: String,
    // http will be host
    pub sni: String,
    pub is_secure: bool,
}

#[derive(Clone)]
pub struct State {
    config: Arc<Config>,
    root_ca: Arc<CA>,
}

impl State {
    pub async fn new() -> Result<Self> {
        let config = Arc::new(Config::load().await?);
        let root_ca = Arc::new(
            CA::load_or_create(&config.root_ca_cert_path, &config.root_ca_key_path).await?,
        );
        Ok(Self { config, root_ca })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.config.local_addr()
    }

    pub fn is_proxy(&self, host: &str) -> bool {
        self.config.is_proxy(host)
    }

    pub fn is_parse(&self) -> bool {
        self.config.parse
    }

    pub fn get_sni<'a>(&'a self, host: &'a str) -> &str {
        if self.config.sni.is_empty() {
            host
        } else {
            &self.config.sni
        }
    }

    pub fn get_signed_cert(&self, host: String) -> Result<CA> {
        match get_cached_cert(host.clone()) {
            Ok(ca) => Ok(ca),
            Err(_) => match self.root_ca.sign(host.clone()) {
                Ok(ca) => match SIGNED_CA.lock() {
                    Ok(mut cache) => {
                        cache.cache_set(host, ca.clone());
                        Ok(ca)
                    }
                    Err(e) => Err(anyhow!("{e}")),
                },
                Err(e) => Err(anyhow!("{e}")),
            },
        }
    }

    pub fn wrap_ssl_stream(
        &self,
        upgraded: TokioIo<Upgraded>,
        host: String,
    ) -> Result<SslStream<TokioIo<Upgraded>>> {
        let signed_ca = Self::get_signed_cert(self, host)?;

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_certificate(&signed_ca.cert)?;
        builder.set_private_key(&signed_ca.key)?;
        let acceptor = builder.build();

        let server_ssl = Ssl::new(acceptor.context())?;
        let input = SslStream::new(server_ssl, upgraded)?;
        Ok(input)
    }
}
