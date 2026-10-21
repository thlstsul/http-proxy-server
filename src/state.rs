use anyhow::{Result, anyhow};
use cached::{Cached, LruCache};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::ca::CA;
use crate::config::Config;

fn signed_config() -> &'static Mutex<LruCache<String, Arc<ServerConfig>>> {
    static SIGNED_CONFIG: OnceLock<Mutex<LruCache<String, Arc<ServerConfig>>>> = OnceLock::new();
    SIGNED_CONFIG.get_or_init(|| Mutex::new(LruCache::new(50)))
}

#[derive(Clone)]
pub struct ClientState {
    pub addr: String,
    // http will be host
    pub sni: String,
    pub is_secure: bool,
    pub parse: bool,
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

    pub fn get_sni<'a>(&'a self, host: &'a str) -> &'a str {
        if self.config.sni.is_empty() {
            host
        } else {
            &self.config.sni
        }
    }

    fn signed_server_config(&self, host: String) -> Result<Arc<ServerConfig>> {
        // 短临界区查询，避免签发（阻塞的 keygen/sign）期间阻塞其它连接
        if let Some(config) = {
            let mut cache = signed_config().lock().map_err(|e| anyhow!("{e}"))?;
            cache.cache_get(&host).cloned()
        } {
            return Ok(config);
        }

        let signed = self.root_ca.sign(host.clone())?;
        let chain = vec![signed.cert.clone(), self.root_ca.cert.clone()];
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, PrivateKeyDer::Pkcs8(signed.key.into()))
                .map_err(|e| anyhow!("{e}"))?,
        );

        let mut cache = signed_config().lock().map_err(|e| anyhow!("{e}"))?;
        if cache.cache_get(&host).is_none() {
            cache.cache_set(host, config.clone());
        }
        Ok(config)
    }

    pub async fn wrap_ssl_stream(
        &self,
        upgraded: TokioIo<Upgraded>,
        host: String,
    ) -> Result<TlsStream<TokioIo<Upgraded>>> {
        let config = Self::signed_server_config(self, host)?;

        TlsAcceptor::from(config)
            .accept(upgraded)
            .await
            .map_err(|e| anyhow!("{e}"))
    }
}
