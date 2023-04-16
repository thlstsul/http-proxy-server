use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

const CONFIG_FILE: &str = "proxy_config.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    pub bind_ip: String,
    pub bind_port: u16,
    pub proxy_hosts: Vec<String>,
    pub sni: String,
    pub root_ca_cert_path: PathBuf,
    pub root_ca_key_path: PathBuf,
    pub parse: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_ip: "127.0.0.1".to_owned(),
            bind_port: 31181,
            proxy_hosts: [].to_vec(),
            sni: "".to_owned(),
            root_ca_cert_path: "proxy.ca.cert.crt".into(),
            root_ca_key_path: "proxy.ca.key.pem".into(),
            parse: false,
        }
    }
}

impl Config {
    pub async fn load() -> Result<Self> {
        match File::open(CONFIG_FILE).await {
            Ok(mut file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).await?;
                Ok(serde_json::from_slice(&buf)?)
            }
            Err(_) => {
                let config = Self::default();
                config.save().await?;
                Ok(config)
            }
        }
    }

    pub async fn save(&self) -> Result<()> {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(CONFIG_FILE)?;
        let mut file = File::from_std(file);
        file.write_all(serde_json::to_string(self)?.as_bytes())
            .await?;
        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(format!("{}:{}", self.bind_ip, self.bind_port).parse()?)
    }

    pub fn is_proxy(&self, domain: &str) -> bool {
        if self.proxy_hosts.is_empty() {
            true
        } else {
            self.proxy_hosts.iter().any(|i| domain.ends_with(i))
        }
    }
}

#[tokio::test]
async fn should_proxy() {
    let config = Config::load().await.unwrap();
    assert!(config.is_proxy("alive.github.com"))
}
