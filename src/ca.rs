use std::io::Error;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use time::{Duration, OffsetDateTime};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn_blocking;

/// 根 CA：持有证书 DER 与私钥 PEM，可从中构造签发者
#[derive(Debug, Clone)]
pub struct CA {
    pub cert: CertificateDer<'static>,
    key_pem: String,
}

/// 由 CA 签发的叶子证书（含私钥）
#[derive(Debug, Clone)]
pub struct SignedCert {
    pub cert: CertificateDer<'static>,
    /// PKCS#8 DER
    pub key: Vec<u8>,
}

impl CA {
    pub async fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self, Error> {
        let open_result = tokio::try_join!(File::open(cert_path), File::open(key_path));
        if let Ok((mut cert_file, mut key_file)) = open_result {
            // 已存在
            let mut cert_pem = vec![];
            let mut key_pem = vec![];
            tokio::try_join!(
                cert_file.read_to_end(&mut cert_pem),
                key_file.read_to_end(&mut key_pem)
            )?;

            spawn_blocking(move || {
                let cert = CertificateDer::from_pem_slice(&cert_pem).map_err(io_err)?;
                let key_pem = String::from_utf8(key_pem).map_err(io_err)?;
                Ok(CA { cert, key_pem })
            })
            .await?
        } else {
            // 重新生成
            let ca = spawn_blocking(mk_ca_cert).await?;
            if let Ok(ref ca) = ca {
                let cert_pem = pem::encode(&pem::Pem::new(
                    "CERTIFICATE".to_string(),
                    ca.cert.as_ref().to_vec(),
                ));
                let (mut cert_file, mut key_file) =
                    tokio::try_join!(File::create(cert_path), File::create(key_path))?;
                tokio::try_join!(
                    cert_file.write_all(cert_pem.as_bytes()),
                    key_file.write_all(ca.key_pem.as_bytes())
                )?;
            }
            ca
        }
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, Error> {
        let key = KeyPair::from_pem(&self.key_pem).map_err(io_err)?;
        Issuer::from_ca_cert_der(&self.cert, key).map_err(io_err)
    }

    /// 签发
    pub fn sign(&self, domain: String) -> Result<SignedCert, Error> {
        let key = KeyPair::generate().map_err(io_err)?;
        let params = leaf_params(&domain)?;
        let cert = params.signed_by(&key, &self.issuer()?).map_err(io_err)?;
        Ok(SignedCert {
            cert: cert.der().clone(),
            key: key.serialize_der(),
        })
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> Error {
    Error::other(e.to_string())
}

fn mk_ca_cert() -> Result<CA, Error> {
    let key = KeyPair::generate().map_err(io_err)?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CountryName, "CN");
    params
        .distinguished_name
        .push(DnType::StateOrProvinceName, "GuangDong");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "thlstsul");
    params
        .distinguished_name
        .push(DnType::CommonName, "thlstsul.github.io");

    let now = OffsetDateTime::now_utc();
    let (serial, not_before, not_after) = validity(&now, Duration::days(365 * 20))?;
    params.serial_number = Some(serial);
    params.not_before = not_before;
    params.not_after = not_after;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = params.self_signed(&key).map_err(io_err)?;
    Ok(CA {
        cert: cert.der().clone(),
        key_pem: key.serialize_pem(),
    })
}

fn leaf_params(domain: &str) -> Result<CertificateParams, Error> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_string());

    let now = OffsetDateTime::now_utc();
    let (serial, not_before, not_after) = validity(&now, Duration::days(365))?;
    params.serial_number = Some(serial);
    params.not_before = not_before;
    params.not_after = not_after;

    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::DnsName(
        domain.to_string().try_into().map_err(io_err)?,
    )];
    Ok(params)
}

fn validity(
    now: &OffsetDateTime,
    lifetime: Duration,
) -> Result<(SerialNumber, OffsetDateTime, OffsetDateTime), Error> {
    let mut serial = [0u8; 20];
    getrandom::getrandom(&mut serial).map_err(io_err)?;
    serial[0] &= 0x7f; // 保持正数
    Ok((SerialNumber::from_slice(&serial), *now, *now + lifetime))
}

#[tokio::test]
async fn signed_and_verified() {
    std::fs::create_dir_all("target").unwrap();
    let cert_path = Path::new("target/test-ca.crt");
    let key_path = Path::new("target/test-ca-key.pem");

    let ca = CA::load_or_create(cert_path, key_path).await.unwrap();
    let signed = ca.sign("localhost".to_string()).unwrap();

    use x509_parser::prelude::*;
    let (_, ca_x) = X509Certificate::from_der(ca.cert.as_ref()).unwrap();
    let (_, leaf_x) = X509Certificate::from_der(signed.cert.as_ref()).unwrap();
    assert_eq!(leaf_x.issuer(), ca_x.subject());
}
