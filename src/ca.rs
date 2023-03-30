use std::io::Error;
use std::path::Path;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder, X509};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::{self, JoinHandle};

#[derive(Debug, Clone)]
pub struct CA {
    pub cert: X509,
    pub key: PKey<Private>,
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

            let cert_future = task::spawn_blocking(move || X509::from_pem(&cert_pem));
            let key_future = task::spawn_blocking(move || PKey::private_key_from_pem(&key_pem));
            let (cert, key) = tokio::try_join!(flatten(cert_future), flatten(key_future))?;

            Ok(Self { cert, key })
        } else {
            // 重新生成
            let ca = task::spawn_blocking(mk_ca_cert).await?;
            if let Ok(ref ca) = ca {
                let cert_pem = ca.cert.to_pem()?;
                let key_pem = ca.key.private_key_to_pem_pkcs8()?;

                let (mut cert_file, mut key_file) =
                    tokio::try_join!(File::create(cert_path), File::create(key_path))?;
                tokio::try_join!(cert_file.write(&cert_pem), key_file.write(&key_pem))?;
            }
            ca
        }
    }

    /// 签发
    pub fn sign(&self, domain: String) -> Result<Self, Error> {
        sign_ca_cert(self, &domain)
    }
}

async fn flatten<T>(handle: JoinHandle<Result<T, ErrorStack>>) -> Result<T, Error> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    }
}

fn mk_ca_cert() -> Result<CA, Error> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "CN")?;
    x509_name.append_entry_by_text("ST", "GuangDong")?;
    x509_name.append_entry_by_text("O", "thlstsul")?;
    x509_name.append_entry_by_text("CN", "thlstsul.github.io")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    // 最长20年
    let not_after = Asn1Time::days_from_now(365 * 20)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok(CA { cert, key })
}

fn mk_request(key: &PKey<Private>, domain: &str) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "CN")?;
    x509_name.append_entry_by_text("ST", "GuangDong")?;
    x509_name.append_entry_by_text("O", "thlstsul")?;
    x509_name.append_entry_by_text("CN", domain)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

fn sign_ca_cert(ca: &CA, domain: &str) -> Result<CA, Error> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let req = mk_request(&key, domain)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca.cert.subject_name())?;
    cert_builder.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(domain)
        .build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(&ca.key, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok(CA { cert, key })
}

#[tokio::test]
async fn signed_and_verified() {
    let cert_path = std::path::PathBuf::from("cert.crt");
    let key_path = std::path::PathBuf::from("key.pem");

    let ca = CA::load_or_create(&cert_path, &key_path).await.unwrap();
    let ca_cert = ca.cert.clone();
    let signed_ca = ca.sign("localhost".to_string()).unwrap();
    assert_eq!(
        ca_cert.issued(&signed_ca.cert),
        openssl::x509::X509VerifyResult::OK
    )
}
