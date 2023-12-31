mod account;
mod config;
mod csr;
mod dns;
mod http_client;

pub use account::new_account;
pub use config::Config;
pub use csr::CertRequest;
pub use dns::{DnsProvider, DnsZone};
use http_client::{aws_config_from_env, HyperTlsClient};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AcmeError(#[from] instant_acme::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    TomlError(#[from] toml::de::Error),
    #[error(transparent)]
    PemParseError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    CsrParseError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("Configuration file already exists")]
    ConfigExists,
    #[error("Unknown DNS Provider {0}")]
    UnknownDnsProvider(String),
}

pub async fn issue_certificates(config: &Config) -> Result<(), Error> {
    let aws_config = aws_config_from_env().await;

    // check if the domains are managed by AWS?
    for req in config.certificate_requests() {
        //let csr = CertRequest::from_pem_file()
    }
    Ok(())
}
