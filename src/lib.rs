mod account;
mod cname_map;
mod config;
mod http_client;

pub use account::new_account;
pub use config::Config;
use http_client::HyperTlsClient;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AcmeError(#[from] instant_acme::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    TomlError(#[from] toml::de::Error),
    #[error("Configuration file already exists")]
    ConfigExists,
    #[error("Unknown DNS Provider {0}")]
    UnknownDnsProvider(String),
}

pub async fn issue_certificates(config: &Config) -> Result<(), Error> {
    Ok(())
}
