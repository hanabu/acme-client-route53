mod account;
mod acme;
mod config;
mod csr;
mod dns;
mod http_client;

pub use account::new_account;
pub use acme::AcmeOrder;
pub use config::{CertReqConfig, Config};
pub use csr::X509Csr;
pub use dns::{AllDnsZones, AwsClient, DnsZone};
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
    #[error(transparent)]
    LightsailGetDomainsError(
        #[from]
        aws_sdk_lightsail::error::SdkError<
            aws_sdk_lightsail::operation::get_domains::GetDomainsError,
        >,
    ),
    #[error(transparent)]
    Route53ListHostedZonesError(
        #[from]
        aws_sdk_route53::error::SdkError<
            aws_sdk_route53::operation::list_hosted_zones::ListHostedZonesError,
        >,
    ),
    #[error("Configuration file already exists")]
    ConfigExists,
    #[error("No DNS zone for {0}")]
    NoDnsZone(String),
    #[error("DNS01 challenge is not supported")]
    DnsChallengeNotSupported,
}

pub async fn issue_certificates(config: &Config) -> Result<(), Error> {
    //use futures::stream::StreamExt;

    // DNS is global resource, end points are located at us-east-1
    let aws_sdk_config = aws_config_from_env("us-east-1").await;
    let aws_client = AwsClient::new(&aws_sdk_config);

    let zones = AllDnsZones::load(&aws_client).await?;

    for crt_req in config.certificate_requests() {
        let order = AcmeOrder::new(config, &crt_req)?;

        let order = order.load_and_check_csr(&zones)?;

        order.request_certificate(&zones).await?;
    }

    Ok(())
}
