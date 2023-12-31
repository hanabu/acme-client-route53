mod account;
mod config;
mod csr;
mod dns;
mod http_client;

pub use account::new_account;
pub use config::Config;
pub use csr::CertRequest;
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
    use futures::stream::StreamExt;

    let aws_sdk_config = aws_config_from_env().await;
    let aws_client = AwsClient::new(&aws_sdk_config);

    let zones = AllDnsZones::load(&aws_client).await?;

    // Read All CSR files
    let csrs = config
        .certificate_requests()
        .map(|req| CertRequest::from_pem_file(req.csr_file_name()))
        .collect::<Result<Vec<_>, _>>()?;

    // check if the domains are managed by AWS, then collect zones
    let mut host_zones = std::collections::HashMap::<&str, (&str, &DnsZone)>::new();
    for csr in &csrs {
        for hostname in csr.subjects() {
            let canonical_host = config.canonical_host(hostname);
            let zone = zones.find_zone(canonical_host);
            if let Some(zone) = zone {
                host_zones.insert(hostname, (canonical_host, zone));
            } else {
                return Err(Error::NoDnsZone(canonical_host.to_string()));
            }
        }
    }

    csrs.iter().map(|csr| async {
        // order validation to ACME server
        csr.issue_certificate(config, &zones)
    });

    Ok(())
}
