mod account;
mod acme;
mod config;
mod csr;
mod dns;
mod http_client;
mod output;

pub use account::new_account;
pub use acme::{AcmeIssuedCertificate, AcmeOrder, AcmeOrderBuilder};
pub use config::{CertReqConfig, Config};
pub use csr::X509Csr;
pub use dns::{AllDnsZones, AwsClient, DnsZone};
use http_client::{aws_config_from_env, HyperTlsClient};
pub use output::write_crt;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AcmeError(#[from] instant_acme::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    TomlError(#[from] toml::de::Error),
    #[error(transparent)]
    CrtPemParseError(#[from] x509_parser::error::PEMError),
    #[error(transparent)]
    CsrPemParseError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
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
    LightsailCreateEntryError(
        #[from]
        aws_sdk_lightsail::error::SdkError<
            aws_sdk_lightsail::operation::create_domain_entry::CreateDomainEntryError,
        >,
    ),
    #[error(transparent)]
    LightsailUpdateEntryError(
        #[from]
        aws_sdk_lightsail::error::SdkError<
            aws_sdk_lightsail::operation::update_domain_entry::UpdateDomainEntryError,
        >,
    ),
    #[error(transparent)]
    Route53ListHostedZonesError(
        #[from]
        aws_sdk_route53::error::SdkError<
            aws_sdk_route53::operation::list_hosted_zones::ListHostedZonesError,
        >,
    ),
    #[error(transparent)]
    S3PutObjectError(
        #[from] aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
    ),
    #[error(transparent)]
    DnsResolveError(#[from] hickory_resolver::error::ResolveError),
    #[error("Configuration file already exists")]
    ConfigExists,
    #[error("No DNS zone for {0}")]
    NoDnsZone(String),
    #[error("DNS01 challenge is not supported")]
    DnsChallengeNotSupported,
    #[error("ACME challenge did not complete unexpectedly")]
    AcmeChallengeIncomplete,
    #[error("DNS update timeout")]
    DnsUpdateTimeout,
    #[error("Certificate issue timeout")]
    CertificateIssueTimeout,
    #[error("Invalid out_crt_file")]
    InvalidOutCrtFile(String),
}

pub async fn issue_certificates(config: &Config) -> Result<(), Error> {
    //use futures::stream::StreamExt;

    // Default region config for S3 put
    let aws_sdk_config = aws_config_from_env(None).await;

    // DNS is global resource, end points are located at us-east-1
    let aws_client = AwsClient::new(&aws_config_from_env("us-east-1").await);
    let zones = AllDnsZones::load(&aws_client).await?;

    for crt_req in config.certificate_requests() {
        // Load & check request
        let order = AcmeOrder::new(config, &crt_req)?.load_and_check_csr(&zones)?;

        // Request certificate to ACME server
        let certificate = order.request_certificate(&zones).await?;

        write_crt(crt_req.crt_file_name(), &certificate, &aws_sdk_config).await?;
    }

    Ok(())
}
