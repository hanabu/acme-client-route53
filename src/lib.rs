mod account;
mod acme;
mod config;
mod csr;
mod dns;
mod http_client;
mod output;

// re-exports
pub use account::new_account;
pub use acme::{AcmeIssuedCertificate, AcmeOrder, AcmeOrderBuilder};
pub use config::{CertReqConfig, Config};
pub use csr::X509Csr;
pub use dns::{AllDnsZones, AwsClient, DnsZone};
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
    Route53ChangeRecordError(
        #[from]
        aws_sdk_route53::error::SdkError<
            aws_sdk_route53::operation::change_resource_record_sets::ChangeResourceRecordSetsError,
        >,
    ),
    #[error(transparent)]
    Route53GetChangeError(
        #[from]
        aws_sdk_route53::error::SdkError<aws_sdk_route53::operation::get_change::GetChangeError>,
    ),
    #[error(transparent)]
    S3PutObjectError(
        #[from] aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
    ),
    #[error(transparent)]
    DnsResolveError(#[from] hickory_resolver::ResolveError),
    #[error("Configuration file already exists")]
    ConfigExists,
    #[error("No DNS zone for {0}")]
    NoDnsZone(String),
    #[error("DNS01 challenge is not supported")]
    DnsChallengeNotSupported,
    #[error("Order must be DNS name")]
    InvalidAcmeOrder,
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
    use futures::StreamExt;
    const REQUEST_CONCURRENT: usize = 4;

    // Default region config for S3 put
    let aws_sdk_config = http_client::aws_config_from_env(None).await;

    // Load DNS records that current AWS credential can manage
    let aws_client = AwsClient::new().await;
    let zones = AllDnsZones::load(&aws_client).await?;

    let fut = config.certificate_requests().map(|crt_req| async {
        // Load & check request
        let crt_req = crt_req.clone();
        let order = AcmeOrder::new(config, &crt_req)?.load_and_check_csr(&zones)?;

        // Request certificate to ACME server
        let certificate = order.request_certificate(&zones).await?;

        // Save certificate
        write_crt(crt_req.crt_file_name(), &certificate, &aws_sdk_config).await?;

        Result::<(), Error>::Ok(())
    });

    // Request certificates concurrently
    let stream = futures::stream::iter(fut).buffer_unordered(REQUEST_CONCURRENT);
    let results = stream.collect::<Vec<_>>().await;

    if let Some(e) = results.into_iter().find_map(|result| result.err()) {
        // Returns first error
        Err(e)
    } else {
        // no error
        Ok(())
    }
}
