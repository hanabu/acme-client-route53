use crate::Error;

pub enum DnsProvider {
    AwsLightsail,
    AwsRoute53,
}

impl DnsProvider {
    pub async fn list_hosted_zones(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<DnsZone>, Error> {
        match self {
            &Self::AwsLightsail => Self::list_lightsail_zones(aws_config).await,
            &Self::AwsRoute53 => Self::list_route53_zones(aws_config).await,
        }
    }

    pub async fn list_lightsail_zones(
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<DnsZone>, Error> {
        todo!()
    }
    pub async fn list_route53_zones(
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<DnsZone>, Error> {
        todo!()
    }
}

impl std::str::FromStr for DnsProvider {
    type Err = crate::Error;
    fn from_str(dns_provider_str: &str) -> Result<Self, Self::Err> {
        match dns_provider_str.to_ascii_lowercase().as_str() {
            "route53" => Ok(Self::AwsRoute53),
            "lightsail" => Ok(Self::AwsLightsail),
            _ => Err(Error::UnknownDnsProvider(dns_provider_str.to_string())),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum DnsZone {
    Lightsail { domain_name: String },
    Route53 { hosted_zone_id: String },
}

impl DnsZone {}
