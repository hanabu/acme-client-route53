use crate::Error;

#[derive(Clone, Debug)]
pub struct AwsClient {
    lightsail_client: aws_sdk_lightsail::Client,
    route53_client: aws_sdk_route53::Client,
}

impl AwsClient {
    pub fn new(aws_sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            lightsail_client: aws_sdk_lightsail::Client::new(aws_sdk_config),
            route53_client: aws_sdk_route53::Client::new(aws_sdk_config),
        }
    }
}

pub struct AllDnsZones {
    dns_zones: Vec<DnsZone>,
    aws_client: AwsClient,
}

impl AllDnsZones {
    pub async fn load(aws_clinet: &AwsClient) -> Result<Self, Error> {
        let lightsail_fut = Self::list_lightsail_zones(&aws_clinet.lightsail_client);
        let route53_fut = Self::list_route53_zones(&aws_clinet.route53_client);

        // concurrent execution of lightsail and route53
        let (lightsail_zones, route53_zones) = futures::try_join!(lightsail_fut, route53_fut)?;

        // Concat Lightsail DNS + Route53 zones
        let mut all_zones = lightsail_zones;
        all_zones.extend(route53_zones);

        Ok(Self {
            dns_zones: all_zones,
            aws_client: aws_clinet.clone(),
        })
    }

    pub fn find_zone<'a>(&'a self, hostname: &str) -> Option<&'a DnsZone> {
        self.dns_zones
            .iter()
            .filter(|zone| zone.contains(hostname))
            .max_by_key(|zone| zone.domain_name().len())
    }

    pub async fn write_txt_record(&self, record_name: &str, txt_value: &str) -> Result<(), Error> {
        match self.find_zone(record_name) {
            Some(DnsZone::Lightsail { domain_name }) => {
                DnsZone::write_txt_record_lightsail(
                    &self.aws_client.lightsail_client,
                    domain_name.as_str(),
                    record_name,
                    txt_value,
                )
                .await
            }
            Some(DnsZone::Route53 {
                domain_name: _,
                hosted_zone_id,
            }) => {
                DnsZone::write_txt_record_route53(
                    &self.aws_client.route53_client,
                    hosted_zone_id.as_str(),
                    record_name,
                    txt_value,
                )
                .await
            }
            None => Err(Error::NoDnsZone(record_name.to_string())),
        }
    }

    /// List all Lightsail DNS zones that AWS IAM role can access
    async fn list_lightsail_zones(
        client: &aws_sdk_lightsail::Client,
    ) -> Result<Vec<DnsZone>, Error> {
        // Call Lightsail GetDomains API
        let resp = client.get_domains().send().await?;
        let domains = resp.domains();
        // AWS SDK response -> DnsZone::Lightsail
        let dns_zones = domains.iter().filter_map(|domain| {
            domain.name().map(|domain_name| DnsZone::Lightsail {
                domain_name: domain_name.to_ascii_lowercase(),
            })
        });

        Ok(dns_zones.collect::<Vec<_>>())
    }

    /// List all Route53 hosted zones that AWS IAM role can access
    async fn list_route53_zones(client: &aws_sdk_route53::Client) -> Result<Vec<DnsZone>, Error> {
        // Call Route53 ListHostedZones API
        let pagenator = client
            .list_hosted_zones()
            .into_paginator()
            .send()
            .try_collect()
            .await?;
        // AWS SDK response -> DnsZone::Route53
        let dns_zones = pagenator
            .into_iter()
            .map(|page| page.hosted_zones)
            .flatten()
            .map(|zone| DnsZone::Route53 {
                domain_name: zone.name,
                hosted_zone_id: zone.id,
            });

        Ok(dns_zones.collect::<Vec<_>>())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum DnsZone {
    Lightsail {
        domain_name: String,
    },
    Route53 {
        domain_name: String,
        hosted_zone_id: String,
    },
}

impl DnsZone {
    pub fn domain_name<'a>(&'a self) -> &'a str {
        match self {
            Self::Lightsail { domain_name } => domain_name.as_str(),
            Self::Route53 {
                domain_name,
                hosted_zone_id: _,
            } => domain_name.as_str(),
        }
    }

    /// Check if the hostname is in this zone
    /// ToDo fix: if this domain has NS record, and hostname matches the NS record, it should be excluded
    pub fn contains(&self, hostname: &str) -> bool {
        let domain_name = self.domain_name();
        hostname.ends_with(domain_name)
    }

    async fn write_txt_record_lightsail(
        client: &aws_sdk_lightsail::Client,
        domain_name: &str,
        record_name: &str,
        txt_value: &str,
    ) -> Result<(), Error> {
        let entry = aws_sdk_lightsail::types::DomainEntry::builder()
            .name(record_name)
            .r#type("TXT")
            .target(format!("\"{}\"",txt_value))
            .build();

        let _resp = client
            .create_domain_entry()
            .domain_name(domain_name)
            .domain_entry(entry)
            .send()
            .await?;

        Ok(())
    }

    async fn write_txt_record_route53(
        client: &aws_sdk_route53::Client,
        hosted_zone_id: &str,
        record_name: &str,
        txt_value: &str,
    ) -> Result<(), Error> {
        todo!()
    }
}
