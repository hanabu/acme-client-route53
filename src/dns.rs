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

    pub async fn update_txt_record(&self, record_name: &str, txt_value: &str) -> Result<(), Error> {
        match self.find_zone(record_name) {
            Some(DnsZone::Lightsail {
                domain_name,
                txt_record_ids,
            }) => {
                DnsZone::update_txt_lightsail(
                    &self.aws_client.lightsail_client,
                    domain_name.as_str(),
                    txt_record_ids,
                    record_name,
                    txt_value,
                )
                .await
            }
            Some(DnsZone::Route53 {
                domain_name: _,
                hosted_zone_id,
            }) => {
                DnsZone::update_txt_route53(
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

    pub async fn wait_for_update(
        record_name: &str,
        expected_txt_value: &str,
        timeout_sec: u32,
    ) -> Result<(), Error> {
        let resolver = hickory_resolver::AsyncResolver::tokio_from_system_conf()?;

        for _retry in 0..=(timeout_sec / 10) {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            println!("lookup {}", record_name);
            resolver.clear_cache();
            let records = resolver.txt_lookup(record_name).await;
            println!("records {:?}", records);
            if let Ok(records) = records {
                for txt_record in records.iter() {
                    for txt_data in txt_record.iter() {
                        let txt_str = std::str::from_utf8(txt_data);
                        println!("TXT value: {:?}", txt_str);
                        if txt_str == Ok(expected_txt_value) {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(Error::DnsUpdateTimeout)
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
            domain.name().map(|domain_name| {
                // Collect entry-ID mapping
                let txt_record_ids = domain
                    .domain_entries()
                    .into_iter()
                    .filter_map(|entry| {
                        if let (Some(name), Some(id)) = (entry.name(), entry.id()) {
                            if entry.r#type.as_deref() == Some("TXT") {
                                Some((name.to_ascii_lowercase(), id.to_string()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect::<std::collections::HashMap<_, _>>();

                DnsZone::Lightsail {
                    domain_name: domain_name.to_ascii_lowercase(),
                    txt_record_ids,
                }
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
        txt_record_ids: std::collections::HashMap<String, String>,
    },
    Route53 {
        domain_name: String,
        hosted_zone_id: String,
    },
}

impl DnsZone {
    pub fn domain_name<'a>(&'a self) -> &'a str {
        match self {
            Self::Lightsail {
                domain_name,
                txt_record_ids: _,
            } => domain_name.as_str(),
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

    async fn update_txt_lightsail(
        client: &aws_sdk_lightsail::Client,
        domain_name: &str,
        txt_record_ids: &std::collections::HashMap<String, String>,
        record_name: &str,
        txt_value: &str,
    ) -> Result<(), Error> {
        let entry = aws_sdk_lightsail::types::DomainEntry::builder()
            .name(record_name)
            .r#type("TXT")
            .target(format!("\"{}\"", txt_value));

        if let Some(entry_id) = txt_record_ids.get(record_name) {
            // record_name entry already exists, update it.
            let _resp = client
                .update_domain_entry()
                .domain_name(domain_name)
                .domain_entry(entry.id(entry_id).build())
                .send()
                .await?;
        } else {
            // No entry exists, create new one
            let _resp = client
                .create_domain_entry()
                .domain_name(domain_name)
                .domain_entry(entry.build())
                .send()
                .await?;
        }

        Ok(())
    }

    async fn update_txt_route53(
        client: &aws_sdk_route53::Client,
        hosted_zone_id: &str,
        record_name: &str,
        txt_value: &str,
    ) -> Result<(), Error> {
        todo!()
    }
}
