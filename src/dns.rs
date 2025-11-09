use crate::Error;

#[derive(Clone, Debug)]
pub struct AwsClient {
    lightsail_client: aws_sdk_lightsail::Client,
    route53_client: aws_sdk_route53::Client,
}

impl AwsClient {
    pub async fn new() -> Self {
        // DNS is global resource, end points are located at us-east-1
        let aws_sdk_config = crate::http_client::aws_config_from_env("us-east-1").await;
        Self {
            lightsail_client: aws_sdk_lightsail::Client::new(&aws_sdk_config),
            route53_client: aws_sdk_route53::Client::new(&aws_sdk_config),
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

    pub async fn update_txt_record<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        record_name: &'b str,
        txt_value: &'b str,
    ) -> Result<DnsChange<'c>, Error> {
        match self.find_zone(record_name) {
            Some(DnsZone::Lightsail {
                domain_name,
                txt_record_ids,
            }) => {
                let initial_wait = DnsZone::update_txt_lightsail(
                    &self.aws_client.lightsail_client,
                    domain_name.as_str(),
                    txt_record_ids,
                    record_name,
                    txt_value,
                )
                .await?;

                Ok(DnsChange {
                    record_name,
                    txt_value,
                    initial_wait,
                })
            }
            Some(DnsZone::Route53 {
                domain_name: _,
                hosted_zone_id,
            }) => {
                let initial_wait = DnsZone::update_txt_route53(
                    &self.aws_client.route53_client,
                    hosted_zone_id.as_str(),
                    record_name,
                    txt_value,
                )
                .await?;
                Ok(DnsChange {
                    record_name,
                    txt_value,
                    initial_wait,
                })
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
                // ListHostedZones returns zone name with '.' suffix, remove it.
                domain_name: zone.name.trim_end_matches('.').to_ascii_lowercase(),
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
    ) -> Result<DnsChangeInitialWait<'static>, Error> {
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

            Ok(DnsChangeInitialWait::ConstTime(10))
        } else {
            // No entry exists, create new one
            let _resp = client
                .create_domain_entry()
                .domain_name(domain_name)
                .domain_entry(entry.build())
                .send()
                .await?;
            // Lightsail DNS has long negatie cache TTL.
            // To avoid NXDOMAIN caching, wait enough time after creation.
            Ok(DnsChangeInitialWait::ConstTime(50))
        }
    }

    async fn update_txt_route53<'a>(
        client: &'a aws_sdk_route53::Client,
        hosted_zone_id: &str,
        record_name: &str,
        txt_value: &str,
    ) -> Result<DnsChangeInitialWait<'a>, Error> {
        use aws_sdk_route53::types::{Change, ChangeAction, ChangeBatch};
        use aws_sdk_route53::types::{ResourceRecord, ResourceRecordSet, RrType};

        let record = ResourceRecordSet::builder()
            .name(record_name)
            .r#type(RrType::Txt)
            .resource_records(
                ResourceRecord::builder()
                    .value(format!("\"{}\"", txt_value))
                    .build()
                    .unwrap(),
            )
            .ttl(60)
            .build()
            .unwrap(); // unwrap() is safe when .name() and .type() were called

        let change = Change::builder()
            .action(ChangeAction::Upsert)
            .resource_record_set(record)
            .build()
            .unwrap(); // unwrap() is safe when .action() was called

        let changes = ChangeBatch::builder().changes(change).build().unwrap(); // unwrap() is safe when .changes() was called

        // Send change request
        let resp = client
            .change_resource_record_sets()
            .hosted_zone_id(hosted_zone_id)
            .change_batch(changes)
            .send()
            .await?;

        if let Some(change_info) = resp.change_info() {
            Ok(DnsChangeInitialWait::Route53Status(
                change_info.id().to_string(),
                client,
            ))
        } else {
            // Unexpected, wait 50 seconds before validate DNS records
            Ok(DnsChangeInitialWait::ConstTime(50))
        }
    }
}

pub struct DnsChange<'a> {
    record_name: &'a str,
    txt_value: &'a str,
    initial_wait: DnsChangeInitialWait<'a>,
}

enum DnsChangeInitialWait<'a> {
    ConstTime(u32),
    Route53Status(String, &'a aws_sdk_route53::Client),
}

impl DnsChange<'_> {
    pub async fn wait_for_propergation(&self, timeout_secs: u32) -> Result<bool, Error> {
        const POLLING_INTERVAL_SECS: u32 = 10;

        let resolver = hickory_resolver::Resolver::builder_tokio()?.build();

        let timeout = std::time::Duration::from_secs(timeout_secs as u64);
        let wait_start = std::time::Instant::now();

        match &self.initial_wait {
            DnsChangeInitialWait::ConstTime(init_wait_secs) => {
                if POLLING_INTERVAL_SECS < *init_wait_secs {
                    let init_wait = std::time::Duration::from_secs(
                        (*init_wait_secs - POLLING_INTERVAL_SECS) as u64,
                    );
                    tokio::time::sleep(init_wait).await;
                }
            }
            DnsChangeInitialWait::Route53Status(change_id, client) => {
                use aws_sdk_route53::types::ChangeStatus;
                while wait_start.elapsed() < timeout {
                    let resp = client.get_change().id(change_id).send().await?;
                    if let Some(change_info) = resp.change_info() {
                        if change_info.status() == &ChangeStatus::Insync {
                            break;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(
                        POLLING_INTERVAL_SECS as u64,
                    ))
                    .await;
                }
            }
        }

        while wait_start.elapsed() < timeout {
            tokio::time::sleep(std::time::Duration::from_secs(POLLING_INTERVAL_SECS as u64)).await;
            println!("lookup {}", self.record_name);
            resolver.clear_cache();
            let records = resolver.txt_lookup(self.record_name).await;
            println!("records {:?}", records);
            if let Ok(records) = records {
                for txt_record in records.iter() {
                    for txt_data in txt_record.iter() {
                        let txt_str = std::str::from_utf8(txt_data);
                        println!("TXT value: {:?}", txt_str);
                        if txt_str == Ok(self.txt_value) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Err(Error::DnsUpdateTimeout)
    }
}
