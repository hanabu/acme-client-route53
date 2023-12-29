//! Configration in TOML format
//!
use hyper::client::connect::dns;

use crate::Error;

pub struct Config {
    account: instant_acme::Account,
    domains: Vec<DomainConfig>,
}

pub struct DomainConfig {
    hostname: String,
    cname: Option<String>,
    csr_file: String,
    dns_provider: DnsProvider,
}

pub enum DnsProvider {
    AwsRoute53,
    AwsLightsail,
}

#[derive(serde::Serialize)]
struct NewConfigToml {
    #[serde(rename = "account")]
    credential: instant_acme::AccountCredentials,
}

#[derive(serde::Deserialize)]
struct ConfigToml {
    #[serde(rename = "account")]
    credential: instant_acme::AccountCredentials,
    domains: std::collections::HashMap<String, DomainConfigToml>,
}

#[derive(serde::Deserialize)]
struct DomainConfigToml {
    cname: Option<String>,
    csr_file: String,
    dns_provider: String,
}

impl Config {
    pub fn new_with_credentials(new_cred: instant_acme::AccountCredentials) -> String {
        let new_toml = NewConfigToml {
            credential: new_cred,
        };

        toml::to_string_pretty(&new_toml).unwrap()
    }

    pub async fn from_file(config_file: &std::path::Path) -> Result<Self, Error> {
        use std::io::Read;

        // Read acme.toml file
        let mut f = std::fs::File::open(config_file)?;
        let mut toml_str = String::new();
        f.read_to_string(&mut toml_str)?;

        // Parse toml, load Account
        let config = Self::from_str(&toml_str).await?;
        Ok(config)
    }

    pub async fn from_str(cfg_toml_str: &str) -> Result<Self, Error> {
        use std::str::FromStr;

        // Parse config toml
        let ConfigToml {
            credential,
            domains,
        } = toml::from_str::<ConfigToml>(cfg_toml_str)?;

        // Load Account from credentials
        let account = instant_acme::Account::from_credentials_and_http(
            credential,
            crate::HyperTlsClient::new_boxed(),
        )
        .await?;

        let domains = domains
            .into_iter()
            .map(|(hostname, cfg)| {
                Ok(DomainConfig {
                    hostname,
                    cname: cfg.cname,
                    csr_file: cfg.csr_file,
                    dns_provider: DnsProvider::from_str(&cfg.dns_provider)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self { account, domains })
    }

    pub fn account<'a>(&'a self) -> &'a instant_acme::Account {
        &self.account
    }

    pub fn domains<'a>(&'a self) -> impl Iterator<Item = &'a DomainConfig> {
        self.domains.iter()
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
