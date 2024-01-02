//! Configration in TOML format
//!
use crate::Error;

pub struct Config {
    account: instant_acme::Account,
    cname: std::collections::HashMap<String, String>,
    cert_requests: Vec<CertReqConfig>,
}

#[derive(serde::Deserialize)]
pub struct CertReqConfig {
    csr_file: String,
    out_crt_file: String,
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
    #[serde(default)]
    cname: std::collections::HashMap<String, String>,
    certificate_requests: Vec<CertReqConfig>,
}

impl Config {
    pub fn new_with_credentials(new_cred: instant_acme::AccountCredentials) -> String {
        let new_toml = NewConfigToml {
            credential: new_cred,
        };

        toml::to_string_pretty(&new_toml).unwrap()
    }

    pub async fn from_file<P: AsRef<std::path::Path>>(config_file: P) -> Result<Self, Error> {
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
        // Parse config toml
        let ConfigToml {
            credential,
            cname,
            certificate_requests,
        } = toml::from_str::<ConfigToml>(cfg_toml_str)?;

        // Load Account from credentials
        let account = instant_acme::Account::from_credentials_and_http(
            credential,
            crate::HyperTlsClient::new_boxed(),
        )
        .await?;

        Ok(Self {
            account,
            cname,
            cert_requests: certificate_requests,
        })
    }

    pub fn account<'a>(&'a self) -> &'a instant_acme::Account {
        &self.account
    }

    pub fn certificate_requests<'a>(&'a self) -> impl Iterator<Item = &'a CertReqConfig> {
        self.cert_requests.iter()
    }

    pub fn canonical_host<'a: 'c, 'b: 'c, 'c>(&'a self, hostname: &'b str) -> &'c str {
        if let Some(cname) = self.cname.get(hostname) {
            cname.as_str()
        } else {
            hostname
        }
    }
}

impl CertReqConfig {
    pub fn csr_file_name<'a>(&'a self) -> &'a str {
        self.csr_file.as_str()
    }

    pub fn crt_file_name<'a>(&'a self) -> &'a str {
        &self.out_crt_file.as_str()
    }
}
