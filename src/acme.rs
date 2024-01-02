use crate::Error;

pub struct AcmeOrder<'a, C = (), U = ()> {
    config: &'a crate::Config,
    cert_cfg: &'a crate::CertReqConfig,
    csr: C,     //crate::X509Csr,
    crt_pem: U, // String
}

impl<'a> AcmeOrder<'a, (), ()> {
    pub fn new<'b: 'a>(
        config: &'b crate::Config,
        cert_cfg: &'b crate::CertReqConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            config,
            cert_cfg,
            csr: (),
            crt_pem: (),
        })
    }

    pub fn load_and_check_csr(
        &self,
        dns_zones: &crate::AllDnsZones,
    ) -> Result<AcmeOrder<'a, crate::csr::X509Csr>, Error> {
        // Read CSR file
        let csr = crate::csr::X509Csr::from_pem_file(self.cert_cfg.csr_file_name())?;

        for hostname in csr.subjects() {
            let canonical_host = self.config.canonical_host(hostname);
            let zone = dns_zones.find_zone(canonical_host);
            if let Some(zone) = zone {
                // ok
            } else {
                return Err(Error::NoDnsZone(canonical_host.to_string()));
            }
        }

        Ok(AcmeOrder {
            config: self.config,
            cert_cfg: self.cert_cfg,
            csr,
            crt_pem: (),
        })
    }
}

impl<'a> AcmeOrder<'a, crate::X509Csr, ()> {
    pub async fn request_certificate(
        &self,
        dns_zones: &crate::AllDnsZones,
    ) -> Result<AcmeOrder<'a, (), String>, Error> {
        let validate_hostnames = self
            .csr
            .subjects()
            .map(|hostname| instant_acme::Identifier::Dns(hostname.to_string()))
            .collect::<Vec<_>>();

        let mut order = self
            .config
            .account()
            .new_order(&instant_acme::NewOrder {
                identifiers: &validate_hostnames,
            })
            .await?;

        let authorizations = order.authorizations().await?;

        // Collect ACME challenges need to be verified
        let challenges = authorizations
            .iter()
            .filter_map(|auth| {
                use instant_acme::AuthorizationStatus::Pending;
                use instant_acme::ChallengeType::Dns01;
                match auth.status {
                    Pending => {
                        // challenge & authorize
                        let dns_challenge = auth.challenges.iter().find(|c| c.r#type == Dns01);
                        if let Some(dns_challenge) = dns_challenge {
                            // DNS01 challenge
                            let hostname = match &auth.identifier {
                                instant_acme::Identifier::Dns(hostname) => hostname.as_str(),
                            };
                            // Retrive TXT record value
                            let key_auth = order.key_authorization(dns_challenge);
                            Some(Ok((
                                hostname,
                                key_auth.dns_value(),
                                dns_challenge.url.as_str(),
                            )))
                        } else {
                            // Oops, No DNS challenge supported in the ACME server?
                            Some(Err(Error::DnsChallengeNotSupported))
                        }
                    }
                    // Valid, Invalid, Revoked, Expired
                    _ => None,
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (hostname, txt_value, challenge_url) in challenges {
            let challenge_record = format!("_acme-challenge.{}", hostname);
            let canonical_challenge_record = self.config.canonical_host(&challenge_record);

            dns_zones
                .update_txt_record(canonical_challenge_record, &txt_value)
                .await?
                .wait_for_propergation(90)
                .await?;

            // DNS change has been propergated. Let ACME server to validate them.
            order.set_challenge_ready(challenge_url).await?;
        }

        // Now, all challenge has validated.
        match order.state().status {
            instant_acme::OrderStatus::Ready
            | instant_acme::OrderStatus::Valid
            | instant_acme::OrderStatus::Processing => {}
            _ => {
                // Unexpected invalid status
                return Err(Error::AcmeChallengeIncomplete);
            }
        }

        // Issue certificate
        order.finalize(self.csr.der_bytes()).await?;
        for _retry in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if let Some(crt_pem) = order.certificate().await? {
                return Ok(AcmeOrder {
                    config: self.config,
                    cert_cfg: self.cert_cfg,
                    csr: (),
                    crt_pem,
                });
            }
        }

        // Timeout
        Err(Error::CertificateIssueTimeout)
    }
}
