use crate::Error;

pub struct AcmeOrder<'a> {
    config: &'a crate::Config,
    csr: crate::X509Csr,
}

pub struct AcmeOrderBuilder<'a> {
    config: &'a crate::Config,
    cert_cfg: &'a crate::CertReqConfig,
}

impl<'a> AcmeOrder<'a> {
    pub fn new<'b: 'a>(
        config: &'b crate::Config,
        cert_cfg: &'b crate::CertReqConfig,
    ) -> Result<AcmeOrderBuilder<'a>, Error> {
        Ok(AcmeOrderBuilder { config, cert_cfg })
    }
}

impl<'a> AcmeOrderBuilder<'a> {
    pub fn load_and_check_csr(
        &self,
        dns_zones: &crate::AllDnsZones,
    ) -> Result<AcmeOrder<'a>, Error> {
        // Read CSR file
        let csr = crate::csr::X509Csr::from_pem_file(self.cert_cfg.csr_file_name())?;

        for hostname in csr.subjects() {
            let canonical_host = self.config.canonical_host(hostname);
            let zone = dns_zones.find_zone(canonical_host);
            if let Some(_zone) = zone {
                // ok
            } else {
                return Err(Error::NoDnsZone(canonical_host.to_string()));
            }
        }

        Ok(AcmeOrder {
            config: self.config,
            csr,
        })
    }
}

impl AcmeOrder<'_> {
    pub async fn request_certificate(
        &self,
        dns_zones: &crate::AllDnsZones,
    ) -> Result<AcmeIssuedCertificate, Error> {
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
        for _retry in 0..3 {
            use instant_acme::OrderStatus::*;
            match order.state().status {
                Ready | Valid => {
                    // Ready for issueing certificate
                    break;
                }
                Processing => {
                    // Wait processing, then continue
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    break;
                }
                Pending => {
                    // Wait for validation complete, retry checking
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                _ => {
                    // Unexpected invalid status
                    return Err(Error::AcmeChallengeIncomplete);
                }
            }
        }

        // Issue certificate
        order.finalize(self.csr.der_bytes()).await?;
        for _retry in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if let Some(crt_pem_str) = order.certificate().await? {
                let crt_pem = x509_parser::pem::Pem::iter_from_buffer(crt_pem_str.as_bytes())
                    .collect::<Result<Vec<_>, x509_parser::error::PEMError>>()?;

                return Ok(AcmeIssuedCertificate { crt_pem });
            }
        }

        // Timeout
        Err(Error::CertificateIssueTimeout)
    }
}

pub struct AcmeIssuedCertificate {
    crt_pem: Vec<x509_parser::pem::Pem>,
}

impl AcmeIssuedCertificate {
    pub fn server_certificate_pem(&self) -> String {
        Self::to_pem_string(&self.crt_pem[0])
    }

    pub fn issuer_certificate_pem(&self) -> String {
        Self::to_pem_string(&self.crt_pem[1])
    }

    fn to_pem_string(pem: &x509_parser::pem::Pem) -> String {
        use base64::engine::Engine;

        // Base64 encode with 64char line wrap
        let b64content = pem
            .contents
            .chunks(48)
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
            .collect::<Vec<String>>()
            .join("\n");

        format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----\n\n",
            pem.label, b64content, pem.label
        )
    }
}
