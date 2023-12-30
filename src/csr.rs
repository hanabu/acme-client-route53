//! Certificate signing request / PKCS#10 defined in RFC2986

use x509_parser::certification_request;

pub struct CertRequest {
    der_bytes: Vec<u8>,
    subject: String,
    alt_names: Vec<String>,
}

impl CertRequest {
    /// Read certificate request from PEM encoded file
    pub fn from_pem_file<P: AsRef<std::path::Path>>(csr_pem_file: P) -> Result<Self, crate::Error> {
        use std::io::Read;

        // Read file as binary
        let mut f = std::fs::File::open(csr_pem_file)?;
        let mut buf = Vec::<u8>::new();
        f.read_to_end(&mut buf)?;

        // Parse PEM
        let (_rem, pem) = x509_parser::pem::parse_x509_pem(&buf)?;

        Self::try_from(pem.contents)
    }

    /// Return all subjects in this CSR
    pub fn subjects<'a>(&'a self) -> impl Iterator<Item = &'a str> {
        std::iter::once(self.subject.as_str())
            .chain(self.alt_names.iter().map(|subj| subj.as_str()))
    }
}

impl TryFrom<Vec<u8>> for CertRequest {
    type Error = crate::Error;

    /// Parse CSR
    fn try_from(der_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        use x509_parser::{error::X509Error, nom, prelude::FromDer};

        let (_rem, csr) = certification_request::X509CertificationRequest::from_der(&der_bytes)?;

        // get subject common name
        let subject_cn = csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .ok_or(nom::Err::Error(X509Error::InvalidX509Name))?;

        let subject = subject_cn
            .as_str()
            .map_err(|e| nom::Err::Error(e))?
            .to_ascii_lowercase();

        // Parse SubjectAltName extension
        let mut alt_names = Vec::<String>::new();
        if let Some(extensions) = csr.requested_extensions() {
            use x509_parser::extensions::{GeneralName, ParsedExtension};
            for ext in extensions {
                if let ParsedExtension::SubjectAlternativeName(alt_name_ext) = ext {
                    for alt_name in &alt_name_ext.general_names {
                        if let GeneralName::DNSName(dns_name) = alt_name {
                            alt_names.push(dns_name.to_ascii_lowercase());
                        }
                    }
                }
            }
        }

        Ok(Self {
            der_bytes,
            subject,
            alt_names,
        })
    }
}

/*


use der_parser::ber::BerObject;
use std::io::Read;



// Read CSR file, returns CN & altnames
pub fn parse_csr_file(csrfile: &str) -> Result<Vec<String>, std::io::Error> {
    // Read CSR file
    let mut buf = Vec::<u8>::new();

    {
        let mut f = std::fs::File::open(csrfile)?;
        f.read_to_end(&mut buf)?;
    };

    parse_csr(&buf)
}

// Read CSR file, returns CN & altnames
fn parse_csr(csrbytes: &[u8]) -> Result<Vec<String>, std::io::Error> {
    match pem::parse(csrbytes) {
        Ok(pem) => match der_parser::parse_der(&pem.contents) {
            Ok((_, der_root)) => parse_certification_request(&der_root),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
        },
        Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
    }
}

/// Parse CertificationRequest defined in RFC2986 - 4.2
fn parse_certification_request(crt_req: &BerObject) -> Result<Vec<String>, std::io::Error> {
    // CertificationRequest ::= SEQUENCE {
    //     certificationRequestInfo,
    //     signatureAlgorithm,
    //     signature
    // }
    if let Ok(seq) = crt_req.as_sequence() {
        if 3 == seq.len() {
            parse_certification_request_info(&seq[0])
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid CSR format",
            ))
        }
    } else {
        // CertificationRequest is not SEQUENCE type
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid CSR format",
        ))
    }
}

/// Parse certificationRequestInfo defined in RFC2986 - 4.1
fn parse_certification_request_info(
    crt_req_info: &BerObject,
) -> Result<Vec<String>, std::io::Error> {
    // CertificationRequestInfo ::= SEQUENCE {
    //    version       INTEGER { v1(0) } (v1,...),
    //    subject       Name,
    //    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    //    attributes    [0] Attributes{{ CRIAttributes }}
    if let Ok(seq) = crt_req_info.as_sequence() {
        if 4 == seq.len() {
            if Ok(0u32) != seq[0].as_u32() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid CSR version",
                ))?;
            }

            let mut server_names = Vec::<String>::new();

            // seq[1]
            // Parse CN in subject
            if let Some(subj_cn) = parse_subject(&seq[1]) {
                server_names.push(subj_cn);
            }

            // ignore subjectPKInfo
            // seq[2]
            // println!("subjectPKInfo = {:?}", seq[2]);

            // parse attributes and x509 extension
            if seq[3].is_contextspecific() && 0u32 == seq[3].header.tag.0 {
                if let Ok(attr) = seq[3].as_slice() {
                    if let Ok(mut altnames) = parse_attributes(attr) {
                        server_names.append(&mut altnames);
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid CSR attr",
                    ))?;
                }
            }
            Ok(server_names)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid CSR format",
            ))
        }
    } else {
        // CertificationRequestInfo is not SEQUENCE type
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid CSR format",
        ))
    }
}

/// parse subject
fn parse_subject(subj: &BerObject) -> Option<String> {
    // Set -> Sequence -> Sequence -> CN
    for subjseq1 in subj.ref_iter() {
        for subjseq2 in subjseq1.ref_iter() {
            // subjseq2 = Sequence[ OID, PrintableString ]
            let mut iterseq2 = subjseq2.ref_iter();
            let subj_oid = iterseq2.next().and_then(|obj| obj.as_oid().ok());
            let subj_obj = iterseq2.next().and_then(|obj| obj.as_str().ok());

            // find CN
            if Some(&der_parser::oid!(2.5.4 .3)) == subj_oid {
                if let Some(cn_str) = subj_obj {
                    return Some(cn_str.to_string());
                }
            }
        }
    }
    None
}

/// parse attributes in CertificationRequestInfo
fn parse_attributes(attrbytes: &[u8]) -> Result<Vec<String>, std::io::Error> {
    if let Ok((_, attr)) = der_parser::parse_ber(attrbytes) {
        // attr = Sequence[ OID, Object ]
        let mut attr_seq = attr.ref_iter();
        let attr_oid = attr_seq.next().and_then(|obj| obj.as_oid().ok());
        let attr_obj = attr_seq.next();

        // OID of ExtensionReq (RFC5272 3.1)
        if Some(&der_parser::oid!(1.2.840 .113549 .1 .9 .14)) == attr_oid {
            if let Some(ext) = attr_obj {
                return Ok(parse_extention_req(ext));
            }
        }

        // ExtensionReq not found, return empty vector
        Ok(Vec::<String>::new())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid ext format",
        ))
    }
}

/// parse extensionRequest RFC5272 3.1 & RFC3280
fn parse_extention_req(ext: &BerObject) -> Vec<String> {
    // Set -> Sequence -> Sequence -> Subject Alt Name
    for extseq1 in ext.ref_iter() {
        for extseq2 in extseq1.ref_iter() {
            // extseq2 = Sequence[ OID, OctetString ]
            let mut iterseq2 = extseq2.ref_iter();
            let ext_oid = iterseq2.next().and_then(|obj| obj.as_oid().ok());
            let ext_obj = iterseq2.next().and_then(|obj| obj.as_slice().ok());

            if Some(&der_parser::oid!(2.5.29 .17)) == ext_oid {
                if let Some(ext_altname) = ext_obj {
                    // Parse OctetString as DER encoded bytes
                    if let Ok((_, altnames)) = der_parser::parse_ber(ext_altname) {
                        return parse_alt_names(&altnames);
                    }
                }
            }
        }
    }

    // ServerAltName extension not found, returns empty vector
    Vec::<String>::new()
}

/// parse altnames
fn parse_alt_names(altnames: &BerObject) -> Vec<String> {
    let mut altname_vec = Vec::<String>::new();
    for altname in altnames.ref_iter() {
        if let Ok(raw_altname) = altname.as_slice() {
            if let Ok(altname_str) = std::str::from_utf8(raw_altname) {
                altname_vec.push(altname_str.to_string());
            }
        }
    }
    altname_vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_csr() {
        let server_names = parse_csr(include_bytes!("unittest.csr")).unwrap();
        assert_eq!(
            server_names,
            vec![
                "www.example.com".to_string(),
                "alt1.example.com".to_string(),
                "alt2.example.com".to_string(),
            ]
        );
    }
}
*/
