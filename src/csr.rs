//! Certificate signing request / PKCS#10 defined in RFC2986
use crate::Error;

pub struct X509Csr {
    der_bytes: Vec<u8>,
    subject: String,
    alt_names: Vec<String>,
}

impl X509Csr {
    /// Read certificate request from PEM encoded file
    pub fn from_pem_file<P: AsRef<std::path::Path>>(csr_pem_file: P) -> Result<Self, Error> {
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

    pub fn der_bytes<'a>(&'a self) -> &'a [u8] {
        self.der_bytes.as_slice()
    }
}

impl TryFrom<Vec<u8>> for X509Csr {
    type Error = Error;

    /// Parse CSR
    fn try_from(der_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        use x509_parser::{certification_request, error::X509Error, nom, prelude::FromDer};

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
