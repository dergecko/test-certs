//! Code to implement certificate generation and test-certs application logic.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::{fmt::Debug, io::Write, path::Path};

use configuration::certificates::CertificateType;
use generation::CertificateGenerator as _;
use rcgen::KeyPair;

pub mod configuration;
mod generation;

/// Errors when working with certificates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors when working with rcgen to create and sign certificates.
    #[error("Could not generate certificate")]
    FailedToCreateCertificate(#[from] rcgen::Error),

    /// Error to write the certificate to disk
    #[error("Could not write certificate")]
    FailedToWriteCertificate(std::io::Error),

    /// Error to write the certificate key to disk
    #[error("Could not write certificate key")]
    FailedToWriteKey(std::io::Error),

    /// Multiple errors that occurred while working with certificates
    #[error("Multiple errors occurred")]
    ErrorCollection(Vec<Error>),
}

/// A pair of a certificate and the corresponding private key.
pub struct Certificate {
    certificate: rcgen::Certificate,
    key: KeyPair,
    export_key: bool,
    name: String,
}

impl Certificate {
    /// Write the certificate and the key if marked for export to the specified folder.
    pub fn write(&self, directory: &Path) -> Result<(), Error> {
        let cert_file = directory.join(format!("{}.pem", &self.name));

        let mut cert =
            std::fs::File::create(&cert_file).map_err(Error::FailedToWriteCertificate)?;
        cert.write_fmt(format_args!("{}", self.certificate.pem()))
            .map_err(Error::FailedToWriteCertificate)?;

        if self.export_key {
            let key_file = directory.join(format!("{}.key", &self.name));
            let mut key = std::fs::File::create(&key_file).map_err(Error::FailedToWriteKey)?;
            key.write_fmt(format_args!("{}", self.key.serialize_pem()))
                .map_err(Error::FailedToWriteKey)?;
        }
        Ok(())
    }
}

/// Generates all certificates that are present in the configuration file.
// TODO: Make builder and return errors and certificates at the same time, maybe with an Iterator?
pub fn generate(
    certificate_config: configuration::certificates::CertificateRoot,
) -> Result<Vec<Certificate>, Error> {
    let certs: Vec<Result<Vec<Certificate>, Error>> = certificate_config
        .certificates
        .iter()
        .map(|(name, config)| generate_certificates(name, config, None))
        .collect();

    let mut errors = vec![];
    let mut certificates = vec![];
    for result in certs.into_iter() {
        match result {
            Ok(mut certs) => certificates.append(&mut certs),
            Err(error) => errors.push(error),
        }
    }

    if !errors.is_empty() {
        return Err(Error::ErrorCollection(errors));
    }

    Ok(certificates)
}

/// Generates the certificate and all certificates issued by this one.
fn generate_certificates(
    name: &str,
    config: &CertificateType,
    issuer: Option<&Certificate>,
) -> Result<Vec<Certificate>, Error> {
    let mut result = vec![];
    let issuer = config.build(name, issuer)?;

    for (name, config) in config.certificates().iter() {
        let mut certificates = generate_certificates(name, config, Some(&issuer))?;
        result.append(&mut certificates);
    }

    result.push(issuer);
    Ok(result)
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertKey")
            .field("certificate", &self.certificate.pem())
            .field("key", &self.key.serialize_pem())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use configuration::certificates::fixtures::{
        ca_with_client_certificate_type, ca_with_client_certificates, client_certificate_type,
    };
    use testdir::testdir;

    use super::*;

    #[test]
    fn should_create_certificates() {
        let certificate_config = ca_with_client_certificates();
        let certificates = generate(certificate_config).unwrap();
        assert_eq!(
            certificates.len(),
            2,
            "Expected to generate one ca certificate and one client certificate: {certificates:?}"
        )
    }

    #[test]
    fn should_generate_certificates() {
        let config = ca_with_client_certificate_type();
        let result = generate_certificates("my-ca", &config, None);

        assert!(result.is_ok())
    }

    #[test]
    fn should_write_certificate_to_file() {
        let dir = testdir!();
        let config = client_certificate_type();
        let certificates = generate_certificates("my-client", &config, None).unwrap();
        let certificate = certificates.first().unwrap();

        certificate.write(&dir).unwrap();

        let file_exists = dir
            .read_dir()
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|f| f.file_name() == "my-client.pem");
        assert!(file_exists)
    }
}
