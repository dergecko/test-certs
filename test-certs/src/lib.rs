//! Code to implement certificate generation and test-certs application logic.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::fmt::Debug;

use configuration::certificates::CertificateTypes;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};

pub mod configuration;

/// Errors when working with certificates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors when working with rcgen to create and sign certificates.
    #[error("Could not generate certificate")]
    FailedToCreateCertificate(#[from] rcgen::Error),
}

/// A pair of a certificate and the corresponding private key.
#[allow(unused, reason = "Initial draft therefore values are not used yet")]
pub struct CertKeyPair {
    certificate: Certificate,
    key: KeyPair,
    export_key: bool,
    name: String,
}

/// Generates all certificates that are present in the configuration file.
///
/// Each certificate chain is evaluated from the specified root certificate.
/// If one certificate in the chain could not be created the corresponding 
/// error is reported and the chain will not be generated.
pub fn generate(
    certificate_config: configuration::certificates::Certificates,
) -> Result<Vec<CertKeyPair>, Vec<Error>> {
    let certs: Vec<Result<Vec<CertKeyPair>, Error>> = certificate_config
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
        return Err(errors);
    }

    Ok(certificates)
}

/// Generates the certificate and all certificates issued by this one.
fn generate_certificates(
    name: &str,
    config: &CertificateTypes,
    issuer: Option<&CertKeyPair>,
) -> Result<Vec<CertKeyPair>, Error> {
    let mut result = vec![];
    let issuer = create_certificate(name, config, issuer)?;

    for (name, config) in config.certificates().iter() {
        let mut certificates = generate_certificates(name, config, Some(&issuer))?;
        result.append(&mut certificates);
    }

    result.push(issuer);
    Ok(result)
}

/// Create the actual certificate and private key.
fn create_certificate(
    name: &str,
    certificate_config: &CertificateTypes,
    issuer: Option<&CertKeyPair>,
) -> Result<CertKeyPair, Error> {
    let key = KeyPair::generate()?;

    // TODO: right now the certificate type is ignored and no client or server auth certs are generated
    let certificate = if let Some(issuer) = issuer {
        issuer_params(name).signed_by(&key, &issuer.certificate, &issuer.key)?
    } else {
        issuer_params(name).self_signed(&key)?
    };

    Ok(CertKeyPair {
        certificate,
        key,
        export_key: certificate_config.export_key(),
        name: name.to_string(),
    })
}

impl Debug for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertKey")
            .field("certificate", &self.certificate.pem())
            .field("key", &self.key.serialize_pem())
            .finish()
    }
}

fn issuer_params(common_name: &str) -> CertificateParams {
    let mut issuer_name = DistinguishedName::new();
    issuer_name.push(DnType::CommonName, common_name);
    let mut issuer_params = CertificateParams::default();
    issuer_params.distinguished_name = issuer_name;
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    issuer_params
}

#[cfg(test)]
mod test {
    use configuration::certificates::fixtures::{
        ca_with_client, certificate_ca_with_client, client,
    };

    use super::*;

    #[test]
    fn should_create_certificates() {
        let certificate_config = certificate_ca_with_client();
        let certificates = generate(certificate_config).unwrap();
        assert_eq!(
            certificates.len(),
            2,
            "Expected to generate one ca certificate and one client certificate: {certificates:?}"
        )
    }

    #[test]
    fn should_create_certificate() {
        let config = client();
        let result = create_certificate("test", &config, None);
        assert!(result.is_ok())
    }

    #[test]
    fn should_generate_certificates() {
        let config = ca_with_client();
        let result = generate_certificates("my-ca", &config, None);
        assert!(result.is_ok())
    }
}
