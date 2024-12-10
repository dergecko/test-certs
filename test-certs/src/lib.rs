//! Code to implement certificate generation and test-certs application logic.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::fmt::Debug;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};

mod configuration;

/// Errors when working with certificates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors when working with rcgen to create and sign certificates.
    #[error("Could not generate certificate")]
    FailedToCreateCertificate(#[from] rcgen::Error),
}

/// A pair of a certificate and the corresponding private key.
pub struct CertKeyPair {
    certificate: Certificate,
    key: KeyPair,
}

impl Debug for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertKey")
            .field("certificate", &self.certificate.pem())
            .field("key", &self.key)
            .finish()
    }
}

/// Create a [`CertKeyPair`] that is our certificate authority to sign other certificates.
pub fn create_root_ca() -> Result<CertKeyPair, Error> {
    let root_key = KeyPair::generate()?;
    let root_ca = issuer_params(env!("CARGO_PKG_NAME")).self_signed(&root_key)?;
    Ok(CertKeyPair {
        certificate: root_ca,
        key: root_key,
    })
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
    use super::*;

    #[test]
    fn should_create_root_ca() {
        let result = create_root_ca();
        assert!(result.is_ok())
    }

    #[test]
    fn root_ca_should_be_ca() {
        let CertKeyPair {
            certificate,
            key: _,
        } = create_root_ca().unwrap();

        assert_eq!(
            certificate.params().is_ca,
            IsCa::Ca(BasicConstraints::Unconstrained)
        );
    }
}
