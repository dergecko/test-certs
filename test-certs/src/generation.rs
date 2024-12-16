use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

use crate::{
    Certificate, Error, Issuer,
    configuration::certificates::{
        CertificateAuthorityConfiguration, CertificateType, ClientConfiguration,
        ServerConfiguration, SubjectAlternativeNames,
    },
};

/// Extension trait to convert [`CertificateType`] to [`Certificate`].
// NOTE: Instead of a trait use actual types?
pub trait CertificateGenerator {
    /// Build a [`Certificate`].
    fn build(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error>;
}

/// Internal trait to actually implement the logic to create a certificate from a specific
/// certificate configuration.
trait ToCertificate {
    fn certificate(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error>;
}

impl CertificateGenerator for CertificateType {
    fn build(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error> {
        match self {
            CertificateType::CertificateAuthority(certificate_authority_configuration) => {
                certificate_authority_configuration.certificate(name, issuer)
            }
            CertificateType::Client(client_configuration) => {
                client_configuration.certificate(name, issuer)
            }
            CertificateType::Server(server_configuration) => {
                server_configuration.certificate(name, issuer)
            }
        }
    }
}

impl ToCertificate for CertificateAuthorityConfiguration {
    fn certificate(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let certificate_params = issuer_params(name);

        let certificate = sign_cert(certificate_params, &key, issuer)?;

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
            issuer: issuer.cloned(),
        })
    }
}

impl ToCertificate for ClientConfiguration {
    fn certificate(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let mut certificate_params = certificate_params(name, &self.subject_alternative_names)?;
        certificate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let certificate = sign_cert(certificate_params, &key, issuer)?;
        let issuer = self
            .include_certificate_chain
            .then(|| issuer.cloned())
            .flatten();

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
            issuer,
        })
    }
}

impl ToCertificate for ServerConfiguration {
    fn certificate(&self, name: &str, issuer: Option<&Issuer>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let mut certificate_params = certificate_params(name, &self.subject_alternative_names)?;
        certificate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let certificate = sign_cert(certificate_params, &key, issuer)?;
        let issuer = self
            .include_certificate_chain
            .then(|| issuer.cloned())
            .flatten();

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
            issuer,
        })
    }
}

/// Signs the certificate either by the provided issuer or makes it self signed.
fn sign_cert(
    certificate_params: CertificateParams,
    key: &KeyPair,
    issuer: Option<&Issuer>,
) -> Result<rcgen::Certificate, Error> {
    let certificate = if let Some(issuer) = issuer {
        certificate_params.signed_by(key, &issuer.certificate, &issuer.key)
    } else {
        certificate_params.self_signed(key)
    }?;

    Ok(certificate)
}

/// Sets basic certificate parameters for CA/issuer certificates.
///
/// Sets the common name and defines CA usage with KeyCertSign and DigitalSignature.
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

/// Sets basic certificate parameter for client and server auth certificates.
///
/// Sets the subject alt names to the name and the ip.
/// IP Addresses can be used in SAN,
/// see [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6).
fn certificate_params(
    name: &str,
    san: &SubjectAlternativeNames,
) -> Result<CertificateParams, Error> {
    let params: Vec<String> = san
        .ip
        .iter()
        .map(|ip| ip.to_string())
        .chain(san.dns_name.iter().cloned())
        .collect();
    let mut certificate_params = CertificateParams::new(params)?;
    let mut common_name = DistinguishedName::new();
    common_name.push(DnType::CommonName, name);
    certificate_params.distinguished_name = common_name;
    certificate_params.is_ca = IsCa::ExplicitNoCa;

    Ok(certificate_params)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rustls::{RootCertStore, pki_types::UnixTime, server::WebPkiClientVerifier};

    use crate::{
        configuration::certificates::fixtures::{
            ca_certificate_type, ca_with_client_certificates,
            ca_with_intermediate_and_client_certificate, client_certificate_type,
            server_certificate_type,
        },
        generate,
    };

    use super::*;

    #[test]
    fn should_create_client_certificate() {
        let config = client_certificate_type();
        let result = config.build("test-client", None);

        assert!(result.is_ok())
    }

    #[test]
    fn should_create_server_certificate() {
        let config = server_certificate_type();
        let result = config.build("test-server", None);

        assert!(result.is_ok())
    }

    #[test]
    fn should_create_ca_certificate() {
        let config = ca_certificate_type();
        let result = config.build("test-ca", None);

        assert!(result.is_ok())
    }

    #[test]
    fn should_include_certificate_chain() {
        let ca = ca_certificate_type();
        let ca_cert = Issuer::new(ca.build("my-ca", None).unwrap());
        let client = client_certificate_type();
        let client_cert = client.build("client", Some(&ca_cert)).unwrap();
        let parent = client_cert.issuer.unwrap();

        assert_eq!(parent, ca_cert);
    }

    #[test]
    fn should_not_include_certificate_chain() {
        let ca = ca_certificate_type();
        let ca_cert = Issuer::new(ca.build("my-ca", None).unwrap());
        let client = CertificateType::Client(ClientConfiguration {
            subject_alternative_names: SubjectAlternativeNames {
                ip: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                dns_name: vec!["my-client.org".to_string()],
            },
            include_certificate_chain: false,
            export_key: ClientConfiguration::default_export_key(),
        });
        let client_cert = client.build("client", Some(&ca_cert)).unwrap();
        assert!(client_cert.issuer.is_none());
    }

    #[test]
    fn should_verify_client_with_ca() {
        let root = ca_with_client_certificates();
        let mut certs = generate(&root).unwrap();
        let ca = certs.pop().unwrap();
        let client = certs.pop().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate.der().clone()).unwrap();

        let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();
        let result =
            client_verifier.verify_client_cert(client.certificate.der(), &[], UnixTime::now());

        assert!(result.is_ok());
    }

    #[test]
    fn should_verify_client_with_intermediate_ca() {
        let root = ca_with_intermediate_and_client_certificate();
        let mut certs = generate(&root).unwrap();
        let root_ca = certs.pop().unwrap();
        let intermediate_ca = certs.pop().unwrap();
        let client = certs.pop().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(root_ca.certificate.der().clone()).unwrap();

        let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();
        let result = client_verifier.verify_client_cert(
            client.certificate.der(),
            &[intermediate_ca.certificate.der().clone()],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }
}
