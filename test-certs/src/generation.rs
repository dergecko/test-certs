use std::net::IpAddr;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

use crate::{
    configuration::certificates::{
        CertificateAuthorityConfiguration, CertificateType, ClientConfiguration,
        ServerConfiguration,
    },
    Certificate, Error,
};

/// Extension trait to convert [`CertificateType`] to [`Certificate`].
// NOTE: Instead of a trait use actual types?
pub trait CertificateGenerator {
    /// Build a [`Certificate`].
    fn build(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error>;
}

/// Internal trait to actually implement the logic to create a certificate from a specific certificate configuration.
trait ToCertificate {
    fn certificate(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error>;
}

impl CertificateGenerator for CertificateType {
    fn build(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error> {
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
    fn certificate(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let certificate_params = issuer_params(name);

        let certificate = sign_cert(certificate_params, &key, issuer)?;

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
        })
    }
}

impl ToCertificate for ClientConfiguration {
    fn certificate(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let mut certificate_params = certificate_params(name, self.ip)?;
        certificate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let certificate = sign_cert(certificate_params, &key, issuer)?;

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
        })
    }
}

impl ToCertificate for ServerConfiguration {
    fn certificate(&self, name: &str, issuer: Option<&Certificate>) -> Result<Certificate, Error> {
        let key = KeyPair::generate()?;

        let mut certificate_params = certificate_params(name, self.ip)?;
        certificate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let certificate = sign_cert(certificate_params, &key, issuer)?;

        Ok(Certificate {
            certificate,
            key,
            export_key: self.export_key,
            name: name.to_string(),
        })
    }
}

/// Signs the certificate either by the provided issuer or makes it self signed.
fn sign_cert(
    certificate_params: CertificateParams,
    key: &KeyPair,
    issuer: Option<&Certificate>,
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
fn certificate_params(name: &str, ip: IpAddr) -> Result<CertificateParams, Error> {
    let mut certificate_params = CertificateParams::new(vec![name.to_string(), ip.to_string()])?;
    let mut common_name = DistinguishedName::new();
    common_name.push(DnType::CommonName, name);
    certificate_params.distinguished_name = common_name;
    certificate_params.is_ca = IsCa::ExplicitNoCa;

    Ok(certificate_params)
}

#[cfg(test)]
mod tests {
    use crate::configuration::certificates::fixtures::{
        ca_certificate_type, client_certificate_type, server_certificate_type,
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

    // TODO: write test to check wether client/server certs are really issued by a ca
}
