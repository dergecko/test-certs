//! Certificate generation configuration.
//!
use std::{collections::HashMap, sync::LazyLock};

use serde::{Deserialize, Serialize};

/// This is the root structure that contains all certificate chains.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRoot {
    /// All certificates
    #[serde(flatten)]
    pub certificates: HashMap<String, CertificateType>,
}

/// The certificate authority to sign other certificates.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CertificateAuthorityConfiguration {
    /// Enables the export of the private key file.
    pub export_key: bool,

    /// Certificates that are signed by this CA.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub certificates: HashMap<String, CertificateType>,
}

/// A certificate used for client authentication.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfiguration {
    /// Enables the export of the private key file.
    pub export_key: bool,
}

/// A certificate used for server authentication.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfiguration {
    /// Enables the export of the private key file.
    pub export_key: bool,
}

/// All kinds of different certificates.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CertificateType {
    /// A certificate that acts as a Certificate Authority.
    #[serde(alias = "ca")]
    CertificateAuthority(CertificateAuthorityConfiguration),

    /// A certificate for client authentication.
    Client(ClientConfiguration),

    /// A certificate for server authentication.
    Server(ServerConfiguration),
}

/// Is used to provide a reference to an empty HashMap.
/// The [`LazyLock`] is required as a HashMap::new is not usable in const expressions.
static NO_CERTIFICATES: LazyLock<HashMap<String, CertificateType>> = LazyLock::new(HashMap::new);

impl CertificateType {
    /// Should the private key be exported or not.
    pub fn export_key(&self) -> bool {
        match self {
            CertificateType::CertificateAuthority(certificate_authority) => {
                certificate_authority.export_key
            }
            CertificateType::Client(client) => client.export_key,
            CertificateType::Server(server) => server.export_key,
        }
    }

    /// Certificates issued by this certificate.
    pub fn certificates(&self) -> &HashMap<String, CertificateType> {
        match self {
            CertificateType::CertificateAuthority(certificate_authority) => {
                &certificate_authority.certificates
            }
            CertificateType::Client(_client) => &NO_CERTIFICATES,
            CertificateType::Server(_server) => &NO_CERTIFICATES,
        }
    }
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        Self { export_key: true }
    }
}

impl Default for ServerConfiguration {
    fn default() -> Self {
        Self { export_key: true }
    }
}

/// Fixtures for testing certificate generation.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures {
    use super::*;

    /// Provides a [`CertificateRoot`] with a ca certificate that issues one client certificate.
    pub fn ca_with_client_certificates() -> CertificateRoot {
        let certs = CertificateRoot {
            certificates: HashMap::from([("ca".to_string(), ca_with_client_certificate_type())]),
        };
        certs
    }

    /// Provides a [`CertificateType`] that is a ca certificate that issues one client certificate.
    pub fn ca_with_client_certificate_type() -> CertificateType {
        CertificateType::CertificateAuthority(CertificateAuthorityConfiguration {
            certificates: HashMap::from([("client".to_string(), client_certificate_type())]),
            ..Default::default()
        })
    }

    /// Provides a [`CertificateRoot`] with only a client certificate.
    pub fn single_client_certificate() -> CertificateRoot {
        let certs = CertificateRoot {
            certificates: HashMap::from([("client".to_string(), client_certificate_type())]),
        };
        certs
    }

    /// Provides a [`CertificateType`] that is a client certificate.
    pub fn client_certificate_type() -> CertificateType {
        CertificateType::Client(ClientConfiguration::default())
    }

    /// Provides a [`CertificateRoot`] with only one ca certificate.
    pub fn single_ca_certificate() -> CertificateRoot {
        let certs = CertificateRoot {
            certificates: HashMap::from([(
                "ca".to_string(),
                CertificateType::CertificateAuthority(CertificateAuthorityConfiguration::default()),
            )]),
        };
        certs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::ca_with_client_certificates;
    use serde_json::json;

    fn get_ca(cert: &CertificateType) -> &CertificateAuthorityConfiguration {
        assert!(matches!(cert, CertificateType::CertificateAuthority(_)));
        let ca = match cert {
            CertificateType::CertificateAuthority(certificate_authority) => certificate_authority,
            _ => panic!("expected ca certificate"),
        };
        ca
    }

    mod json {
        use super::*;

        #[test]
        fn should_deserialize_ca() {
            let json = json!({
                "type": "ca",
            });

            let ca: CertificateType = serde_json::from_value(json).unwrap();

            assert!(matches!(ca, CertificateType::CertificateAuthority(_)))
        }

        #[test]
        fn should_fail_on_unknown_field() {
            let json = json!({
                "type": "ca",
                "bambu": "solala"
            });

            let result: Result<CertificateType, _> = serde_json::from_value(json);

            assert!(result.is_err())
        }

        #[test]
        fn should_deserialize_nested_certificates() {
            let json = json!({
                "type": "ca",
                "certificates": {
                    "intermediate_ca": {
                    "type": "ca",
                    "certificates": {
                        "client_cert": {
                            "type": "client",
                            "export_key": true
                        },
                        "server_cert": {
                            "type": "client",
                            "export_key": true
                        }
                    }
                }
            }
            });

            let ca: CertificateType = serde_json::from_value(json).unwrap();
            let ca = get_ca(&ca);
            let intermediate_ca = ca.certificates.get("intermediate_ca").unwrap();
            let intermediate_ca = get_ca(intermediate_ca);

            assert_eq!(intermediate_ca.certificates.len(), 2);
        }

        #[test]
        fn should_serde_roundtrip() {
            let certs = ca_with_client_certificates();

            let serialized = serde_json::to_string(&certs).unwrap();
            let deserialized: CertificateRoot = serde_json::from_str(&serialized).unwrap();

            assert_eq!(deserialized, certs)
        }
    }

    mod yaml {
        use super::*;

        #[test]
        fn should_serialize_certificateauthority() {
            let certificates = CertificateRoot {
                certificates: HashMap::from([(
                    "my-ca".to_string(),
                    CertificateType::CertificateAuthority(CertificateAuthorityConfiguration {
                        certificates: HashMap::new(),
                        export_key: false,
                    }),
                )]),
            };

            let certificates_yaml = serde_yaml::to_string(&certificates).unwrap();

            assert_eq!(
                r#"my-ca:
  type: certificateauthority
  export_key: false
"#,
                certificates_yaml
            );
        }

        #[test]
        fn should_deserialize_ca() {
            let yaml = r#"type: ca"#;

            let ca: CertificateType = serde_yaml::from_str(yaml).unwrap();

            assert!(matches!(ca, CertificateType::CertificateAuthority(_)))
        }

        #[test]
        fn should_deserialize_certificateauthority() {
            let yaml = r#"type: certificateauthority"#;

            let ca: CertificateType = serde_yaml::from_str(yaml).unwrap();

            assert!(matches!(ca, CertificateType::CertificateAuthority(_)))
        }

        #[test]
        fn should_serde_roundtrip() {
            let certs = ca_with_client_certificates();

            let serialized = serde_yaml::to_string(&certs).unwrap();
            let deserialized: CertificateRoot = serde_yaml::from_str(&serialized).unwrap();

            assert_eq!(deserialized, certs)
        }
    }
}
