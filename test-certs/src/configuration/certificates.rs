//! Certificate generation configuration.
//!
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// This is the root structure that contains all certificate chains.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificates {
    /// All certificates
    #[serde(flatten)]
    pub certificates: HashMap<String, CertificateTypes>,
}

/// The certificate authority to sign other certificates.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CertificateAuthority {
    /// Enables the export of the private key file
    pub export_key: bool,

    /// Certificates that are signed by this CA
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub certificates: HashMap<String, CertificateTypes>,
}

/// A certificate used for client authentication
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    /// Enables the export of the private key file
    pub export_key: bool,
}

/// A certificate used for server authentication
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Enables the export of the private key file
    pub export_key: bool,
}

/// All kinds of different certificates
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CertificateTypes {
    /// A certificate that acts as a Certificate Authority
    #[serde(alias = "ca")]
    CertificateAuthority(CertificateAuthority),

    /// A certificate for client authentication
    Client(Client),

    /// A certificate for server authentication
    Server(Server),
}

impl Default for Client {
    fn default() -> Self {
        Self { export_key: true }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self { export_key: true }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn get_ca(cert: &CertificateTypes) -> &CertificateAuthority {
        assert!(matches!(cert, CertificateTypes::CertificateAuthority(_)));
        let ca = match cert {
            CertificateTypes::CertificateAuthority(certificate_authority) => certificate_authority,
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

            let ca: CertificateTypes = serde_json::from_value(json).unwrap();

            assert!(matches!(ca, CertificateTypes::CertificateAuthority(_)))
        }

        #[test]
        fn should_fail_on_unknown_field() {
            let json = json!({
                "type": "ca",
                "bambu": "solala"
            });

            let result: Result<CertificateTypes, _> = serde_json::from_value(json);

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

            let ca: CertificateTypes = serde_json::from_value(json).unwrap();
            let ca = get_ca(&ca);
            let intermediate_ca = ca.certificates.get("intermediate_ca").unwrap();
            let intermediate_ca = get_ca(intermediate_ca);

            assert_eq!(intermediate_ca.certificates.len(), 2);
        }

        #[test]
        fn should_serde_roundtrip() {
            let certs = Certificates {
                certificates: HashMap::from_iter([(
                    "my-ca".to_string(),
                    CertificateTypes::CertificateAuthority(CertificateAuthority {
                        export_key: true,
                        certificates: HashMap::from_iter([(
                            "client".to_string(),
                            CertificateTypes::Client(Client { export_key: true }),
                        )]),
                    }),
                )]),
            };

            let serialized = serde_json::to_string(&certs).unwrap();
            let deserialized: Certificates = serde_json::from_str(&serialized).unwrap();

            assert_eq!(deserialized, certs)
        }
    }

    mod yaml {
        use super::*;

        #[test]
        fn should_serialize_certificateauthority() {
            let certificates = Certificates {
                certificates: HashMap::from([(
                    "my-ca".to_string(),
                    CertificateTypes::CertificateAuthority(CertificateAuthority {
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

            let ca: CertificateTypes = serde_yaml::from_str(yaml).unwrap();

            assert!(matches!(ca, CertificateTypes::CertificateAuthority(_)))
        }

        #[test]
        fn should_deserialize_certificateauthority() {
            let yaml = r#"type: certificateauthority"#;

            let ca: CertificateTypes = serde_yaml::from_str(yaml).unwrap();

            assert!(matches!(ca, CertificateTypes::CertificateAuthority(_)))
        }
    }
}
