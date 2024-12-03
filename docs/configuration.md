# Configuration

This documents the evaluation and ideas how to descriibe the certifiacte chain with YAML (or any other serializable/deserializable format supported by [serde]).

## Idea 1

Define each cert on it's own and have a relation wit the property `signed`, where `self` is a specific key word that this is a self-signed certificate.

```yaml
certificate:
    name: root
    signed: self
    key_usages:
        - KeyCertSign
        - DigitalSignature

certificate: 
    name: intermediate
    signed: root
    key_usages:
        - KeyCertSign
        - DigitalSignature

certificate: 
    name: client
    signed: intermediate
    export_key: true
    include_certificate_chain: true
    extended_key_usages:
        - ClientAuth

certificate: 
    name: server
    signed: intermediate
    export_key: true
    include_certificate_chain: true
    extended_key_usages:
        - ServerAuth
```

## Idea 2

Define a chain of nested certificates and specialize the type of certificate with the `type` property.
All certificates will be exported excluding their private key file.
Only for certificates of type `client` or `server` the private key is also exported.

```yaml
my-root-ca:
    type: ca
    children:
        - my-intermediate-ca:
          type: ca
          children:
            - my-client:
              type: client
              include_certificate_chain: true
              dns_name: my-client.org
              ip: 192.168.17.35
           - my-server:
              type: server
              include_certificate_chain: true
              dns_name: my-server.org
              ip: 192.168.17.77
```

[serde]: (https://crates.io/crates/serde)