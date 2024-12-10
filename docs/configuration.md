# Configuration

This documents the evaluation and ideas how to describe the certificate chain with YAML (or any other serializable/deserializable format supported by [serde]).

## Idea

Define a chain of nested certificates and specialize the type of certificate with the `type` property.
All certificates will be exported excluding their private key file.
Only for certificates of type `client` or `server` the private key is also exported.

```yaml
my-root-ca:
    type: ca
    export_key: true
    meta_data: ...
    certificates:
        - my-intermediate-ca:
          type: ca
          export_key: true
          certificates:
            - my-client:
              type: client
              signature_algorithm: rsa
              include_certificate_chain: true
              dns_name: my-client.org
              ip: 192.168.17.35
           - my-server:
              type: server
              signature_algorithm: ecdsa
              include_certificate_chain: true
              dns_name: my-server.org
              ip: 192.168.17.77
```

Client certificate without a ca.

```yaml
my-client:
    type: client
    signature_algorithm: 
        type: rsa
        key_length: 4048
    dns_name: my-client.org
    ip: 192.168.17.35
```

[serde]: (https://crates.io/crates/serde)