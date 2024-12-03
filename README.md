# test-certs
A simple tool to generate a root certificate authority (CA), intermediate, client, and server certificates.

## Idea 1
 
The idea is instead of having a binary with a lot of arguments to configure certificates we utilize YAML.

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
    include_certificate_chain: true
    extended_key_usages:
        - ClientAuth

certificate: 
    name: server
    signed: intermediate
    include_certificate_chain: true
    extended_key_usages:
        - ServerAuth
```