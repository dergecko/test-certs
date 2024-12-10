[![Pipeline](https://github.com/dergecko/test-certs/actions/workflows/rust.yml/badge.svg)](https://github.com/dergecko/test-certs/actions/workflows/rust.yml)

# test-certs
A simple tool to generate a root certificate authority (CA), intermediate, client, and server certificates for testing purposes.

This tool is not intended for production use. Instead use tools like [`step-ca`](https://smallstep.com/docs/step-ca/) or similar.


## Example

An example on how to create an intermediate ca with a server and a client certificate.

[Intermediate CA](./test-certs/tests/examples/intermediate_ca.yaml)