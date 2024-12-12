[![Pipeline](https://github.com/dergecko/test-certs/actions/workflows/rust.yml/badge.svg)](https://github.com/dergecko/test-certs/actions/workflows/rust.yml)

# test-certs
A simple tool to generate a root certificate authority (CA), intermediate, client, and server certificates for testing purposes.

> This tool is not intended for production use. Please use a dedicated certificate infrastructure!

## Motivation

You want to have an easy and fast way to test TLS or even mTLS connections with x509 certificates but your infrastructure lags the processes or ways to get them?
Or you have a testing environment that you deploy via ansible and want to create your on certificates to test TLS connections reliably?

This project could be the answer then!

Write your certificate chain configuration once and create all necessary certificates when ever you need new ones!

## Example

An example configuration file on how to create a root certificate that issues an intermediate ca which again issues a server and a client certificate.

[Intermediate CA](./test-certs/tests/examples/intermediate_ca.yaml)

## Other Tools

- [`step-ca`](https://smallstep.com/docs/step-ca/): A complete Public-Key-Infrastructure (PKI) that has a lot of features!
- openssl: The good old way to create any certificate you need.