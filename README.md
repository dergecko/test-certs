[![Pipeline](https://github.com/dergecko/test-certs/actions/workflows/rust.yml/badge.svg)](https://github.com/dergecko/test-certs/actions/workflows/rust.yml)

# test-certs
A simple tool to generate a root certificate authority (CA), intermediate, client, and server certificates for testing purposes.

> This tool is not intended for production use. Please use a dedicated certificate infrastructure!

## Motivation

You want to have an easy and fast way to test TLS or even mTLS connections with x509 certificates but your infrastructure lags the processes or ways to get them?
Or you have a testing environment that you deploy via ansible and want to create your on certificates to test TLS connections reliably?

This project could be the answer then!

Write your certificate chain configuration once and create all necessary certificates when ever you need new ones!

## Usage

For detailed information about the CLI run `test-certs --help`.

It is possible to specific the input file via the command line.
The input file can either be parsed as YAML or JSON 

`test-certs --input ./cert.yaml --out-dir ./certs yaml`

You can also pipe in a configuration via stdin:

`echo "my-client:\n type: client\n ip: 127.0.0.1\n dns_name: my-client.com" | test-certs`

This enables you to use heredoc to generate certificates:

```bash
cat << EOF | test-certs
my-client:
  type: client
  ip: 127.0.0.1
  dns_name: my-client.org
EOF
```



## Example Configuration

An example configuration file on how to create a root certificate that issues an intermediate ca which again issues a server and a client certificate.

[Intermediate CA](./test-certs/tests/examples/intermediate_ca.yaml)

## Other Tools

- [`step-ca`](https://smallstep.com/docs/step-ca/): A complete Public-Key-Infrastructure (PKI) that has a lot of features!
- openssl: The good old way to create any certificate you need.