# Self Certification Bot

_A library to enable automatic certificate issuance and renewal for self-hosted architectures_

## Introduction

The Self certification bot is a reimplementation of the popular certification bot core feature,
designed to be minimal and to be deployed into self-hosted architectures.
The project is structured to be built as a library, enabling seamless integration with other projects, 
with an additional main for building it as a binary.
Further details on the project will soon be available in my blog.

_*Disclaimer*: the project does not feature rate limiting or other types of security measures yet.
It is meant to make HTTPS easier to use in closed-network setups where Certbot is not reachable.

## JASC - Just A Simple Challenge
Domain ownership is proven by solving a simple challenge.
It works as follows:
1. The claimant connects to the server and communicates the requested domain, its public key and certificate fields.
2. The server generates a secret and sends it to the claimant.
3. The server resolves the requested domain using the DNS and opens a connection, 
expecting to receive the challenge back.
4. - If the secret matches the challenge is considered solved, and the certificate is signed and issued. 
   - Otherwise, the challenge fails and the connection eventually closed.

## Installation
The project will soon be packaged for common Linux distributions.
Until then, it requires manual compilation and installation.
Moreover, a Docker image for both the server and the client side is scheduled to be developed.

### External dependencies:
- [OpenSSL](https://openssl-library.org/)
- [nlohmann_json](https://json.nlohmann.me/)
- [Boost](https://www.boost.org)

In the near future I'm considering managing dependencies using [Conan](https://conan.io),
till then, they must be included either using your distro's package manager or by building them locally.

### Build
The build process is handled with cmake, hence it can be built as follows:

```bash
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## Usage

### Server
Configuration:
```json
{
  "port": 8080,
  "ca_cert_path": "./data/yourCA.pem",
  "ca_key_path": "./data/yourCA.key",
  "ca_passkey_path": "./data/passkey.txt"
}
```
Usage:
```bash
$ self-cert -m server -c ./settings/server.json
```

### Client
The client supports both an interactive mode and a configuration-based mode,  
the latter being useful for enforcing automatic renewal.

Configuration:
```json
{
  "domain": "example.com",
  "out_path": "./data/generated",
  "port": 14024,
  "server_ip": "10.0.0.1",
  "server_port": 8080,
  "C": "CN",
  "ST": "ST",
  "O": "Organization",
  "OU": "Organization Unit"
}
```
Usage:
```bash
$ self-cert -m client --interactive
```
```bash
$ self-cert -m client -c ./settings/client.json
```
