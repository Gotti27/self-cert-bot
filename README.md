# Self Certification Bot

_A library to enable automatic certificate issuing and renewal for self-hosted architectures_

## Description


## JASC - Just a simple challenge
Domain ownership is proven by solving a simple challenge.


## Installation

### External dependencies:
- [OpenSSL](https://openssl-library.org/)
- [nlohmann_json](https://json.nlohmann.me/)

### Build

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
  "domain": "example.com",
  "outPath": "./data/generated",
  "port": 14024,
  "serverIp": "10.0.0.1",
  "serverPort": 8080,
  "C": "CN",
  "ST":  "ST",
  "O": "Organization",
  "OU": "Organization Unit"
}
```
Usage:
```bash
$ self-cert -m server -c ./settings/server.json
```

### Client
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
$ self-cert -m client --parallel
```
```bash
$ self-cert -m client -c ./settings/client.json
```
