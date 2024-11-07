# rustls-openssl
An experimental [rustls Crypto Provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) that uses OpenSSL for cryptographic operations.

## Usage
The main entry points are the `rustls_openssl::default_provider` and `rustls_openssl::custom_provider` functions.
See the [rustls documentation]((https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)) for how to use them.

## Supported Ciphers

Supported cipher suites are listed below, in descending order of preference.

### TLS 1.3

```
TLS13_AES_256_GCM_SHA384
TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
```

### TLS 1.2

```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
```
## Supported Key Exchanges

Key exchanges, in descending order ofpreference:

```
SECP384R1
SECP256R1
X25519 // Requires the `x25519` feature
```

## Signature verification algorithms

ECDSA signature verification is done using the webpki ring implementation. ED25119 and RSA signature verification is done using openssl.
