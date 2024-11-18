# rustls-openssl
A [rustls Crypto Provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) that uses OpenSSL for cryptographic operations.

## Status
**Early in development.**

## Usage
The main entry points are the `rustls_openssl::default_provider` and `rustls_openssl::custom_provider` functions.
See the [rustls documentation]((https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)) for how to use them.

## Supported Ciphers

Supported cipher suites are listed below, in descending order of preference.
If OpenSSL is compiled with the `OPENSSL_NO_CHACHA` option, the ChaCha20-Poly1305 ciphers will not be available.

### TLS 1.3

The following cipher suites are supported for TLS 1.3. These support QUIC.

```
TLS13_AES_256_GCM_SHA384
TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256
```

### TLS 1.2
*Requires the `tls12` feature, which is a default feature.*

```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```
## Supported Key Exchanges

Key exchanges, in descending order ofpreference:

```
SECP384R1
SECP256R1
X25519 // Requires the `x25519` feature
```

