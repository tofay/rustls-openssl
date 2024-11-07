# rustls-openssl
An experimental [rustls Crypto Provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) that uses OpenSSL for cryptographic operations.

## Usage
The main entry points are the `rustls_openssl::default_provider` and `rustls_openssl::custom_provider` functions.
See the [rustls documentation]((https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)) for how to use them.
