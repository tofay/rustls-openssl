//! # OpenSSL Provider for Rustls
//!
//! A Rustls crypto provider that uses `OpenSSL` for crypto.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, ordered by preference. IE: The default configuration prioritizes `TLS13_AES_256_GCM_SHA384` over `TLS13_AES_128_GCM_SHA256`.
//!
//! ### TLS 1.3
//!
//! ```ignore
//! TLS13_AES_256_GCM_SHA384
//! TLS13_AES_128_GCM_SHA256
//! TLS13_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
//! ```
//!
//! ### TLS 1.2
//!
//! ```ignore
//! TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
//! TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
//! ```
//! ## Supported Key Exchanges
//!
//! Key exchanges are listed below, ordered by preference. IE: `SECP384R1` is preferred over `SECP256R1`.
//!
//! ```ignore
//! SECP384R1
//! SECP256R1
//! X25519 // Requires the `x25519` feature
//! ```
//!
//! ## Usage
//!
//! Add `rustls-openssl` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rustls = { version = "0.23.0", features = ["tls12", "std"], default-features = false }
//! rustls_openssl = "0.1.0"
//! ```
//!
//! ### Default Configuration
//!
//! Use `default_provider()` for a `ClientConfig` that utilizes the default cipher suites and key exchange groups listed above:
//!
//! ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_openssl::default_provider;
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! let mut root_store = RootCertStore {
//!     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//! };
//!
//! let mut config =
//!     ClientConfig::builder_with_provider(Arc::new(default_provider()))
//!         .with_safe_default_protocol_versions()
//!         .unwrap()
//!         .with_root_certificates(root_store)
//!         .with_no_client_auth();
//! ```
//!
//! ### Custom Configuration
//!
//! To modify or change the order of negotiated cipher suites for `ClientConfig`, use `custom_provider()`.
//!
//! ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_openssl::custom_provider;
//! use rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256;
//! use rustls_openssl::kx_group::SECP256R1;
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! let mut root_store = RootCertStore {
//!     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//! };
//!  
//! // Set custom config of cipher suites that have been imported from rustls_openssl.
//! let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
//! let kx_group = vec![SECP256R1];
//!
//! let mut config =
//!     ClientConfig::builder_with_provider(Arc::new(custom_provider(
//!         Some(cipher_suites), Some(kx_group))))
//!             .with_safe_default_protocol_versions()
//!             .unwrap()
//!             .with_root_certificates(root_store)
//!             .with_no_client_auth();
//! ```
//!
//! # Features
//! The following non-default features are available:
//! - `chacha`: Enables ChaCha20-Poly1305 cipher suites for TLS 1.2 and TLS 1.3.
//! - `x25519`: Enables X25519 key exchange group.

// Mimic rustls code no_std usage.
#![no_std]
extern crate alloc;
extern crate std;

use alloc::vec::Vec;
use openssl::rand::rand_bytes;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup};
use rustls::SupportedCipherSuite;

pub(crate) mod aead;
pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
pub mod quic;
mod signer;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;
mod verify;

pub mod cipher_suite {
    //! All supported cipher suites.
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    };
    #[cfg(all(feature = "tls12", feature = "chacha"))]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    #[cfg(feature = "chacha")]
    pub use super::tls13::TLS13_CHACHA20_POLY1305_SHA256;
    pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
}

pub use kx::ALL_KX_GROUPS;

/// All supported key exchange groups are exported via the `kx_group` module.
pub mod kx_group {
    #[cfg(feature = "x25519")]
    pub use super::kx::X25519;
    pub use super::kx::{SECP256R1, SECP384R1};
}

pub use verify::SUPPORTED_SIG_ALGS;

/// `default_provider` returns a `CryptoProvider` using default and cipher suites.
/// For cipher suites see[`DEFAULT_CIPHER_SUITES`].
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_openssl::default_provider;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(default_provider()))
///        .with_safe_default_protocol_versions()
///         .unwrap()
///         .with_root_certificates(root_store)
///         .with_no_client_auth();
///
/// ```
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

/// Create a `CryptoProvider` with specific cipher suites and key exchange groups during setup.
///
/// `provided_cipher_suites` takes in an optional `Vec<>` of `SupportedCipherSuites`
/// The supplied arguments for `provided_cipher_suite` will be used when when negotiating the TLS cipher suite;
/// and should be placed in preference order, where the first element has highest priority.
/// If `None` or an empty `Vec<>` is provided the [`DEFAULT_CIPHER_SUITES`] will be used instead.
///
/// `provided_kx_group` takes in an optional `Vec<>` of `SupportedKxGroup`
/// The supplied arguments for `provided_kx_group` will be used when when negotiating the TLS key exchange;
/// and should be placed in preference order, where the first element has highest priority.
/// If `None` or an empty `Vec<>` is provided the default will be used instead.
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_openssl::custom_provider;
/// use rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256;
/// use rustls_openssl::kx_group::SECP256R1;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///  
/// // Set custom config of cipher suites that have been imported from rustls_openssl.
/// let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
/// let kx_group = vec![SECP256R1];
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(custom_provider(
///         Some(cipher_suites), Some(kx_group))))
///             .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///
///
/// ```
pub fn custom_provider(
    provided_cipher_suites: Option<Vec<SupportedCipherSuite>>,
    provided_kx_group: Option<Vec<&'static dyn SupportedKxGroup>>,
) -> CryptoProvider {
    let cipher_suites = match provided_cipher_suites {
        Some(suites) if !suites.is_empty() => suites,
        _ => DEFAULT_CIPHER_SUITES.to_vec(),
    };

    let kx_group = match provided_kx_group {
        Some(groups) if !groups.is_empty() => groups,
        _ => ALL_KX_GROUPS.to_vec(),
    };

    CryptoProvider {
        cipher_suites,
        kx_groups: kx_group,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

/// List of supported cipher suites in a preference order.
/// The first element has highest priority when negotiating cipher suites.
/// ```ignore
/// // TLS 1.3 suites
/// TLS13_AES_256_GCM_SHA384
/// TLS13_AES_128_GCM_SHA256
/// TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// // TLS 1.2 suites, enabled with the `tls12` feature
/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
/// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
/// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
/// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// ```
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", feature = "chacha"))]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", feature = "chacha"))]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Rustls Openssl crypto provider.
/// Implements `SecureRandom` and `KeyProvider` traits.
#[derive(Debug)]
pub struct Provider;

impl SecureRandom for Provider {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        rand_bytes(buf).map_err(|_| GetRandomFailed)
    }
}
