//! # OpenSSL Provider for Rustls
//!
//! A Rustls crypto provider that uses `OpenSSL` for crypto.
//!
//! ## Limitations
//!
//! - TLS 1.2: No ECDSA support.
//! - QUIC Protocol: Not supported.
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
// //! TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
// //! TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// //! TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Requires the `chacha` feature
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
//! use rustls_openssl::{custom_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
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

use openssl::rand::rand_bytes;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::{SignatureScheme, SupportedCipherSuite};

mod cipher_suites;
mod ecdh;
mod hash;
mod hmac;
mod signer;
mod tls12;
mod tls13;
mod verify;

/// Exporting default cipher suites for TLS 1.3
pub use cipher_suites::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};

/// Exporting default cipher suites for TLS 1.2
pub use cipher_suites::{
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

/// Exporting ChaCha suites for TLS 1.2 and TLS 1.3
#[cfg(feature = "chacha")]
pub use cipher_suites::{
    TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

/// Exporting default key exchange groups
pub use ecdh::{SECP256R1, SECP384R1};

/// Exporting X25519 key exchange group
#[cfg(feature = "x25519")]
pub use ecdh::X25519;

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
        kx_groups: ecdh::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Rng,
        key_provider: &signer::Provider,
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
/// use rustls_openssl::{custom_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
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
        _ => ecdh::ALL_KX_GROUPS.to_vec(),
    };

    CryptoProvider {
        cipher_suites,
        kx_groups: kx_group,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Rng,
        key_provider: &signer::Provider,
    }
}

/// List of supported cipher suites in a preference order.
/// The first element has highest priority when negotiating cipher suites.
/// ```ignore
/// // TLS 1.3 suites
/// TLS13_AES_256_GCM_SHA384
/// TLS13_AES_128_GCM_SHA256
/// TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// // TLS 1.2 suites
/// // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
/// // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
/// // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
/// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
/// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// ```
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3 suites
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 suites
    // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // #[cfg(feature = "chacha")]
    // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        // webpki_algs::ECDSA_P256_SHA256,
        // webpki_algs::ECDSA_P256_SHA384,
        // webpki_algs::ECDSA_P384_SHA256,
        // webpki_algs::ECDSA_P384_SHA384,
        verify::ED25519,
        verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        verify::RSA_PKCS1_2048_8192_SHA256,
        verify::RSA_PKCS1_2048_8192_SHA384,
        verify::RSA_PKCS1_2048_8192_SHA512,
        verify::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        // (
        //     SignatureScheme::ECDSA_NISTP384_SHA384,
        //     &[
        //         webpki_algs::ECDSA_P384_SHA384,
        //         webpki_algs::ECDSA_P256_SHA384,
        //     ],
        // ),
        // (
        //     SignatureScheme::ECDSA_NISTP256_SHA256,
        //     &[
        //         webpki_algs::ECDSA_P256_SHA256,
        //         webpki_algs::ECDSA_P384_SHA256,
        //     ],
        // ),
        (SignatureScheme::ED25519, &[verify::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[verify::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[verify::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[verify::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};
#[derive(Debug)]
struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        rand_bytes(buf).map_err(|_| GetRandomFailed)
    }
}
