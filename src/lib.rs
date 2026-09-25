//! # rustls-openssl
//!
//! A [rustls crypto provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)  that uses OpenSSL for crypto.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, in descending order of preference.
//!
//! The default provider includes all of these cipher suites, filtered by whether the encryption
//! algorithm is actually available:
//!
//! - **OpenSSL 3.0+:** availability is checked at runtime, via the provider API (`EVP_CIPHER_fetch`),
//!   against whatever providers are loaded in the OpenSSL library the binary is running against. This
//!   is re-checked each time the provider is created, so the same compiled binary can offer different
//!   cipher suites depending on the runtime OpenSSL configuration.
//! - **Earlier than OpenSSL 3.0:** availability is fixed at compile time, based on the OpenSSL being compiled against.
//!
//! If the `tls12` feature is disabled, then the TLS 1.2 cipher suites will not be available.
//! [ALL_CIPHER_SUITES] lists all supported cipher suites.
//! Use [available_cipher_suites()] to get the set of cipher suites available at runtime.
//!
//! ### TLS 1.3
//!
//! * TLS13_AES_256_GCM_SHA384
//! * TLS13_AES_128_GCM_SHA256
//! * TLS13_CHACHA20_POLY1305_SHA256
//!
//! ### TLS 1.2
//!
//! * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! * TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
//! * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! * TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
//!
//! ## Supported Key Exchanges
//!
//! In descending order of preference:
//!
//! * X25519MLKEM768
//! * SECP384R1
//! * SECP256R1
//! * X25519
//! * SECP521R1
//! * MLKEM768
//! * MLKEM1024
//!
//! If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will be the first group offered, otherwise it will be the last.
//! MLKEM768, MLKEM1024 and SECP521R1 are not offered by default, but can be used by specifying them in the `custom_provider()` function.
//!
//! The default provider also filters based on runtime availability of the algorithms.
//! Use [kx_group::available_default_groups()] to get the runtime-available set of default key exchange groups,
//! and [kx_group::available_groups()] for the runtime-available set of all key exchange groups.
//!
//! ## Usage
//!
//! Add `rustls-openssl` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rustls = { version = "0.23", features = ["tls12", "std"], default-features = false }
//! rustls_openssl = "0.4"
//! ```
//!
//! ### Configuration
//!
//! Use [default_provider()] to create a provider using cipher suites and key exchange groups listed above.
//! Use [custom_provider()] to specify custom cipher suites and key exchange groups.
//!
//! # Features
//! - `tls12`: Enables TLS 1.2 cipher suites. Enabled by default.
//! - `prefer-post-quantum`: Enables X25519MLKEM768 as the first key exchange group. Enabled by default.
//! - `vendored`: Enables vendored OpenSSL. Disabled by default.
//! - `fips`: No longer used. See [fips] for FIPS support.
//!
//! # OpenSSL API Usage
//!
//! When targeting OpenSSL 3.0 or later, this crate strictly uses modern, provider APIs (`EVP_*`).
//! Legacy cryptographic interfaces (e.g., direct `HMAC_*` or `RSA_*` functions) are used only when
//! targeting OpenSSL 1.1.1.
#![warn(missing_docs)]
use openssl::rand::rand_priv_bytes;
use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};

mod aead;
mod cipher;
mod hash;
mod hkdf;
mod hmac;
pub mod kx_group;
mod openssl_internal;
#[cfg(feature = "tls12")]
mod prf;
mod quic;
mod signer;
mod spki;
#[cfg(test)]
mod test_support;
#[cfg(feature = "tls12")]
mod tls12;
mod tls13;
mod verify;

pub mod cipher_suite {
    //! Supported cipher suites.
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    };
    #[cfg(all(feature = "tls12", chacha))]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::TLS13_CHACHA20_POLY1305_SHA256;
    pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
}

pub use signer::KeyProvider;
pub use verify::SUPPORTED_SIG_ALGS;

/// Returns an OpenSSL-based [CryptoProvider] using default available cipher suites ([available_cipher_suites()]) and key exchange groups ([kx_group::available_default_groups()]).
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
        cipher_suites: available_cipher_suites(),
        kx_groups: kx_group::available_default_groups(),
        signature_verification_algorithms: *verify::available_supported_sig_algs(),
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

/// Returns the cipher suites from [ALL_CIPHER_SUITES] that are available at runtime.
pub fn available_cipher_suites() -> Vec<SupportedCipherSuite> {
    ALL_CIPHER_SUITES
        .iter()
        .copied()
        .filter(cipher_suite_available)
        .collect()
}

fn cipher_suite_available(cipher_suite: &SupportedCipherSuite) -> bool {
    match cipher_suite.suite() {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            aead::Algorithm::Aes128Gcm.is_available()
        }
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
        | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            aead::Algorithm::Aes256Gcm.is_available()
        }
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            aead::Algorithm::ChaCha20Poly1305.is_available()
        }
        _ => true,
    }
}

/// Create a [CryptoProvider] with specific cipher suites and key exchange groups
///
/// The specified cipher suites and key exchange groups should be defined in descending order of preference.
/// i.e the first elements have the highest priority during negotiation.
///
/// No runtime filtering is performed on the provided cipher suites and key exchange groups,
/// so the caller is responsible for ensuring that the provided algorithms are available at runtime,
/// by calling [available_cipher_suites()] and [kx_group::available_groups()].
///
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
///         cipher_suites, kx_group)))
///             .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///
///
/// ```
pub fn custom_provider(
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites,
        kx_groups,
        signature_verification_algorithms: *verify::available_supported_sig_algs(),
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

/// All supported cipher suites in descending order of preference:
/// * TLS13_AES_256_GCM_SHA384
/// * TLS13_AES_128_GCM_SHA256
/// * TLS13_CHACHA20_POLY1305_SHA256
/// * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
/// * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
/// * TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
/// * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
/// * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
/// * TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
///
/// ChaCha20-Poly1305 suites are runtime-filtered by [available_cipher_suites()].
/// If the default `tls12` feature is disabled then the TLS 1.2 cipher suites will not be included.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A struct that implements [rustls::crypto::SecureRandom].
#[derive(Debug)]
pub struct SecureRandom;

impl rustls::crypto::SecureRandom for SecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        rand_priv_bytes(buf).map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips::enabled()
    }
}

pub mod fips {
    //! # FIPS support
    //!
    //! To use rustls with OpenSSL in FIPS mode, perform the following actions.
    //!
    //! ## 1. Specify `require_ems` when constructing [rustls::ClientConfig] or [rustls::ServerConfig]
    //!
    //! See [rustls documentation](https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.require_ems) for rationale.
    //!
    //! ## 2. Enable FIPS mode for OpenSSL
    //!
    //! See [enable()].
    //!
    //! ## 3. Validate the FIPS status of your ClientConfig or ServerConfig at runtime
    //! See [rustls documenation on FIPS](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html#3-validate-the-fips-status-of-your-clientconfigserverconfig-at-run-time).

    /// Returns `true` if OpenSSL is running in FIPS mode.
    #[cfg(fips_module)]
    pub(crate) fn enabled() -> bool {
        openssl::fips::enabled()
    }
    #[cfg(not(fips_module))]
    pub(crate) fn enabled() -> bool {
        unsafe { openssl_sys::EVP_default_properties_is_fips_enabled(std::ptr::null_mut()) == 1 }
    }

    /// Enable FIPS mode for OpenSSL.
    ///
    /// This should be called on application startup before the provider is used.
    ///
    /// On OpenSSL 1.1.1 this calls [FIPS_mode_set](https://wiki.openssl.org/index.php/FIPS_mode_set()).
    /// On OpenSSL 3 this loads a FIPS provider, which must be available.
    ///
    /// Panics if FIPS cannot be enabled
    #[cfg(fips_module)]
    pub fn enable() {
        openssl::fips::enable(true).expect("Failed to enable FIPS mode.");
    }

    /// Enable FIPS mode for OpenSSL.
    ///
    /// This function is a convenience helper to programmatically enforce FIPS mode
    /// on OpenSSL 3.x. Calling this is optional if OpenSSL is already configured
    /// for FIPS externally (e.g., via `openssl.cnf`, system environment variables,
    /// or system-wide cryptographic policies).
    ///
    /// On OpenSSL 3.x, this loads the `fips`, and `base` providers, and sets default
    /// properties to strictly require `fips=yes`.
    /// On OpenSSL 1.1.1 this calls [FIPS_mode_set](https://wiki.openssl.org/index.php/FIPS_mode_set()).
    ///
    /// Panics if FIPS cannot be enabled
    #[cfg(not(fips_module))]
    pub fn enable() {
        // Use OnceCell to ensure that the provider is only loaded once
        use once_cell::sync::OnceCell;

        use crate::openssl_internal;
        static LOADED: OnceCell<bool> = OnceCell::new();
        LOADED.get_or_init(|| {
            openssl::provider::Provider::load(None, "fips").expect("Failed to load FIPS provider.");
            openssl::provider::Provider::load(None, "base").expect("Failed to load Base provider.");
            openssl_internal::set_default_properties("fips=yes")
                .expect("Failed to set 'fips=yes'.");
            true
        });
    }
}

#[cfg(test)]
mod tests {
    /// ChaCha20-Poly1305 is not FIPS-approved at any provider version, so it must report
    /// `false` regardless of OpenSSL's state.
    ///
    /// Note this holds without OpenSSL being in FIPS mode; the FIPS-mode behaviour of the
    /// suites is covered by `provider_is_fips` in tests/it.rs, which runs under the `fips`
    /// feature.
    #[test]
    fn chacha_is_never_fips_approved() {
        assert!(!crate::aead::Algorithm::ChaCha20Poly1305.fips());
    }

    /// AES-GCM must still track OpenSSL, so the check above cannot be satisfied by
    /// reporting `false` everywhere.
    #[test]
    fn aes_gcm_tracks_openssl_fips_state() {
        let expected = super::fips::enabled();
        assert_eq!(crate::aead::Algorithm::Aes128Gcm.fips(), expected);
        assert_eq!(crate::aead::Algorithm::Aes256Gcm.fips(), expected);
    }

    /// Each AEAD `fips()` impl, called directly.
    ///
    /// Not reachable through `SupportedCipherSuite::fips()` outside FIPS mode: rustls
    /// aggregates with `&&` -- `Tls13CipherSuite::fips()` is
    /// `common && hkdf && aead_alg && quic` -- and `common.fips()` is
    /// `crate::fips::enabled()`, so the chain short-circuits on the first term and never
    /// evaluates these. Without a direct call the reporting this crate exists to fix has
    /// no coverage in the default configuration.
    #[test]
    fn aead_trait_impls_report_fips_directly() {
        // `Tls12AeadAlgorithm` is implemented in `mod tls12`, which is behind the `tls12`
        // feature, so the TLS 1.2 half of this test has to be gated the same way.
        #[cfg(feature = "tls12")]
        use rustls::crypto::cipher::Tls12AeadAlgorithm;
        use rustls::crypto::cipher::Tls13AeadAlgorithm;

        let fips = super::fips::enabled();
        for alg in [
            crate::aead::Algorithm::Aes128Gcm,
            crate::aead::Algorithm::Aes256Gcm,
        ] {
            #[cfg(feature = "tls12")]
            assert_eq!(Tls12AeadAlgorithm::fips(&alg), fips, "tls12 {alg:?}");
            assert_eq!(Tls13AeadAlgorithm::fips(&alg), fips, "tls13 {alg:?}");
        }

        let chacha = crate::aead::Algorithm::ChaCha20Poly1305;
        #[cfg(feature = "tls12")]
        assert!(!Tls12AeadAlgorithm::fips(&chacha));
        assert!(!Tls13AeadAlgorithm::fips(&chacha));
    }

    /// Every suite's `fips()` must agree with the one rule: approved exactly when OpenSSL
    /// is in FIPS mode and the suite is not ChaCha20-Poly1305.
    ///
    /// This is the user-visible invariant, and it holds in both states. It does not on its
    /// own cover the constituent impls -- see above.
    #[test]
    fn every_suite_reports_fips_consistently() {
        let fips = super::fips::enabled();
        for suite in super::ALL_CIPHER_SUITES {
            let name = format!("{:?}", suite.suite());
            let expected = fips && !name.contains("CHACHA20");
            assert_eq!(
                suite.fips(),
                expected,
                "{name}: fips() should be {expected} (OpenSSL FIPS mode: {fips})"
            );
        }
    }

    #[cfg(feature = "fips")]
    use ctor::ctor;

    // Allows running tests with FIPS enabled.
    #[cfg(feature = "fips")]
    #[ctor(unsafe)]
    fn global_fips_setup() {
        use crate::fips;
        fips::enable();
    }
}
