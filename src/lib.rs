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
//! When targeting OpenSSL 3.0 or later this crate uses OpenSSL's provider APIs (`EVP_*`).
//! Legacy cryptographic interfaces (e.g., direct `HMAC_*` or `RSA_*` functions) are used only when
//! targeting OpenSSL 1.1.1.
#![warn(missing_docs)]

// So that `src/test_support.rs` can name this crate the same way whether it is compiled as
// part of it or as part of `tests/it.rs`, which includes it with `#[path]`. It forces that
// file through the public API, which is what makes it usable from both.
extern crate self as rustls_openssl;

#[cfg(not(ossl300))]
use openssl::rand::rand_priv_bytes;
use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};

mod aead;
mod cipher;
pub mod fips;
mod hash;
mod hkdf;
mod hmac;
pub mod kx_group;
#[cfg(ossl300)]
mod lib_ctx;
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

// The library context and its accessors, re-exported so that this crate's name for them is
// the same as the `rustls_openssl::…` path the test support module uses.
#[cfg(ossl300)]
#[doc(hidden)]
pub use lib_ctx::get_global_lib_ctx;
#[cfg(ossl300)]
pub(crate) use lib_ctx::primed_lib_ctx;
#[cfg(ossl300)]
pub use lib_ctx::{LibCtx, LibCtxError, LibCtxRef, set_global_lib_ctx};

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
/// No runtime filtering is performed on the provided cipher suites and key exchange groups
/// so the caller is responsible for ensuring that the provided algorithms are available at runtime.
/// This can be done by using [available_cipher_suites()] and [kx_group::available_groups()].
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
    #[cfg(ossl300)]
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::openssl_internal::rand::priv_bytes(get_global_lib_ctx(), buf)
            .map_err(|_| GetRandomFailed)
    }

    #[cfg(not(ossl300))]
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        rand_priv_bytes(buf).map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips::enabled()
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

    #[cfg(all(feature = "ossl-context", ossl300))]
    #[test]
    fn secure_random_fills_from_the_global_lib_ctx() {
        use rustls::crypto::SecureRandom as _;

        assert!(
            crate::get_global_lib_ctx().is_some(),
            "the `ossl-context` feature is on but no global context was set, so this test \
             proved nothing"
        );

        // The premise: the default context is restricted to a provider that does not exist, so
        // a random source that ignored the context and used the default one would fail here.
        // Without this the "not all zeros" assert below would pass either way.
        let mut from_default = [0u8; 32];
        assert!(
            openssl::rand::rand_priv_bytes(&mut from_default).is_err(),
            "the default library context is not canaried, so this test cannot tell the two \
             apart"
        );

        let mut buf = [0u8; 32];
        crate::SecureRandom
            .fill(&mut buf)
            .expect("failed to get random bytes from the global library context");
        assert!(buf.iter().any(|byte| *byte != 0), "all-zero random bytes");
    }

    /// The rest of this module's context-sensitive tests only mean anything if the constructor
    /// ran and the canary is really in place.
    #[cfg(all(feature = "ossl-context", ossl300))]
    #[test]
    fn the_global_lib_ctx_canary_is_in_place() {
        assert!(
            crate::get_global_lib_ctx().is_some(),
            "the `ossl-context` feature is on but no global library context was set"
        );
        assert!(
            openssl::cipher::Cipher::fetch(None, "AES-128-GCM", None).is_err(),
            "the default library context can still fetch a cipher, so it is not canaried and \
             the context-sensitive tests here prove nothing"
        );
    }

    // Allows running tests with FIPS enabled, and against a custom library context.
    #[cfg(any(feature = "fips", feature = "ossl-context"))]
    use ctor::ctor;

    /// Puts the test suite in the same position as an application that has configured its
    /// own library context, and enables FIPS mode if it was asked for.
    ///
    /// `tests/it.rs` has the same constructor, for the same reason: the canary is only worth
    /// something if the code that would violate it is exercised in the same process.
    #[cfg(any(feature = "fips", feature = "ossl-context"))]
    #[ctor(unsafe)]
    fn global_lib_ctx_setup() {
        #[cfg(all(feature = "ossl-context", ossl300))]
        crate::set_global_lib_ctx(crate::test_support::global_lib_ctx())
            .expect("the global library context has already been set");

        #[cfg(feature = "fips")]
        crate::fips::enable();
    }
}
