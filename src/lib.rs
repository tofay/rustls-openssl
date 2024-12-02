//! # rustls-openssl
//!
//! A [rustls crypto provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)  that uses OpenSSL for crypto.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, in descending order of preference.
//!
//! If OpenSSL is compiled with the `OPENSSL_NO_CHACHA` option, or the `fips` feature is enabled,
//! then the suites using ChaCha20-Poly1305 will not be available.
//! If the `tls12` feature is disabled then the TLS 1.2 cipher suites will not be available.
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
//! * SECP384R1
//! * SECP256R1
//! * X25519
//!
//! If the `fips` feature is enabled then X25519 will not be available.
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
//! ### Configuration
//!
//! Use [default_provider()] to create a provider using cipher suites and key exchange groups listed above.
//! Use [custom_provider()] to specify custom cipher suites and key exchange groups.
//!
//! # Features
//! - `tls12`: Enables TLS 1.2 cipher suites. Enabled by default.
//! - `fips`: Enabling this feature removes non-FIPS-approved cipher suites and key exchanges. Disabled by default. See [fips].
#![warn(missing_docs)]
use openssl::error::ErrorStack;
use openssl::rand::rand_priv_bytes;
use openssl_sys::c_int;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};
use rustls::SupportedCipherSuite;

use rustls::Error;
use windows::{
    core::{Interface, PCWSTR},
    Storage::Streams::IBuffer,
    Win32::System::WinRT::IBufferByteAccess,
};

mod aead;
mod hash;
mod hkdf;
mod hmac;
mod kx;

fn to_null_terminated_le_bytes(str: PCWSTR) -> Vec<u8> {
    unsafe {
        str.as_wide()
            .iter()
            .copied()
            .chain(Some(0))
            .map(u16::to_le_bytes)
            .flatten()
            .collect()
    }
}

#[cfg(feature = "tls12")]
mod prf;
mod quic;
mod signer;
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
    #[cfg(all(feature = "tls12", chacha, not(feature = "fips")))]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
}

pub use kx::ALL_KX_GROUPS;

pub mod kx_group {
    //! Supported key exchange groups.
    #[cfg(not(feature = "fips"))]
    pub use super::kx::X25519;
    pub use super::kx::{SECP256R1, SECP384R1};
}
pub use signer::KeyProvider;
pub use verify::SUPPORTED_SIG_ALGS;

/// Returns an OpenSSL-based [CryptoProvider] using all available cipher suites ([ALL_CIPHER_SUITES]) and key exchange groups ([ALL_KX_GROUPS]).
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
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

/// Create a [CryptoProvider] with specific cipher suites and key exchange groups
///
/// The specified cipher suites and key exchange groups should be defined in descending order of preference.
/// i.e the first elements have the highest priority during negotiation.
///
/// If the `fips` feature is enabled then fips mode will be enabled for OpenSSL, and this function will panic if this fails.
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
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
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
/// If the non-default `fips` feature is enabled, or OpenSSL is compiled with the `OPENSSL_NO_CHACHA` option, then the ChaCha20-Poly1305 cipher suites will not be included.
/// If the default `tls12` feature is disabled then the TLS 1.2 cipher suites will not be included.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", chacha, not(feature = "fips")))]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", chacha, not(feature = "fips")))]
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

pub(crate) fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub mod fips {
    //! # FIPS support
    //!
    //! To use rustls with OpenSSL in FIPS mode, perform the following actions.
    //!
    //! ## 1. Enable the `fips` feature
    //!
    //! This removes non-FIPS-approved cipher suites and key exchanges.
    //!
    //! ## 2. Specify `require_ems` when constructing [rustls::ClientConfig] or [rustls::ServerConfig]
    //!
    //! See [rustls documentation](https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.require_ems) for rationale.
    //!
    //! ## 3. Enable FIPS mode for OpenSSL
    //!
    //! See [enable()].
    //!
    //! ## 4. Validate the FIPS status of your ClientConfig or ServerConfig at runtime
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
    /// This should be called on application startup before the provider is used.
    ///
    /// On OpenSSL 1.1.1 this calls [FIPS_mode_set](https://wiki.openssl.org/index.php/FIPS_mode_set()).
    /// On OpenSSL 3 this loads a FIPS provider, which must be available.
    ///
    /// Panics if FIPS cannot be enabled
    #[cfg(not(fips_module))]
    pub fn enable() {
        // Use OnceCell to ensure that the provider is only loaded once
        use once_cell::sync::OnceCell;
        static PROVIDER: OnceCell<openssl::provider::Provider> = OnceCell::new();
        PROVIDER.get_or_init(|| {
            let provider = openssl::provider::Provider::load(None, "fips")
                .expect("Failed to load FIPS provider.");
            unsafe {
                crate::cvt(openssl_sys::EVP_default_properties_enable_fips(
                    std::ptr::null_mut(),
                    1,
                ))
                .expect("Failed to enable FIPS properties.");
            }
            provider
        });
    }
}

unsafe fn as_mut_bytes(buffer: &IBuffer) -> Result<&mut [u8], Error> {
    buffer
        .cast::<IBufferByteAccess>()
        .and_then(|byte_acess| {
            let data = byte_acess.Buffer()?;
            Ok(std::slice::from_raw_parts_mut(
                data,
                buffer.Length()? as usize,
            ))
        })
        .map_err(|e| Error::General(e.to_string()))
}

unsafe fn as_bytes(buffer: &IBuffer) -> Result<&[u8], Error> {
    buffer
        .cast::<IBufferByteAccess>()
        .and_then(|byte_acess| {
            let data = byte_acess.Buffer()?;
            Ok(std::slice::from_raw_parts(data, buffer.Length()? as usize))
        })
        .map_err(|e| Error::General(e.to_string()))
}
