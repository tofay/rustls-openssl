//! Key exchange groups using OpenSSL
use rustls::crypto::SupportedKxGroup;

mod ec;
pub use ec::{SECP256R1, SECP384R1};

#[cfg(not(feature = "fips"))]
mod x25519;
#[cfg(not(feature = "fips"))]
pub use x25519::X25519;

#[cfg(ossl350)]
mod kem;
#[cfg(ossl350)]
pub use kem::{MLKEM768, X25519MLKEM768};

/// Key exchanges enabled by default by this provider:
/// * [X25519MLKEM768] (OpenSSL 3.5+)
/// * [X25519] (if fips feature not enabled)
/// * [SECP384R1]
/// * [SECP256R1]
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(all(ossl350, feature = "prefer-post-quantum"))]
    X25519MLKEM768,
    #[cfg(not(feature = "fips"))]
    X25519,
    SECP256R1,
    SECP384R1,
    #[cfg(all(ossl350, not(feature = "prefer-post-quantum")))]
    X25519MLKEM768,
];

/// All key exchanges supported by this provider:
/// * [X25519MLKEM768] (OpenSSL 3.5+)
/// * [X25519] (if fips feature not enabled)
/// * [SECP384R1]
/// * [SECP256R1]
/// * [MLKEM768] (OpenSSL 3.5+)
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(all(ossl350, feature = "prefer-post-quantum"))]
    X25519MLKEM768,
    #[cfg(not(feature = "fips"))]
    X25519,
    SECP256R1,
    SECP384R1,
    #[cfg(all(ossl350, not(feature = "prefer-post-quantum")))]
    X25519MLKEM768,
    #[cfg(ossl350)]
    MLKEM768,
];
