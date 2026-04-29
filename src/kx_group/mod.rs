//! Key exchange groups using OpenSSL
use rustls::crypto::SupportedKxGroup;

mod ec;
pub use ec::{SECP256R1, SECP384R1};

mod x25519;
pub use x25519::X25519;

#[cfg(ossl300)]
mod kem;
#[cfg(ossl300)]
pub use kem::{MLKEM768, X25519MLKEM768};

/// Key exchanges enabled by default by this provider.
///
/// This compile-time list is filtered at runtime based on OpenSSL algorithm
/// availability.
/// Use [available_default_groups()] for runtime-available defaults.
///
/// Compile-time set:
/// * [X25519MLKEM768] (OpenSSL 3.5+)
/// * [X25519]
/// * [SECP384R1]
/// * [SECP256R1]
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(all(ossl300, feature = "prefer-post-quantum"))]
    X25519MLKEM768,
    X25519,
    SECP256R1,
    SECP384R1,
    #[cfg(all(ossl300, not(feature = "prefer-post-quantum")))]
    X25519MLKEM768,
];

/// All key exchanges supported by this provider.
///
/// This compile-time list is filtered at runtime based on OpenSSL algorithm
/// availability.
/// Use [available_groups()] for runtime-available groups.
///
/// Compile-time set:
/// * [X25519MLKEM768] (OpenSSL 3.5+)
/// * [X25519]
/// * [SECP384R1]
/// * [SECP256R1]
/// * [MLKEM768] (OpenSSL 3.5+)
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(all(ossl300, feature = "prefer-post-quantum"))]
    X25519MLKEM768,
    X25519,
    SECP256R1,
    SECP384R1,
    #[cfg(all(ossl300, not(feature = "prefer-post-quantum")))]
    X25519MLKEM768,
    #[cfg(ossl300)]
    MLKEM768,
];

/// Returns the algorithms from [DEFAULT_KX_GROUPS] that are available at runtime.
pub fn available_default_groups() -> Vec<&'static dyn SupportedKxGroup> {
    DEFAULT_KX_GROUPS
        .iter()
        .copied()
        .filter(|group| group.start().is_ok())
        .collect()
}

/// Returns the algorithms from [ALL_KX_GROUPS] that are available at runtime.
pub fn available_groups() -> Vec<&'static dyn SupportedKxGroup> {
    ALL_KX_GROUPS
        .iter()
        .copied()
        .filter(|group| group.start().is_ok())
        .collect()
}
