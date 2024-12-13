//! Supported key exchange groups.
use rustls::crypto::SupportedKxGroup;

mod ec;
#[cfg(ossl300)]
mod kem;
#[cfg(not(feature = "fips"))]
mod x25519;

pub use ec::{SECP256R1, SECP384R1};
#[cfg(ossl300)]
pub use kem::KxGroup as KemKxGroup;
#[cfg(not(feature = "fips"))]
pub use x25519::X25519;

/// [Supported KeyExchange groups](SupportedKxGroup).
/// * [X25519]
/// * [SECP384R1]
/// * [SECP256R1]
///
/// If the `fips` feature is enabled, only [SECP384R1] and [SECP256R1] are available.
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(not(feature = "fips"))]
    X25519,
    SECP256R1,
    SECP384R1,
];
