use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use windows::core::{Owned, Param, PCWSTR};
use windows::Win32::Security::Cryptography::{
    BCryptDeriveKey, BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair,
    BCryptImportKeyPair, BCryptOpenAlgorithmProvider, BCryptSecretAgreement, BCryptSetProperty,
    BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECC_CURVE_25519,
    BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_NISTP256, BCRYPT_ECC_CURVE_NISTP384,
    BCRYPT_ECDH_ALGORITHM, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_HANDLE, BCRYPT_KDF_RAW_SECRET,
    BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
};

use crate::to_null_terminated_le_bytes;

/// The maximum size of the shared secret produced by a supported key exchange group.
const MAX_SECRET_SIZE: usize = 48;

/// [Supported KeyExchange groups](SupportedKxGroup).
/// * [SECP384R1]
/// * [SECP256R1]
/// * [X25519]
///
/// If the `fips` feature is enabled, only [SECP384R1] and [SECP256R1] are available.
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[SECP256R1, SECP384R1, X25519];

#[derive(Debug, Copy, Clone)]
enum KxGroup {
    SECP256R1,
    SECP384R1,
    X25519,
}

impl KxGroup {
    fn ecc_curve(&self) -> PCWSTR {
        match self {
            Self::SECP256R1 => BCRYPT_ECC_CURVE_NISTP256,
            Self::SECP384R1 => BCRYPT_ECC_CURVE_NISTP384,
            Self::X25519 => BCRYPT_ECC_CURVE_25519,
        }
    }

    fn named_group(&self) -> NamedGroup {
        match self {
            Self::SECP256R1 => NamedGroup::secp256r1,
            Self::SECP384R1 => NamedGroup::secp384r1,
            Self::X25519 => NamedGroup::X25519,
        }
    }

    fn is_nist(&self) -> bool {
        match self {
            Self::SECP256R1 | Self::SECP384R1 => true,
            Self::X25519 => false,
        }
    }

    fn key_bits(&self) -> usize {
        match self {
            Self::SECP256R1 => 256,
            Self::SECP384R1 => 384,
            Self::X25519 => 255,
        }
    }
}

struct EcKeyExchange {
    kx_group: KxGroup,
    alg_handle: Owned<BCRYPT_ALG_HANDLE>,
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    public_key: Vec<u8>,
}

unsafe impl Send for EcKeyExchange {}
unsafe impl Sync for EcKeyExchange {}

/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &KxGroup::X25519;
/// secp256r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP256R1: &dyn SupportedKxGroup = &KxGroup::SECP256R1;
/// secp384r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP384R1: &dyn SupportedKxGroup = &KxGroup::SECP384R1;

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        let mut key_handle = Owned::default();
        let mut alg_handle = Owned::default();
        unsafe {
            BCryptOpenAlgorithmProvider(
                &mut *alg_handle,
                BCRYPT_ECDH_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;

            let curve = self.ecc_curve();
            let bits = self.key_bits();

            let bcrypt_handle = BCRYPT_HANDLE(&mut *alg_handle.0);
            BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_ECC_CURVE_NAME,
                &to_null_terminated_le_bytes(curve),
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
            BCryptGenerateKeyPair(*alg_handle, &mut *key_handle, bits as u32, 0)
                .ok()
                .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
            BCryptFinalizeKeyPair(*key_handle, 0)
                .ok()
                .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
        }

        // Export the public key
        let mut size = 0u32;
        unsafe {
            BCryptExportKey(
                *key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
        }

        let mut public_key = vec![0; size as usize];
        unsafe {
            BCryptExportKey(
                *key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                Some(&mut public_key),
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
        }

        // Remove the BCRYPT_ECCKEY_BLOB header
        public_key.drain(..core::mem::size_of::<BCRYPT_ECCKEY_BLOB>());

        if self.is_nist() {
            // Add the uncompressed format byte per RFC 8446 https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
            public_key.insert(0, 0x04);
        }

        Ok(Box::new(EcKeyExchange {
            kx_group: *self,
            key_handle,
            alg_handle,
            public_key,
        }) as Box<dyn ActiveKeyExchange>)
    }

    fn name(&self) -> NamedGroup {
        self.named_group()
    }
}

impl ActiveKeyExchange for EcKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let new_peer_pub_key = if self.kx_group.is_nist() {
            // Reject if not in uncompressed format
            if peer_pub_key.first() != Some(&0x04) {
                return Err(Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::InvalidKeyShare,
                ));
            }
            &peer_pub_key[1..]
        } else {
            &peer_pub_key
        };

        // Reject empty public keys and those at infinity
        if new_peer_pub_key.is_empty() || new_peer_pub_key.iter().all(|&b| b == 0) {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        let key_len = (self.kx_group.key_bits() + 7) / 8;
        let num_parts = if self.kx_group.is_nist() { 2 } else { 1 };
        if new_peer_pub_key.len() != key_len * num_parts {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        // Determine the x and y coordinates of the peer's public key
        let x = &new_peer_pub_key[..key_len];
        let y = if num_parts == 2 {
            &new_peer_pub_key[key_len..]
        } else {
            &[0; 32]
        };

        let mut peer_key_handle = Owned::default();

        match &self.kx_group {
            KxGroup::SECP256R1 => {
                PublicKeyBlob::<32>::load(*self.alg_handle, &mut *peer_key_handle, x, y)?;
            }
            KxGroup::SECP384R1 => {
                PublicKeyBlob::<48>::load(*self.alg_handle, &mut *peer_key_handle, x, y)?;
            }
            KxGroup::X25519 => {
                PublicKeyBlob::<32>::load(*self.alg_handle, &mut *peer_key_handle, x, y)?;
            }
        };

        // Now derive the shared secret
        let mut secret = Owned::default();
        let mut size = 0u32;
        unsafe {
            BCryptSecretAgreement(*self.key_handle, *peer_key_handle, &mut *secret, 0)
                .ok()
                .map_err(|e| {
                    Error::General(format!("Failed to agree secret: {}", e.to_string()))
                })?;
            // Get hold of the secret.
            // First we need to get the size of the secret
            BCryptDeriveKey(*secret, BCRYPT_KDF_RAW_SECRET, None, None, &mut size, 0)
                .ok()
                .map_err(|e| {
                    Error::General(format!("Failed to export secret: {}", e.to_string()))
                })?;
        }

        let mut secret_bytes = [0; MAX_SECRET_SIZE];
        unsafe {
            BCryptDeriveKey(
                *secret,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut secret_bytes[..size as usize]),
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("Failed to export secret: {}", e.to_string())))?;
        }
        secret_bytes[..size as usize].reverse();
        let secret = SharedSecret::from(&secret_bytes[..size as usize]);
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        self.kx_group.named_group()
    }
}

/// A public key blob for loading into CNG.
#[repr(C)]
struct PublicKeyBlob<const SIZE: usize> {
    header: BCRYPT_ECCKEY_BLOB,
    x: [u8; SIZE],
    y: [u8; SIZE],
}

impl<const SIZE: usize> PublicKeyBlob<SIZE> {
    /// Load a public key blob into CNG.
    ///
    /// Params:
    /// * `alg_handle` - The algorithm handle.
    /// * `key_handle` - The key handle for the resulting key.
    /// * `x` - The x coordinate of the public key.
    /// * `y` - The y coordinate of the public key.
    ///
    fn load(
        alg_handle: impl Param<BCRYPT_ALG_HANDLE>,
        key_handle: *mut BCRYPT_KEY_HANDLE,
        x: &[u8],
        y: &[u8],
    ) -> Result<(), Error> {
        if x.len() != SIZE || y.len() != SIZE {
            return Err(Error::General("Invalid key length".to_string()));
        }

        let mut blob = Self {
            header: BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey: SIZE as u32,
            },
            x: [0; SIZE],
            y: [0; SIZE],
        };
        blob.x.copy_from_slice(x);
        blob.y.copy_from_slice(y);

        unsafe {
            let p: *const PublicKeyBlob<SIZE> = &blob;
            let p: *const u8 = p as *const u8;
            let slice = std::slice::from_raw_parts(p, core::mem::size_of::<PublicKeyBlob<SIZE>>());

            BCryptImportKeyPair(
                alg_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                key_handle,
                &slice,
                0,
            )
            .ok()
            .map_err(|e| {
                Error::General(format!(
                    "Error importing public key blob: {}",
                    e.to_string()
                ))
            })
        }
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::ActiveKeyExchange;
    use windows::Win32::Security::Cryptography::{
        BCryptImportKeyPair, BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_ECCKEY_BLOB,
        BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECC_CURVE_NAME, BCRYPT_ECDH_ALGORITHM,
        BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, BCRYPT_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    };
    use wycheproof::{ecdh::TestName, TestResult};

    use crate::{kx::EcKeyExchange, to_null_terminated_le_bytes};

    const CURVE_SIZE: usize = 32;

    #[repr(C)]
    pub(super) struct PrivateKey {
        pub header: BCRYPT_ECCKEY_BLOB,
        pub x: [u8; CURVE_SIZE],
        pub y: [u8; CURVE_SIZE],
        pub d: [u8; CURVE_SIZE],
    }
    impl PrivateKey {
        pub(super) fn new(d: &[u8]) -> Self {
            let mut blob = Self {
                header: BCRYPT_ECCKEY_BLOB {
                    dwMagic: BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC,
                    cbKey: CURVE_SIZE as u32,
                },
                x: [0; CURVE_SIZE],
                y: [0; CURVE_SIZE],
                d: [0; CURVE_SIZE],
            };
            blob.d.copy_from_slice(d);
            blob
        }
    }

    #[test]
    fn secp256r1() {
        let test_set = wycheproof::ecdh::TestSet::load(TestName::EcdhSecp256r1Ecpoint).unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.private_key.len() != CURVE_SIZE {
                    continue;
                }
                dbg!(test);

                let mut kx = EcKeyExchange {
                    kx_group: crate::kx::KxGroup::SECP256R1,
                    alg_handle: Default::default(),
                    key_handle: Default::default(),
                    public_key: Vec::new(),
                };

                // load the key
                unsafe {
                    BCryptOpenAlgorithmProvider(
                        &mut *kx.alg_handle,
                        BCRYPT_ECDH_ALGORITHM,
                        None,
                        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
                    )
                    .ok()
                    .unwrap();
                    let bcrypt_handle = BCRYPT_HANDLE(&mut *kx.alg_handle.0);
                    BCryptSetProperty(
                        bcrypt_handle,
                        BCRYPT_ECC_CURVE_NAME,
                        &to_null_terminated_le_bytes(kx.kx_group.ecc_curve()),
                        0,
                    )
                    .ok()
                    .unwrap();
                }

                let key_blob = PrivateKey::new(&test.private_key);

                unsafe {
                    let p: *const PrivateKey = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice = std::slice::from_raw_parts(p, core::mem::size_of::<PrivateKey>());

                    BCryptImportKeyPair(
                        *kx.alg_handle,
                        BCRYPT_KEY_HANDLE::default(),
                        BCRYPT_ECCPRIVATE_BLOB,
                        &mut *kx.key_handle,
                        &slice,
                        0,
                    )
                    .ok()
                    .unwrap();
                }

                let res = Box::new(kx).complete(&test.public_key);
                let pub_key_uncompressed = test.public_key.first() == Some(&0x04);

                match (&test.result, pub_key_uncompressed) {
                    (TestResult::Acceptable, true) | (TestResult::Valid, true) => {
                        assert!(res.is_ok());
                        assert_eq!(res.unwrap().secret_bytes(), &test.shared_secret[..]);
                    }
                    _ => {
                        assert!(res.is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn x25519() {
        let test_set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.private_key.len() != CURVE_SIZE {
                    continue;
                }
                dbg!(test);

                let mut kx = EcKeyExchange {
                    kx_group: crate::kx::KxGroup::X25519,
                    alg_handle: Default::default(),
                    key_handle: Default::default(),
                    public_key: Vec::new(),
                };

                // load the key
                unsafe {
                    BCryptOpenAlgorithmProvider(
                        &mut *kx.alg_handle,
                        BCRYPT_ECDH_ALGORITHM,
                        None,
                        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
                    )
                    .ok()
                    .unwrap();
                    let bcrypt_handle = BCRYPT_HANDLE(&mut *kx.alg_handle.0);
                    BCryptSetProperty(
                        bcrypt_handle,
                        BCRYPT_ECC_CURVE_NAME,
                        &to_null_terminated_le_bytes(kx.kx_group.ecc_curve()),
                        0,
                    )
                    .ok()
                    .unwrap();
                }

                // Convert to DivHTimesH format https://github.com/microsoft/SymCrypt/blob/1d7e34b8d11870c6bb239caf580ece63785e973a/inc/symcrypt.h#L7027
                let mut key = test.private_key.to_vec();
                key[0] &= 0xf8;
                key[31] &= 0x7f;
                key[31] |= 0x40;

                let key_blob = PrivateKey::new(&key);

                unsafe {
                    let p: *const PrivateKey = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice = std::slice::from_raw_parts(p, core::mem::size_of::<PrivateKey>());

                    BCryptImportKeyPair(
                        *kx.alg_handle,
                        BCRYPT_KEY_HANDLE::default(),
                        BCRYPT_ECCPRIVATE_BLOB,
                        &mut *kx.key_handle,
                        &slice,
                        0,
                    )
                    .ok()
                    .unwrap();
                }

                let res = Box::new(kx).complete(&test.public_key);

                // CNG doesn't support these
                let should_fail = test
                    .flags
                    .contains(&wycheproof::xdh::TestFlag::ZeroSharedSecret)
                    || test
                        .flags
                        .contains(&wycheproof::xdh::TestFlag::NonCanonicalPublic);

                match (&test.result, should_fail) {
                    (TestResult::Acceptable, false) | (TestResult::Valid, false) => match res {
                        Ok(sharedsecret) => {
                            assert_eq!(
                                sharedsecret.secret_bytes(),
                                &test.shared_secret[..],
                                "Derived incorrect secret: {:?}",
                                test
                            );
                        }
                        Err(e) => {
                            panic!("Test failed: {:?}. Error {:?}", test, e);
                        }
                    },
                    _ => {
                        assert!(res.is_err(), "Expected error: {:?}", test);
                    }
                }
            }
        }
    }
}
