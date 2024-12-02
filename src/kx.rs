use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use windows::core::{Owned, PCWSTR};
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
            &[]
        };

        let mut peer_key_handle = Owned::default();

        match &self.kx_group {
            KxGroup::SECP256R1 => {
                let key_blob = KeyBlobP256::new(x, y)?;
                unsafe {
                    let p: *const KeyBlobP256 = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice = std::slice::from_raw_parts(p, core::mem::size_of::<KeyBlobP256>());

                    BCryptImportKeyPair(
                        *self.alg_handle,
                        BCRYPT_KEY_HANDLE::default(),
                        BCRYPT_ECCPUBLIC_BLOB,
                        &mut *peer_key_handle,
                        &slice,
                        0,
                    )
                    .ok()
                    .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
                }
            }
            KxGroup::SECP384R1 => {
                let key_blob = KeyBlobP384::new(x, y)?;
                unsafe {
                    let p: *const KeyBlobP384 = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice = std::slice::from_raw_parts(p, core::mem::size_of::<KeyBlobP384>());

                    BCryptImportKeyPair(
                        *self.alg_handle,
                        BCRYPT_KEY_HANDLE::default(),
                        BCRYPT_ECCPUBLIC_BLOB,
                        &mut *peer_key_handle,
                        &slice,
                        0,
                    )
                    .ok()
                    .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
                }
            }
            KxGroup::X25519 => {
                let key_blob = KeyBlobX25519::new(x)?;
                unsafe {
                    let p: *const KeyBlobX25519 = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice =
                        std::slice::from_raw_parts(p, core::mem::size_of::<KeyBlobX25519>());

                    BCryptImportKeyPair(
                        *self.alg_handle,
                        BCRYPT_KEY_HANDLE::default(),
                        BCRYPT_ECCPUBLIC_BLOB,
                        &mut *peer_key_handle,
                        &slice,
                        0,
                    )
                    .ok()
                    .map_err(|e| Error::General(format!("CNG error: {}", e.to_string())))?;
                }
            }
        };

        // Now derive the shared secret
        let mut secret = Owned::default();
        let mut size = 0u32;
        unsafe {
            BCryptSecretAgreement(*self.key_handle, *peer_key_handle, &mut *secret, 0)
                .ok()
                .unwrap();
            // Get hold of the secret.
            // First we need to get the size of the secret
            BCryptDeriveKey(*secret, BCRYPT_KDF_RAW_SECRET, None, None, &mut size, 0)
                .ok()
                .unwrap();
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
            .unwrap();
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

const P256_CURVE_SIZE: usize = 32;
const P384_CURVE_SIZE: usize = 48;
const X25519_CURVE_SIZE: usize = 32;

#[repr(C)]
struct KeyBlobP256 {
    pub header: BCRYPT_ECCKEY_BLOB,
    pub x: [u8; P256_CURVE_SIZE],
    pub y: [u8; P256_CURVE_SIZE],
}

#[repr(C)]
struct KeyBlobP384 {
    pub header: BCRYPT_ECCKEY_BLOB,
    pub x: [u8; P384_CURVE_SIZE],
    pub y: [u8; P384_CURVE_SIZE],
}

#[repr(C)]
struct KeyBlobX25519 {
    pub header: BCRYPT_ECCKEY_BLOB,
    pub x: [u8; X25519_CURVE_SIZE],
}
impl KeyBlobP256 {
    fn new(x: &[u8], y: &[u8]) -> Result<Self, Error> {
        if x.len() != P256_CURVE_SIZE || y.len() != P256_CURVE_SIZE {
            return Err(Error::General("Invalid key length".to_string()));
        }

        let mut blob = Self {
            header: BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey: P256_CURVE_SIZE as u32,
            },
            x: [0; P256_CURVE_SIZE],
            y: [0; P256_CURVE_SIZE],
        };
        blob.x.copy_from_slice(x);
        blob.y.copy_from_slice(y);
        Ok(blob)
    }
}

impl KeyBlobP384 {
    fn new(x: &[u8], y: &[u8]) -> Result<Self, Error> {
        if x.len() != P384_CURVE_SIZE || y.len() != P384_CURVE_SIZE {
            return Err(Error::General("Invalid key length".to_string()));
        }

        let mut blob = Self {
            header: BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey: P384_CURVE_SIZE as u32,
            },
            x: [0; P384_CURVE_SIZE],
            y: [0; P384_CURVE_SIZE],
        };
        blob.x.copy_from_slice(x);
        blob.y.copy_from_slice(y);
        Ok(blob)
    }
}

impl KeyBlobX25519 {
    fn new(x: &[u8]) -> Result<Self, Error> {
        if x.len() != X25519_CURVE_SIZE {
            return Err(Error::General("Invalid key length".to_string()));
        }
        let mut blob = Self {
            header: BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey: X25519_CURVE_SIZE as u32,
            },
            x: [0; X25519_CURVE_SIZE],
        };
        blob.x.copy_from_slice(x);
        Ok(blob)
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

    use super::P256_CURVE_SIZE;

    #[repr(C)]
    struct KeyBlobP256Private {
        pub header: BCRYPT_ECCKEY_BLOB,
        pub x: [u8; P256_CURVE_SIZE],
        pub y: [u8; P256_CURVE_SIZE],
        pub d: [u8; P256_CURVE_SIZE],
    }

    impl KeyBlobP256Private {
        fn new(d: &[u8]) -> Self {
            let mut blob = Self {
                header: BCRYPT_ECCKEY_BLOB {
                    dwMagic: BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC,
                    cbKey: P256_CURVE_SIZE as u32,
                },
                x: [0; P256_CURVE_SIZE],
                y: [0; P256_CURVE_SIZE],
                d: [0; P256_CURVE_SIZE],
            };
            blob.d.copy_from_slice(d);
            blob
        }
    }

    #[test]
    fn test_secp256r1() {
        let test_set = wycheproof::ecdh::TestSet::load(TestName::EcdhSecp256r1Ecpoint).unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.private_key.len() != P256_CURVE_SIZE {
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

                let key_blob = KeyBlobP256Private::new(&test.private_key);

                unsafe {
                    let p: *const KeyBlobP256Private = &key_blob;
                    let p: *const u8 = p as *const u8;
                    let slice =
                        std::slice::from_raw_parts(p, core::mem::size_of::<KeyBlobP256Private>());

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
}
