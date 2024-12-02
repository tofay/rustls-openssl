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
use zeroize::Zeroize;

use crate::to_null_terminated_le_bytes;

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
            .unwrap();

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
            .unwrap();
            BCryptGenerateKeyPair(*alg_handle, &mut *key_handle, bits as u32, 0)
                .ok()
                .unwrap();
            BCryptFinalizeKeyPair(*key_handle, 0).ok().unwrap();
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
            .unwrap();
        }

        let mut public_key = Vec::with_capacity(size as usize);

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
            .unwrap();
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
        // Reject if peer public key is NIST and not in uncompressed format
        if self.kx_group.is_nist() && peer_pub_key.first() != Some(&0x04) {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        let key_len = self.kx_group.key_bits() + 7 / 8;
        let (uncompressed_key, num_parts) = if self.kx_group.is_nist() {
            (&peer_pub_key[1..], 2)
        } else {
            (peer_pub_key, 1)
        };
        if uncompressed_key.len() != key_len * num_parts {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }
        let x = &uncompressed_key[..key_len];
        let y = if num_parts == 2 {
            &uncompressed_key[key_len..]
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
                    .unwrap();
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
                    .unwrap();
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
                    .unwrap();
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
        let mut secret_bytes = Vec::with_capacity(size as usize);
        unsafe {
            BCryptDeriveKey(
                *secret,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut secret_bytes),
                &mut size,
                0,
            )
            .ok()
            .unwrap();
        }
        let secret = SharedSecret::from(&secret_bytes[..]);
        secret_bytes.zeroize();
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

// #[cfg(test)]
// mod test {
//     use wycheproof::{ecdh::TestName, TestResult};

//     use crate::kx::EcKeyExchange;

//     #[test]
//     fn test_secp256r1() {
//         let test_set = wycheproof::ecdh::TestSet::load(TestName::EcdhSecp256r1Ecpoint).unwrap();

//         for test_group in test_set.test_groups.iter() {
//             for test in test_group.tests {
//                 if test.private_key.len() != 32 {
//                     continue;
//                 }
//                 // Create ActiveKeyExchange

//                 let mut kx = EcKeyExchange {
//                     kx_group: crate::kx::KxGroup::SECP256R1,
//                     alg_handle: Default::default(),
//                     key_handle: Default::default(),
//                     public_key: Vec::new(),
//                 };

//                 dbg!(&test);

//                 let prk_expander = hkdf.extract_from_secret(Some(&test.salt), &test.ikm);

//                 let mut okm = vec![0; test.size];
//                 let res = prk_expander.expand_slice(&[&test.info], &mut okm);

//                 match &test.result {
//                     TestResult::Acceptable | TestResult::Valid => {
//                         assert!(res.is_ok());
//                         assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
//                     }
//                     TestResult::Invalid => {
//                         dbg!(&res);
//                         assert!(res.is_err(), "Failed test: {}", test.comment)
//                     }
//                 }
//             }
//         }
//     }
// }
