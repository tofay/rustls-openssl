use crate::hash::Algorithm as HashAlgorithm;
use crate::hmac::Hmac;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
    Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, OkmBlock, OutputLengthError,
};
use windows::core::Owned;
use windows::Win32::Security::Cryptography::{
    BCryptBuffer, BCryptBufferDesc, BCryptExportKey, BCryptGenerateSymmetricKey,
    BCryptKeyDerivation, BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPTBUFFER_VERSION,
    BCRYPT_HANDLE, BCRYPT_HKDF_ALGORITHM, BCRYPT_HKDF_HASH_ALGORITHM,
    BCRYPT_HKDF_SALT_AND_FINALIZE, BCRYPT_KEY_DATA_BLOB, BCRYPT_KEY_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, KDF_HKDF_INFO, KDF_SECRET_APPEND,
};

const MAX_MD_SIZE: usize = 64;

// Null terminated UTF-16 strings for SHA256 and SHA384
const SHA256_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 50, 0, 53, 0, 54, 0, 0, 0];
const SHA384_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 51, 0, 56, 0, 52, 0, 0, 0];

/// HKDF implementation using HMAC with the specified Hash Algorithm
pub(crate) struct Hkdf(pub(crate) HashAlgorithm);

struct HkdfExpander {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    hash: HashAlgorithm,
}

unsafe impl Send for HkdfExpander {}
unsafe impl Sync for HkdfExpander {}

impl Hkdf {
    fn bcrypt_hash_id(&self) -> &[u8] {
        match self.0 {
            HashAlgorithm::SHA256 => SHA256_ID,
            HashAlgorithm::SHA384 => SHA384_ID,
        }
    }
}

impl RustlsHkdf for Hkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn RustlsHkdfExpander> {
        let hash_size = self.0.output_len();
        let secret = [0u8; MAX_MD_SIZE];
        self.extract_from_secret(salt, &secret[..hash_size])
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn RustlsHkdfExpander> {
        let hash_size = self.0.output_len();
        let mut key_handle = Owned::default();

        unsafe {
            let mut alg_handle = Owned::default();
            BCryptOpenAlgorithmProvider(
                &mut *alg_handle,
                BCRYPT_HKDF_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
            .ok()
            .unwrap();

            BCryptGenerateSymmetricKey(*alg_handle, &mut *key_handle, None, secret, 0)
                .ok()
                .unwrap();
            let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
            BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_HASH_ALGORITHM,
                &self.bcrypt_hash_id(),
                0,
            )
            .ok()
            .unwrap();

            BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_SALT_AND_FINALIZE,
                salt.unwrap_or(&[0u8; MAX_MD_SIZE][..hash_size]),
                0,
            )
            .ok()
            .unwrap();

            let mut size = 0u32;
            BCryptExportKey(
                *key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_KEY_DATA_BLOB,
                None,
                &mut size,
                0,
            )
            .ok()
            .unwrap();
        };

        Box::new(HkdfExpander {
            key_handle: key_handle,
            hash: self.0,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn RustlsHkdfExpander> {
        let okm = okm.as_ref();

        let mut key_handle = Owned::default();
        unsafe {
            let mut alg_handle = Owned::default();
            BCryptOpenAlgorithmProvider(
                &mut *alg_handle,
                BCRYPT_HKDF_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
            .ok()
            .unwrap();

            BCryptGenerateSymmetricKey(*alg_handle, &mut *key_handle, None, okm, 0)
                .ok()
                .unwrap();
        };

        Box::new(HkdfExpander {
            key_handle: key_handle,
            hash: self.0,
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        Hmac(self.0).with_key(key.as_ref()).sign(&[message])
    }
}

impl RustlsHkdfExpander for HkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let buffers = info
            .iter()
            .filter(|info| !info.is_empty())
            .map(|info| BCryptBuffer {
                cbBuffer: info.len() as u32,
                BufferType: KDF_HKDF_INFO,
                pvBuffer: info.as_ptr() as *mut _,
            })
            .collect::<Vec<_>>();

        let buffer_desc = BCryptBufferDesc {
            ulVersion: BCRYPTBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_ptr() as *mut _,
        };

        dbg!(&buffer_desc);
        dbg!(&output);

        let mut size = output.len() as u32;

        unsafe {
            BCryptKeyDerivation(*self.key_handle, Some(&buffer_desc), output, &mut size, 0)
                .ok()
                .map_err(|e| {
                    dbg!(e);
                    OutputLengthError
                })?;
        };
        if size != output.len() as u32 {
            return Err(OutputLengthError);
        }

        eprintln!("success");
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        dbg!(info);
        let mut output = [0u8; MAX_MD_SIZE];
        let len = self.hash_len();

        self.expand_slice(info, &mut output[..len])
            .expect("HDKF-Expand failed");
        OkmBlock::new(&output[..len])
    }

    fn hash_len(&self) -> usize {
        self.hash.output_len()
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::tls13::Hkdf as _;
    use wycheproof::{hkdf::TestName, TestResult};

    use super::Hkdf;

    fn test_hkdf(hkdf: Hkdf, test_name: TestName) {
        let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

        for test_group in test_set.test_groups {
            for test in test_group.tests {
                dbg!(&test);

                let prk_expander = hkdf.extract_from_secret(Some(&test.salt), &test.ikm);

                let mut okm = vec![0; test.size];
                let res = prk_expander.expand_slice(&[&test.info], &mut okm);

                match &test.result {
                    TestResult::Acceptable | TestResult::Valid => {
                        assert!(res.is_ok());
                        assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
                    }
                    TestResult::Invalid => {
                        dbg!(&res);
                        assert!(res.is_err(), "Failed test: {}", test.comment)
                    }
                }
            }
        }
    }

    #[test]
    fn hkdf_sha256() {
        let hkdf = Hkdf(crate::hash::Algorithm::SHA256);
        test_hkdf(hkdf, TestName::HkdfSha256);
    }

    #[test]
    fn hkdf_sha384() {
        let hkdf = Hkdf(crate::hash::Algorithm::SHA384);
        test_hkdf(hkdf, TestName::HkdfSha384);
    }
}
