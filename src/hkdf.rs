use crate::hash::{Algorithm as HashAlgorithm, MAX_HASH_SIZE};
use crate::load_algorithm;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
    Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, OkmBlock, OutputLengthError,
};
use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptBuffer, BCryptBufferDesc, BCryptGenerateSymmetricKey, BCryptKeyDerivation,
    BCryptOpenAlgorithmProvider, BCryptSetProperty as Win32BCryptSetProperty, BCRYPTBUFFER_VERSION,
    BCRYPT_HANDLE, BCRYPT_HKDF_ALGORITHM, BCRYPT_HKDF_HASH_ALGORITHM, BCRYPT_HKDF_PRK_AND_FINALIZE,
    BCRYPT_HKDF_SALT_AND_FINALIZE, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    KDF_HKDF_INFO,
};

// Follows instructions at https://github.com/kdschlosser/pyWinAPI/blob/43e0be2dfe80aa701e01f43b806d1e8e52c3c221/shared/bcrypt_h.py#L637
// for using the BCrypt HKDF API.

/// HKDF implementation using HMAC with the specified Hash Algorithm
pub(crate) struct Hkdf<const HASH_SIZE: usize>(pub(crate) HashAlgorithm<HASH_SIZE>);

struct HkdfExpander<const HASH_SIZE: usize> {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    hash: HashAlgorithm<HASH_SIZE>,
}

unsafe impl<const HASH_SIZE: usize> Send for HkdfExpander<HASH_SIZE> {}
unsafe impl<const HASH_SIZE: usize> Sync for HkdfExpander<HASH_SIZE> {}

impl<const HASH_SIZE: usize> RustlsHkdf for Hkdf<HASH_SIZE> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn RustlsHkdfExpander> {
        let secret = [0u8; HASH_SIZE];
        self.extract_from_secret(salt, &secret)
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn RustlsHkdfExpander> {
        let alg_handle = load_algorithm(BCRYPT_HKDF_ALGORITHM);
        let mut key_handle = Owned::default();

        unsafe {
            BCryptGenerateSymmetricKey(*alg_handle, &mut *key_handle, None, secret, 0)
                .ok()
                .unwrap();
            let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
            Win32BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_HASH_ALGORITHM,
                &self.0.id_bytes,
                0,
            )
            .ok()
            .unwrap();

            Win32BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_SALT_AND_FINALIZE,
                salt.unwrap_or(&[0u8; HASH_SIZE]),
                0,
            )
            .ok()
            .unwrap();
        };

        Box::new(HkdfExpander::<HASH_SIZE> {
            key_handle: key_handle,
            hash: self.0,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn RustlsHkdfExpander> {
        let okm = okm.as_ref();
        let alg_handle = load_algorithm(BCRYPT_HKDF_ALGORITHM);
        let mut key_handle = Owned::default();

        unsafe {
            BCryptGenerateSymmetricKey(*alg_handle, &mut *key_handle, None, okm, 0)
                .ok()
                .unwrap();

            let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
            Win32BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_HASH_ALGORITHM,
                &self.0.id_bytes,
                0,
            )
            .ok()
            .unwrap();

            // Use extern fn directly to pass a null pointer
            BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_HKDF_PRK_AND_FINALIZE,
                std::ptr::null(),
                0,
                0,
            )
            .ok()
            .unwrap();
        };

        Box::new(HkdfExpander::<HASH_SIZE> {
            key_handle,
            hash: self.0,
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        self.0.with_key(key.as_ref()).sign(&[message])
    }
}

// required for passing null pointer when setting HDKF_PRK_AND_FINALIZE
// can be removed if switched to windows-sys
extern "system" {
    fn BCryptSetProperty(
        hobject: BCRYPT_HANDLE,
        pszproperty: PCWSTR,
        pbinput: *const u8,
        cbinput: u32,
        dwflags: u32,
    ) -> NTSTATUS;
}

impl<const HASH_SIZE: usize> RustlsHkdfExpander for HkdfExpander<HASH_SIZE> {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        // BCrypt expects a single info buffer
        let info = info
            .iter()
            .flat_map(|info| info.iter())
            .copied()
            .collect::<Vec<u8>>();
        let mut buffer = BCryptBuffer {
            cbBuffer: info.len() as u32,
            BufferType: KDF_HKDF_INFO,
            pvBuffer: info.as_ptr() as *mut _,
        };

        let params = if info.is_empty() {
            BCryptBufferDesc::default()
        } else {
            BCryptBufferDesc {
                ulVersion: BCRYPTBUFFER_VERSION,
                cBuffers: 1u32,
                pBuffers: &mut buffer,
            }
        };

        let mut size = 0u32;
        unsafe {
            BCryptKeyDerivation(*self.key_handle, Some(&params), output, &mut size, 0)
                .ok()
                .map_err(|e| {
                    dbg!(e);
                    OutputLengthError
                })?;
        };
        // Ensure info outlives the call to BCryptKeyDerivation
        drop(info);
        if size != output.len() as u32 {
            return Err(OutputLengthError);
        }
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; HASH_SIZE];
        self.expand_slice(info, &mut output)
            .expect("HDKF-Expand failed");
        OkmBlock::new(&output)
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

    fn test_hkdf<const HASH_SIZE: usize>(hkdf: Hkdf<HASH_SIZE>, test_name: TestName) {
        let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

        for test_group in test_set.test_groups {
            for test in test_group.tests {
                dbg!(&test);

                let prk_expander = hkdf.extract_from_secret(Some(&test.salt), &test.ikm);

                let mut okm = vec![0; test.size];

                let infos = test.info.chunks(2).collect::<Vec<_>>();

                let res = prk_expander.expand_slice(&infos, &mut okm);

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
        let hkdf = Hkdf(crate::hash::SHA256);
        test_hkdf(hkdf, TestName::HkdfSha256);
    }

    #[test]
    fn hkdf_sha384() {
        let hkdf = Hkdf(crate::hash::SHA384);
        test_hkdf(hkdf, TestName::HkdfSha384);
    }
}
