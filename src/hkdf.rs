use crate::hash::Algorithm as HashAlgorithm;
use crate::hmac::Hmac;
use openssl::error::ErrorStack;
use openssl::pkey::Id;
use openssl::pkey_ctx::{HkdfMode, PkeyCtx, PkeyCtxRef};
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
    Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, OkmBlock, OutputLengthError,
};
use zeroize::Zeroize;

const MAX_MD_SIZE: usize = openssl_sys::EVP_MAX_MD_SIZE as usize;

/// HKDF implementation using HMAC with the specified Hash Algorithm
pub(crate) struct Hkdf(pub(crate) HashAlgorithm);

struct HkdfExpander {
    private_key: [u8; MAX_MD_SIZE],
    size: usize,
    hash: HashAlgorithm,
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
        let mut private_key = [0u8; MAX_MD_SIZE];
        PkeyCtx::new_id(Id::HKDF)
            .and_then(|mut ctx| {
                ctx.derive_init()?;
                ctx.set_hkdf_mode(HkdfMode::EXTRACT_ONLY)?;
                ctx.set_hkdf_md(self.0.mdref())?;
                ctx.set_hkdf_key(secret)?;
                if let Some(salt) = salt {
                    ctx.set_hkdf_salt(salt)?;
                } else {
                    ctx.set_hkdf_salt([0u8; MAX_MD_SIZE][..hash_size].as_ref())?;
                }
                ctx.derive(Some(&mut private_key[..hash_size]))?;
                Ok(())
            })
            .expect("HDKF-Extract failed");

        Box::new(HkdfExpander {
            private_key,
            size: hash_size,
            hash: self.0,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn RustlsHkdfExpander> {
        let okm = okm.as_ref();
        let mut private_key = [0u8; MAX_MD_SIZE];
        private_key[..okm.len()].copy_from_slice(okm);
        Box::new(HkdfExpander {
            private_key,
            size: okm.len(),
            hash: self.0,
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        Hmac(self.0).with_key(key.as_ref()).sign(&[message])
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl RustlsHkdfExpander for HkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        PkeyCtx::new_id(Id::HKDF)
            .and_then(|mut ctx| {
                ctx.derive_init()?;
                ctx.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
                ctx.set_hkdf_md(self.hash.mdref())?;
                ctx.set_hkdf_key(&self.private_key[..self.size])?;
                add_hkdf_info(&mut ctx, info)?;
                ctx.derive(Some(output))?;
                Ok(())
            })
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
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

#[cfg(bugged_add_hkdf_info)]
fn add_hkdf_info<T>(ctx: &mut PkeyCtxRef<T>, info: &[&[u8]]) -> Result<(), ErrorStack> {
    // Concatenate the info strings to work around https://github.com/openssl/openssl/issues/23448
    let infos = info.iter().fold(Vec::new(), |mut acc, i| {
        acc.extend_from_slice(i);
        acc
    });
    ctx.add_hkdf_info(&infos)
}

#[cfg(not(bugged_add_hkdf_info))]
fn add_hkdf_info<T>(ctx: &mut PkeyCtxRef<T>, info: &[&[u8]]) -> Result<(), ErrorStack> {
    for info in info {
        ctx.add_hkdf_info(info)?;
    }
    Ok(())
}

impl Drop for HkdfExpander {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::tls13::Hkdf;
    use wycheproof::{TestResult, hkdf::TestName};

    fn test_hkdf(hkdf: &dyn Hkdf, test_name: TestName) {
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
        let suite = crate::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let hkdf = suite.tls13().unwrap().hkdf_provider;
        test_hkdf(hkdf, TestName::HkdfSha256);
    }

    #[test]
    fn hkdf_sha384() {
        let suite = crate::cipher_suite::TLS13_AES_256_GCM_SHA384;
        let hkdf = suite.tls13().unwrap().hkdf_provider;
        test_hkdf(hkdf, TestName::HkdfSha384);
    }
}
