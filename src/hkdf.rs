use crate::hash::Algorithm as HashAlgorithm;
use crate::hmac::Hmac;
use alloc::boxed::Box;
use openssl::{
    pkey::Id,
    pkey_ctx::{HkdfMode, PkeyCtx},
};
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
    Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, OkmBlock, OutputLengthError,
};

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
}

impl RustlsHkdfExpander for HkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        PkeyCtx::new_id(Id::HKDF)
            .and_then(|mut ctx| {
                ctx.derive_init()?;
                ctx.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
                ctx.set_hkdf_md(self.hash.mdref())?;
                ctx.set_hkdf_key(&self.private_key[..self.size])?;
                for info in info {
                    ctx.add_hkdf_info(info)?;
                }
                ctx.derive(Some(output))?;
                Ok(())
            })
            .expect("HDKF-Expand failed");
        Ok(())
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

/// Test against rfc5869 test vectors
#[cfg(test)]
mod tests {
    use super::super::hash::SHA256;
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        let hkdf = Hkdf(SHA256);
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk_expander = hkdf.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0; 42];
        prk_expander.expand_slice(&[&info], &mut okm).unwrap();
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm.as_ref(), expected_okm);
    }

    #[test]
    fn test_hkdf_sha256_extended() {
        let hkdf = Hkdf(SHA256);
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0u8; 82];
        expander.expand_slice(&[&info], &mut okm).unwrap();
        let expected_okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )
        .unwrap();
        assert_eq!(okm.as_ref(), expected_okm);
    }
}
