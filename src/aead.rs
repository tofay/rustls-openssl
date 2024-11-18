use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use rustls::crypto::cipher::NONCE_LEN;
use rustls::Error;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    #[cfg(all(chacha, not(feature = "fips")))]
    ChaCha20Poly1305,
}

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

impl Algorithm {
    fn openssl_cipher(self) -> &'static CipherRef {
        match self {
            Self::Aes128Gcm => Cipher::aes_128_gcm(),
            Self::Aes256Gcm => Cipher::aes_256_gcm(),
            #[cfg(all(chacha, not(feature = "fips")))]
            Self::ChaCha20Poly1305 => Cipher::chacha20_poly1305(),
        }
    }

    pub(crate) fn key_size(self) -> usize {
        self.openssl_cipher().key_length()
    }

    /// Encrypts data in place and returns the tag.
    pub(crate) fn encrypt_in_place(
        self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(Some(self.openssl_cipher()), Some(key), Some(nonce))?;
                // Providing no output buffer implies input is AAD.
                ctx.cipher_update(aad, None)?;
                // The ciphers are all stream ciphers, so we shound encrypt the same amount of data...
                let count = ctx.cipher_update_inplace(data, data.len())?;
                debug_assert!(count == data.len());
                // ... and no more data should be written at the end.
                let rest = ctx.cipher_final(&mut [])?;
                debug_assert!(rest == 0);
                let mut tag = [0u8; TAG_LEN];
                ctx.tag(&mut tag)?;
                Ok(tag)
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    /// Decrypts in place, verifying the tag and returns the length of the
    /// plaintext.
    /// The data is expected to be in the form of [ciphertext, tag].
    pub(crate) fn decrypt_in_place(
        self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_len = data.len();
        if payload_len < TAG_LEN {
            return Err(Error::DecryptError);
        }

        let (ciphertext, tag) = data.split_at_mut(payload_len - TAG_LEN);

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(Some(self.openssl_cipher()), Some(key), Some(nonce))?;
                ctx.cipher_update(aad, None)?;
                ctx.set_tag(tag)?;
                let count = ctx.cipher_update_inplace(ciphertext, ciphertext.len())?;
                debug_assert!(count == ciphertext.len());
                let rest = ctx.cipher_final(&mut [])?;
                debug_assert!(rest == 0);
                Ok(count + rest)
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }
}

#[cfg(test)]
mod test {

    use crate::test::schemas::aead;
    use std::{fs, path::PathBuf};

    fn test_aes(alg: super::Algorithm) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("test")
            .join("vectors")
            .join("aes_gcm_test.json");
        let tests: aead::AeadTestFile =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

        for group in tests
            .test_groups
            .unwrap()
            .iter()
            .filter(|group| group.key_size.unwrap() == 8 * i64::try_from(alg.key_size()).unwrap())
            .filter(|group| group.iv_size.unwrap() == 96)
        {
            for test in group.tests.as_ref().unwrap() {
                dbg!(test.tc_id);
                let key = test
                    .key
                    .as_deref()
                    .map(|key| hex::decode(key).unwrap())
                    .unwrap();
                let iv = test
                    .iv
                    .as_deref()
                    .map(|iv| hex::decode(iv).unwrap())
                    .unwrap();
                let aad = test
                    .aad
                    .as_deref()
                    .map(|aad| hex::decode(aad).unwrap())
                    .unwrap();
                let msg = test
                    .msg
                    .as_deref()
                    .map(|msg| hex::decode(msg).unwrap())
                    .unwrap();
                let ciphertext = test
                    .ct
                    .as_deref()
                    .map(|ct| hex::decode(ct).unwrap())
                    .unwrap();
                let tag = test
                    .tag
                    .as_deref()
                    .map(|tag| hex::decode(tag).unwrap())
                    .unwrap();

                let mut iv_bytes = [0u8; 12];
                iv_bytes.copy_from_slice(&iv[0..12]);

                let mut actual_ciphertext = msg.clone();
                let actual_tag = alg
                    .encrypt_in_place(&key, &iv_bytes, &aad, &mut actual_ciphertext)
                    .unwrap();

                match test.result.as_ref().unwrap() {
                    aead::Result::Invalid => {
                        if test
                            .flags
                            .as_ref()
                            .unwrap()
                            .iter()
                            .any(|flag| flag == "ModifiedTag")
                        {
                            assert_ne!(
                                actual_tag[..],
                                tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id.unwrap(),
                                test.comment.as_deref().unwrap()
                            );
                        }
                    }
                    aead::Result::Valid | aead::Result::Acceptable => {
                        assert_eq!(
                            actual_ciphertext,
                            ciphertext,
                            "Test case failed {}: {}",
                            test.tc_id.unwrap(),
                            test.comment.as_deref().unwrap()
                        );
                        assert_eq!(
                            actual_tag[..],
                            tag[..],
                            "Test case failed {}: {}",
                            test.tc_id.unwrap(),
                            test.comment.as_deref().unwrap()
                        );
                    }
                }

                let mut data = ciphertext.to_vec();
                data.extend_from_slice(&tag);
                let res = alg.decrypt_in_place(&key, &iv_bytes, &aad, &mut data);

                match test.result.as_ref().unwrap() {
                    aead::Result::Invalid => {
                        assert!(res.is_err());
                    }
                    aead::Result::Valid | aead::Result::Acceptable => {
                        assert_eq!(res, Ok(msg.len()));
                        assert_eq!(&data[..res.unwrap()], &msg[..]);
                    }
                }
            }
        }
    }

    #[test]
    fn test_aes_128() {
        test_aes(super::Algorithm::Aes128Gcm);
    }

    #[test]
    fn test_aes_256() {
        test_aes(super::Algorithm::Aes256Gcm);
    }
}
