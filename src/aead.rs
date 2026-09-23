use crate::cipher::CipherKind;
use openssl::cipher_ctx::CipherCtx;
use rustls::Error;
use rustls::crypto::cipher::NONCE_LEN;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

impl Algorithm {
    fn cipher_kind(self) -> CipherKind {
        match self {
            Self::Aes128Gcm => CipherKind::Aes128Gcm,
            Self::Aes256Gcm => CipherKind::Aes256Gcm,
            Self::ChaCha20Poly1305 => CipherKind::ChaCha20Poly1305,
        }
    }

    pub(crate) fn is_available(self) -> bool {
        self.cipher_kind().is_available()
    }

    pub(crate) fn key_size(self) -> usize {
        self.cipher_kind()
            .load()
            .map_or(0, |handle| handle.key_length())
    }

    /// Encrypts data in place and returns the tag.
    pub(crate) fn encrypt_in_place(
        self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let cipher = self.cipher_kind().load()?;
        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(Some(cipher), Some(key), Some(nonce))?;
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
        let cipher = self.cipher_kind().load()?;

        let payload_len = data.len();
        if payload_len < TAG_LEN {
            return Err(Error::DecryptError);
        }

        let (ciphertext, tag) = data.split_at_mut(payload_len - TAG_LEN);

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(Some(cipher), Some(key), Some(nonce))?;
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
    use super::Algorithm;
    use wycheproof::{TestResult, aead::TestFlag};

    #[rstest::rstest]
    #[case(Algorithm::Aes128Gcm)]
    #[case(Algorithm::Aes256Gcm)]
    #[case(Algorithm::ChaCha20Poly1305)]
    fn test_aead(#[case] alg: Algorithm) {
        if !alg.is_available() {
            return;
        }

        let test_name = match alg {
            Algorithm::Aes128Gcm | Algorithm::Aes256Gcm => wycheproof::aead::TestName::AesGcm,
            Algorithm::ChaCha20Poly1305 => wycheproof::aead::TestName::ChaCha20Poly1305,
        };
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();

        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 8 * alg.key_size())
            .filter(|group| group.nonce_size == 96)
        {
            for test in group.tests {
                counter += 1;
                let mut iv_bytes = [0u8; 12];
                iv_bytes.copy_from_slice(&test.nonce[0..12]);

                let mut actual_ciphertext = test.pt.to_vec();
                let actual_tag = alg
                    .encrypt_in_place(&test.key, &iv_bytes, &test.aad, &mut actual_ciphertext)
                    .unwrap();

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.contains(&TestFlag::ModifiedTag) {
                            assert_ne!(
                                actual_tag[..],
                                test.tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id,
                                test.comment
                            );
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(
                            actual_ciphertext[..],
                            test.ct[..],
                            "Test case failed {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Test case failed {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }

                let mut data = test.ct.to_vec();
                data.extend_from_slice(&test.tag);
                let res = alg.decrypt_in_place(&test.key, &iv_bytes, &test.aad, &mut data);

                match &test.result {
                    TestResult::Invalid => {
                        assert!(res.is_err());
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(res, Ok(test.pt.len()));
                        assert_eq!(&data[..res.unwrap()], &test.pt[..]);
                    }
                }
            }
        }

        // Ensure we ran some tests.
        assert!(counter > 50);
    }

    #[test]
    fn test_aes_available() {
        assert!(Algorithm::Aes128Gcm.is_available());
        assert!(Algorithm::Aes256Gcm.is_available());
    }
}
