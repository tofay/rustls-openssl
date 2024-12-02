use rustls::crypto::cipher::NONCE_LEN;
use rustls::Error;
use windows::core::{Array, HSTRING};
use windows::Security::Cryptography::Core::{
    CryptographicEngine, SymmetricAlgorithmNames, SymmetricKeyAlgorithmProvider,
};
use windows::Security::Cryptography::CryptographicBuffer;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
}

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

impl Algorithm {
    fn name(&self) -> HSTRING {
        match &self {
            Self::Aes128Gcm | Self::Aes256Gcm => SymmetricAlgorithmNames::AesGcm().unwrap(),
        }
    }

    pub(crate) fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// Encrypts data in place and returns the tag.
    pub(crate) fn encrypt_in_place(
        self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        SymmetricKeyAlgorithmProvider::OpenAlgorithm(&self.name())
            .and_then(|provider| {
                let key = provider
                    .CreateSymmetricKey(&CryptographicBuffer::CreateFromByteArray(&key)?)?;
                let data_buffer = CryptographicBuffer::CreateFromByteArray(&data)?;
                let aad_buffer = CryptographicBuffer::CreateFromByteArray(aad)?;
                let nonce_buffer = CryptographicBuffer::CreateFromByteArray(nonce)?;
                let res = CryptographicEngine::EncryptAndAuthenticate(
                    &key,
                    &data_buffer,
                    &nonce_buffer,
                    &aad_buffer,
                )?;

                let encrypted_data_buffer = res.EncryptedData()?;
                let mut encrypted_data_array =
                    Array::<u8>::with_len(encrypted_data_buffer.Length()? as usize);
                CryptographicBuffer::CopyToByteArray(
                    &encrypted_data_buffer,
                    &mut encrypted_data_array,
                )?;
                data.copy_from_slice(encrypted_data_array.as_slice());
                let tag_buffer = res.AuthenticationTag()?;
                let mut tag = [0u8; TAG_LEN];
                let mut tag_array = Array::<u8>::with_len(TAG_LEN);
                CryptographicBuffer::CopyToByteArray(&tag_buffer, &mut tag_array)?;
                tag.copy_from_slice(tag_array.as_slice());
                Ok(tag)
            })
            .map_err(|e| Error::General(format!("CNfG error: {}", e.to_string())))
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

        dbg!(&ciphertext, &tag, &key, &nonce, &aad);

        SymmetricKeyAlgorithmProvider::OpenAlgorithm(&self.name())
            .and_then(|provider| {
                let key_buffer = CryptographicBuffer::CreateFromByteArray(&key)?;
                let key = provider.CreateSymmetricKey(&key_buffer)?;
                let data_buffer = CryptographicBuffer::CreateFromByteArray(&ciphertext)?;
                let aad_buffer = CryptographicBuffer::CreateFromByteArray(aad)?;
                let nonce_buffer = CryptographicBuffer::CreateFromByteArray(nonce)?;
                let tag_buffer = CryptographicBuffer::CreateFromByteArray(tag)?;
                let plaintext_buffer = CryptographicEngine::DecryptAndAuthenticate(
                    &key,
                    &data_buffer,
                    &nonce_buffer,
                    &tag_buffer,
                    &aad_buffer,
                )?;

                let plaintext_len = plaintext_buffer.Length()? as usize;
                let mut plaintext_array = Array::<u8>::with_len(plaintext_len);
                CryptographicBuffer::CopyToByteArray(&plaintext_buffer, &mut plaintext_array)?;
                ciphertext[..plaintext_len].copy_from_slice(plaintext_array.as_slice());
                Ok(plaintext_len)
            })
            .map_err(|e| Error::General(format!("CNdG error: {}", e.to_string())))

        // CipherCtx::new()
        //     .and_then(|mut ctx| {
        //         ctx.decrypt_init(Some(self.openssl_cipher()), Some(key), Some(nonce))?;
        //         ctx.cipher_update(aad, None)?;
        //         ctx.set_tag(tag)?;
        //         let count = ctx.cipher_update_inplace(ciphertext, ciphertext.len())?;
        //         debug_assert!(count == ciphertext.len());
        //         let rest = ctx.cipher_final(&mut [])?;
        //         debug_assert!(rest == 0);
        //         Ok(count + rest)
        //     })
        //     .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }
}

#[cfg(test)]
mod test {
    use wycheproof::{aead::TestFlag, TestResult};

    fn test_aead(alg: super::Algorithm) {
        let test_name = match alg {
            super::Algorithm::Aes128Gcm | super::Algorithm::Aes256Gcm => {
                wycheproof::aead::TestName::AesGcm
            }
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
                        if test.flags.iter().any(|flag| *flag == TestFlag::ModifiedTag) {
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
                            "Incorrect ciphertext on testcase {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Incorrect tag on testcase {}: {}",
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
    fn test_aes_128() {
        test_aead(super::Algorithm::Aes128Gcm);
    }

    #[test]
    fn test_aes_256() {
        test_aead(super::Algorithm::Aes256Gcm);
    }
}
