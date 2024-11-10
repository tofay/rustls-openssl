use openssl::{cipher::CipherRef, cipher_ctx::CipherCtx};
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};

pub(crate) struct AeadMessageCrypter {
    pub algo: AeadAlgorithm,
    pub key: AeadKey,
    pub iv: Iv,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    #[cfg(feature = "chacha")]
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub(crate) fn openssl_cipher(&self) -> &'static CipherRef {
        match self {
            AeadAlgorithm::Aes128Gcm => openssl::cipher::Cipher::aes_128_gcm(),
            AeadAlgorithm::Aes256Gcm => openssl::cipher::Cipher::aes_256_gcm(),
            #[cfg(feature = "chacha")]
            AeadAlgorithm::ChaCha20Poly1305 => openssl::cipher::Cipher::chacha20_poly1305(),
        }
    }

    pub(crate) fn tag_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 16,
            #[cfg(feature = "chacha")]
            AeadAlgorithm::ChaCha20Poly1305 => 16,
        }
    }
}

impl AeadMessageCrypter {
    /// Encrypts the data in place and returns the tag.
    pub(crate) fn encrypt_in_place(
        &self,
        sequence_number: u64,
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Vec<u8>, rustls::Error> {
        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(
                    Some(self.algo.openssl_cipher()),
                    Some(self.key.as_ref()),
                    Some(&Nonce::new(&self.iv, sequence_number).0),
                )?;
                // Providing no output buffer implies input is AAD.
                ctx.cipher_update(aad, None)?;
                // The ciphers are all stream ciphers, so we shound encrypt the same amount of data...
                let count = ctx.cipher_update_inplace(data, data.len())?;
                debug_assert!(count == data.len());
                // ... and no more data should be written at the end.
                let rest = ctx.cipher_final(&mut [])?;
                debug_assert!(rest == 0);
                let mut tag = vec![0u8; self.algo.tag_len()];
                ctx.tag(&mut tag)?;
                Ok(tag)
            })
            .map_err(|e| rustls::Error::General(format!("OpeenSSL error: {}", e)))
    }

    /// Decrypts in place, verifying the tag and returns the length of the
    /// plaintext.
    /// The data is expected to be in the form of [ciphertext, tag].
    pub(crate) fn decrypt_in_place(
        &self,
        sequence_number: u64,
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<usize, rustls::Error> {
        let payload_len = data.len();
        if payload_len < self.algo.tag_len() {
            return Err(rustls::Error::DecryptError);
        }

        let (ciphertext, tag) = data.split_at_mut(payload_len - self.algo.tag_len());

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(
                    Some(self.algo.openssl_cipher()),
                    Some(self.key.as_ref()),
                    Some(&Nonce::new(&self.iv, sequence_number).0),
                )?;
                ctx.cipher_update(aad, None)?;
                ctx.set_tag(tag)?;
                let count = ctx.cipher_update_inplace(ciphertext, ciphertext.len())?;
                debug_assert!(count == ciphertext.len());
                let rest = ctx.cipher_final(&mut [])?;
                debug_assert!(rest == 0);
                Ok(count + rest)
            })
            .map_err(|e| rustls::Error::General(format!("OpenSSL error: {}", e)))
    }
}
