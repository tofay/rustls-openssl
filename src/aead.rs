use alloc::format;
use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
};
use rustls::{
    crypto::cipher::{AeadKey, Iv, Nonce},
    Error,
};

pub(crate) struct MessageCrypter {
    pub algo: Algorithm,
    pub key: AeadKey,
    pub iv: Iv,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    #[cfg(chacha)]
    ChaCha20Poly1305,
}

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

impl Algorithm {
    pub(crate) fn openssl_cipher(self) -> &'static CipherRef {
        match self {
            Self::Aes128Gcm => Cipher::aes_128_gcm(),
            Self::Aes256Gcm => Cipher::aes_256_gcm(),
            #[cfg(chacha)]
            Self::ChaCha20Poly1305 => Cipher::chacha20_poly1305(),
        }
    }
}

impl MessageCrypter {
    /// Encrypts the data in place and returns the tag.
    pub(crate) fn encrypt_in_place(
        &self,
        sequence_number: u64,
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
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
        &self,
        sequence_number: u64,
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
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }
}
