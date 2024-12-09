//! Provides openssl backed implementation of Quinn's crypto traits.
use std::sync::Arc;

use crate::aead::Algorithm;
use crate::hkdf::{Hkdf, HkdfExpander};
use crate::hmac::HmacKey;
use openssl::pkey::PKey;
use quinn::crypto::HandshakeTokenKey;
use rustls::crypto::{cipher::AeadKey, tls13::HkdfExpander as _, SecureRandom};

const AES_256_KEY_LEN: usize = 32;
struct Aes256GcmKey(AeadKey);

/// Create a new endpoint reset key   
pub fn reset_key() -> Arc<dyn quinn::crypto::HmacKey> {
    let mut reset_key = [0; 64];
    crate::SecureRandom {}
        .fill(&mut reset_key)
        .expect("Failed to generate random key");
    Arc::new(HmacKey::sha256(
        PKey::hmac(&reset_key).expect("Failed to read Hmac Key"),
    ))
}

/// Create new handshake token key  
pub fn handshake_token_key() -> Arc<dyn HandshakeTokenKey> {
    let mut master_key = [0u8; 64];
    crate::SecureRandom {}
        .fill(&mut master_key)
        .expect("Failed to generate random key");
    let hkdf = Hkdf(crate::hash::Algorithm::SHA256);
    let expander = hkdf.extract_from_secret_internal(None, &master_key);
    Arc::new(expander)
}

impl quinn::crypto::HandshakeTokenKey for HkdfExpander {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn quinn::crypto::AeadKey> {
        debug_assert!(self.hash_len() >= AES_256_KEY_LEN);
        let mut key_buffer = [0u8; AES_256_KEY_LEN];
        let okm = self.expand_block(&[random_bytes]);
        key_buffer.copy_from_slice(&okm.as_ref()[..AES_256_KEY_LEN]);
        Box::new(Aes256GcmKey(AeadKey::from(key_buffer)))
    }
}

impl quinn::crypto::AeadKey for Aes256GcmKey {
    fn seal(
        &self,
        data: &mut Vec<u8>,
        additional_data: &[u8],
    ) -> Result<(), quinn::crypto::CryptoError> {
        let tag = Algorithm::Aes256Gcm
            .encrypt_in_place(self.0.as_ref(), &[0u8; 12], additional_data, data)
            .map_err(|_| quinn::crypto::CryptoError)?;
        data.extend_from_slice(&tag);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], quinn::crypto::CryptoError> {
        let plaintext_len = Algorithm::Aes256Gcm
            .decrypt_in_place(self.0.as_ref(), &[0u8; 12], additional_data, data)
            .map_err(|_| quinn::crypto::CryptoError)?;
        Ok(data[..plaintext_len].as_mut())
    }
}
