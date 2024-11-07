use openssl::cipher::CipherRef;
use openssl::cipher_ctx::CipherCtx;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::ConnectionTrafficSecrets;

pub(crate) struct AeadMessageCrypter {
    pub algo: AeadAlgorithm,
    pub key: AeadKey,
    pub iv: Iv,
}

#[derive(Clone)]
pub(crate) enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    #[cfg(feature = "chacha")]
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    fn openssl_cipher(&self) -> &'static CipherRef {
        match self {
            AeadAlgorithm::Aes128Gcm => openssl::cipher::Cipher::aes_128_gcm(),
            AeadAlgorithm::Aes256Gcm => openssl::cipher::Cipher::aes_256_gcm(),
            #[cfg(feature = "chacha")]
            AeadAlgorithm::ChaCha20Poly1305 => openssl::cipher::Cipher::chacha20_poly1305(),
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 16,
            #[cfg(feature = "chacha")]
            AeadAlgorithm::ChaCha20Poly1305 => 16,
        }
    }
}

impl Tls13AeadAlgorithm for AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadMessageCrypter {
            algo: self.clone(),
            key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadMessageCrypter {
            algo: self.clone(),
            key,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.openssl_cipher().key_length()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self {
            AeadAlgorithm::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            AeadAlgorithm::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            #[cfg(feature = "chacha")]
            AeadAlgorithm::ChaCha20Poly1305 => {
                ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
            }
        })
    }
}

impl MessageEncrypter for AeadMessageCrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        // https://docs.rs/openssl/latest/openssl/cipher_ctx/struct.CipherCtxRef.html#method.cipher_update_inplace
        // below requires the buffer to be block_size larger than the actual data
        payload.extend_from_slice(&vec![0u8; self.algo.openssl_cipher().block_size()]);
        let mut tag = vec![0u8; self.algo.tag_len()];

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(
                    Some(self.algo.openssl_cipher()),
                    Some(self.key.as_ref()),
                    Some(&nonce.0),
                )?;
                // Providing no output buffer implies input is AAD.
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(payload.as_mut(), msg.payload.len() + 1)?;
                let rest = ctx.cipher_final(&mut payload.as_mut()[count..])?;
                payload.truncate(count + rest);
                ctx.tag(&mut tag)?;
                payload.extend_from_slice(&tag);
                Ok(OutboundOpaqueMessage::new(
                    rustls::ContentType::ApplicationData,
                    // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
                    // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                    rustls::ProtocolVersion::TLSv1_2,
                    payload,
                ))
            })
            .map_err(|e| rustls::Error::General(format!("OpeenSSL error: {}", e)))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.algo.tag_len()
    }
}

impl MessageDecrypter for AeadMessageCrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.algo.tag_len() {
            return Err(rustls::Error::DecryptError);
        }

        let message_len = payload.len() - self.algo.tag_len();
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut tag = vec![0u8; self.algo.tag_len()];
        tag.copy_from_slice(&payload[message_len..]);

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(
                    Some(self.algo.openssl_cipher()),
                    Some(self.key.as_ref()),
                    Some(&nonce.0),
                )
                .unwrap();
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(payload, message_len)?;
                ctx.set_tag(&tag)?;
                let rest = ctx.cipher_final(&mut payload[count..]).unwrap();
                payload.truncate(count + rest);
                Ok(())
            })
            .map_err(|e| rustls::Error::General(format!("OpenSSL error: {}", e)))?;
        msg.into_tls13_unpadded_message()
    }
}
