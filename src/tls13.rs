use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::ConnectionTrafficSecrets;

use crate::aead::{AeadAlgorithm, AeadMessageCrypter};

impl Tls13AeadAlgorithm for AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadMessageCrypter {
            algo: *self,
            key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadMessageCrypter {
            algo: *self,
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
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = self.encrypt_in_place(seq, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
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
        let aad = make_tls13_aad(payload.len());
        let plaintext_len = self.decrypt_in_place(seq, &aad, payload.as_mut())?;
        // Remove the tag from the end of the payload.
        payload.truncate(plaintext_len);
        msg.into_tls13_unpadded_message()
    }
}
