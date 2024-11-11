use super::aead;
use super::hash::{SHA256, SHA384};
use super::hmac::{HmacSha256, HmacSha384};
use super::quic;
use alloc::boxed::Box;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, Error, SupportedCipherSuite, Tls13CipherSuite,
};

/// The TLS1.3 ciphersuite `TLS_CHACHA20_POLY1305_SHA256`
#[cfg(feature = "chacha")]
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

#[cfg(feature = "chacha")]
pub static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&HmacSha256),
    aead_alg: &aead::Algorithm::ChaCha20Poly1305,
    quic: Some(&quic::KeyBuilder {
        packet_algo: aead::Algorithm::ChaCha20Poly1305,
        header_algo: quic::HeaderProtectionAlgorithm::ChaCha20,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        confidentiality_limit: u64::MAX,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite `TLS_AES_256_GCM_SHA384`
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha384),
        aead_alg: &aead::Algorithm::Aes256Gcm,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::Algorithm::Aes256Gcm,
            header_algo: quic::HeaderProtectionAlgorithm::Aes256,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_128_GCM_SHA256`
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &HkdfUsingHmac(&HmacSha256),
    aead_alg: &aead::Algorithm::Aes128Gcm,
    quic: Some(&quic::KeyBuilder {
        packet_algo: aead::Algorithm::Aes128Gcm,
        header_algo: quic::HeaderProtectionAlgorithm::Aes128,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

impl Tls13AeadAlgorithm for aead::Algorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(aead::MessageCrypter {
            algo: *self,
            key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(aead::MessageCrypter {
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
            aead::Algorithm::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            aead::Algorithm::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            #[cfg(feature = "chacha")]
            aead::Algorithm::ChaCha20Poly1305 => {
                ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
            }
        })
    }
}

impl MessageEncrypter for aead::MessageCrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
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
        payload_len + 1 + aead::TAG_LEN
    }
}

impl MessageDecrypter for aead::MessageCrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let aad = make_tls13_aad(payload.len());
        let plaintext_len = self.decrypt_in_place(seq, &aad, payload.as_mut())?;
        // Remove the tag from the end of the payload.
        payload.truncate(plaintext_len);
        msg.into_tls13_unpadded_message()
    }
}
