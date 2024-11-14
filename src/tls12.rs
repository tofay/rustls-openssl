use crate::hash::{SHA256, SHA384};
use crate::prf::Prf;
use crate::signer::{ECDSA_SCHEMES, RSA_SCHEMES};
use alloc::boxed::Box;
use alloc::format;
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{
    crypto::KeyExchangeAlgorithm, CipherSuite, CipherSuiteCommon, SupportedCipherSuite,
    Tls12CipherSuite,
};
use rustls::{ConnectionTrafficSecrets, Error};

const GCM_FULL_NONCE_LENGTH: usize = 12;
const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_IMPLICIT_NONCE_LENGTH: usize = 4;
const GCM_TAG_LENGTH: usize = 16;

#[cfg(chacha)]
const CHACHA_TAG_LENGTH: usize = 16;
#[cfg(chacha)]
const CHAHCA_NONCE_LENGTH: usize = 12;
#[cfg(chacha)]
const CHACHA_KEY_LENGTH: usize = 32;

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
#[cfg(chacha)]
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &Tls12ChaCha,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
#[cfg(chacha)]
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &Tls12ChaCha,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes128Gcm,
        },
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes256Gcm,
        },
        prf_provider: &Prf(SHA384),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes128Gcm,
        },
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes256Gcm,
        },
        prf_provider: &Prf(SHA384),
    });

#[cfg(chacha)]
pub(crate) struct Tls12ChaCha;

#[cfg(chacha)]
pub(crate) struct Tls12ChaCha20Poly1305 {
    key: [u8; CHACHA_KEY_LENGTH],
    iv: Iv,
}

#[cfg(chacha)]
impl Tls12AeadAlgorithm for Tls12ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        // The caller ensures that the key is the correct length.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key.copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // The caller ensures that the key is the correct length.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key.copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: CHACHA_KEY_LENGTH,
            fixed_iv_len: CHAHCA_NONCE_LENGTH,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

#[cfg(chacha)]
impl MessageEncrypter for Tls12ChaCha20Poly1305 {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        let cipher = Cipher::chacha20_poly1305();
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&alloc::vec![0u8; cipher.block_size()]);

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(Some(cipher), Some(self.key.as_ref()), Some(&nonce.0))?;
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(payload.as_mut(), msg.payload.len())?;
                let rest = ctx.cipher_final(&mut payload.as_mut()[count..])?;
                payload.truncate(count + rest);
                ctx.tag(&mut tag)?;
                payload.extend_from_slice(&tag);
                Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHA_TAG_LENGTH
    }
}

#[cfg(chacha)]
impl MessageDecrypter for Tls12ChaCha20Poly1305 {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < CHACHA_TAG_LENGTH {
            return Err(Error::DecryptError);
        }
        let message_len = payload_len - CHACHA_TAG_LENGTH;

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_len..]);

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(
                    Some(Cipher::chacha20_poly1305()),
                    Some(self.key.as_ref()),
                    Some(&nonce.0),
                )?;
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(payload, message_len)?;
                ctx.set_tag(&tag)?;
                let rest = ctx.cipher_final(&mut payload[count..])?;
                payload.truncate(count + rest);
                Ok(())
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        Ok(msg.into_plain_message())
    }
}

#[derive(Debug, Clone)]
pub(crate) enum AesGcm {
    Aes128Gcm,
    Aes256Gcm,
}

impl AesGcm {
    fn key_size(&self) -> usize {
        match self {
            AesGcm::Aes128Gcm => 16,
            AesGcm::Aes256Gcm => 32,
        }
    }

    fn openssl_cipher(&self) -> &'static CipherRef {
        match self {
            AesGcm::Aes128Gcm => Cipher::aes_128_gcm(),
            AesGcm::Aes256Gcm => Cipher::aes_256_gcm(),
        }
    }
}

pub(crate) struct Tls12Gcm {
    pub(crate) algo_type: AesGcm,
}

pub(crate) struct Gcm12Decrypt {
    algo_type: AesGcm,
    key: AeadKey,
    iv: [u8; GCM_IMPLICIT_NONCE_LENGTH],
}

pub(crate) struct Gcm12Encrypt {
    algo_type: AesGcm,
    key: AeadKey,
    full_iv: [u8; GCM_FULL_NONCE_LENGTH],
}

impl Tls12AeadAlgorithm for Tls12Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut full_iv = [0u8; GCM_FULL_NONCE_LENGTH];
        full_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        full_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(extra);

        Box::new(Gcm12Encrypt {
            algo_type: self.algo_type.clone(),
            key,
            full_iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut implicit_iv = [0u8; GCM_IMPLICIT_NONCE_LENGTH];
        implicit_iv.copy_from_slice(iv);

        Box::new(Gcm12Decrypt {
            algo_type: self.algo_type.clone(),
            key,
            iv: implicit_iv,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.algo_type.key_size(),
            fixed_iv_len: GCM_IMPLICIT_NONCE_LENGTH,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LENGTH,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut gcm_iv = [0; GCM_FULL_NONCE_LENGTH];
        gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);

        match self.algo_type.key_size() {
            16 => Ok(ConnectionTrafficSecrets::Aes128Gcm {
                key,
                iv: Iv::new(gcm_iv),
            }),
            32 => Ok(ConnectionTrafficSecrets::Aes256Gcm {
                key,
                iv: Iv::new(gcm_iv),
            }),
            _ => Err(UnsupportedOperationError),
        }
    }
}

impl MessageEncrypter for Gcm12Encrypt {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let cipher = self.algo_type.openssl_cipher();

        let nonce = Nonce::new(&Iv::copy(&self.full_iv), seq);
        payload.extend_from_slice(&nonce.0[GCM_IMPLICIT_NONCE_LENGTH..]);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&alloc::vec![0u8; cipher.block_size()]);

        let mut tag = [0u8; GCM_TAG_LENGTH];
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.encrypt_init(Some(cipher), Some(self.key.as_ref()), Some(&nonce.0))?;
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(
                    &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LENGTH..],
                    msg.payload.len(),
                )?;
                let rest = ctx.cipher_final(&mut payload.as_mut()[count..])?;
                payload.truncate(GCM_EXPLICIT_NONCE_LENGTH + count + rest);
                ctx.tag(&mut tag)?;
                payload.extend_from_slice(&tag);

                Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for Gcm12Decrypt {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < GCM_TAG_LENGTH + GCM_EXPLICIT_NONCE_LENGTH {
            return Err(Error::DecryptError);
        }

        let cipher = self.algo_type.openssl_cipher();
        let mut nonce = [0u8; GCM_FULL_NONCE_LENGTH];
        nonce[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(&self.iv);
        nonce[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LENGTH]);

        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload_len - GCM_TAG_LENGTH - GCM_EXPLICIT_NONCE_LENGTH,
        );

        // This is more complicated that the others as we have `GCM_EXPLICIT_NONCE_LENGTH`
        // bytes at the front that we don't need to decrypt, and nor do we want to include
        // in the plaintext.
        CipherCtx::new()
            .and_then(|mut ctx| {
                ctx.decrypt_init(Some(cipher), Some(self.key.as_ref()), Some(&nonce))?;
                ctx.cipher_update(&aad, None)?;
                let count = ctx.cipher_update_inplace(
                    &mut payload[GCM_EXPLICIT_NONCE_LENGTH..],
                    payload_len - GCM_TAG_LENGTH - GCM_EXPLICIT_NONCE_LENGTH,
                )?;
                ctx.set_tag(&tag)?;
                let rest = ctx.cipher_final(&mut payload[GCM_EXPLICIT_NONCE_LENGTH + count..])?;
                // copy the decrypted bytes to the front of the buffer
                payload.copy_within(
                    GCM_EXPLICIT_NONCE_LENGTH..(GCM_EXPLICIT_NONCE_LENGTH + count + rest),
                    0,
                );
                // and remove all but the decrypted bytes
                payload.truncate(count + rest);
                Ok(())
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        Ok(msg.into_plain_message())
    }
}
