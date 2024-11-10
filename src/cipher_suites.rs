pub mod tls13 {
    use crate::hash::HashAlgorithm;
    use crate::hmac::{HmacSha256, HmacSha384};
    use rustls::crypto::CipherSuiteCommon;
    use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

    use rustls::crypto::tls13::HkdfUsingHmac;

    use crate::tls13::AeadAlgorithm;

    /// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
    #[cfg(feature = "chacha")]
    pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &HkdfUsingHmac(&HmacSha256),
            aead_alg: &AeadAlgorithm::ChaCha20Poly1305,
            quic: None,
        });

    /// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
    pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &HashAlgorithm::SHA384,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &HkdfUsingHmac(&HmacSha384),
            aead_alg: &AeadAlgorithm::Aes256Gcm,
            quic: None,
        });

    /// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
    pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &HkdfUsingHmac(&HmacSha256),
            aead_alg: &AeadAlgorithm::Aes128Gcm,
            quic: None,
        });
}

/// TLS 1.2
#[cfg(feature = "tls12")]
pub mod tls12 {
    use crate::hash::HashAlgorithm;
    use crate::hmac::{HmacSha256, HmacSha384};
    use crate::signer::{ECDSA_SCHEMES, RSA_SCHEMES};
    use crate::tls12::{AesGcm, Tls12Gcm};
    use rustls::{
        crypto::{tls12::PrfUsingHmac, KeyExchangeAlgorithm},
        CipherSuite, CipherSuiteCommon, SupportedCipherSuite, Tls12CipherSuite,
    };

    /// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
    #[cfg(feature = "chacha")]
    pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: u64::MAX,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: ECDSA_SCHEMES,
            aead_alg: &crate::tls12::Tls12ChaCha,
            prf_provider: &PrfUsingHmac(&HmacSha256),
        });

    /// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    #[cfg(feature = "chacha")]
    pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: u64::MAX,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: RSA_SCHEMES,
            aead_alg: &crate::tls12::Tls12ChaCha,
            prf_provider: &PrfUsingHmac(&HmacSha256),
        });

    /// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: 1 << 23,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: RSA_SCHEMES,
            aead_alg: &Tls12Gcm {
                algo_type: AesGcm::Aes128Gcm,
            },
            prf_provider: &PrfUsingHmac(&HmacSha256),
        });

    /// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                hash_provider: &HashAlgorithm::SHA384,
                confidentiality_limit: 1 << 23,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: RSA_SCHEMES,
            aead_alg: &Tls12Gcm {
                algo_type: AesGcm::Aes256Gcm,
            },
            prf_provider: &PrfUsingHmac(&HmacSha384),
        });

    /// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                hash_provider: &HashAlgorithm::SHA256,
                confidentiality_limit: 1 << 23,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: ECDSA_SCHEMES,
            aead_alg: &Tls12Gcm {
                algo_type: AesGcm::Aes128Gcm,
            },
            prf_provider: &PrfUsingHmac(&HmacSha256),
        });

    /// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                hash_provider: &HashAlgorithm::SHA384,
                confidentiality_limit: 1 << 23,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: ECDSA_SCHEMES,
            aead_alg: &Tls12Gcm {
                algo_type: AesGcm::Aes256Gcm,
            },
            prf_provider: &PrfUsingHmac(&HmacSha384),
        });
}
