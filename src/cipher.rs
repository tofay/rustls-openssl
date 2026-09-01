use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
};
use rustls::Error;
use std::sync::OnceLock;

/// Every distinct OpenSSL cipher this crate loads
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Ecb,
    Aes256Ecb,
    ChaCha20,
}

impl CipherKind {
    fn fetch_name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Aes128Ecb => "AES-128-ECB",
            Self::Aes256Ecb => "AES-256-ECB",
            Self::ChaCha20 => "ChaCha20",
        }
    }

    /// Load the OpenSSL cipher for this algorithm, caching it in a static variable.
    #[cfg(ossl300)]
    pub(crate) fn load(self) -> Result<&'static CipherRef, Error> {
        static AES128_GCM: OnceLock<Result<Cipher, Error>> = OnceLock::new();
        static AES256_GCM: OnceLock<Result<Cipher, Error>> = OnceLock::new();
        static CHACHA20_POLY1305: OnceLock<Result<Cipher, Error>> = OnceLock::new();
        static AES128_ECB: OnceLock<Result<Cipher, Error>> = OnceLock::new();
        static AES256_ECB: OnceLock<Result<Cipher, Error>> = OnceLock::new();
        static CHACHA20: OnceLock<Result<Cipher, Error>> = OnceLock::new();

        let cache = match self {
            Self::Aes128Gcm => &AES128_GCM,
            Self::Aes256Gcm => &AES256_GCM,
            Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            Self::Aes128Ecb => &AES128_ECB,
            Self::Aes256Ecb => &AES256_ECB,
            Self::ChaCha20 => &CHACHA20,
        };

        let name = self.fetch_name();
        match cache.get_or_init(|| {
            Cipher::fetch(None, name, None)
                .map_err(|e| Error::General(format!("Failed to load {name}: {e}")))
        }) {
            Ok(cipher) => Ok(&**cipher),
            Err(e) => Err(e.clone()),
        }
    }

    #[cfg(not(ossl300))]
    pub(crate) fn load(self) -> Result<&'static CipherRef, Error> {
        match self {
            Self::Aes128Gcm => Ok(Cipher::aes_128_gcm()),
            Self::Aes256Gcm => Ok(Cipher::aes_256_gcm()),
            Self::Aes128Ecb => Ok(Cipher::aes_128_ecb()),
            Self::Aes256Ecb => Ok(Cipher::aes_256_ecb()),
            Self::ChaCha20Poly1305 => Self::chacha20_poly1305_static(),
            Self::ChaCha20 => Self::chacha20_static(),
        }
    }

    #[cfg(all(not(ossl300), chacha))]
    fn chacha20_poly1305_static() -> Result<&'static CipherRef, Error> {
        Ok(Cipher::chacha20_poly1305())
    }
    #[cfg(all(not(ossl300), not(chacha)))]
    fn chacha20_poly1305_static() -> Result<&'static CipherRef, Error> {
        Err(Error::General(
            "ChaCha20-Poly1305 not available: OpenSSL built without ChaCha support".into(),
        ))
    }

    #[cfg(all(not(ossl300), chacha))]
    fn chacha20_static() -> Result<&'static CipherRef, Error> {
        Ok(Cipher::chacha20())
    }
    #[cfg(all(not(ossl300), not(chacha)))]
    fn chacha20_static() -> Result<&'static CipherRef, Error> {
        Err(Error::General(
            "ChaCha20 not available: OpenSSL built without ChaCha support".into(),
        ))
    }

    pub(crate) fn is_available(self) -> bool {
        static AVAIL: [OnceLock<bool>; 6] = [const { OnceLock::new() }; 6];
        *AVAIL[self as usize].get_or_init(|| self.probe_availability())
    }

    /// Check if this cipher is available at runtime.
    /// This performs actual OpenSSL initialization to verify the cipher is usable.
    fn probe_availability(self) -> bool {
        self.load()
            .map(|handle| {
                let key = vec![0u8; handle.key_length()];
                let nonce = vec![0u8; handle.iv_length()];

                CipherCtx::new()
                    .and_then(|mut ctx| ctx.encrypt_init(Some(handle), Some(&key), Some(&nonce)))
                    .is_ok()
            })
            .unwrap_or(false)
    }
}
