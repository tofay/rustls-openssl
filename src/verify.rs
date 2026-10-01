use crate::{
    hash::Algorithm,
    hash::Algorithm::{SHA256, SHA384, SHA512},
    spki::subject_public_key_info,
};
use core::fmt;
use once_cell::sync::Lazy;
use openssl::{
    pkey::{PKey, Public},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
    sign::{RsaPssSaltlen, Verifier},
};
use rustls::pki_types::alg_id;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm},
};

#[cfg(ossl300)]
use crate::openssl_internal::PkeyCtxExt as _;

/// A [WebPkiSupportedAlgorithms] value defining the supported signature algorithms.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        ED25519,
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        //Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
        ),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

/// A [WebPkiSupportedAlgorithms] value defining the supported signature algorithms,
/// excluding ED25519 which is not available on fips enabled OpenSSL < 3.4.
static SUPPORTED_SIG_ALGS_NO_ED25519: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
        ),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static AVAILABLE_SIG_ALGS: Lazy<&'static WebPkiSupportedAlgorithms> = Lazy::new(|| {
    // ED25519 won't be available on fips enabled OpenSSL < 3.4.
    if ed25519_available() {
        &SUPPORTED_SIG_ALGS
    } else {
        &SUPPORTED_SIG_ALGS_NO_ED25519
    }
});

/// Whether this build can do Ed25519 at all.
#[cfg(ossl300)]
static ED25519_AVAILABLE: Lazy<bool> = Lazy::new(|| {
    PkeyCtx::<()>::new_from_name(crate::primed_lib_ctx(), b"ED25519\0")
        .and_then(|mut ctx| {
            ctx.keygen_init()?;
            ctx.keygen()
        })
        .is_ok()
});

/// As above, for OpenSSL before 3.0, which has one context and no way to name it.
#[cfg(not(ossl300))]
static ED25519_AVAILABLE: Lazy<bool> = Lazy::new(|| PKey::generate_ed25519().is_ok());

pub(crate) fn available_supported_sig_algs() -> &'static WebPkiSupportedAlgorithms {
    *AVAILABLE_SIG_ALGS
}

pub(crate) fn ed25519_available() -> bool {
    *ED25519_AVAILABLE
}

/// RSA PKCS#1 1.5 signatures using SHA-256.
pub(crate) static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PKCS1_SHA256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384.
pub(crate) static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PKCS1_SHA384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512.
pub(crate) static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PKCS1_SHA512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};

/// RSA PSS signatures using SHA-256.
pub(crate) static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PSS_SHA256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};

/// RSA PSS signatures using SHA-384.
pub(crate) static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PSS_SHA384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};

/// RSA PSS signatures using SHA-512.
pub(crate) static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "RSA_PSS_SHA512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

/// ED25519 signatures according to RFC 8410
pub(crate) static ED25519: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ED25519",
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
};

/// ECDSA signatures using the P-256 curve and SHA-256.
pub(crate) static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P256_SHA256",
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub(crate) static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P256_SHA384",
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub(crate) static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P384_SHA256",
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub(crate) static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P384_SHA384",
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-521 curve and SHA-256.
pub(crate) static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P521_SHA256",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-521 curve and SHA-384.
pub(crate) static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P521_SHA384",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-521 curve and SHA-512.
pub(crate) static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    display_name: "ECDSA_P521_SHA512",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
};

struct OpenSslAlgorithm {
    display_name: &'static str,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl fmt::Debug for OpenSslAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rustls_openssl Signature Verification Algorithm: {}",
            self.display_name
        )
    }
}

impl OpenSslAlgorithm {
    #[cfg(not(ossl300))]
    fn public_key(&self, public_key: &[u8]) -> Result<PKey<Public>, InvalidSignature> {
        // Only import algorithms this provider actually verifies with; `d2i_PUBKEY` would
        // otherwise happily decode anything else OpenSSL knows about.
        match self.public_key_alg_id {
            alg_id::RSA_ENCRYPTION
            | alg_id::ECDSA_P256
            | alg_id::ECDSA_P384
            | alg_id::ECDSA_P521
            | alg_id::ED25519 => {}
            _ => return Err(InvalidSignature),
        }

        let spki =
            subject_public_key_info(self.public_key_alg_id, public_key).ok_or(InvalidSignature)?;
        PKey::public_key_from_der(&spki).map_err(|_| InvalidSignature)
    }

    #[cfg(ossl300)]
    fn public_key(&self, public_key: &[u8]) -> Result<PKey<Public>, InvalidSignature> {
        match self.public_key_alg_id {
            alg_id::RSA_ENCRYPTION
            | alg_id::ECDSA_P256
            | alg_id::ECDSA_P384
            | alg_id::ECDSA_P521
            | alg_id::ED25519 => {}
            _ => return Err(InvalidSignature),
        }

        let spki =
            subject_public_key_info(self.public_key_alg_id, public_key).ok_or(InvalidSignature)?;
        use crate::openssl_internal::PKeyPublicExt;
        // Import public key into the custom library context
        PKey::<Public>::public_key_from_der_ex(crate::get_global_lib_ctx(), &spki, None)
            .map_err(|_| InvalidSignature)
    }

    fn message_digest(&self) -> Option<Algorithm> {
        match self.signature_alg_id {
            alg_id::RSA_PKCS1_SHA256 | alg_id::ECDSA_SHA256 | alg_id::RSA_PSS_SHA256 => {
                Some(SHA256)
            }
            alg_id::RSA_PKCS1_SHA384 | alg_id::ECDSA_SHA384 | alg_id::RSA_PSS_SHA384 => {
                Some(SHA384)
            }
            alg_id::RSA_PKCS1_SHA512 | alg_id::ECDSA_SHA512 | alg_id::RSA_PSS_SHA512 => {
                Some(SHA512)
            }
            _ => None,
        }
    }

    fn mgf1(&self) -> Option<Algorithm> {
        match self.signature_alg_id {
            alg_id::RSA_PSS_SHA256 => Some(SHA256),
            alg_id::RSA_PSS_SHA384 => Some(SHA384),
            alg_id::RSA_PSS_SHA512 => Some(SHA512),
            _ => None,
        }
    }

    fn pss_salt_len(&self) -> Option<RsaPssSaltlen> {
        match self.signature_alg_id {
            alg_id::RSA_PSS_SHA256 | alg_id::RSA_PSS_SHA384 | alg_id::RSA_PSS_SHA512 => {
                Some(RsaPssSaltlen::DIGEST_LENGTH)
            }
            _ => None,
        }
    }

    fn rsa_padding(&self) -> Option<Padding> {
        match self.signature_alg_id {
            alg_id::RSA_PSS_SHA512 | alg_id::RSA_PSS_SHA384 | alg_id::RSA_PSS_SHA256 => {
                Some(Padding::PKCS1_PSS)
            }
            alg_id::RSA_PKCS1_SHA512 | alg_id::RSA_PKCS1_SHA384 | alg_id::RSA_PKCS1_SHA256 => {
                Some(Padding::PKCS1)
            }
            _ => None,
        }
    }
}

impl SignatureVerificationAlgorithm for OpenSslAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if matches!(
            self.public_key_alg_id,
            alg_id::ECDSA_P256 | alg_id::ECDSA_P384 | alg_id::ECDSA_P521
        ) {
            // Restrict the allowed encodings of EC public keys.
            //
            // "The first octet of the OCTET STRING indicates whether the key is
            //  compressed or uncompressed.  The uncompressed form is indicated
            //  by 0x04 and the compressed form is indicated by either 0x02 or
            //  0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
            //  any other value is included in the first octet."
            // -- <https://datatracker.ietf.org/doc/html/rfc5480#section-2.2>
            match public_key.first() {
                Some(0x02..=0x04) => {}
                _ => {
                    return Err(InvalidSignature);
                }
            };
        }

        let pkey = self.public_key(public_key)?;

        match self.message_digest() {
            Some(algorithm) => {
                let digest = algorithm.digest(message).map_err(|_| InvalidSignature)?;

                PkeyCtx::new(&pkey)
                    .and_then(|mut ctx| {
                        ctx.verify_init()?;
                        ctx.set_signature_md(algorithm.mdref()?)?;

                        if let Some(padding) = self.rsa_padding() {
                            ctx.set_rsa_padding(padding)?;
                        }
                        if let Some(mgf1) = self.mgf1() {
                            ctx.set_rsa_mgf1_md(mgf1.mdref()?)?;
                        }
                        if let Some(salt_len) = self.pss_salt_len() {
                            ctx.set_rsa_pss_saltlen(salt_len)?;
                        }

                        ctx.verify(digest.as_ref(), signature)
                    })
                    .map_err(|_| InvalidSignature)
                    .and_then(|valid| if valid { Ok(()) } else { Err(InvalidSignature) })
            }

            // Ed25519 and Ed448 have no separate digest step: the signature is over the
            // message.
            None => Verifier::new_without_digest(&pkey)
                .and_then(|mut verifier| verifier.verify_oneshot(signature, message))
                .map_err(|_| InvalidSignature)
                .and_then(|valid| if valid { Ok(()) } else { Err(InvalidSignature) }),
        }
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(ossl300)]
    use crate::openssl_internal::PkeyCtxExt;
    use crate::hash::Algorithm;
    use openssl::{
        error::ErrorStack,
        nid::Nid,
        pkey::{Id, Private},
        pkey_ctx::PkeyCtx,
    };

    /// A fresh key, generated the way this crate generates the keys of the same kind: in the
    /// library context the whole crate works in. `name` is how the key type is spelled there,
    /// and `setup` supplies the key type's own parameters.
    #[cfg(ossl300)]
    fn generate_key(
        name: &'static [u8],
        setup: impl FnOnce(&mut PkeyCtx<()>) -> Result<(), ErrorStack>,
    ) -> PKey<Private> {
        let mut ctx = PkeyCtx::new_from_name(crate::get_global_lib_ctx(), name).unwrap();
        ctx.keygen_init().unwrap();
        setup(&mut ctx).unwrap();
        ctx.keygen().unwrap()
    }

    /// As above, for OpenSSL before 3.0, which names key types by `NID` and has one context.
    #[cfg(not(ossl300))]
    fn generate_key(
        name: &'static [u8],
        setup: impl FnOnce(&mut PkeyCtx<()>) -> Result<(), ErrorStack>,
    ) -> PKey<Private> {
        let key_type = match name {
            b"RSA\0" => Id::RSA,
            b"EC\0" => Id::EC,
            _ => unreachable!("no key type by this name in these tests"),
        };
        let mut ctx = PkeyCtx::new_id(key_type).unwrap();
        ctx.keygen_init().unwrap();
        setup(&mut ctx).unwrap();
        ctx.keygen().unwrap()
    }

    /// The type-specific public key, as the provider that holds the key reports it.
    ///
    /// On OpenSSL 3.0+ that is the key's own provider, which is where the crate's runtime
    /// code gets the same material from: the `encoded-pub-key` parameter for the EC shares,
    /// the type-specific encoding for RSA. The `not(ossl300)` arm below has no provider layer
    /// to ask, and goes through libcrypto's encoders instead.
    #[cfg(ossl300)]
    fn public_key_payload(key: &PKey<Private>, key_type: Id) -> Vec<u8> {
        use crate::openssl_internal::{PKeyRefExt as _, key::rsa_pkcs1_public_key};

        match key_type {
            Id::RSA => rsa_pkcs1_public_key(key).expect("OpenSSL public-key encoding failed"),
            Id::EC => key
                .get_octet_string_param(b"encoded-pub-key\0")
                .expect("OpenSSL public-key encoding failed"),
            _ => unreachable!(),
        }
    }

    #[cfg(not(ossl300))]
    fn public_key_payload(key: &PKey<Private>, key_type: Id) -> Vec<u8> {
        use openssl::bn::BigNumContext;
        use openssl::ec::PointConversionForm;

        match key_type {
            Id::RSA => key.rsa().unwrap().public_key_to_der_pkcs1().unwrap(),
            Id::EC => {
                let ec = key.ec_key().unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                ec.public_key()
                    .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                    .unwrap()
            }
            _ => unreachable!(),
        }
    }

    /// Import a public key the way this crate does at runtime.
    ///
    /// Same library context as the key generation these round-trips are checking: with the
    /// `ossl-context` tests in `lib.rs` a global context is set, and the default one holds no
    /// provider that could decode a key.
    fn import_public_key(spki: &[u8]) -> Result<PKey<Public>, openssl::error::ErrorStack> {
        #[cfg(not(ossl300))]
        {
            PKey::public_key_from_der(spki)
        }
        #[cfg(ossl300)]
        {
            use crate::openssl_internal::PKeyPublicExt;
            PKey::<Public>::public_key_from_der_ex(crate::get_global_lib_ctx(), spki, None)
        }
    }

    /// The SPKI we build must be exactly what OpenSSL itself would emit for the same key.
    fn assert_spki_matches_openssl(alg: AlgorithmIdentifier, payload: &[u8], key: &PKey<Private>) {
        let expected = key.public_key_to_der().unwrap();
        let spki = subject_public_key_info(alg, payload).unwrap();
        assert_eq!(spki, expected, "SPKI differs from OpenSSL's encoding");

        // ... and it must import back to the same key.
        let imported = import_public_key(&spki).unwrap();
        assert_eq!(imported.public_key_to_der().unwrap(), expected);
    }

    #[test]
    fn rsa_spki_matches_openssl() {
        // 2048-bit: the payload is well over 127 bytes, so this covers long-form lengths.
        let key = generate_key(b"RSA\0", |ctx| ctx.set_rsa_keygen_bits(2048));
        let payload = public_key_payload(&key, Id::RSA);
        assert_spki_matches_openssl(alg_id::RSA_ENCRYPTION, &payload, &key);
    }

    #[rstest::rstest]
    #[case::p256(Nid::X9_62_PRIME256V1, alg_id::ECDSA_P256)]
    #[case::p384(Nid::SECP384R1, alg_id::ECDSA_P384)]
    #[case::p521(Nid::SECP521R1, alg_id::ECDSA_P521)]
    fn ecdsa_spki_matches_openssl(#[case] nid: Nid, #[case] alg: AlgorithmIdentifier) {
        let key = generate_key(b"EC\0", |ctx| ctx.set_ec_paramgen_curve_nid(nid));
        let payload = public_key_payload(&key, Id::EC);

        assert_spki_matches_openssl(alg, &payload, &key);
    }

    #[test]
    fn ed25519_spki_matches_openssl() {
        // Ed25519 is FIPS-approved under FIPS 186-5, but modules validated before it --
        // RHEL 9's 3.0.7 provider, for one -- do not implement it. Skip rather than fail
        // when OpenSSL cannot supply it; `ed25519_available()` exists for the same reason, and
        // asks the same context this crate works in, so this is not a skip just because the
        // tests happen to have a global one.
        if !super::ed25519_available() {
            println!("skipping: OpenSSL cannot supply Ed25519 in this configuration");
            return;
        }
        let (key, payload) = crate::test_support::ed25519_key_pair();
        assert_spki_matches_openssl(alg_id::ED25519, &payload, &key);
    }

    /// `d2i_PUBKEY` decodes far more than this provider verifies with, so `public_key()`
    /// must reject anything outside its own allowlist before handing bytes to OpenSSL.
    #[test]
    fn unsupported_key_algorithms_are_rejected() {
        if crate::fips::enabled() {
            println!("skipping: FIPS provider rejects secp256k1 outright");
            return;
        }

        let secp256k1 = OpenSslAlgorithm {
            display_name: "test",
            public_key_alg_id: alg_id::ECDSA_P256K1,
            signature_alg_id: alg_id::ECDSA_SHA256,
        };

        // A well-formed secp256k1 key.
        let key = generate_key(b"EC\0", |ctx| ctx.set_ec_paramgen_curve_nid(Nid::SECP256K1));
        let payload = public_key_payload(&key, Id::EC);

        // The allowlist must reject it regardless of what OpenSSL would do with it.
        assert!(secp256k1.public_key(&payload).is_err());

        // The check above is only meaningful if OpenSSL would otherwise have accepted the
        // key, so assert that too.
        let spki = subject_public_key_info(alg_id::ECDSA_P256K1, &payload).unwrap();
        assert!(import_public_key(&spki).is_ok());
    }

    #[test]
    fn test_open_ssl_algorithm_debug() {
        assert_eq!(
            format!("{:?}", ECDSA_P256_SHA256),
            "rustls_openssl Signature Verification Algorithm: ECDSA_P256_SHA256"
        );
        assert_eq!(
            format!("{:?}", RSA_PSS_SHA256),
            "rustls_openssl Signature Verification Algorithm: RSA_PSS_SHA256"
        );
    }

    /// Wycheproof ECDSA vectors, run through the verification algorithms.
    ///
    /// Each vector's `(msg, sig, result)` is what this exercises: the algorithms are reached
    /// through a `PkeyCtx` and a pre-hashed message rather than the digest-signing API, and
    /// that path is only correct if a valid signature verifies and an invalid one does not.
    /// The `publicKeyDer` is the input side, and it has to import first for any of that to mean
    /// anything.
    #[cfg(ossl300)]
    #[test]
    fn wycheproof_ecdsa_verification() {
        use crate::openssl_internal::PKeyRefExt as _;
        use wycheproof::{TestResult, ecdsa};

        // The scheme is a property of the file, not of the individual vector.
        let sets: &[(ecdsa::TestName, SignatureScheme)] = &[
            (
                ecdsa::TestName::EcdsaSecp256r1Sha256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                ecdsa::TestName::EcdsaSecp384r1Sha384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
            (
                ecdsa::TestName::EcdsaSecp521r1Sha512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ),
        ];

        let mut checked = 0;
        let mut rejected = 0;
        for (test_name, scheme) in sets {
            let test_set = ecdsa::TestSet::load(*test_name).unwrap();
            let algorithms = SUPPORTED_SIG_ALGS
                .mapping
                .iter()
                .find(|(s, _)| s == scheme)
                .map(|(_, algorithms)| *algorithms)
                .unwrap_or_else(|| panic!("{test_name:?} has no algorithms for {scheme:?}"));

            for group in &test_set.test_groups {
                let key = import_public_key(&group.der)
                    .unwrap_or_else(|e| panic!("{test_name:?} public key should import: {e}"));
                // `verify_signature` is handed the raw public key, which for EC is the
                // uncompressed point rather than a DER structure.
                let public = key
                    .get_octet_string_param(b"encoded-pub-key\0")
                    .expect("an EC key should report its encoded public point");

                for test in &group.tests {
                    let accepted = algorithms
                        .iter()
                        .any(|alg| alg.verify_signature(&public, &test.msg, &test.sig).is_ok());
                    match test.result {
                        TestResult::Valid => assert!(
                            accepted,
                            "{test_name:?} rejected a valid signature: {}",
                            test.comment
                        ),
                        TestResult::Invalid => {
                            assert!(
                                !accepted,
                                "{test_name:?} accepted an invalid signature: {}",
                                test.comment
                            );
                            rejected += 1;
                        }
                        // `Acceptable` means the signature may or may not verify, so there is
                        // nothing to assert either way.
                        _ => {}
                    }
                    checked += 1;
                }
            }
        }

        assert!(checked > 100, "only {checked} vectors were checked");
        assert!(
            rejected > 50,
            "only {rejected} invalid vectors were checked"
        );
    }

    /// The input side: every vector's SPKI has to import, and inputs that are not keys must be
    /// refused.
    #[cfg(ossl300)]
    #[test]
    fn wycheproof_ecdsa_spki_parsing() {
        use wycheproof::ecdsa;

        // Hoisted out of the loop below: these do not depend on the vector.
        assert!(
            import_public_key(&[]).is_err(),
            "empty input should be rejected"
        );
        assert!(
            import_public_key(&[0xde, 0xad, 0xbe, 0xef]).is_err(),
            "garbage input should be rejected"
        );

        for test_name in [
            ecdsa::TestName::EcdsaSecp256r1Sha256,
            ecdsa::TestName::EcdsaSecp384r1Sha384,
            ecdsa::TestName::EcdsaSecp521r1Sha512,
        ] {
            let test_set = ecdsa::TestSet::load(test_name).unwrap();

            for (group_idx, group) in test_set.test_groups.iter().enumerate() {
                let spki: &[u8] = group.der.as_ref();

                assert!(
                    import_public_key(spki).is_ok(),
                    "{test_name:?} group {group_idx} public key should parse"
                );

                // A truncated SPKI must be rejected, not decoded as a shorter key.
                assert!(
                    import_public_key(&spki[..spki.len() - 1]).is_err(),
                    "{test_name:?} group {group_idx} truncated SPKI should be rejected"
                );
            }
        }
    }
}
