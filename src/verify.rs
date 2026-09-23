use crate::spki::subject_public_key_info;
use core::fmt;
use once_cell::sync::Lazy;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Verifier},
};
use rustls::pki_types::alg_id;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm},
};

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

    fn message_digest(&self) -> Option<MessageDigest> {
        match self.signature_alg_id {
            alg_id::RSA_PKCS1_SHA256 | alg_id::ECDSA_SHA256 | alg_id::RSA_PSS_SHA256 => {
                Some(MessageDigest::sha256())
            }
            alg_id::RSA_PKCS1_SHA384 | alg_id::ECDSA_SHA384 | alg_id::RSA_PSS_SHA384 => {
                Some(MessageDigest::sha384())
            }
            alg_id::RSA_PKCS1_SHA512 | alg_id::ECDSA_SHA512 | alg_id::RSA_PSS_SHA512 => {
                Some(MessageDigest::sha512())
            }
            _ => None,
        }
    }

    fn mgf1(&self) -> Option<MessageDigest> {
        match self.signature_alg_id {
            alg_id::RSA_PSS_SHA256 => Some(MessageDigest::sha256()),
            alg_id::RSA_PSS_SHA384 => Some(MessageDigest::sha384()),
            alg_id::RSA_PSS_SHA512 => Some(MessageDigest::sha512()),
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

        if let Some(message_digest) = self.message_digest() {
            Verifier::new(message_digest, &pkey).and_then(|mut verifier| {
                if let Some(padding) = self.rsa_padding() {
                    verifier.set_rsa_padding(padding)?;
                }
                if let Some(mgf1_md) = self.mgf1() {
                    verifier.set_rsa_mgf1_md(mgf1_md)?;
                }
                if let Some(salt_len) = self.pss_salt_len() {
                    verifier.set_rsa_pss_saltlen(salt_len)?;
                }
                verifier.update(message)?;
                verifier.verify(signature)
            })
        } else {
            Verifier::new_without_digest(&pkey)
                .and_then(|mut verifier| verifier.verify_oneshot(signature, message))
        }
        .map_err(|e| {
            std::dbg!(e);
            InvalidSignature
        })
        .and_then(|valid| if valid { Ok(()) } else { Err(InvalidSignature) })
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::public_key_payload;
    use openssl::{
        nid::Nid,
        pkey::{Id, Private},
        pkey_ctx::PkeyCtx,
    };

    /// The SPKI we build must be exactly what OpenSSL itself would emit for the same key.
    fn assert_spki_matches_openssl(alg: AlgorithmIdentifier, payload: &[u8], key: &PKey<Private>) {
        let expected = key.public_key_to_der().unwrap();
        let spki = subject_public_key_info(alg, payload).unwrap();
        assert_eq!(spki, expected, "SPKI differs from OpenSSL's encoding");

        // ... and it must import back to the same key.
        let imported = PKey::public_key_from_der(&spki).unwrap();
        assert_eq!(imported.public_key_to_der().unwrap(), expected);
    }

    #[test]
    fn rsa_spki_matches_openssl() {
        // 2048-bit: the payload is well over 127 bytes, so this covers long-form lengths.
        let mut ctx = PkeyCtx::new_id(Id::RSA).unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_rsa_keygen_bits(2048).unwrap();
        let key = ctx.keygen().unwrap();
        let payload = public_key_payload(&key, Id::RSA);
        assert_spki_matches_openssl(alg_id::RSA_ENCRYPTION, &payload, &key);
    }

    #[rstest::rstest]
    #[case::p256(Nid::X9_62_PRIME256V1, alg_id::ECDSA_P256)]
    #[case::p384(Nid::SECP384R1, alg_id::ECDSA_P384)]
    #[case::p521(Nid::SECP521R1, alg_id::ECDSA_P521)]
    fn ecdsa_spki_matches_openssl(#[case] nid: Nid, #[case] alg: AlgorithmIdentifier) {
        let mut ctx = PkeyCtx::new_id(Id::EC).unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_ec_paramgen_curve_nid(nid).unwrap();
        let key = ctx.keygen().unwrap();
        let payload = public_key_payload(&key, Id::EC);

        assert_spki_matches_openssl(alg, &payload, &key);
    }

    #[test]
    fn ed25519_spki_matches_openssl() {
        // Ed25519 is FIPS-approved under FIPS 186-5, but modules validated before it --
        // RHEL 9's 3.0.7 provider, for one -- do not implement it. Skip rather than fail
        // when OpenSSL cannot supply it; `ed25519_available()` exists for the same reason.
        let Ok(key) = PKey::generate_ed25519() else {
            println!("skipping: OpenSSL cannot supply Ed25519 in this configuration");
            return;
        };
        let payload = key.raw_public_key().unwrap();
        assert_spki_matches_openssl(alg_id::ED25519, &payload, &key);
    }

    /// `d2i_PUBKEY` decodes far more than this provider verifies with, so `public_key()`
    /// must reject anything outside its own allowlist before handing bytes to OpenSSL.
    #[test]
    fn unsupported_key_algorithms_are_rejected() {
        let secp256k1 = OpenSslAlgorithm {
            display_name: "test",
            public_key_alg_id: alg_id::ECDSA_P256K1,
            signature_alg_id: alg_id::ECDSA_SHA256,
        };

        // A well-formed secp256k1 key.
        let mut ctx = PkeyCtx::new_id(Id::EC).unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_ec_paramgen_curve_nid(Nid::SECP256K1).unwrap();
        let key = ctx.keygen().unwrap();
        let payload = public_key_payload(&key, Id::EC);

        // The allowlist must reject it regardless of what OpenSSL would do with it.
        assert!(secp256k1.public_key(&payload).is_err());

        // The check above is only meaningful if OpenSSL would otherwise have accepted the
        // key, so assert that too -- but a FIPS provider refuses secp256k1 outright, which
        // makes the point moot rather than false. Don't fail the test over it.
        let spki = subject_public_key_info(alg_id::ECDSA_P256K1, &payload).unwrap();
        assert!(
            PKey::public_key_from_der(&spki).is_ok() || crate::fips::enabled(),
            "OpenSSL rejected secp256k1 outside FIPS mode; this test proves nothing here"
        );
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
}
