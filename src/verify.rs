use core::fmt;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use rustls::{
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm},
    SignatureScheme,
};
use webpki::alg_id;

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

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};

/// RSA PSS signatures using SHA-256
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};

/// RSA PSS signatures using SHA-384
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};

/// RSA PSS signatures using SHA-512
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

/// ED25519 signatures according to RFC 8410
pub static ED25519: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
};

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-521 curve and SHA-256.
pub static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
};

/// ECDSA signatures using the P-521 curve and SHA-384.
pub static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

/// ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &OpenSslAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
};

struct OpenSslAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl fmt::Debug for OpenSslAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSSLAlgorithm")
            .field("public_key_alg_id", &self.public_key_alg_id)
            .field("signature_alg_id", &self.signature_alg_id)
            .finish()
    }
}

fn ecdsa_public_key(curve_name: Nid, public_key: &[u8]) -> Result<PKey<Public>, InvalidSignature> {
    EcGroup::from_curve_name(curve_name)
        .and_then(|group| {
            let mut ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, public_key, &mut ctx)?;
            let key = EcKey::from_public_key(&group, &point)?;
            key.try_into()
        })
        .map_err(|_| InvalidSignature)
}

impl OpenSslAlgorithm {
    fn public_key(&self, public_key: &[u8]) -> Result<PKey<Public>, InvalidSignature> {
        match self.public_key_alg_id {
            alg_id::RSA_ENCRYPTION => Rsa::public_key_from_der_pkcs1(public_key)
                .and_then(|rsa| rsa.try_into())
                .map_err(|_| InvalidSignature),
            alg_id::ECDSA_P521 => ecdsa_public_key(Nid::SECP521R1, public_key),
            alg_id::ECDSA_P384 => ecdsa_public_key(Nid::SECP384R1, public_key),
            alg_id::ECDSA_P256 => ecdsa_public_key(Nid::X9_62_PRIME256V1, public_key),
            alg_id::ED25519 => PKey::public_key_from_raw_bytes(public_key, Id::ED25519)
                .map_err(|_| InvalidSignature),

            _ => Err(InvalidSignature),
        }
    }

    fn message_digest(&self) -> Option<MessageDigest> {
        match self.signature_alg_id {
            alg_id::RSA_PKCS1_SHA256 => Some(MessageDigest::sha256()),
            alg_id::RSA_PKCS1_SHA384 => Some(MessageDigest::sha384()),
            alg_id::RSA_PKCS1_SHA512 => Some(MessageDigest::sha512()),
            alg_id::RSA_PSS_SHA256 => Some(MessageDigest::sha256()),
            alg_id::RSA_PSS_SHA384 => Some(MessageDigest::sha384()),
            alg_id::RSA_PSS_SHA512 => Some(MessageDigest::sha512()),
            alg_id::ECDSA_SHA256 => Some(MessageDigest::sha256()),
            alg_id::ECDSA_SHA384 => Some(MessageDigest::sha384()),
            alg_id::ECDSA_SHA512 => Some(MessageDigest::sha512()),
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
            alg_id::RSA_PSS_SHA256 => Some(RsaPssSaltlen::DIGEST_LENGTH),
            alg_id::RSA_PSS_SHA384 => Some(RsaPssSaltlen::DIGEST_LENGTH),
            alg_id::RSA_PSS_SHA512 => Some(RsaPssSaltlen::DIGEST_LENGTH),
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
                Some(0x04) | Some(0x02) | Some(0x03) => {}
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
        .map_err(|_| InvalidSignature)
        .and_then(|valid| if valid { Ok(()) } else { Err(InvalidSignature) })
    }
}
