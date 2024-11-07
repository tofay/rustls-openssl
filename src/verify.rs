use core::fmt;
use std::ops::RangeInclusive;

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use webpki::alg_id;

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &MyAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    range: 2048..=8192,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &MyAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    range: 2048..=8192,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &MyAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    range: 2048..=8192,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: &dyn SignatureVerificationAlgorithm = &MyAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    range: 3072..=8192,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &MyAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA256,
        range: 2048..=8192,
    };

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &MyAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA384,
        range: 2048..=8192,
    };

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &MyAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA512,
        range: 2048..=8192,
    };

struct MyAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    range: RangeInclusive<u32>, //verification_alg: &'static dyn signature::VerificationAlgorithm,
}

impl fmt::Debug for MyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MyAlgorithm")
            .field("public_key_alg_id", &self.public_key_alg_id)
            .field("signature_alg_id", &self.signature_alg_id)
            .finish()
    }
}

impl MyAlgorithm {
    fn public_key(&self, public_key: &[u8]) -> Result<PKey<Public>, InvalidSignature> {
        match self.public_key_alg_id {
            alg_id::RSA_ENCRYPTION => Rsa::public_key_from_der_pkcs1(public_key)
                .and_then(|rsa| rsa.try_into())
                .map_err(|_| InvalidSignature),
            _ => Err(InvalidSignature),
        }
    }

    fn message_digest(&self) -> Result<MessageDigest, InvalidSignature> {
        match self.signature_alg_id {
            alg_id::RSA_PKCS1_SHA256 => Ok(MessageDigest::sha256()),
            alg_id::RSA_PKCS1_SHA384 => Ok(MessageDigest::sha384()),
            alg_id::RSA_PKCS1_SHA512 => Ok(MessageDigest::sha512()),
            alg_id::RSA_PSS_SHA256 => Ok(MessageDigest::sha256()),
            alg_id::RSA_PSS_SHA384 => Ok(MessageDigest::sha384()),
            alg_id::RSA_PSS_SHA512 => Ok(MessageDigest::sha512()),
            _ => Err(InvalidSignature),
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

impl SignatureVerificationAlgorithm for MyAlgorithm {
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
        eprintln!("determining message digest");
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
        eprintln!("determining public key");
        let pkey = self.public_key(public_key)?;

        eprintln!("got public key");
        // Check the length is in the range.
        if !self.range.contains(&pkey.bits()) {
            eprintln!("key outwidth desired range");
            return Err(InvalidSignature);
        }

        let message_digest = self.message_digest()?;
        eprintln!("got message digest");
        Verifier::new(message_digest, &pkey)
            .and_then(|mut verifier| {
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
                verifier.verify(signature)?;
                Ok(())
            })
            .map_err(|e| {
                eprintln!("OpenSSL error: {}", e);
                InvalidSignature
            })
    }
}
