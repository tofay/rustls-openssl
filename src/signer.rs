use openssl::hash::MessageDigest;
use openssl::pkey::{Id, Private};
use openssl::rsa::Padding;
use openssl::sign::RsaPssSaltlen;
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;

/// A struct that implements [rustls::crypto::KeyProvider].
#[derive(Debug)]
pub struct KeyProvider;

/// RSA schemes in descending order of preference
pub(crate) static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
struct Signer {
    key: Arc<openssl::pkey::PKey<Private>>,
    scheme: SignatureScheme,
}

#[derive(Debug)]
struct PKey(Arc<openssl::pkey::PKey<Private>>);

fn rsa_padding(scheme: SignatureScheme) -> Option<Padding> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => Some(Padding::PKCS1),
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(Padding::PKCS1_PSS),
        _ => None,
    }
}

fn message_digest(scheme: SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::ECDSA_NISTP256_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::ECDSA_NISTP384_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA512
        | SignatureScheme::ECDSA_NISTP521_SHA512 => Some(MessageDigest::sha512()),
        _ => None,
    }
}

fn mgf1(scheme: SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::RSA_PSS_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::RSA_PSS_SHA512 => Some(MessageDigest::sha512()),
        _ => None,
    }
}

fn pss_salt_len(scheme: SignatureScheme) -> Option<RsaPssSaltlen> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(RsaPssSaltlen::DIGEST_LENGTH),
        _ => None,
    }
}

impl PKey {
    fn signer(&self, scheme: SignatureScheme) -> Signer {
        Signer {
            key: Arc::clone(&self.0),
            scheme,
        }
    }

    /// The ECDSA signature scheme for this key's curve, or `None` if it is not a curve
    /// this provider signs with.
    ///
    /// Read via `EVP_PKEY_get_utf8_string_param` rather than `EVP_PKEY_get1_EC_KEY`: the
    /// latter is deprecated as of OpenSSL 3.0 and downgrades a provider-backed key to a
    /// legacy one just to read its curve name.
    #[cfg(ossl300)]
    fn ecdsa_scheme(&self) -> Option<SignatureScheme> {
        use crate::openssl_internal::kem::PKeyRefExt;
        const OSSL_PKEY_PARAM_GROUP_NAME: &[u8] = b"group\0";

        let group = self
            .0
            .get_utf8_string_param(OSSL_PKEY_PARAM_GROUP_NAME)
            .ok()?;

        // OpenSSL reports the curve by its short name.
        match group.as_str() {
            "prime256v1" | "P-256" => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
            "secp384r1" | "P-384" => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
            "secp521r1" | "P-521" => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
            _ => None,
        }
    }

    /// As above, for OpenSSL before 3.0, which has no `OSSL_PARAM` accessors.
    ///
    /// This reads the curve out of the key rather than performing any cryptography, and
    /// there is no provider layer to bypass on 1.1.1 in any case.
    #[cfg(not(ossl300))]
    fn ecdsa_scheme(&self) -> Option<SignatureScheme> {
        match self.0.ec_key().ok()?.group().curve_name()? {
            openssl::nid::Nid::X9_62_PRIME256V1 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
            openssl::nid::Nid::SECP384R1 => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
            openssl::nid::Nid::SECP521R1 => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
            _ => None,
        }
    }
}

impl rustls::crypto::KeyProvider for KeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        let pkey = openssl::pkey::PKey::private_key_from_der(key_der.secret_der())
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        Ok(Arc::new(PKey(Arc::new(pkey))))
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl SigningKey for PKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        match self.algorithm() {
            SignatureAlgorithm::RSA => RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .map(|scheme| Box::new(self.signer(*scheme)) as Box<dyn rustls::sign::Signer>),

            SignatureAlgorithm::ED25519 => {
                if crate::verify::ed25519_available() && offered.contains(&SignatureScheme::ED25519)
                {
                    Some(Box::new(Signer {
                        key: Arc::clone(&self.0),
                        scheme: SignatureScheme::ED25519,
                    }))
                } else {
                    None
                }
            }
            SignatureAlgorithm::ED448 => {
                if offered.contains(&SignatureScheme::ED448) {
                    Some(Box::new(Signer {
                        key: Arc::clone(&self.0),
                        scheme: SignatureScheme::ED448,
                    }))
                } else {
                    None
                }
            }
            SignatureAlgorithm::ECDSA => {
                // First determine our scheme, then see if that was offered.
                self.ecdsa_scheme().and_then(|scheme| {
                    if offered.contains(&scheme) {
                        Some(Box::new(self.signer(scheme)) as Box<dyn rustls::sign::Signer>)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    /// Return the RFC 5280 SubjectPublicKeyInfo for this key.
    ///
    /// The `SigningKey` trait opts out of this by default, returning `None`.
    /// Leaving it at the default is not harmless: it makes
    /// [`rustls::sign::CertifiedKey::keys_match`] fail with
    /// `InconsistentKeys::Unknown` rather than succeed, because that check
    /// starts by asking the key for its SPKI and gives up when none is
    /// available. A caller that verifies its certificate and private key
    /// agree before serving — a reasonable thing to do at startup — can
    /// therefore load no certificate at all with this provider.
    ///
    /// OpenSSL already holds the public half, so producing the SPKI is a
    /// direct call. Errors map to `None` to match the trait's "unavailable"
    /// contract, which has no fallible variant.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key_to_der().ok().map(Into::into)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.0.id() {
            Id::RSA => SignatureAlgorithm::RSA,
            Id::EC => SignatureAlgorithm::ECDSA,
            Id::ED448 => SignatureAlgorithm::ED448,
            Id::ED25519 => SignatureAlgorithm::ED25519,
            _ => SignatureAlgorithm::Unknown(self.0.id().as_raw().try_into().unwrap_or_default()),
        }
    }
}

impl rustls::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(message_digest) = message_digest(self.scheme) {
            openssl::sign::Signer::new(message_digest, &self.key)
                .and_then(|mut signer| {
                    if let Some(padding) = rsa_padding(self.scheme) {
                        signer.set_rsa_padding(padding)?;
                    }
                    if let Some(mgf1) = mgf1(self.scheme) {
                        signer.set_rsa_mgf1_md(mgf1)?;
                    }
                    if let Some(len) = pss_salt_len(self.scheme) {
                        signer.set_rsa_pss_saltlen(len)?;
                    }
                    signer.update(message)?;
                    signer.sign_to_vec()
                })
                .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
        } else {
            openssl::sign::Signer::new_without_digest(&self.key)
                .and_then(|mut signer| signer.sign_oneshot_to_vec(message))
                .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
