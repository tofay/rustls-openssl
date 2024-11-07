use openssl::hash::MessageDigest;
use openssl::pkey::{Id, Private};
use openssl::rsa::Padding;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;

use crate::cipher_suites::TLS12_RSA_SCHEMES;

#[derive(Debug)]
pub(crate) struct Provider;

#[derive(Debug)]
struct PKey(Arc<openssl::pkey::PKey<Private>>);

fn rsa_padding(scheme: &SignatureScheme) -> Option<Padding> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA1
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => Some(Padding::PKCS1),
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(Padding::PKCS1_PSS),
        _ => None,
    }
}

fn message_digest(scheme: &SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => Some(MessageDigest::sha1()),
        SignatureScheme::RSA_PKCS1_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::RSA_PKCS1_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::RSA_PKCS1_SHA512 => Some(MessageDigest::sha512()),
        SignatureScheme::RSA_PSS_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::RSA_PSS_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::RSA_PSS_SHA512 => Some(MessageDigest::sha512()),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Some(MessageDigest::sha512()),
        _ => None,
    }
}

impl PKey {
    fn signer(&self, scheme: &SignatureScheme) -> Signer {
        Signer {
            key: Arc::clone(&self.0),
            scheme: *scheme,
        }
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Ok(Arc::new(PKey(Arc::new(
            openssl::pkey::PKey::private_key_from_der(key_der.secret_der()).unwrap(),
        ))))
    }
}

impl SigningKey for PKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        match self.algorithm() {
            SignatureAlgorithm::RSA => TLS12_RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .map(|scheme| Box::new(self.signer(scheme)) as Box<dyn rustls::sign::Signer>),

            SignatureAlgorithm::ED25519 => {
                if offered.contains(&SignatureScheme::ED25519) {
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
            // SignatureAlgorithm::ECDSA => ALL_ECDSA_SCHEMES
            //     .iter()
            //     .find(|scheme| offered.contains(scheme))
            //     .map(|scheme| {
            //         Box::new(self.digest_signer(scheme)) as Box<dyn rustls::sign::Signer>
            //     }),
            _ => None,
        }
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

#[derive(Debug)]
struct Signer {
    key: Arc<openssl::pkey::PKey<Private>>,
    scheme: SignatureScheme,
}

impl rustls::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(message_digest) = message_digest(&self.scheme) {
            openssl::sign::Signer::new(message_digest, &self.key)
                .and_then(|mut signer| {
                    if let Some(padding) = rsa_padding(&self.scheme) {
                        signer.set_rsa_padding(padding)?;
                    }
                    signer.update(message)?;
                    signer.sign_to_vec()
                })
                .map_err(|e| Error::General(format!("OpenSSL error: {}", e)))
        } else {
            openssl::sign::Signer::new_without_digest(&self.key)
                .and_then(|mut signer| signer.sign_oneshot_to_vec(message))
                .map_err(|e| Error::General(format!("OpenSSL error: {}", e)))
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
