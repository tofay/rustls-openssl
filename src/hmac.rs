use crate::hash::Algorithm;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
#[cfg(feature = "quinn")]
use openssl::sign::Verifier;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Key, Tag};

pub(crate) struct Hmac(pub(crate) Algorithm);
pub(crate) struct HmacKey {
    key: PKey<Private>,
    hash: Algorithm,
}

impl rustls::crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey {
            key: PKey::hmac(key).expect("Failed to read Hmac Key"),
            hash: self.0,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl Key for HmacKey {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        Signer::new(self.hash.message_digest(), &self.key)
            .and_then(|mut signer| {
                signer.update(first)?;
                for d in middle {
                    signer.update(d)?;
                }
                signer.update(last)?;
                Ok(Tag::new(&signer.sign_to_vec()?))
            })
            .expect("HMAC signing failed")
    }

    fn tag_len(&self) -> usize {
        self.hash.output_len()
    }
}

#[cfg(feature = "quinn")]
impl HmacKey {
    pub(crate) fn sha256(key: PKey<Private>) -> Self {
        Self {
            key,
            hash: Algorithm::SHA256,
        }
    }
}

#[cfg(feature = "quinn")]
impl quinn::crypto::HmacKey for HmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let tag = rustls::crypto::hmac::Key::sign(self, &[data]);
        signature_out.copy_from_slice(tag.as_ref());
    }

    fn signature_len(&self) -> usize {
        self.tag_len()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), quinn::crypto::CryptoError> {
        Verifier::new(self.hash.message_digest(), &self.key)
            .and_then(|mut verifier| {
                verifier.update(data)?;
                verifier.verify(signature)
            })
            .map_err(|_| quinn::crypto::CryptoError)
            .and_then(|valid| {
                if valid {
                    Ok(())
                } else {
                    Err(quinn::crypto::CryptoError)
                }
            })
    }
}
