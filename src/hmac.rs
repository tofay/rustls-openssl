use crate::hash::Algorithm;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Key, Tag};

pub(crate) struct Hmac(pub(crate) Algorithm);
struct HmacKey {
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
