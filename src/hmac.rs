use alloc::boxed::Box;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};
use rustls::crypto::hmac::{Hmac, Key, Tag};

pub(crate) struct HmacSha256;
pub(crate) struct HmacSha256Key(PKey<Private>);

pub(crate) struct HmacSha384;
pub(crate) struct HmacSha384Key(PKey<Private>);

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha256Key(PKey::hmac(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl Key for HmacSha256Key {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.0).unwrap();
        signer.update(first).unwrap();
        for d in middle {
            signer.update(d).unwrap();
        }
        signer.update(last).unwrap();
        Tag::new(&signer.sign_to_vec().unwrap())
    }

    fn tag_len(&self) -> usize {
        32
    }
}

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha384Key(PKey::hmac(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

impl Key for HmacSha384Key {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut signer = Signer::new(MessageDigest::sha384(), &self.0).unwrap();
        signer.update(first).unwrap();
        for d in middle {
            signer.update(d).unwrap();
        }
        signer.update(last).unwrap();
        Tag::new(&signer.sign_to_vec().unwrap())
    }

    fn tag_len(&self) -> usize {
        48
    }
}
