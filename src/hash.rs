//! Provide Rustls `Hash` implementation using OpenSSL `MessageDigest`.
use openssl::hash::{Hasher, MessageDigest};
use openssl::md::{Md, MdRef};
use rustls::crypto::hash::Output;

pub(crate) static SHA256: Algorithm = Algorithm::SHA256;
pub(crate) static SHA384: Algorithm = Algorithm::SHA384;

/// Supported Hash algorithms.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Algorithm {
    SHA256,
    SHA384,
}

/// A Hash context using the EVP API.
struct Context(Hasher);

impl Clone for Context {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Algorithm {
    pub(crate) fn mdref(self) -> &'static MdRef {
        match &self {
            Algorithm::SHA256 => Md::sha256(),
            Algorithm::SHA384 => Md::sha384(),
        }
    }

    pub(crate) fn message_digest(self) -> MessageDigest {
        match &self {
            Algorithm::SHA256 => MessageDigest::sha256(),
            Algorithm::SHA384 => MessageDigest::sha384(),
        }
    }
}

impl rustls::crypto::hash::Hash for Algorithm {
    fn start(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(Context(
            Hasher::new(self.message_digest()).expect("EVP_DigestInit_ex failed"),
        ))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut hasher = Hasher::new(self.message_digest()).expect("EVP_DigestInit_ex failed");
        hasher.update(data).expect("EVP_DigestUpdate failed");
        let digest = hasher.finish().expect("EVP_DigestFinal_ex failed");
        Output::new(&digest[..])
    }

    fn output_len(&self) -> usize {
        self.message_digest().size()
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        match &self {
            Algorithm::SHA256 => rustls::crypto::hash::HashAlgorithm::SHA256,
            Algorithm::SHA384 => rustls::crypto::hash::HashAlgorithm::SHA384,
        }
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl rustls::crypto::hash::Context for Context {
    fn fork_finish(&self) -> Output {
        let mut forked = self.0.clone();
        let digest = forked.finish().expect("EVP_DigestFinal_ex failed");
        Output::new(&digest[..])
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(self.clone())
    }

    fn finish(mut self: Box<Self>) -> Output {
        let digest = self.0.finish().expect("EVP_DigestFinal_ex failed");
        Output::new(&digest[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("EVP_DigestUpdate failed");
    }
}
