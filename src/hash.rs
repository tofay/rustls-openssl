//! Provide Rustls `Hash` implementation using OpenSSL `MessageDigest`.
use openssl::hash::MessageDigest;
use openssl::md::{Md, MdRef};
use openssl::sha::{self, sha256, sha384};
use rustls::crypto::hash::Output;

pub(crate) static SHA256: Algorithm = Algorithm::SHA256;
pub(crate) static SHA384: Algorithm = Algorithm::SHA384;

/// Supported Hash algorithms.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Algorithm {
    SHA256,
    SHA384,
}

/// A Hash context
#[derive(Clone)]
enum Context {
    Sha256(sha::Sha256),
    Sha384(sha::Sha384),
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
        match &self {
            Algorithm::SHA256 => Box::new(Context::Sha256(sha::Sha256::new())),
            Algorithm::SHA384 => Box::new(Context::Sha384(sha::Sha384::new())),
        }
    }

    fn hash(&self, data: &[u8]) -> Output {
        match &self {
            Algorithm::SHA256 => Output::new(&sha256(data)[..]),
            Algorithm::SHA384 => Output::new(&sha384(data)[..]),
        }
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

impl Context {
    fn finish_inner(self) -> Output {
        match self {
            Self::Sha256(context) => Output::new(&context.finish()[..]),
            Self::Sha384(context) => Output::new(&context.finish()[..]),
        }
    }
}

impl rustls::crypto::hash::Context for Context {
    fn fork_finish(&self) -> Output {
        let new_context = Box::new(self.clone());
        new_context.finish_inner()
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> Output {
        self.finish_inner()
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(context) => context.update(data),
            Self::Sha384(context) => context.update(data),
        }
    }
}
