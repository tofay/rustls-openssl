//! Provide Rustls `Hash` implementation using OpenSSL `MessageDigest`.
use openssl::{
    hash::MessageDigest,
    sha::{self, sha256, sha384},
};
use rustls::crypto::hash::{Context, Hash, Output};

pub(crate) enum HashAlgorithm {
    SHA256,
    SHA384,
}

impl HashAlgorithm {
    pub fn message_digest(&self) -> MessageDigest {
        match &self {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
        }
    }
}

impl Hash for HashAlgorithm {
    fn start(&self) -> Box<dyn Context> {
        match &self {
            HashAlgorithm::SHA256 => Box::new(Sha256Context(sha::Sha256::new())),
            HashAlgorithm::SHA384 => Box::new(Sha384Context(sha::Sha384::new())),
        }
    }

    fn hash(&self, data: &[u8]) -> Output {
        match &self {
            HashAlgorithm::SHA256 => Output::new(&sha256(data)[..]),
            HashAlgorithm::SHA384 => Output::new(&sha384(data)[..]),
        }
    }

    fn output_len(&self) -> usize {
        self.message_digest().size()
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        match &self {
            HashAlgorithm::SHA256 => rustls::crypto::hash::HashAlgorithm::SHA256,
            HashAlgorithm::SHA384 => rustls::crypto::hash::HashAlgorithm::SHA384,
        }
    }
}

struct Sha256Context(sha::Sha256);
struct Sha384Context(sha::Sha384);

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        let new_context = self.0.clone();

        Output::new(&new_context.finish()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finish()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        let new_context = self.0.clone();
        Output::new(&new_context.finish()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finish()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
