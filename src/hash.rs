//! Provide Rustls `Hash` implementation using OpenSSL `MessageDigest`.
use rustls::crypto::hash::Output;
use windows::core::{Array, HSTRING};
use windows::Security::Cryptography::Core::{
    CryptographicHash, HashAlgorithmNames, HashAlgorithmProvider,
};
use windows::Security::Cryptography::CryptographicBuffer;

pub(crate) static SHA256: Algorithm = Algorithm::SHA256;
pub(crate) static SHA384: Algorithm = Algorithm::SHA384;

// Null terminated UTF-16 strings for SHA256 and SHA384
// Is there a windows macro for this?
const SHA256_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 50, 0, 53, 0, 54, 0, 0, 0];
const SHA384_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 51, 0, 56, 0, 52, 0, 0, 0];

/// The maximum hash size produced by a supported algorithm.
pub(crate) const MAX_HASH_SIZE: usize = 48;

/// Supported Hash algorithms.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Algorithm {
    SHA256,
    SHA384,
}

/// A Hash context
#[derive(Clone)]
struct Context(CryptographicHash);

impl Algorithm {
    pub(crate) fn name(&self) -> HSTRING {
        match &self {
            Self::SHA256 => HashAlgorithmNames::Sha256(),
            Self::SHA384 => HashAlgorithmNames::Sha384(),
        }
        .unwrap()
    }

    pub(crate) fn hash_algorithm_provider(&self) -> HashAlgorithmProvider {
        HashAlgorithmProvider::OpenAlgorithm(&self.name()).unwrap()
    }

    pub(crate) fn bcrypt_hash_id(&self) -> &[u8] {
        match self {
            Self::SHA256 => SHA256_ID,
            Self::SHA384 => SHA384_ID,
        }
    }
}

impl rustls::crypto::hash::Hash for Algorithm {
    fn start(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(Context(
            self.hash_algorithm_provider().CreateHash().unwrap(),
        ))
    }

    fn hash(&self, data: &[u8]) -> Output {
        //convert u8 into IBuffer
        let input_buffer = CryptographicBuffer::CreateFromByteArray(&data).unwrap();
        let output_buffer = self
            .hash_algorithm_provider()
            .HashData(&input_buffer)
            .unwrap();
        let mut array = Array::new();
        CryptographicBuffer::CopyToByteArray(&output_buffer, &mut array).unwrap();
        Output::new(&array[..])
    }

    fn output_len(&self) -> usize {
        self.hash_algorithm_provider().HashLength().unwrap() as usize
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        match &self {
            Algorithm::SHA256 => rustls::crypto::hash::HashAlgorithm::SHA256,
            Algorithm::SHA384 => rustls::crypto::hash::HashAlgorithm::SHA384,
        }
    }
}

impl Context {
    fn finish_inner(self) -> Output {
        let output_buffer = self.0.GetValueAndReset().unwrap();
        let mut array = Array::new();
        CryptographicBuffer::CopyToByteArray(&output_buffer, &mut array).unwrap();
        Output::new(&array[..])
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
        let buffer = CryptographicBuffer::CreateFromByteArray(&data).unwrap();
        self.0.Append(&buffer).unwrap();
    }
}
