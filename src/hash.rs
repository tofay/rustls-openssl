//! Provide Rustls `Hash` implementation using OpenSSL `MessageDigest`.
use rustls::crypto::hash::Output;
use rustls::Error;
use windows::core::{Array, Interface, HSTRING};
use windows::Security::Cryptography::Core::{
    CryptographicHash, HashAlgorithmNames, HashAlgorithmProvider,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::{Buffer, IBuffer};
use windows::Win32::System::WinRT::IBufferByteAccess;

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
