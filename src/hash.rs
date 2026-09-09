//! Provide Rustls `Hash` implementation using OpenSSL `EVP_MD` digests.
//!
//! Digests must go through `EVP_MD`/`EVP_MD_CTX` rather than the low-level `SHA256_Init`
//! family: only the EVP calls are dispatched through OpenSSL's provider layer, so only they
//! reach the FIPS provider when it is in use.
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

/// A Hash context, wrapping an `EVP_MD_CTX`.
///
/// `Hasher`'s `Clone` impl is `EVP_MD_CTX_copy_ex`, which is what lets [`Context::fork`] and
/// [`Context::fork_finish`] snapshot a partial transcript.
#[derive(Clone)]
struct Context(Hasher);

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
            Hasher::new(self.message_digest()).expect("Failed to create OpenSSL digest context"),
        ))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(
            &openssl::hash::hash(self.message_digest(), data).expect("OpenSSL digest failed")[..],
        )
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
    fn finish_inner(mut self) -> Output {
        Output::new(&self.0.finish().expect("OpenSSL digest failed")[..])
    }
}

impl rustls::crypto::hash::Context for Context {
    fn fork_finish(&self) -> Output {
        self.clone().finish_inner()
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> Output {
        self.finish_inner()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("OpenSSL digest update failed");
    }
}

#[cfg(test)]
mod tests {
    use super::{SHA256, SHA384};
    use rustls::crypto::hash::Hash as _;

    // Known-answer vectors from FIPS 180-4.
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA384_ABC: &str = concat!(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163",
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    const SHA384_EMPTY: &str = concat!(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743",
        "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    #[test]
    fn one_shot_matches_known_answers() {
        assert_eq!(hex::encode(SHA256.hash(b"abc").as_ref()), SHA256_ABC);
        assert_eq!(hex::encode(SHA256.hash(b"").as_ref()), SHA256_EMPTY);
        assert_eq!(hex::encode(SHA384.hash(b"abc").as_ref()), SHA384_ABC);
        assert_eq!(hex::encode(SHA384.hash(b"").as_ref()), SHA384_EMPTY);
    }

    #[test]
    fn streaming_matches_known_answers() {
        // Fed in several updates, as the handshake transcript is.
        let mut ctx = SHA256.start();
        ctx.update(b"a");
        ctx.update(b"");
        ctx.update(b"bc");
        assert_eq!(hex::encode(ctx.finish().as_ref()), SHA256_ABC);

        let mut ctx = SHA384.start();
        ctx.update(b"ab");
        ctx.update(b"c");
        assert_eq!(hex::encode(ctx.finish().as_ref()), SHA384_ABC);

        let ctx = SHA256.start();
        assert_eq!(hex::encode(ctx.finish().as_ref()), SHA256_EMPTY);
    }

    #[test]
    fn output_len_matches_digest() {
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA384.output_len(), 48);
    }

    /// `fork` must copy the context (`EVP_MD_CTX_copy_ex`), not alias it.
    #[test]
    fn fork_produces_an_independent_context() {
        let mut ctx = SHA256.start();
        ctx.update(b"a");

        let mut forked = ctx.fork();
        forked.update(b"bc");
        // Diverge the original, to prove the two are not sharing state.
        ctx.update(b"XX");

        assert_eq!(hex::encode(forked.finish().as_ref()), SHA256_ABC);
        assert_eq!(
            hex::encode(ctx.finish().as_ref()),
            hex::encode(SHA256.hash(b"aXX").as_ref())
        );
    }

    /// `fork_finish` snapshots the transcript; the trait requires the context stay usable.
    #[test]
    fn fork_finish_leaves_the_original_usable() {
        let mut ctx = SHA384.start();
        ctx.update(b"abc");

        assert_eq!(hex::encode(ctx.fork_finish().as_ref()), SHA384_ABC);
        // Repeatable, and non-consuming.
        assert_eq!(hex::encode(ctx.fork_finish().as_ref()), SHA384_ABC);

        ctx.update(b"def");
        assert_eq!(
            hex::encode(ctx.finish().as_ref()),
            hex::encode(SHA384.hash(b"abcdef").as_ref())
        );
    }
}
