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

    /// Markers exchanged with the child process below. Gated with the tests that use
    /// them: on OpenSSL 1.1.1 there is no provider layer, so neither is compiled.
    #[cfg(ossl300)]
    const CHILD_STARTED: &str = "provider-routing-child-started";
    #[cfg(ossl300)]
    const CHILD_BYPASSED: &str = "provider-routing-child-BYPASSED-the-provider-layer";
    #[cfg(ossl300)]
    const CHILD_PREMISE_BROKEN: &str = "provider-routing-child-PREMISE-BROKEN";

    /// Digests must be dispatched through OpenSSL's provider layer.
    ///
    /// This is the property that decides whether this provider can be used in FIPS mode: the
    /// validated module *is* a provider, so a digest that never reaches the provider layer
    /// never reaches the FIPS module -- while still returning a correct answer, and while
    /// `fips()` still reports `true`. No functional test can catch that, because nothing
    /// fails.
    ///
    /// So test it directly. A child process is run against an OpenSSL config that activates
    /// only the `base` provider, which implements no cryptographic algorithms. Declaring a
    /// provider section also suppresses auto-activation of the `default` provider, so in that
    /// child *no provider can supply SHA-256*. A provider-routed digest must therefore fail.
    /// One that succeeds computed in libcrypto, outside any provider, and would do the same
    /// thing inside a FIPS deployment.
    ///
    /// The child checks that premise before drawing any conclusion. On a RHEL-family host
    /// with the kernel FIPS flag set, libcrypto activates the FIPS provider whatever the
    /// config says, so SHA-256 *is* available to a provider-routed fetch and a successful
    /// digest proves nothing. Rather than fail wrongly there, the child reports the negative
    /// control as void and this test skips -- see the Rocky Linux 10.2 result in
    /// `ci/fips-vm-report.sh` output, where it first showed up as a false failure.
    ///
    /// Implemented as a subprocess because `OPENSSL_CONF` is read once, when OpenSSL
    /// initialises.
    #[cfg(ossl300)]
    #[test]
    fn digests_are_dispatched_through_the_provider_layer() {
        use std::io::Write as _;

        let conf_path = std::env::temp_dir().join(format!(
            "rustls-openssl-base-only-{}.cnf",
            std::process::id()
        ));
        let mut conf = std::fs::File::create(&conf_path).expect("failed to write OpenSSL config");
        conf.write_all(
            b"openssl_conf = openssl_init\n\
              [openssl_init]\n\
              providers = provider_sect\n\
              [provider_sect]\n\
              base = base_sect\n\
              [base_sect]\n\
              activate = 1\n",
        )
        .unwrap();
        drop(conf);

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hash::tests::digest_under_a_base_only_provider",
                "--ignored",
                "--nocapture",
            ])
            .env("OPENSSL_CONF", &conf_path)
            .output()
            .expect("failed to run child process");

        let _ = std::fs::remove_file(&conf_path);

        let out = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        // Guard against a vacuous pass: the child must actually have got as far as hashing.
        assert!(
            out.contains(CHILD_STARTED),
            "child never reached the digest; this test proved nothing.\n{out}"
        );

        // A provider supplied SHA-256 despite the config, so there is nothing to conclude.
        if out.contains(CHILD_PREMISE_BROKEN) {
            eprintln!(
                "skipping: this host activates a crypto provider regardless of OPENSSL_CONF, \
                 so the base-only negative control does not hold here.\n{out}"
            );
            return;
        }

        assert!(
            !out.contains(CHILD_BYPASSED),
            "SHA-256 was computed with only the `base` provider active, so it did not go \
             through OpenSSL's provider layer at all. In a FIPS deployment this digest would \
             be computed outside the validated module while `fips()` still reported true. \
             Digests must use EVP_MD/EVP_MD_CTX, not the low-level SHA256_* functions.\n{out}"
        );
    }

    /// The child half of [`digests_are_dispatched_through_the_provider_layer`]. Ignored so it
    /// only ever runs when that test invokes it with the right `OPENSSL_CONF`.
    #[cfg(ossl300)]
    #[test]
    #[ignore]
    fn digest_under_a_base_only_provider() {
        println!("{CHILD_STARTED}");

        // Verify the negative control: with only `base` active, no provider can supply
        // SHA-256, so this fetch must fail. If it succeeds, something outside the config
        // activated a provider and a successful digest below would prove nothing.
        if let Ok(md) = openssl::md::Md::fetch(None, "SHA256", None) {
            println!(
                "{CHILD_PREMISE_BROKEN} EVP_MD_fetch(SHA256) succeeded ({} bytes), so a \
                 provider is active despite the base-only config",
                md.size()
            );
            return;
        }

        // Provider-routed: this must fail, and `Algorithm::hash` panics when it does.
        let digest = SHA256.hash(b"abc");

        // Reaching here at all is the failure; the value is printed only to make it obvious
        // that a real digest came back.
        println!("{CHILD_BYPASSED} {}", hex::encode(digest.as_ref()));
    }
}
