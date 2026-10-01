//! Test support, shared by the unit tests and the integration tests.
//!
//! `tests/it.rs` includes this file with `#[path]`, so it is compiled as part of that crate
//! too. That is why everything here goes through `rustls_openssl`'s *public* API -- which the
//! crate can name in itself too, via `extern crate self` in `lib.rs`. The point of the
//! constraint is that this file behaves the same way in both binaries: what the integration
//! tests can reach, the unit tests can too, and vice versa.

// Each binary uses a different part of this file -- the unit tests do not need the SPKI
// reader, and the standalone `tests/server.rs` target only needs the Ed25519 key -- so not
// everything here is used by every one of them.
#![allow(dead_code)]

use openssl::pkey::{PKey, Private};

/// Poison the default library context with a canary property query.
///
/// This is declared here rather than going through the crate's private `openssl_internal`
/// module because this file is included via `#[path]` in both the lib and the integration
/// tests, and the integration test crate cannot access private modules of `rustls_openssl`.
#[cfg(all(feature = "ossl-context", ossl300))]
fn restrict_default_lib_ctx() {
    use openssl_sys::OSSL_LIB_CTX;
    use std::ffi::{CString, c_char};
    use std::ptr;

    unsafe extern "C" {
        fn EVP_set_default_properties(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> i32;
    }

    let propq = CString::new("provider=rustls-openssl-canary").unwrap();
    let rc = unsafe { EVP_set_default_properties(ptr::null_mut(), propq.as_ptr()) };
    if rc != 1 {
        panic!("failed to restrict the default library context");
    }
}

/// The library context for the tests, with the canary that says the default context must not
/// be used.
///
/// Requires OpenSSL 3.0 or later, the first version with library contexts; on OpenSSL 1.1.1
/// there is nothing to build and the crate runs in the single default one.
///
/// The default context is restricted to a provider that does not exist, so every fetch from it
/// fails, and the asserts below pin that down: the custom context has to be able to do real
/// work, and the default one must not be able to. That is what makes the difference between
/// "this crate uses the application's providers" and "this crate happens to work" visible.
///
/// A property query is how that is arranged, rather than loading the `null` provider into the
/// default context, because the providers a process finds there are not this crate's to
/// choose: a system with crypto policies in force, or one built for FIPS, arrives with
/// providers already active, and a provider loaded alongside those supplies nothing and
/// displaces nothing. A property query they cannot satisfy does displace them.
///
/// There is no need to load the `default` provider into the returned context: OpenSSL 3.0
/// activates it on first use in any library context, so the key operations in the test suite
/// go through a real provider in the custom context.
#[cfg(all(feature = "ossl-context", ossl300))]
pub fn global_lib_ctx() -> openssl::lib_ctx::LibCtx {
    use openssl::cipher::Cipher;
    use openssl::lib_ctx::LibCtx;

    let ctx = LibCtx::new().expect("failed to create a library context");
    restrict_default_lib_ctx();
    assert!(Cipher::fetch(Some(&ctx), "AES-128-GCM", None).is_ok());
    assert!(Cipher::fetch(None, "AES-256-GCM", None).is_err());
    ctx
}

/// An Ed25519 key, and its public half, in the global library context.
///
/// From OpenSSL, because rcgen's Ed25519 keys are PKCS#8 v2, which OpenSSL cannot read
/// (<https://github.com/openssl/openssl/issues/10468>).
///
/// On OpenSSL 3.0 and later the seed is imported into the global library context rather than
/// generated, because `PKey::generate_ed25519` names the default one, which with the
/// `ossl-context` tests can do nothing at all. The seed is fixed:
/// this is a throwaway key for the tests, and a deterministic one is easier to debug than a
/// random one.
#[cfg(ossl300)]
pub fn ed25519_key_pair() -> (PKey<Private>, Vec<u8>) {
    use openssl::pkey::KeyType;

    let key = PKey::private_key_from_raw_bytes_ex(
        rustls_openssl::get_global_lib_ctx(),
        KeyType::ED25519,
        None,
        &[7u8; 32],
    )
    .expect("failed to import an Ed25519 key");
    let public = key
        .raw_public_key()
        .expect("failed to export the Ed25519 public key");
    (key, public)
}

/// As above, for OpenSSL before 3.0, which has no library context to import into.
#[cfg(not(ossl300))]
pub fn ed25519_key_pair() -> (PKey<Private>, Vec<u8>) {
    let key = PKey::generate_ed25519().expect("failed to generate an Ed25519 key");
    let public = key
        .raw_public_key()
        .expect("failed to export the Ed25519 public key");
    (key, public)
}

/// The type-specific public-key encoding consumed by rustls: a PKCS#1 `RSAPublicKey` for RSA,
/// an uncompressed SEC1 point for EC.
///
/// Not the SPKI: the payload `SignatureVerificationAlgorithm::verify_signature` is handed at
/// runtime is the PKCS#1 body for RSA and the bare point for EC, so that is what a test
/// checking a signature has to pass. Read out of the SubjectPublicKeyInfo of a key rcgen
/// generated, which is what the tests here use: the payload a TLS stack hands to
/// `verify_signature` is exactly the `subjectPublicKey` of the peer's SPKI, so this is if
/// anything more faithful than asking OpenSSL for the key's idea of itself.
pub fn public_key_payload_from_spki(spki: &[u8]) -> Vec<u8> {
    /// One DER TLV: the tag, the length header, and the rest of the input.
    fn read_tlv(input: &[u8], tag: u8) -> (Vec<u8>, &[u8]) {
        assert_eq!(
            input.first(),
            Some(&tag),
            "expected DER tag {tag:#x}, got {input:?}"
        );
        let (len, header_len) = match input.get(1) {
            Some(&len) if len < 0x80 => (len as usize, 2),
            Some(&0x81) => (*input.get(2).expect("truncated DER length") as usize, 3),
            Some(&0x82) => (
                u16::from_be_bytes([
                    *input.get(2).expect("truncated DER length"),
                    *input.get(3).expect("truncated DER length"),
                ]) as usize,
                4,
            ),
            other => panic!("unsupported DER length header: {other:?}"),
        };
        let content = input
            .get(header_len..header_len + len)
            .expect("truncated DER value")
            .to_vec();
        (content, &input[header_len + len..])
    }

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let (contents, rest) = read_tlv(spki, 0x30);
    assert!(
        rest.is_empty(),
        "trailing data after the SubjectPublicKeyInfo"
    );
    let (algorithm, rest) = read_tlv(&contents, 0x30);
    assert!(!algorithm.is_empty(), "empty AlgorithmIdentifier");
    let (subject_public_key, rest) = read_tlv(rest, 0x03);
    assert!(rest.is_empty(), "trailing data after the subjectPublicKey");

    // The first content octet of a BIT STRING is the count of unused bits, which is zero for
    // every key encoding.
    assert_eq!(
        subject_public_key.first(),
        Some(&0),
        "expected no unused bits in the subjectPublicKey"
    );
    subject_public_key[1..].to_vec()
}
