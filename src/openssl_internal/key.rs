//! Key import, export and parameter access, for OpenSSL 3.0 and later.

use std::ffi::{CString, c_char, c_long, c_uchar};
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::lib_ctx::LibCtxRef;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl_sys::{EVP_PKEY, OSSL_LIB_CTX, c_int};

use super::{cvt, cvt_p};

unsafe extern "C" {
    fn d2i_PUBKEY_ex(
        a: *mut *mut EVP_PKEY,
        pp: *mut *const c_uchar,
        length: c_long,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> *mut EVP_PKEY;

    fn d2i_AutoPrivateKey_ex(
        a: *mut *mut EVP_PKEY,
        pp: *mut *const c_uchar,
        length: c_long,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> *mut EVP_PKEY;

    fn EVP_PKEY_get_octet_string_param(
        pkey: *const EVP_PKEY,
        key_name: *const c_char,
        buf: *mut c_uchar,
        max_buf_sz: usize,
        out_sz: *mut usize,
    ) -> c_int;

    fn EVP_PKEY_get_utf8_string_param(
        pkey: *const EVP_PKEY,
        key_name: *const c_char,
        str_: *mut c_char,
        max_buf_sz: usize,
        out_sz: *mut usize,
    ) -> c_int;
}

pub trait PKeyPublicExt {
    /// Decodes a DER-encoded SubjectPublicKeyInfo structure within a specific `OSSL_LIB_CTX`.
    ///
    /// Corresponds to `d2i_PUBKEY_ex`.
    fn public_key_from_der_ex(
        ctx: Option<&LibCtxRef>,
        der: &[u8],
        propq: Option<&str>,
    ) -> Result<PKey<Public>, ErrorStack>;
}

impl PKeyPublicExt for PKey<Public> {
    fn public_key_from_der_ex(
        ctx: Option<&LibCtxRef>,
        der: &[u8],
        propq: Option<&str>,
    ) -> Result<PKey<Public>, ErrorStack> {
        unsafe {
            openssl_sys::init();

            let propq_c = propq_c(propq)?;
            let len = der_len(der)?;
            let mut der_ptr = der.as_ptr();

            let pkey_ptr = cvt_p(d2i_PUBKEY_ex(
                ptr::null_mut(),
                &mut der_ptr,
                len,
                raw_libctx(ctx),
                raw_propq(propq_c.as_ref()),
            ))?;

            Ok(PKey::from_ptr(pkey_ptr))
        }
    }
}

pub trait PKeyPrivateExt {
    /// Decodes a DER-encoded private key within a specific `OSSL_LIB_CTX`.
    ///
    /// Corresponds to `d2i_AutoPrivateKey_ex`.
    fn private_key_from_der_ex(
        ctx: Option<&LibCtxRef>,
        der: &[u8],
        propq: Option<&str>,
    ) -> Result<PKey<Private>, ErrorStack>;
}

impl PKeyPrivateExt for PKey<Private> {
    fn private_key_from_der_ex(
        ctx: Option<&LibCtxRef>,
        der: &[u8],
        propq: Option<&str>,
    ) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            openssl_sys::init();

            let propq_c = propq_c(propq)?;
            let len = der_len(der)?;
            let mut der_ptr = der.as_ptr();

            let pkey_ptr = cvt_p(d2i_AutoPrivateKey_ex(
                ptr::null_mut(),
                &mut der_ptr,
                len,
                raw_libctx(ctx),
                raw_propq(propq_c.as_ref()),
            ))?;

            Ok(PKey::from_ptr(pkey_ptr))
        }
    }
}

pub trait PKeyRefExt {
    /// Returns the octet string parameter for the specified key name.
    fn get_octet_string_param(&self, key_name: &[u8]) -> Result<Vec<u8>, ErrorStack>;
    /// Returns the UTF-8 string parameter for the specified key name.
    fn get_utf8_string_param(&self, key_name: &[u8]) -> Result<String, ErrorStack>;
}

impl<T> PKeyRefExt for PKeyRef<T> {
    fn get_octet_string_param(&self, key_name: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let mut out_len = 0;
        unsafe {
            cvt(EVP_PKEY_get_octet_string_param(
                self.as_ptr(),
                key_name.as_ptr().cast(),
                ptr::null_mut(),
                0,
                &mut out_len,
            ))?;
        }

        let mut out = vec![0; out_len];
        unsafe {
            cvt(EVP_PKEY_get_octet_string_param(
                self.as_ptr(),
                key_name.as_ptr().cast(),
                out.as_mut_ptr(),
                out_len,
                &mut out_len,
            ))?;
        }
        out.truncate(out_len);
        Ok(out)
    }

    fn get_utf8_string_param(&self, key_name: &[u8]) -> Result<String, ErrorStack> {
        let mut out_len = 0;
        unsafe {
            cvt(EVP_PKEY_get_utf8_string_param(
                self.as_ptr(),
                key_name.as_ptr().cast(),
                ptr::null_mut(),
                0,
                &mut out_len,
            ))?;
        }

        // `EVP_PKEY_get_utf8_string_param` reports the length *excluding* the NUL terminator,
        // and fails outright when the buffer is exactly that long, because it null-terminates
        // what it writes. A 10-byte buffer for a P-256 key's 10-character `"prime256v1"` group
        // name returns 0 and leaves the error queue empty, so one extra byte is required.
        let mut buf = vec![0 as c_char; out_len + 1];
        unsafe {
            cvt(EVP_PKEY_get_utf8_string_param(
                self.as_ptr(),
                key_name.as_ptr().cast(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut out_len,
            ))?;
        }

        let bytes: Vec<u8> = buf[..out_len].iter().map(|&c| c as u8).collect();
        // A non-UTF-8 parameter would be an OpenSSL bug; there is nothing useful to add to the
        // error, and `ErrorStack::get()` drains whatever OpenSSL did leave behind.
        String::from_utf8(bytes).map_err(|_| ErrorStack::get())
    }
}

/// The public half of an RSA key, as a PKCS#1 `RSAPublicKey`.
///
/// This is the encoding TLS and rustls use for RSA key shares, and it is what
/// [`crate::spki::subject_public_key_info`] is handed at verification time.
#[cfg(test)]
pub fn rsa_pkcs1_public_key(key: &PKeyRef<Private>) -> Result<Vec<u8>, ErrorStack> {
    use openssl_sys::{
        EVP_PKEY_PUBLIC_KEY, OPENSSL_free, OSSL_ENCODER_CTX_free, OSSL_ENCODER_CTX_new_for_pkey,
        OSSL_ENCODER_to_data,
    };

    let encoder = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            key.as_ptr(),
            EVP_PKEY_PUBLIC_KEY,
            c"DER".as_ptr(),
            c"type-specific".as_ptr(),
            ptr::null(),
        )
    };
    if encoder.is_null() {
        return Err(ErrorStack::get());
    }

    let mut der = ptr::null_mut();
    let mut der_len = 0;
    let encoded = unsafe { OSSL_ENCODER_to_data(encoder, &mut der, &mut der_len) };
    let payload = if encoded == 1 {
        // `OSSL_ENCODER_to_data` only sets `der` on success.
        Some(unsafe { std::slice::from_raw_parts(der.cast_const(), der_len) }.to_vec())
    } else {
        None
    };
    if !der.is_null() {
        unsafe { OPENSSL_free(der.cast()) };
    }
    unsafe { OSSL_ENCODER_CTX_free(encoder) };

    // A failure here leaves OpenSSL's error queue empty, so this reports nothing useful; the
    // caller adds its own context.
    payload.ok_or_else(ErrorStack::get)
}

/// The `propq` of a decoder or fetcher, as the C string OpenSSL wants.
fn propq_c(propq: Option<&str>) -> Result<Option<CString>, ErrorStack> {
    propq
        .map(|propq| CString::new(propq).map_err(|_| ErrorStack::get()))
        .transpose()
}

/// The length argument of the `d2i_*` functions, which take a `long`.
///
/// Fails rather than saturating: telling a decoder that the buffer is *longer* than it is would
/// have it read past the end, and telling it it is zero-length is a clean rejection.
fn der_len(der: &[u8]) -> Result<c_long, ErrorStack> {
    c_long::try_from(der.len()).map_err(|_| ErrorStack::get())
}

/// A library context for the `d2i_*` functions, which take a nullable one.
fn raw_libctx(ctx: Option<&LibCtxRef>) -> *mut OSSL_LIB_CTX {
    ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr)
}

/// A property query for the `d2i_*` functions, which take a nullable one.
fn raw_propq(propq: Option<&CString>) -> *const c_char {
    propq.map_or(ptr::null(), |propq| propq.as_ptr())
}

// These tests use the context this binary is configured with, so they run in both the default
// and the `ossl-context` configuration.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssl_internal::PkeyCtxExt as _;
    use openssl::pkey_ctx::PkeyCtx;

    fn ctx() -> Option<&'static LibCtxRef> {
        None
    }

    fn rsa_key() -> PKey<Private> {
        let mut ctx = PkeyCtx::<()>::new_from_name(None, b"RSA\0").unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_rsa_keygen_bits(2048).unwrap();
        ctx.keygen().unwrap()
    }

    fn ec_key(nid: openssl::nid::Nid) -> PKey<Private> {
        let mut ctx = PkeyCtx::<()>::new_from_name(None, b"EC\0").unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_ec_paramgen_curve_nid(nid).unwrap();
        ctx.keygen().unwrap()
    }

    fn rsa_spki() -> Vec<u8> {
        rsa_key().public_key_to_der().unwrap()
    }

    #[test]
    fn public_key_from_der_ex_empty() {
        assert!(PKey::<Public>::public_key_from_der_ex(ctx(), &[], None).is_err());
    }

    #[test]
    fn public_key_from_der_ex_garbage() {
        assert!(
            PKey::<Public>::public_key_from_der_ex(ctx(), &[0xde, 0xad, 0xbe, 0xef], None).is_err()
        );
    }

    #[test]
    fn public_key_from_der_ex_truncated() {
        let spki = rsa_spki();
        for len in [0, 1, 5, 10, spki.len() / 2, spki.len() - 1] {
            assert!(
                PKey::<Public>::public_key_from_der_ex(ctx(), &spki[..len], None).is_err(),
                "truncated SPKI at {len} bytes should be rejected"
            );
        }
    }

    #[test]
    fn public_key_from_der_ex_round_trips() {
        // The success path, in the context the crate actually uses.
        let spki = rsa_spki();
        let imported = PKey::<Public>::public_key_from_der_ex(ctx(), &spki, None).unwrap();
        assert_eq!(imported.public_key_to_der().unwrap(), spki);
    }

    #[test]
    fn public_key_from_der_ex_rejects_an_interior_nul_propq() {
        // `propq` is handed to the decoder as a C string, so a value that cannot be one has to
        // be rejected here rather than silently truncated at the NUL.
        let spki = rsa_spki();
        assert!(
            PKey::<Public>::public_key_from_der_ex(ctx(), &spki, Some("has\0nul")).is_err(),
            "an interior NUL must be rejected rather than truncated"
        );
    }

    // Note: d2i_PUBKEY_ex does not reject trailing data after a valid SPKI -- it reads
    // one ASN.1 object and ignores the rest. This is fine for our use case because the
    // SPKI is always a precise slice from a certificate's subjectPublicKeyInfo field.

    #[test]
    fn private_key_from_der_ex_empty() {
        assert!(PKey::<Private>::private_key_from_der_ex(ctx(), &[], None).is_err());
    }

    #[test]
    fn private_key_from_der_ex_garbage() {
        assert!(
            PKey::<Private>::private_key_from_der_ex(ctx(), &[0xde, 0xad, 0xbe, 0xef], None)
                .is_err()
        );
    }

    #[test]
    fn private_key_from_der_ex_truncated() {
        let der = rsa_key().private_key_to_der().unwrap();

        for len in [0, 1, 5, 10, der.len() / 2, der.len() - 1] {
            assert!(
                PKey::<Private>::private_key_from_der_ex(ctx(), &der[..len], None).is_err(),
                "truncated PKCS#8 at {len} bytes should be rejected"
            );
        }
    }

    #[test]
    fn private_key_from_der_ex_wrong_type() {
        // A valid SPKI (public key) should not be accepted as a private key.
        let spki = rsa_spki();
        assert!(
            PKey::<Private>::private_key_from_der_ex(ctx(), &spki, None).is_err(),
            "public key DER should not parse as a private key"
        );
    }

    #[test]
    fn private_key_from_der_ex_round_trips() {
        let der = rsa_key().private_key_to_der().unwrap();
        let imported = PKey::<Private>::private_key_from_der_ex(ctx(), &der, None).unwrap();
        assert_eq!(imported.private_key_to_der().unwrap(), der);
    }

    /// The `ctx` argument has to reach the decoder.
    ///
    /// This only asserts the direction that can be observed. Under `ossl-context` the default
    /// context is restricted to a provider that does not exist, but `d2i_*_ex` with a null
    /// context still succeeds there on an OpenSSL built with its legacy ASN.1 decoders,
    /// because that path imports through `EC_KEY`/`RSA` and consults no provider. So the
    /// canary cannot prove the public half honours its context on such a build, and asserting
    /// that it fails would be asserting an OpenSSL implementation detail. The `None` direction
    /// is covered where the canary *is* a valid oracle -- see `new_from_name_honours_its_libctx`.
    #[cfg(feature = "ossl-context")]
    #[test]
    fn key_import_succeeds_in_the_configured_libctx() {
        let spki = rsa_spki();
        let der = rsa_key().private_key_to_der().unwrap();
        let ctx = ctx().expect("the `ossl-context` feature is enabled but no context is set");

        assert!(
            PKey::<Public>::public_key_from_der_ex(Some(ctx), &spki, None).is_ok(),
            "public key import failed in the configured library context"
        );
        assert!(
            PKey::<Private>::private_key_from_der_ex(Some(ctx), &der, None).is_ok(),
            "private key import failed in the configured library context"
        );
    }

    /// And so must `PkeyCtxExt::new_from_name`, which every other binding is built on.
    #[cfg(feature = "ossl-context")]
    #[test]
    fn new_from_name_honours_its_libctx() {
        assert!(
            PkeyCtx::<()>::new_from_name(None, b"HKDF\0").is_err(),
            "a KDF context was created in the default library context"
        );
        assert!(
            PkeyCtx::<()>::new_from_name(ctx(), b"HKDF\0").is_ok(),
            "a KDF context could not be created in the configured library context"
        );
    }

    #[test]
    fn get_utf8_string_param_returns_the_group() {
        // The success path, not just the error path: `PKey::ecdsa_scheme` reads this to pick a
        // signature scheme, so a failure here silently disables every ECDSA signature.
        let key = ec_key(openssl::nid::Nid::X9_62_PRIME256V1);
        assert_eq!(key.get_utf8_string_param(b"group\0").unwrap(), "prime256v1");
    }

    #[test]
    fn get_utf8_string_param_reports_no_trailing_nul() {
        // `EVP_PKEY_get_utf8_string_param` null-terminates what it writes and reports the
        // length excluding the terminator, so the returned `String` must not contain one.
        let key = ec_key(openssl::nid::Nid::SECP384R1);
        assert_eq!(key.get_utf8_string_param(b"group\0").unwrap(), "secp384r1");
    }

    #[test]
    fn get_octet_string_param_returns_the_encoded_point() {
        let key = ec_key(openssl::nid::Nid::X9_62_PRIME256V1);
        let point = key.get_octet_string_param(b"encoded-pub-key\0").unwrap();
        assert_eq!(point.len(), 65, "an uncompressed P-256 point");
        assert_eq!(point.first(), Some(&0x04));
    }

    #[test]
    fn get_utf8_string_param_missing() {
        // RSA keys have no "group" parameter.
        assert!(rsa_key().get_utf8_string_param(b"group\0").is_err());
    }

    #[test]
    fn get_octet_string_param_missing() {
        // RSA keys have no "encoded-pub-key" parameter.
        assert!(
            rsa_key()
                .get_octet_string_param(b"encoded-pub-key\0")
                .is_err()
        );
    }

    #[test]
    fn der_len_rejects_an_input_too_long_for_c_long() {
        // On a 32-bit target this is reachable with a >2GiB buffer; the point is that it
        // returns an error rather than telling the decoder the buffer is *longer* than it is.
        #[cfg(target_pointer_width = "32")]
        assert!(der_len(&vec![0u8; usize::MAX / 2]).is_err());

        // Everywhere else the conversion cannot fail for a slice that exists.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(der_len(&[1, 2, 3]).unwrap(), 3);
    }

    #[test]
    fn propq_c_rejects_an_interior_nul() {
        assert!(propq_c(None).unwrap().is_none());
        assert!(propq_c(Some("provider=default")).unwrap().is_some());
        assert!(propq_c(Some("has\0nul")).is_err());
    }
}
