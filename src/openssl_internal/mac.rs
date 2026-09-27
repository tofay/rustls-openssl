//! MACs, via OpenSSL's `EVP_MAC` interface, for 3.0 and later.
//!
//! `EVP_MAC` is the MAC interface that takes a library context, so it is the one that computes
//! a tag with the providers this crate is configured to use. The key and the digest are named
//! to it, the same way everything else here is named to a fetch call. See [`crate::hmac`],
//! the caller.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::lib_ctx::LibCtxRef;
use openssl_sys::{
    EVP_MAC, EVP_MAC_CTX, EVP_MAC_CTX_free, EVP_MAC_CTX_get_mac_size, EVP_MAC_CTX_new,
    EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_update, OSSL_PARAM,
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_utf8_string,
    OSSL_PARAM_BLD_to_param, OSSL_PARAM_free,
};

use super::{cvt, cvt_p};

/// `OSSL_MAC_PARAM_DIGEST`: the name of the hash a MAC is to use, which for HMAC is the only
/// parameter it takes.
const OSSL_MAC_PARAM_DIGEST: &[u8] = b"digest\0";

/// A MAC algorithm, fetched from a library context.
///
/// Fetched once and reusable: `EVP_MAC` is immutable, and the per-message state lives in the
/// [`Mac::sign`] call.
///
/// A fetched `EVP_MAC` is a method structure owned by a provider, and a provider
/// implementation lives inside the `OSSL_LIB_CTX` it was loaded into. `EVP_MAC_fetch` does not
/// take a reference on that context, and `EVP_MAC_free` does not check one, so the context
/// passed to [`Mac::fetch`] has to outlive the `Mac`: use the default context (`None`) or one
/// that lives for the whole process.
pub struct Mac {
    mac: *mut EVP_MAC,
}

// An `EVP_MAC` is immutable once fetched, and the per-message state this module creates is a
// separate `EVP_MAC_CTX` per call, so one fetched `Mac` can be shared across threads.
unsafe impl Send for Mac {}
unsafe impl Sync for Mac {}

impl Mac {
    /// Fetch `algorithm` -- `"HMAC"` -- from `ctx`, or from the default library context if
    /// `ctx` is `None`.
    pub fn fetch(ctx: Option<&LibCtxRef>, algorithm: &str) -> Result<Self, ErrorStack> {
        openssl_sys::init();

        let name = CString::new(algorithm).map_err(|_| ErrorStack::get())?;
        let mac = unsafe {
            cvt_p(EVP_MAC_fetch(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr(),
                ptr::null(),
            ))?
        };

        Ok(Self { mac })
    }

    /// MAC `data` under `key`, using the hash named `digest`.
    ///
    /// The parts of `data` are concatenated, which is what the `Key` trait this serves means
    /// by `sign_concat`.
    pub fn sign(&self, digest: &str, key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>, ErrorStack> {
        let digest_c = CString::new(digest).map_err(|_| ErrorStack::get())?;
        // Has to outlive the `EVP_MAC_init` call below: the parameters are only read during
        // it, but the strings they point at are owned by the array.
        let params = Params::digest(digest_c.as_c_str())?;

        let ctx = unsafe { cvt_p(EVP_MAC_CTX_new(self.mac))? };
        let result = self.sign_with(ctx, &params, key, data);
        unsafe { EVP_MAC_CTX_free(ctx) };
        result
    }

    /// The body of [`Self::sign`], for a context the caller has allocated.
    fn sign_with(
        &self,
        ctx: *mut EVP_MAC_CTX,
        params: &Params,
        key: &[u8],
        data: &[&[u8]],
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            // An empty key is a null pointer with a length of zero, not a dangling one: the
            // two are indistinguishable to C but only one is a valid argument.
            let key_ptr = if key.is_empty() {
                ptr::null()
            } else {
                key.as_ptr()
            };
            cvt(EVP_MAC_init(ctx, key_ptr, key.len(), params.as_ptr()))?;

            // Zero is a failure here, not a zero-length tag: every MAC this crate uses has a
            // fixed, non-zero size, so an empty output buffer would be a buffer overrun.
            let mac_size = EVP_MAC_CTX_get_mac_size(ctx);
            if mac_size == 0 {
                return Err(ErrorStack::get());
            }
            let mut out = vec![0; mac_size as usize];
            for part in data {
                cvt(EVP_MAC_update(ctx, part.as_ptr(), part.len()))?;
            }

            let mut len = 0;
            cvt(EVP_MAC_final(ctx, out.as_mut_ptr(), &mut len, out.len()))?;
            out.truncate(len);
            Ok(out)
        }
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        unsafe { EVP_MAC_free(self.mac) };
    }
}

/// The single `digest` parameter a MAC is configured with, as an `OSSL_PARAM` array.
struct Params(*mut OSSL_PARAM);

impl Params {
    /// The `digest` parameter, naming the hash the MAC is to use.
    fn digest(digest: &CStr) -> Result<Self, ErrorStack> {
        unsafe {
            let builder = cvt_p(OSSL_PARAM_BLD_new())?;
            let built = (|| {
                cvt(OSSL_PARAM_BLD_push_utf8_string(
                    builder,
                    OSSL_MAC_PARAM_DIGEST.as_ptr().cast::<c_char>(),
                    digest.as_ptr(),
                    // Includes the NUL, which OpenSSL copies out of the builder.
                    digest.to_bytes().len() + 1,
                ))?;
                // `to_param` returns NULL when the builder is empty, which is not an error
                // OpenSSL reports, so this is the only place it can be caught. The builder is
                // freed either way, which is what makes that NULL safe to turn into an `Err`.
                cvt_p(OSSL_PARAM_BLD_to_param(builder))
            })();
            OSSL_PARAM_BLD_free(builder);

            Ok(Self(built?))
        }
    }

    fn as_ptr(&self) -> *const OSSL_PARAM {
        self.0
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        unsafe { OSSL_PARAM_free(self.0) };
    }
}
