//! OpenSSL bindings that take a library context, or that rust-openssl does not provide.
//!
//! The modules are split by subject:
//!
//! - `key`: key import, export and parameter access
//! - `mac`: MACs
//! - `properties`: library context default properties
//! - `rand`: random bytes
//! - `kem`: key encapsulation
//! - `prf`: the TLS 1.2 PRF, which OpenSSL spells `TLS1-PRF`
//! - `hpke`: HPKE, on OpenSSL 3.2 and later
//!
#[cfg(ossl300)]
use foreign_types::{ForeignType, ForeignTypeRef};
#[cfg(any(ossl300, feature = "tls12"))]
use openssl::error::ErrorStack;
#[cfg(ossl300)]
use openssl::lib_ctx::LibCtxRef;
#[cfg(ossl300)]
use openssl::pkey_ctx::PkeyCtx;
#[cfg(ossl300)]
use openssl_sys::EVP_PKEY_CTX_new_from_name;
#[cfg(any(ossl300, feature = "tls12"))]
use openssl_sys::c_int;
#[cfg(ossl300)]
use std::ptr;

/// Turn a return code that is a length or a success into a `Result`.
#[cfg(any(ossl300, feature = "tls12"))]
#[inline]
pub(crate) fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(ossl300)]
#[inline]
pub(crate) fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// The largest digest OpenSSL can produce, as a buffer length.
pub(crate) const MAX_MD_SIZE: usize = openssl_sys::EVP_MAX_MD_SIZE as usize;

#[cfg(ossl300)]
pub(crate) mod kem;
#[cfg(ossl300)]
pub(crate) mod key;
#[cfg(ossl300)]
pub(crate) mod mac;
#[cfg(feature = "tls12")]
pub(crate) mod prf;
#[cfg(ossl300)]
pub(crate) mod properties;
#[cfg(ossl300)]
pub(crate) mod rand;

#[cfg(ossl300)]
pub use mac::Mac;

#[cfg(ossl320)]
mod hpke;

#[cfg(ossl300)]
pub use key::{PKeyPrivateExt, PKeyPublicExt, PKeyRefExt};
#[cfg(ossl300)]
pub use properties::{fips_enabled, set_default_properties};

#[cfg(ossl300)]
pub(crate) trait PkeyCtxExt: Sized {
    /// Creates a new [`PkeyCtx`] from the algorithm name.
    ///
    /// The algorithm name is a static, null-terminated, string that identifies the algorithm to use.
    ///
    /// Unlike rust-openssl's `PkeyCtx::new_id`, this names the algorithm rather than giving
    /// its `NID`, and -- more to the point -- takes the library context to create the
    /// context in, so the operation it is set up for is dispatched through the providers of
    /// that context. Requires OpenSSL 3.0, for `EVP_PKEY_CTX_new_from_name`.
    fn new_from_name(ctx: Option<&LibCtxRef>, name: &'static [u8]) -> Result<Self, ErrorStack>;
}

#[cfg(ossl300)]
impl PkeyCtxExt for PkeyCtx<()> {
    fn new_from_name(ctx: Option<&LibCtxRef>, name: &'static [u8]) -> Result<Self, ErrorStack> {
        openssl_sys::init();
        unsafe {
            let ptr = cvt_p(EVP_PKEY_CTX_new_from_name(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr().cast(),
                ptr::null(),
            ))?;
            Ok(PkeyCtx::from_ptr(ptr))
        }
    }
}
