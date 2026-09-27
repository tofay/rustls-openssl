//! Library context properties, for OpenSSL 3.0 and later.
use std::ffi::{CString, c_char};
use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::lib_ctx::LibCtxRef;
use openssl_sys::{EVP_default_properties_is_fips_enabled, OSSL_LIB_CTX};

use super::cvt;

// `EVP_set_default_properties` is not in openssl-sys, unlike
// `EVP_default_properties_is_fips_enabled` just below.
unsafe extern "C" {
    fn EVP_set_default_properties(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> i32;
}

/// Sets the default property query of `ctx`, or of the default library context if `ctx` is
/// `None`.
pub fn set_default_properties(ctx: Option<&LibCtxRef>, properties: &str) -> Result<(), ErrorStack> {
    let prop_c = CString::new(properties).map_err(|_| ErrorStack::get())?;
    unsafe {
        cvt(EVP_set_default_properties(raw_libctx(ctx), prop_c.as_ptr()))?;
        Ok(())
    }
}

/// Whether `ctx`, or the default library context if `ctx` is `None`, has `fips=yes` among its
/// default properties.
pub fn fips_enabled(ctx: Option<&LibCtxRef>) -> bool {
    unsafe { EVP_default_properties_is_fips_enabled(raw_libctx(ctx)) == 1 }
}

/// A library context for the property functions, which take a nullable one.
fn raw_libctx(ctx: Option<&LibCtxRef>) -> *mut OSSL_LIB_CTX {
    ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr)
}
