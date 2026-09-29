//! Random bytes, from the providers of a particular library context.

use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::lib_ctx::LibCtxRef;
use openssl_sys::OSSL_LIB_CTX;

use super::cvt;

unsafe extern "C" {
    fn RAND_priv_bytes_ex(
        libctx: *mut OSSL_LIB_CTX,
        buf: *mut u8,
        num: usize,
        strength: u32,
    ) -> i32;
}

/// Fill `buf` with random bytes, from the private DRBG of `ctx`.
pub fn priv_bytes(ctx: Option<&LibCtxRef>, buf: &mut [u8]) -> Result<(), ErrorStack> {
    let raw_libctx = ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr);
    unsafe {
        cvt(RAND_priv_bytes_ex(
            raw_libctx,
            buf.as_mut_ptr(),
            buf.len(),
            0,
        ))?;
        Ok(())
    }
}
