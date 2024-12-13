use std::{
    ffi::{c_char, c_uchar},
    ptr,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::pkey_ctx::{PkeyCtx, PkeyCtxRef};
use openssl_sys::{c_int, EVP_PKEY_CTX, OSSL_LIB_CTX, OSSL_PARAM};

use super::{cvt, cvt_p};

pub(crate) fn encapsulate_init<T>(
    ctx: &mut PkeyCtxRef<T>,
) -> Result<(), openssl::error::ErrorStack> {
    unsafe {
        cvt(EVP_PKEY_encapsulate_init(ctx.as_ptr(), ptr::null()))?;
    }

    Ok(())
}

pub(crate) fn encapsulate_to_vec<T>(
    ctx: &mut PkeyCtxRef<T>,
) -> Result<(Vec<u8>, Vec<u8>), openssl::error::ErrorStack> {
    let mut out_len = 0;
    let mut secret_len = 0;

    unsafe {
        cvt(EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ptr::null_mut(),
            &mut out_len,
            ptr::null_mut(),
            &mut secret_len,
        ))?;
    }

    let mut out = vec![0; out_len];
    let mut secret = vec![0; secret_len];

    unsafe {
        cvt(EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            out.as_mut_ptr() as *mut _,
            &mut out_len,
            secret.as_mut_ptr() as *mut _,
            &mut secret_len,
        ))?;
    }

    Ok((out, secret))
}

pub(crate) fn decapsulate_init<T>(
    ctx: &mut PkeyCtxRef<T>,
) -> Result<(), openssl::error::ErrorStack> {
    unsafe {
        cvt(EVP_PKEY_decapsulate_init(ctx.as_ptr(), ptr::null()))?;
    }

    Ok(())
}

pub(crate) fn decapsulate_to_vec<T>(
    ctx: &mut PkeyCtxRef<T>,
    enc: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut unwrapped_len = 0;

    unsafe {
        cvt(EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            ptr::null_mut(),
            &mut unwrapped_len,
            enc.as_ptr() as *const _,
            enc.len(),
        ))?;
    }

    let mut unwrapped = vec![0; unwrapped_len];

    unsafe {
        cvt(EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            unwrapped.as_mut_ptr() as *mut _,
            &mut unwrapped_len,
            enc.as_ptr() as *const _,
            enc.len(),
        ))?;
    }

    Ok(unwrapped)
}

extern "C" {
    pub fn EVP_PKEY_encapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
}

extern "C" {
    pub fn EVP_PKEY_encapsulate(
        ctx: *mut EVP_PKEY_CTX,
        wrappedkey: *mut c_uchar,
        wrappedkeylen: *mut usize,
        genkey: *mut c_uchar,
        genkeylen: *mut usize,
    ) -> c_int;
}
extern "C" {
    pub fn EVP_PKEY_decapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
}
extern "C" {
    pub fn EVP_PKEY_decapsulate(
        ctx: *mut EVP_PKEY_CTX,
        unwrapped: *mut c_uchar,
        unwrappedlen: *mut usize,
        wrapped: *const c_uchar,
        wrappedlen: usize,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
}

pub(crate) fn new_pkey_ctx_from_name(
    name: &[u8],
) -> Result<PkeyCtx<()>, openssl::error::ErrorStack> {
    openssl_sys::init();
    unsafe {
        let ptr = cvt_p(EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            name.as_ptr() as *const _,
            ptr::null(),
        ))?;
        Ok(PkeyCtx::from_ptr(ptr))
    }
}
