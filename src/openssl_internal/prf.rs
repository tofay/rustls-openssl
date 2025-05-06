//! OpenSSL PRF bindings
//! https://github.com/sfackler/rust-openssl/pull/2329
use core::ffi::c_void;
use foreign_types::ForeignTypeRef;
use openssl::{error::ErrorStack, md::MdRef, pkey_ctx::PkeyCtxRef};
use openssl_sys::{EVP_MD, EVP_PKEY_ALG_CTRL, EVP_PKEY_CTX, EVP_PKEY_OP_DERIVE, c_int};

use super::cvt;

unsafe extern "C" {
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: c_int,
        optype: c_int,
        cmd: c_int,
        p1: c_int,
        p2: *mut c_void,
    ) -> c_int;
}

const EVP_PKEY_CTRL_TLS_MD: c_int = EVP_PKEY_ALG_CTRL;
const EVP_PKEY_CTRL_TLS_SECRET: c_int = EVP_PKEY_ALG_CTRL + 1;
const EVP_PKEY_CTRL_TLS_SEED: c_int = EVP_PKEY_ALG_CTRL + 2;

#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_set_tls1_prf_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int {
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            -1,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_MD,
            0,
            md as *mut c_void,
        )
    }
}

#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_set1_tls1_prf_secret(
    ctx: *mut EVP_PKEY_CTX,
    sec: *const u8,
    seclen: c_int,
) -> c_int {
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            -1,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_SECRET,
            seclen,
            sec as *mut c_void,
        )
    }
}

#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_add1_tls1_prf_seed(
    ctx: *mut EVP_PKEY_CTX,
    seed: *const u8,
    seedlen: c_int,
) -> c_int {
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            -1,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_SEED,
            seedlen,
            seed as *mut c_void,
        )
    }
}

pub(crate) fn set_tls1_prf_secret<T>(
    ctx: &mut PkeyCtxRef<T>,
    secret: &[u8],
) -> Result<(), openssl::error::ErrorStack> {
    let len = c_int::try_from(secret.len()).unwrap();

    unsafe {
        cvt(EVP_PKEY_CTX_set1_tls1_prf_secret(
            ctx.as_ptr(),
            secret.as_ptr(),
            len,
        ))?;
    }

    Ok(())
}

pub(crate) fn add_tls1_prf_seed<T>(
    ctx: &mut PkeyCtxRef<T>,
    seed: &[u8],
) -> Result<(), openssl::error::ErrorStack> {
    let len = c_int::try_from(seed.len()).unwrap();

    unsafe {
        cvt(EVP_PKEY_CTX_add1_tls1_prf_seed(
            ctx.as_ptr(),
            seed.as_ptr(),
            len,
        ))?;
    }

    Ok(())
}

pub(crate) fn set_tls1_prf_md<T>(
    ctx: &mut PkeyCtxRef<T>,
    digest: &MdRef,
) -> Result<(), ErrorStack> {
    unsafe {
        cvt(EVP_PKEY_CTX_set_tls1_prf_md(ctx.as_ptr(), digest.as_ptr()))?;
    }

    Ok(())
}
