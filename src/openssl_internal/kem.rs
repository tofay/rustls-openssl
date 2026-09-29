//! OpenSSL kem bindings
use std::ffi::{c_char, c_uchar};
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    error::ErrorStack,
    lib_ctx::LibCtxRef,
    pkey::{PKey, Public},
    pkey_ctx::{PkeyCtx, PkeyCtxRef},
};
use openssl_sys::{EVP_PKEY, EVP_PKEY_CTX, OSSL_PARAM, c_int};

use super::PkeyCtxExt;

use super::{cvt, cvt_p};

/// Extension trait for [`PkeyCtxRef`] to support key encapsulation mechanism (KEM) operations.
pub(crate) trait PkeyCtxRefKemExt {
    /// Initializes the encapsulation operation.
    fn encapsulate_init(&mut self) -> Result<(), ErrorStack>;
    /// Returns the encapsulated key and the shared secret.
    fn encapsulate_to_vec(&mut self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack>;
    /// Initializes the decapsulation operation.
    fn decapsulate_init(&mut self) -> Result<(), ErrorStack>;
    /// Returns the shared secret from the encapsulated key.
    fn decapsulate_to_vec(&self, enc: &[u8]) -> Result<Vec<u8>, ErrorStack>;
}

pub(crate) trait PkeyExt: Sized {
    /// Creates a new [`PKey`] from an encoded public key for the specified algorithm.
    fn from_encoded_public_key(
        ctx: Option<&LibCtxRef>,
        encoded_public_key: &[u8],
        algorithm_name: &'static [u8],
    ) -> Result<Self, ErrorStack>;
}

impl<T> PkeyCtxRefKemExt for PkeyCtxRef<T> {
    fn encapsulate_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(EVP_PKEY_encapsulate_init(self.as_ptr(), ptr::null()))?;
        }

        Ok(())
    }

    fn encapsulate_to_vec(&mut self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let mut out_len = 0;
        let mut secret_len = 0;

        unsafe {
            cvt(EVP_PKEY_encapsulate(
                self.as_ptr(),
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
                self.as_ptr(),
                out.as_mut_ptr().cast(),
                &mut out_len,
                secret.as_mut_ptr().cast(),
                &mut secret_len,
            ))?;
        }

        out.truncate(out_len);
        secret.truncate(secret_len);
        Ok((out, secret))
    }

    fn decapsulate_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(EVP_PKEY_decapsulate_init(self.as_ptr(), ptr::null()))?;
        }

        Ok(())
    }

    fn decapsulate_to_vec(&self, enc: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let mut unwrapped_len = 0;

        unsafe {
            cvt(EVP_PKEY_decapsulate(
                self.as_ptr(),
                ptr::null_mut(),
                &mut unwrapped_len,
                enc.as_ptr().cast(),
                enc.len(),
            ))?;
        }

        let mut unwrapped = vec![0; unwrapped_len];

        unsafe {
            cvt(EVP_PKEY_decapsulate(
                self.as_ptr(),
                unwrapped.as_mut_ptr().cast(),
                &mut unwrapped_len,
                enc.as_ptr().cast(),
                enc.len(),
            ))?;
        }

        unwrapped.truncate(unwrapped_len);
        Ok(unwrapped)
    }
}

impl PkeyExt for PKey<Public> {
    fn from_encoded_public_key(
        ctx: Option<&LibCtxRef>,
        encoded_public_key: &[u8],
        algorithm_name: &'static [u8],
    ) -> Result<Self, ErrorStack> {
        let ctx = PkeyCtx::<()>::new_from_name(ctx, algorithm_name)?;
        unsafe {
            let mut evp = ptr::null_mut();
            cvt(EVP_PKEY_paramgen_init(ctx.as_ptr()))?;
            cvt(EVP_PKEY_paramgen(ctx.as_ptr(), &mut evp))?;
            let evp = cvt_p(evp)?;
            cvt(EVP_PKEY_set1_encoded_public_key(
                evp,
                encoded_public_key.as_ptr(),
                encoded_public_key.len(),
            ))?;
            Ok(PKey::from_ptr(evp))
        }
    }
}

unsafe extern "C" {
    pub fn EVP_PKEY_encapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
}

unsafe extern "C" {
    pub fn EVP_PKEY_encapsulate(
        ctx: *mut EVP_PKEY_CTX,
        wrappedkey: *mut c_uchar,
        wrappedkeylen: *mut usize,
        genkey: *mut c_uchar,
        genkeylen: *mut usize,
    ) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_decapsulate_init(
        ctx: *mut EVP_PKEY_CTX,
        params: *const OSSL_PARAM,
    ) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_decapsulate(
        ctx: *mut EVP_PKEY_CTX,
        unwrapped: *mut c_uchar,
        unwrappedlen: *mut usize,
        wrapped: *const c_uchar,
        wrappedlen: usize,
    ) -> c_int;
}

unsafe extern "C" {
    pub unsafe fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
}

unsafe extern "C" {
    pub unsafe fn EVP_PKEY_get_octet_string_param(
        pkey: *const EVP_PKEY,
        key_name: *const c_char,
        buf: *mut c_uchar,
        max_buf_sz: usize,
        out_sz: *mut usize,
    ) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_get_utf8_string_param(
        pkey: *const EVP_PKEY,
        key_name: *const c_char,
        str_: *mut c_char,
        max_buf_sz: usize,
        out_sz: *mut usize,
    ) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_set1_encoded_public_key(
        pkey: *mut EVP_PKEY,
        pub_: *const c_uchar,
        publen: usize,
    ) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_paramgen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
}
unsafe extern "C" {
    pub unsafe fn EVP_PKEY_paramgen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int;
}
