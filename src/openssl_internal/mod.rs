/// Contains OpenSSL bindings not in rust-openssl
use openssl::error::ErrorStack;
use openssl_sys::c_int;
use std::ffi::{CString, c_char};

#[cfg(ossl320)]
mod hpke;
#[cfg(ossl300)]
pub(crate) mod kem;
#[cfg(feature = "tls12")]
pub(crate) mod prf;

#[inline]
pub(crate) fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
#[cfg(ossl300)]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(ossl300)]
unsafe extern "C" {
    pub fn EVP_set_default_properties(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> c_int;
}

/// Sets global default properties.
#[cfg(ossl300)]
pub fn set_default_properties(properties: &str) -> Result<(), ErrorStack> {
    let prop_c = CString::new(properties).map_err(|_| ErrorStack::get())?;
    unsafe {
        cvt(EVP_set_default_properties(
            std::ptr::null_mut(),
            prop_c.as_ptr(),
        ))?;
        Ok(())
    }
}
