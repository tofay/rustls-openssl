/// Contains OpenSSL bindings not in rust-openssl
use openssl::error::ErrorStack;
use openssl_sys::c_int;

#[cfg(ossl320)]
mod hpke;
#[cfg(ossl350)]
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

#[cfg(ossl320)]
#[inline]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
