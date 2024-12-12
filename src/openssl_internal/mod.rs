/// Contains OpenSSL bindings not in rust-openssl
use openssl::error::ErrorStack;
use openssl_sys::c_int;

#[cfg(ossl320)]
mod hpke;
#[cfg(feature = "tls12")]
pub(crate) mod prf;

pub(crate) fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
