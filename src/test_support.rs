use openssl::pkey::{Id, PKey, Private};

/// Returns the type-specific public-key encoding consumed by rustls.
#[cfg(ossl300)]
pub(crate) fn public_key_payload(key: &PKey<Private>, key_type: Id) -> Vec<u8> {
    use foreign_types::ForeignTypeRef;
    use openssl::error::ErrorStack;
    use std::{ptr, slice};

    match key_type {
        Id::RSA => {
            use openssl_sys::{
                EVP_PKEY_PUBLIC_KEY, OPENSSL_free, OSSL_ENCODER_CTX_free,
                OSSL_ENCODER_CTX_new_for_pkey, OSSL_ENCODER_to_data,
            };

            let encoder = unsafe {
                OSSL_ENCODER_CTX_new_for_pkey(
                    key.as_ptr(),
                    EVP_PKEY_PUBLIC_KEY,
                    c"DER".as_ptr(),
                    c"type-specific".as_ptr(),
                    ptr::null(),
                )
            };
            assert!(!encoder.is_null(), "{:#?}", ErrorStack::get());

            let mut der = ptr::null_mut();
            let mut der_len = 0;
            let encoded = unsafe { OSSL_ENCODER_to_data(encoder, &mut der, &mut der_len) };
            let payload = (encoded == 1)
                .then(|| unsafe { slice::from_raw_parts(der.cast_const(), der_len).to_vec() });
            if !der.is_null() {
                unsafe { OPENSSL_free(der.cast()) };
            }
            unsafe { OSSL_ENCODER_CTX_free(encoder) };

            payload.unwrap_or_else(|| {
                panic!(
                    "OpenSSL public-key encoding failed: {:#?}",
                    ErrorStack::get()
                )
            })
        }
        Id::EC => {
            use openssl_sys::EVP_PKEY_get_octet_string_param;

            const ENCODED_PUBLIC_KEY: &[u8] = b"encoded-pub-key\0";
            let mut len = 0;
            let queried = unsafe {
                EVP_PKEY_get_octet_string_param(
                    key.as_ptr(),
                    ENCODED_PUBLIC_KEY.as_ptr().cast(),
                    ptr::null_mut(),
                    0,
                    &mut len,
                )
            };
            assert_eq!(queried, 1, "{:#?}", ErrorStack::get());

            let mut encoded = vec![0; len];
            let read = unsafe {
                EVP_PKEY_get_octet_string_param(
                    key.as_ptr(),
                    ENCODED_PUBLIC_KEY.as_ptr().cast(),
                    encoded.as_mut_ptr(),
                    len,
                    &mut len,
                )
            };
            assert_eq!(read, 1, "{:#?}", ErrorStack::get());
            encoded.truncate(len);
            encoded
        }
        _ => unreachable!(),
    }
}

/// Returns the type-specific public-key encoding consumed by rustls.
#[cfg(not(ossl300))]
pub(crate) fn public_key_payload(key: &PKey<Private>, key_type: Id) -> Vec<u8> {
    match key_type {
        Id::RSA => key.rsa().unwrap().public_key_to_der_pkcs1().unwrap(),
        Id::EC => {
            use openssl::bn::BigNumContext;
            use openssl::ec::PointConversionForm;

            let ec = key.ec_key().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            ec.public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .unwrap()
        }
        _ => unreachable!(),
    }
}
