//! HPKE bindings being upstreamed at https://github.com/sfackler/rust-openssl/pull/2337
#![allow(unused)]
#![allow(non_camel_case_types)]
use std::{
    ffi::{c_char, CString},
    ptr,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    error::ErrorStack,
    pkey::{PKey, PKeyRef, Private},
};
use openssl_sys::{c_int, EVP_PKEY, OSSL_LIB_CTX};

use super::cvt;

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub enum OSSL_HPKE_CTX {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct OSSL_HPKE_SUITE {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
}

const OSSL_HPKE_MODE_BASE: c_int = 0x00;
const OSSL_HPKE_MODE_PSK: c_int = 0x01;
const OSSL_HPKE_MODE_AUTH: c_int = 0x02;
const OSSL_HPKE_MODE_PSKAUTH: c_int = 0x03;

const OSSL_HPKE_ROLE_SENDER: c_int = 0x00;
const OSSL_HPKE_ROLE_RECEIVER: c_int = 0x01;

const OSSL_HPKE_KEM_ID_P256: u16 = 0x10;
const OSSL_HPKE_KEM_ID_P384: u16 = 0x11;
const OSSL_HPKE_KEM_ID_P521: u16 = 0x12;
const OSSL_HPKE_KEM_ID_X25519: u16 = 0x20;
const OSSL_HPKE_KEM_ID_X448: u16 = 0x21;

const OSSL_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x01;
const OSSL_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x02;
const OSSL_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x03;

const OSSL_HPKE_AEAD_ID_AES_GCM_128: u16 = 0x01;
const OSSL_HPKE_AEAD_ID_AES_GCM_256: u16 = 0x02;
const OSSL_HPKE_AEAD_ID_CHACHA_POLY1305: u16 = 0x03;
const OSSL_HPKE_AEAD_ID_EXPORTONLY: u16 = 0xFFFF;

const OSSL_HPKE_SUITE_DEFAULT: OSSL_HPKE_SUITE = OSSL_HPKE_SUITE {
    kem_id: OSSL_HPKE_KEM_ID_X25519,
    kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA256,
    aead_id: OSSL_HPKE_AEAD_ID_AES_GCM_128,
};

extern "C" {
    fn OSSL_HPKE_CTX_new(
        mode: c_int,
        suite: OSSL_HPKE_SUITE,
        role: c_int,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> *mut OSSL_HPKE_CTX;
    fn OSSL_HPKE_CTX_free(ctx: *mut OSSL_HPKE_CTX);
    fn OSSL_HPKE_encap(
        ctx: *mut OSSL_HPKE_CTX,
        enc: *mut u8,
        enclen: *mut usize,
        pub_: *const u8,
        publen: usize,
        info: *const u8,
        infolen: usize,
    ) -> c_int;
    fn OSSL_HPKE_seal(
        ctx: *mut OSSL_HPKE_CTX,
        ct: *mut u8,
        ctlen: *mut usize,
        aad: *const u8,
        aadlen: usize,
        pt: *const u8,
        ptlen: usize,
    ) -> c_int;
    fn OSSL_HPKE_keygen(
        suite: OSSL_HPKE_SUITE,
        pub_: *mut u8,
        publen: *mut usize,
        priv_: *mut *mut EVP_PKEY,
        ikm: *const u8,
        ikmlen: usize,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> c_int;
    fn OSSL_HPKE_decap(
        ctx: *mut OSSL_HPKE_CTX,
        enc: *const u8,
        enclen: usize,
        recippriv: *mut EVP_PKEY,
        info: *const u8,
        infolen: usize,
    ) -> c_int;
    fn OSSL_HPKE_open(
        ctx: *mut OSSL_HPKE_CTX,
        pt: *mut u8,
        ptlen: *mut usize,
        aad: *const u8,
        aadlen: usize,
        ct: *const u8,
        ctlen: usize,
    ) -> c_int;
    fn OSSL_HPKE_export(
        ctx: *mut OSSL_HPKE_CTX,
        secret: *mut u8,
        secretlen: usize,
        label: *const u8,
        labellen: usize,
    ) -> c_int;
    fn OSSL_HPKE_CTX_set1_authpriv(ctx: *mut OSSL_HPKE_CTX, priv_: *mut EVP_PKEY) -> c_int;
    fn OSSL_HPKE_CTX_set1_authpub(ctx: *mut OSSL_HPKE_CTX, pub_: *const u8, publen: usize)
        -> c_int;
    fn OSSL_HPKE_CTX_set1_psk(
        ctx: *mut OSSL_HPKE_CTX,
        pskid: *const c_char,
        psk: *const u8,
        psklen: usize,
    ) -> c_int;
    fn OSSL_HPKE_CTX_set1_ikme(ctx: *mut OSSL_HPKE_CTX, ikme: *const u8, ikmelen: usize) -> c_int;
    fn OSSL_HPKE_CTX_set_seq(ctx: *mut OSSL_HPKE_CTX, seq: u64) -> c_int;
    fn OSSL_HPKE_CTX_get_seq(ctx: *mut OSSL_HPKE_CTX, seq: *mut u64) -> c_int;
    fn OSSL_HPKE_suite_check(suite: OSSL_HPKE_SUITE) -> c_int;
    fn OSSL_HPKE_get_grease_value(
        suite_in: *const OSSL_HPKE_SUITE,
        suite: *mut OSSL_HPKE_SUITE,
        enc: *mut u8,
        enclen: *mut usize,
        ct: *mut u8,
        ctlen: usize,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> c_int;
    fn OSSL_HPKE_str2suite(str_: *const c_char, suite: *mut OSSL_HPKE_SUITE) -> c_int;
    fn OSSL_HPKE_get_ciphertext_size(suite: OSSL_HPKE_SUITE, clearlen: usize) -> usize;
    fn OSSL_HPKE_get_public_encap_size(suite: OSSL_HPKE_SUITE) -> usize;
    fn OSSL_HPKE_get_recommended_ikmelen(suite: OSSL_HPKE_SUITE) -> usize;
}

/// HPKE authentication modes.
///
/// OpenSSL documentation at [`hpke-modes`].
///
/// [`hpke-modes`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#hpke-modes
pub struct Mode(c_int);

impl Mode {
    /// Authentication is not used.
    pub const BASE: Self = Mode(OSSL_HPKE_MODE_BASE);
    /// Authenticates possession of a pre-shared key (PSK).
    pub const PSK: Self = Mode(OSSL_HPKE_MODE_PSK);
    /// Authenticates possession of a KEM-based sender private key.
    pub const AUTH: Self = Mode(OSSL_HPKE_MODE_AUTH);
    /// A combination of OSSL_HPKE_MODE_PSK and OSSL_HPKE_MODE_AUTH.
    /// Both the PSK and the senders authentication public/private must be supplied before the encapsulation/decapsulation operation will work.
    pub const PSKAUTH: Self = Mode(OSSL_HPKE_MODE_PSKAUTH);
}

/// HPKE Key Encapsulation Method identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Kem(u16);

/// HPKE Key Derivation Function identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Kdf(u16);

/// HPKE authenticated encryption with additional data algorithm identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Aead(u16);

impl Kem {
    /// The NIST P-256 curve.
    pub const P256: Self = Kem(OSSL_HPKE_KEM_ID_P256);
    /// The NIST P-384 curve.
    pub const P384: Self = Kem(OSSL_HPKE_KEM_ID_P384);
    /// The NIST P-521 curve.
    pub const P521: Self = Kem(OSSL_HPKE_KEM_ID_P521);
    /// The X25519 curve.
    pub const X25519: Self = Kem(OSSL_HPKE_KEM_ID_X25519);
    /// The X448 curve.
    pub const X448: Self = Kem(OSSL_HPKE_KEM_ID_X448);
}

impl Kdf {
    /// HKDF with SHA-256.
    pub const HKDF_SHA256: Self = Kdf(OSSL_HPKE_KDF_ID_HKDF_SHA256);
    /// HKDF with SHA-384.
    pub const HKDF_SHA384: Self = Kdf(OSSL_HPKE_KDF_ID_HKDF_SHA384);
    /// HKDF with SHA-512.
    pub const HKDF_SHA512: Self = Kdf(OSSL_HPKE_KDF_ID_HKDF_SHA512);
}

impl Aead {
    /// AES-GCM with 128-bit key.
    pub const AES_GCM_128: Self = Aead(OSSL_HPKE_AEAD_ID_AES_GCM_128);
    /// AES-GCM with 256-bit key.
    pub const AES_GCM_256: Self = Aead(OSSL_HPKE_AEAD_ID_AES_GCM_256);
    /// ChaCha20-Poly1305.
    pub const CHACHA_POLY1305: Self = Aead(OSSL_HPKE_AEAD_ID_CHACHA_POLY1305);
    /// Indicates that AEAD operations are not needed.
    /// [SenderCtxRef::export] or [ReceiverCtxRef::export] can be used, but
    /// [SenderCtxRef::seal] and [ReceiverCtxRef::open] will return an error
    /// if called with a context using this AEAD identifier.
    pub const EXPORTONLY: Self = Aead(OSSL_HPKE_AEAD_ID_EXPORTONLY);
}

/// A HPKE suite.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone)]
pub struct Suite {
    pub kem_id: Kem,
    pub kdf_id: Kdf,
    pub aead_id: Aead,
}

foreign_types::foreign_type! {
    type CType = OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    /// A HPKE context for sending messages.
    ///
    /// OpenSSL documentation at [`sender-apis`].
    ///
    /// [`sender-apis`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#sender-apis
    pub struct SenderCtx;
    /// A reference to an [`SenderCtx`].
    pub struct SenderCtxRef;
}

unsafe impl Send for SenderCtx {}
unsafe impl Send for SenderCtxRef {}
unsafe impl Sync for SenderCtx {}
unsafe impl Sync for SenderCtxRef {}

foreign_types::foreign_type! {
    type CType = OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    /// A HPKE context for receiving messages.
    ///
    /// OpenSSL documentation at [`recipient-apis`].
    ///
    /// [`recipient-apis`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#recipient-apis
    pub struct ReceiverCtx;
    /// A reference to an [`ReceiverCtx`].
    pub struct ReceiverCtxRef;
}

unsafe impl Send for ReceiverCtx {}
unsafe impl Send for ReceiverCtxRef {}
unsafe impl Sync for ReceiverCtx {}
unsafe impl Sync for ReceiverCtxRef {}

impl SenderCtxRef {
    /// Encapsulates a public key.
    ///
    /// The encapsulation will be written to the input `enc` buffer, and the number of bytes written will be returned.
    /// Calling this function more than once on the same context will result in an error.
    /// If `enc` is smaller than the value returned by [`Suite::public_encap_size`], an error will be returned.
    #[inline]
    pub fn encap(&self, enc: &mut [u8], pub_key: &[u8], info: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_encap(
                self.as_ptr(),
                enc.as_mut_ptr(),
                &mut enclen,
                pub_key.as_ptr(),
                pub_key.len(),
                info.as_ptr(),
                info.len(),
            ))
            .map(|_| enclen)
        }
    }

    /// Seals a plaintext message.
    ///
    /// The ciphertext will be written to the input `ct` buffer, and the number of bytes written will be returned.
    /// If `ct` is smaller than the value returned by [`Suite::ciphertext_size`], an error will be returned.
    ///
    /// This function can be called multiple times on the same context.
    #[inline]
    pub fn seal(&self, ct: &mut [u8], aad: &[u8], pt: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut ctlen = ct.len();
            cvt(OSSL_HPKE_seal(
                self.as_ptr(),
                ct.as_mut_ptr(),
                &mut ctlen,
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
            ))
            .map(|_| ctlen)
        }
    }

    /// Set the input key material for the context.
    ///
    /// This enables deterministic key generation.
    /// OpenSSL documentation at [`deterministic-key-generation`].
    ///
    /// [`deterministic-key-generation`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#deterministic-key-generation-for-senders
    #[inline]
    pub fn set1_ikme(&self, ikm: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_ikme(
                self.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
            ))?;
            Ok(())
        }
    }

    /// Bind the sender's private key to the context.
    ///
    /// This is for use with the [`Mode::AUTH`] and [`Mode::PSKAUTH`] modes. An error will be
    /// returned if the input key was not generated with the same KEM as the context's suite.
    #[inline]
    pub fn set1_authpriv(&self, pkey_key: &mut PKeyRef<Private>) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpriv(
                self.as_ptr(),
                pkey_key.as_ptr(),
            ))?;
            Ok(())
        }
    }
}

impl ReceiverCtxRef {
    /// Decapsulates a sender's encapsulated public value.
    ///
    /// An optional info parameter allows binding that derived secret to other application/protocol artefacts.
    /// Calling this function more than once on the same context will result in an error.
    #[inline]
    pub fn decap(
        &self,
        enc: &[u8],
        private_key: &PKeyRef<Private>,
        info: &[u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_decap(
                self.as_ptr(),
                enc.as_ptr(),
                enc.len(),
                private_key.as_ptr(),
                info.as_ptr(),
                info.len(),
            ))?;
            Ok(())
        }
    }

    /// Opens a encrypted message.
    ///
    /// The plaintext will be written to the input `pt` buffer, and the number of bytes written will be returned.
    /// If `pt` is too small then an error will be returned. The plaintext length will be a little smaller than the ciphertext length.
    ///
    /// This function can be called multiple times on the same context.
    #[inline]
    pub fn open(&self, pt: &mut [u8], aad: &[u8], ct: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut ptlen = pt.len();
            cvt(OSSL_HPKE_open(
                self.as_ptr(),
                pt.as_mut_ptr(),
                &mut ptlen,
                aad.as_ptr(),
                aad.len(),
                ct.as_ptr(),
                ct.len(),
            ))
            .map(|_| ptlen)
        }
    }

    /// Bind the sender's public key to the context.
    ///
    /// This is for use with the [`Mode::AUTH`] and [`Mode::PSKAUTH`] modes. An error will be
    /// returned if the input key was not generated with the same KEM as the context's suite.
    #[inline]
    pub fn set1_authpub(&self, public_key: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpub(
                self.as_ptr(),
                public_key.as_ptr(),
                public_key.len(),
            ))?;
            Ok(())
        }
    }

    /// Set the sequence number for the context.
    ///
    /// Use of this can be dangerous, as it can lead to nonce reuse with GCM-based AEADs.
    /// OpenSSL documentation at [`re-sequencing`].
    ///
    /// [`re-sequencing`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#re-sequencing
    #[inline]
    pub fn set_seq(&self, seq: u64) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set_seq(self.as_ptr(), seq))?;
            Ok(())
        }
    }
}

macro_rules! common {
    ($t:ident) => {
        impl $t {
            /// Export a secret.
            ///
            /// OpenSSL documentation at [`exporting-secrets`].
            /// [`exporting-secrets`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#exporting-secrets
            #[inline]
            pub fn export(&self, secret: &mut [u8], label: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_export(
                        self.as_ptr(),
                        secret.as_mut_ptr(),
                        secret.len(),
                        label.as_ptr(),
                        label.len(),
                    ))?;
                    Ok(())
                }
            }

            /// Bind the pre shared key to the context.
            ///
            /// This is for use with the [`Mode::PSK`] and [`Mode::PSKAUTH`] modes.
            #[inline]
            pub fn set1_psk(&self, psk_id: &str, psk: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_CTX_set1_psk(
                        self.as_ptr(),
                        psk_id.as_ptr() as *const _,
                        psk.as_ptr(),
                        psk.len(),
                    ))?;
                    Ok(())
                }
            }

            /// Get the sequence number for the context
            ///
            /// OpenSSL documentation at [`re-sequencing`].
            ///
            /// [`re-sequencing`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#re-sequencing
            #[inline]
            pub fn get_seq(&self) -> Result<u64, ErrorStack> {
                let mut seq = 0;
                unsafe {
                    cvt(OSSL_HPKE_CTX_get_seq(self.as_ptr(), &mut seq))?;
                }
                Ok(seq)
            }
        }
    };
}

common!(SenderCtxRef);
common!(ReceiverCtxRef);

impl Suite {
    /// Creates a new sender context.
    #[inline]
    pub fn new_sender(&self, mode: Mode) -> Result<SenderCtx, ErrorStack> {
        openssl_sys::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                OSSL_HPKE_ROLE_SENDER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(SenderCtx::from_ptr(ptr))
        }
    }

    /// Creates a new receiver context.
    #[inline]
    pub fn new_receiver(&self, mode: Mode) -> Result<ReceiverCtx, ErrorStack> {
        openssl_sys::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                OSSL_HPKE_ROLE_RECEIVER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(ReceiverCtx::from_ptr(ptr))
        }
    }

    fn ffi(&self) -> OSSL_HPKE_SUITE {
        OSSL_HPKE_SUITE {
            kem_id: self.kem_id.0,
            kdf_id: self.kdf_id.0,
            aead_id: self.aead_id.0,
        }
    }

    /// Check that the suite is supported locally.
    #[inline]
    pub fn check(&self) -> Result<(), ErrorStack> {
        openssl_sys::init();
        unsafe {
            cvt(OSSL_HPKE_suite_check(self.ffi()))?;
            Ok(())
        }
    }

    /// Generate a new key pair.
    ///
    /// Returns the private key and the public key, which can be used by a receiver and sender respectively.
    #[inline]
    pub fn keygen(&self, ikm: Option<&[u8]>) -> Result<(PKey<Private>, Vec<u8>), ErrorStack> {
        openssl_sys::init();
        let mut public_key = vec![0; self.public_encap_size()];
        let mut private_key = ptr::null_mut();

        unsafe {
            cvt(OSSL_HPKE_keygen(
                self.ffi(),
                public_key.as_mut_ptr(),
                &mut public_key.len(),
                &mut private_key,
                ikm.map(|ikm| ikm.as_ptr()).unwrap_or(ptr::null()),
                ikm.map(|ikm| ikm.len()).unwrap_or(0),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((PKey::from_ptr(private_key), public_key))
        }
    }

    /// Get the size of the public encapsulation.
    ///
    /// This is a helper function to determine the size of the buffer needed for the encapsulation.
    #[inline]
    pub fn public_encap_size(&self) -> usize {
        openssl_sys::init();
        unsafe {
            OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    /// Get the size of the ciphertext for a given plaintext length.
    #[inline]
    pub fn ciphertext_size(&self, clear_len: usize) -> usize {
        openssl_sys::init();
        unsafe {
            OSSL_HPKE_get_ciphertext_size(
                OSSL_HPKE_SUITE {
                    kem_id: self.kem_id.0,
                    kdf_id: self.kdf_id.0,
                    aead_id: self.aead_id.0,
                },
                clear_len,
            )
        }
    }

    /// Get the recommended length for the initial key material.
    #[inline]
    pub fn recommended_ikmelen(&self) -> usize {
        openssl_sys::init();
        unsafe {
            OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    /// Creates a grease value.
    ///
    /// This value is of the appropriate length for a given suite_in value (or a random value if suite_in is not provided)
    /// so that a protocol using HPKE can send so-called GREASE (see RFC8701) values that are harder to distinguish
    /// from a real use of HPKE.
    /// Returns a tuple of `enc` and `ct`. The output `enc` value will have an appropriate length for the suite and a random value,
    /// and the ct output will be a random value.
    #[inline]
    pub fn get_grease_value(
        &self,
        suite_in: Option<Suite>,
        clear_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        openssl_sys::init();
        let mut enc = vec![0; self.public_encap_size()];
        let mut ct = vec![0; self.ciphertext_size(clear_len)];

        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_get_grease_value(
                suite_in.as_ref().map_or(ptr::null_mut(), |s| {
                    &s.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE
                }),
                &self.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE,
                enc.as_mut_ptr(),
                &mut enclen,
                ct.as_mut_ptr(),
                ct.len(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((enc, ct))
        }
    }
}

impl TryFrom<&str> for Suite {
    type Error = ErrorStack;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        openssl_sys::init();
        unsafe {
            let s = CString::new(s).unwrap();
            let mut suite = OSSL_HPKE_SUITE_DEFAULT;
            cvt(OSSL_HPKE_str2suite(s.as_ptr(), &mut suite as *mut _))?;
            Ok(Suite {
                kem_id: Kem(suite.kem_id),
                kdf_id: Kdf(suite.kdf_id),
                aead_id: Aead(suite.aead_id),
            })
        }
    }
}

impl Default for Suite {
    /// The default suite is X25519, HKDF-SHA256, and AES-GCM-128.
    ///
    /// If compiled without ECX support, the default suite is P-256, HKDF-SHA256, and AES-GCM-128.
    fn default() -> Self {
        let suite = OSSL_HPKE_SUITE_DEFAULT;
        Suite {
            kem_id: Kem(suite.kem_id),
            kdf_id: Kdf(suite.kdf_id),
            aead_id: Aead(suite.aead_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mode, Suite};

    // https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#examples
    #[test]
    fn roundtrip() {
        let suite = Suite::default();
        let pt = b"a message not in a bottle";
        let info = b"Some info";
        let aad: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut enc = vec![0; suite.public_encap_size()];
        let mut ct = vec![0; suite.ciphertext_size(pt.len())];

        // Generate receiver's key pair.
        let (private_key, public_key) = suite.keygen(None).unwrap();

        // Sender - encrypt the message with the receiver's public key.
        let sender = suite.new_sender(Mode::BASE).unwrap();
        sender.encap(&mut enc, &public_key, info).unwrap();
        sender.seal(&mut ct, &aad, pt).unwrap();

        // Receiver - decrypt the message with the private key.
        let receiver = suite.new_receiver(Mode::BASE).unwrap();
        receiver.decap(&enc, &private_key, info).unwrap();
        let mut pt2 = vec![0; ct.len()];
        let pt_len = receiver.open(&mut pt2, &aad, &ct).unwrap();
        assert_eq!(pt, &pt2[..pt_len]);
    }

    #[test]
    fn try_from() {
        let suite = Suite::try_from("p-256,hkdf-sha256,aes-128-gcm").unwrap();
        assert_eq!(suite.kem_id, super::Kem::P256);
    }
}
