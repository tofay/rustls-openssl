use crate::hash::Algorithm;
use core::ffi::c_void;
use foreign_types_shared::ForeignTypeRef;
use openssl::{
    error::ErrorStack,
    md::MdRef,
    pkey::Id,
    pkey_ctx::{PkeyCtx, PkeyCtxRef},
};
use openssl_sys::{c_int, EVP_MD, EVP_PKEY_ALG_CTRL, EVP_PKEY_CTX, EVP_PKEY_OP_DERIVE};
use rustls::crypto::ActiveKeyExchange;
use std::boxed::Box;

pub(crate) struct Prf(pub(crate) Algorithm);

// https://github.com/openssl/openssl/blob/21f6c3b4fb35af03e1fedb3fc15d68846ed2235b/include/openssl/obj_mac.h#L5471
const NID_TLS1_PRF: i32 = 1021;

impl rustls::crypto::tls12::Prf for Prf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;
        self.for_secret(output, secret.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        PkeyCtx::new_id(Id::from_raw(NID_TLS1_PRF))
            .and_then(|mut ctx| {
                ctx.derive_init()?;
                set_tls1_prf_md(&mut ctx, self.0.mdref())?;
                set_tls1_prf_secret(&mut ctx, secret)?;
                add_tls1_prf_seed(&mut ctx, label)?;
                add_tls1_prf_seed(&mut ctx, seed)?;
                ctx.derive(Some(output))?;
                Ok(())
            })
            .expect("HDKF-Extract failed");
    }

    fn fips(&self) -> bool {
        crate::fips()
    }
}

// rust-openssl doesn't expose tls1_prf function yet: https://github.com/sfackler/rust-openssl/pull/2329
fn cvt(r: c_int) -> Result<i32, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

extern "C" {
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
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_MD,
        0,
        md as *mut c_void,
    )
}

#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_set1_tls1_prf_secret(
    ctx: *mut EVP_PKEY_CTX,
    sec: *const u8,
    seclen: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_SECRET,
        seclen,
        sec as *mut c_void,
    )
}

#[allow(non_snake_case)]
unsafe fn EVP_PKEY_CTX_add1_tls1_prf_seed(
    ctx: *mut EVP_PKEY_CTX,
    seed: *const u8,
    seedlen: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_SEED,
        seedlen,
        seed as *mut c_void,
    )
}

fn set_tls1_prf_secret<T>(
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

fn add_tls1_prf_seed<T>(
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

fn set_tls1_prf_md<T>(ctx: &mut PkeyCtxRef<T>, digest: &MdRef) -> Result<(), ErrorStack> {
    unsafe {
        cvt(EVP_PKEY_CTX_set_tls1_prf_md(ctx.as_ptr(), digest.as_ptr()))?;
    }

    Ok(())
}

// Test prf using test vectors from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
#[cfg(test)]
mod test {
    use rustls::crypto::tls12::Prf as _;

    use super::super::hash::{SHA256, SHA384};

    use super::Prf;

    #[test]
    fn test_sha256() {
        const SECRET: [u8; 16] = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];

        const SEED: [u8; 16] = [
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5,
            0x19, 0x8c,
        ];

        const LABEL: [u8; 10] = [0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c];

        const EXPECTED: [u8; 100] = [
            0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c,
            0xd4, 0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4,
            0xe6, 0x1e, 0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4,
            0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
            0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d,
            0xef, 0x9b, 0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1,
            0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34,
            0x7b, 0x66,
        ];

        let prf = Prf(SHA256);
        let mut output = [0u8; 100];

        prf.for_secret(&mut output, &SECRET, &LABEL, &SEED);
        assert_eq!(output, EXPECTED);
    }

    #[test]
    fn test_tls1_prf_sha384() {
        const SECRET: [u8; 16] = [
            0xb8, 0x0b, 0x73, 0x3d, 0x6c, 0xee, 0xfc, 0xdc, 0x71, 0x56, 0x6e, 0xa4, 0x8e, 0x55,
            0x67, 0xdf,
        ];

        const SEED: [u8; 16] = [
            0xcd, 0x66, 0x5c, 0xf6, 0xa8, 0x44, 0x7d, 0xd6, 0xff, 0x8b, 0x27, 0x55, 0x5e, 0xdb,
            0x74, 0x65,
        ];

        const LABEL: [u8; 10] = [0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c];

        const EXPECTED: [u8; 148] = [
            0x7b, 0x0c, 0x18, 0xe9, 0xce, 0xd4, 0x10, 0xed, 0x18, 0x04, 0xf2, 0xcf, 0xa3, 0x4a,
            0x33, 0x6a, 0x1c, 0x14, 0xdf, 0xfb, 0x49, 0x00, 0xbb, 0x5f, 0xd7, 0x94, 0x21, 0x07,
            0xe8, 0x1c, 0x83, 0xcd, 0xe9, 0xca, 0x0f, 0xaa, 0x60, 0xbe, 0x9f, 0xe3, 0x4f, 0x82,
            0xb1, 0x23, 0x3c, 0x91, 0x46, 0xa0, 0xe5, 0x34, 0xcb, 0x40, 0x0f, 0xed, 0x27, 0x00,
            0x88, 0x4f, 0x9d, 0xc2, 0x36, 0xf8, 0x0e, 0xdd, 0x8b, 0xfa, 0x96, 0x11, 0x44, 0xc9,
            0xe8, 0xd7, 0x92, 0xec, 0xa7, 0x22, 0xa7, 0xb3, 0x2f, 0xc3, 0xd4, 0x16, 0xd4, 0x73,
            0xeb, 0xc2, 0xc5, 0xfd, 0x4a, 0xbf, 0xda, 0xd0, 0x5d, 0x91, 0x84, 0x25, 0x9b, 0x5b,
            0xf8, 0xcd, 0x4d, 0x90, 0xfa, 0x0d, 0x31, 0xe2, 0xde, 0xc4, 0x79, 0xe4, 0xf1, 0xa2,
            0x60, 0x66, 0xf2, 0xee, 0xa9, 0xa6, 0x92, 0x36, 0xa3, 0xe5, 0x26, 0x55, 0xc9, 0xe9,
            0xae, 0xe6, 0x91, 0xc8, 0xf3, 0xa2, 0x68, 0x54, 0x30, 0x8d, 0x5e, 0xaa, 0x3b, 0xe8,
            0x5e, 0x09, 0x90, 0x70, 0x3d, 0x73, 0xe5, 0x6f,
        ];

        let prf = Prf(SHA384);
        let mut output = [0u8; 148];

        prf.for_secret(&mut output, &SECRET, &LABEL, &SEED);
        assert_eq!(output, EXPECTED);
    }
}
