//! Building `SubjectPublicKeyInfo` structures, so public keys can be imported with
//! `d2i_PUBKEY`.
//!
//! Every public key this crate imports goes through here. `d2i_PUBKEY` runs through
//! OpenSSL's decoder framework and yields a provider-backed key, unlike `d2i_RSAPublicKey`
//! and the `EC_KEY_*` setters it replaces: those are implemented in libcrypto, are
//! deprecated as of OpenSSL 3.0, and do not get the provider's import-time key validation.

use rustls::pki_types::AlgorithmIdentifier;

/// Append a DER definite-length header for a `len`-byte value.
fn push_len(out: &mut Vec<u8>, len: usize) -> Option<()> {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len <= 0xffff {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        // No public key this crate accepts is anywhere near 64KiB.
        return None;
    }
    Some(())
}

/// Wrap a raw public key in a `SubjectPublicKeyInfo`.
///
/// `alg_id` is the DER *contents* of the AlgorithmIdentifier SEQUENCE, which is the form
/// `rustls::pki_types::alg_id` provides. `public_key` is the subjectPublicKey payload: for
/// EC keys an uncompressed SEC1 point, for RSA a PKCS#1 `RSAPublicKey`, for Ed25519 the raw
/// 32 bytes.
///
/// Returns `None` only if the input is too large to encode, which no key this crate accepts
/// can be.
pub(crate) fn subject_public_key_info(
    alg_id: AlgorithmIdentifier,
    public_key: &[u8],
) -> Option<Vec<u8>> {
    let alg_id = alg_id.as_ref();

    // AlgorithmIdentifier ::= SEQUENCE { .. }
    let mut algorithm = Vec::with_capacity(alg_id.len() + 4);
    algorithm.push(0x30);
    push_len(&mut algorithm, alg_id.len())?;
    algorithm.extend_from_slice(alg_id);

    // subjectPublicKey ::= BIT STRING, with no unused bits.
    let mut subject_public_key = Vec::with_capacity(public_key.len() + 5);
    subject_public_key.push(0x03);
    push_len(&mut subject_public_key, public_key.len() + 1)?;
    subject_public_key.push(0x00);
    subject_public_key.extend_from_slice(public_key);

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let mut spki = Vec::with_capacity(algorithm.len() + subject_public_key.len() + 4);
    spki.push(0x30);
    push_len(&mut spki, algorithm.len() + subject_public_key.len())?;
    spki.extend_from_slice(&algorithm);
    spki.extend_from_slice(&subject_public_key);
    Some(spki)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_lengths_use_the_shortest_form() {
        for (len, expected) in [
            (0x00, &[0x00][..]),
            (0x7f, &[0x7f][..]),
            (0x80, &[0x81, 0x80][..]),
            (0xff, &[0x81, 0xff][..]),
            (0x100, &[0x82, 0x01, 0x00][..]),
            (0xffff, &[0x82, 0xff, 0xff][..]),
        ] {
            let mut out = Vec::new();
            push_len(&mut out, len).unwrap();
            assert_eq!(out, expected, "wrong header for length {len:#x}");
        }

        let mut out = Vec::new();
        assert!(push_len(&mut out, 0x1_0000).is_none());
    }
}
