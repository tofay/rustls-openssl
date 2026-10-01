use crate::hash::Algorithm;
#[cfg(not(ossl300))]
use openssl::pkey::{PKey, Private};
#[cfg(not(ossl300))]
use openssl::sign::Signer;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Key, Tag};

#[cfg(ossl300)]
use crate::openssl_internal::Mac;
#[cfg(ossl300)]
use zeroize::Zeroizing;

pub(crate) struct Hmac(pub(crate) Algorithm);

/// An HMAC key, and the state needed to compute tags with it.
#[cfg(ossl300)]
struct HmacKey {
    mac: &'static Mac,
    hash: Algorithm,
    /// Zeroized on drop. This is a TLS 1.3 traffic secret or an HKDF PRK, and a plain `Vec<u8>`
    /// would hand it back to the allocator intact.
    key: Zeroizing<Vec<u8>>,
}

/// As above, for OpenSSL before 3.0, where there is no provider layer to fetch a MAC from.
#[cfg(not(ossl300))]
struct HmacKey {
    key: PKey<Private>,
    hash: Algorithm,
}

/// The fetched HMAC implementation.
///
/// Cached because an `EVP_MAC` is immutable and shareable, and rustls asks for a key on every
/// transcript hash and every key derivation, so a fetch per key is a provider lookup per call.
///
/// A `OnceLock` never runs its value's destructor, so this `Mac` is never freed: like the
/// cached digests in [`crate::hash`] and ciphers in [`crate::cipher`], it is a process-lifetime
/// object, and freeing it during teardown would reach into providers that may already be gone.
#[cfg(ossl300)]
static HMAC: std::sync::OnceLock<Mac> = std::sync::OnceLock::new();

#[cfg(ossl300)]
fn hmac() -> &'static Mac {
    HMAC.get_or_init(|| {
        Mac::fetch(crate::primed_lib_ctx(), "HMAC").expect("Failed to fetch the HMAC algorithm")
    })
}

impl rustls::crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        #[cfg(ossl300)]
        {
            Box::new(HmacKey {
                mac: hmac(),
                hash: self.0,
                key: Zeroizing::new(key.to_vec()),
            })
        }

        #[cfg(not(ossl300))]
        {
            Box::new(HmacKey {
                key: PKey::hmac(key).expect("Failed to read Hmac Key"),
                hash: self.0,
            })
        }
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

#[cfg(ossl300)]
impl Key for HmacKey {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let data: Vec<&[u8]> = std::iter::once(first)
            .chain(middle.iter().copied())
            .chain(std::iter::once(last))
            .collect();
        Tag::new(
            &self
                .mac
                .sign(self.hash.name(), &self.key, &data)
                .expect("HMAC signing failed"),
        )
    }

    fn tag_len(&self) -> usize {
        self.hash.output_len()
    }
}

#[cfg(not(ossl300))]
impl Key for HmacKey {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        Signer::new(self.hash.message_digest(), &self.key)
            .and_then(|mut signer| {
                signer.update(first)?;
                for part in middle {
                    signer.update(part)?;
                }
                signer.update(last)?;
                Ok(Tag::new(&signer.sign_to_vec()?))
            })
            .expect("HMAC signing failed")
    }

    fn tag_len(&self) -> usize {
        self.hash.output_len()
    }
}

#[cfg(test)]
mod tests {
    use super::Hmac;
    use crate::hash::Algorithm::{SHA256, SHA384, SHA512};
    use rustls::crypto::hmac::Hmac as _;

    /// The RFC 4231 test cases, with the keys OpenSSL is given here.
    #[test]
    fn tags_match_rfc4231() {
        // RFC 4231 case 1: 20 bytes of 0x0b.
        let tag = Hmac(SHA256).with_key(&[0x0b; 20]).sign(&[b"Hi There"]);
        assert_eq!(
            hex::encode(tag.as_ref()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 case 2: "Jefe" as the key.
        let tag = Hmac(SHA384).with_key(b"Jefe").sign_concat(
            &[],
            &[&b"what do ya want "[..]],
            &b"for nothing?"[..],
        );
        assert_eq!(
            hex::encode(tag.as_ref()),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );

        // SHA-512, cross-checked against an independent HMAC-SHA-512 over the same key and
        // message.
        let tag = Hmac(SHA512).with_key(&[0x0b; 20]).sign_concat(
            &[],
            &[&b"test with "[..]],
            &b"SHA-512"[..],
        );
        assert_eq!(
            hex::encode(tag.as_ref()),
            "a475edd09dd5039eef1f5fcf404741c3296a61602e5156eaa282ef903cc9fb38\
             d03aa1c7fc16727c03021441b23b6aeb088151a932f962125d35dcf841b7c921"
        );
    }

    /// The parts have to be concatenated, not hashed separately: this is the property the
    /// TLS 1.3 transcript hashing depends on, and the one a chunked `update` loop could get
    /// wrong without it being visible anywhere else.
    #[test]
    fn parts_are_concatenated() {
        let whole = Hmac(SHA256).with_key(&[0x0b; 20]).sign(&[b"Hi There"]);
        let chunked =
            Hmac(SHA256)
                .with_key(&[0x0b; 20])
                .sign_concat(&[], &[b"Hi ", b"Ther", b"e"], &[]);
        assert_eq!(whole.as_ref(), chunked.as_ref());
    }

    /// `first` and `last` are not decoration: a `chain` that dropped `last`, or swapped the two,
    /// would pass every other test here, because they all leave them empty.
    #[test]
    fn first_and_last_parts_are_included_in_order() {
        let key = [0x0b; 20];
        let whole = Hmac(SHA256).with_key(&key).sign(&[b"Hi There!"]);
        let chunked = Hmac(SHA256)
            .with_key(&key)
            .sign_concat(&b"Hi "[..], &[b"There"], &b"!"[..]);
        assert_eq!(whole.as_ref(), chunked.as_ref());

        // Order matters, so swapping the ends is a different tag.
        let swapped = Hmac(SHA256)
            .with_key(&key)
            .sign_concat(&b"!"[..], &[b"There"], &b"Hi "[..]);
        assert_ne!(whole.as_ref(), swapped.as_ref());
    }

    /// The tag length rustls asks each `Key` for, against the tag that is actually produced.
    #[test]
    fn tag_length_matches_the_digest_and_the_tag() {
        for algorithm in [SHA256, SHA384, SHA512] {
            let key = Hmac(algorithm).with_key(b"key");
            let tag = key.sign(&[b"message"]);
            assert_eq!(key.tag_len(), tag.as_ref().len());
            assert_eq!(Hmac(algorithm).hash_output_len(), tag.as_ref().len());
        }
    }
}
