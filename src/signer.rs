use openssl::error::ErrorStack;
use openssl::pkey::{Id, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Padding;
use openssl::sign::RsaPssSaltlen;

use crate::hash::Algorithm;
use crate::hash::Algorithm::{SHA256, SHA384, SHA512};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;

/// A struct that implements [rustls::crypto::KeyProvider].
#[derive(Debug)]
pub struct KeyProvider;

/// RSA schemes in descending order of preference
pub(crate) static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
struct Signer {
    key: Arc<openssl::pkey::PKey<Private>>,
    scheme: SignatureScheme,
}

#[derive(Debug)]
struct PKey(Arc<openssl::pkey::PKey<Private>>);

fn rsa_padding(scheme: SignatureScheme) -> Option<Padding> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => Some(Padding::PKCS1),
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(Padding::PKCS1_PSS),
        _ => None,
    }
}

fn message_digest(scheme: SignatureScheme) -> Option<Algorithm> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::ECDSA_NISTP256_SHA256 => Some(SHA256),
        SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::ECDSA_NISTP384_SHA384 => Some(SHA384),
        SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA512
        | SignatureScheme::ECDSA_NISTP521_SHA512 => Some(SHA512),
        _ => None,
    }
}

fn mgf1(scheme: SignatureScheme) -> Option<Algorithm> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Some(SHA256),
        SignatureScheme::RSA_PSS_SHA384 => Some(SHA384),
        SignatureScheme::RSA_PSS_SHA512 => Some(SHA512),
        _ => None,
    }
}

fn pss_salt_len(scheme: SignatureScheme) -> Option<RsaPssSaltlen> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(RsaPssSaltlen::DIGEST_LENGTH),
        _ => None,
    }
}

impl PKey {
    fn signer(&self, scheme: SignatureScheme) -> Signer {
        Signer {
            key: Arc::clone(&self.0),
            scheme,
        }
    }

    /// The ECDSA signature scheme for this key's curve, or `None` if it is not a curve
    /// this provider signs with.
    ///
    /// Read via `EVP_PKEY_get_utf8_string_param` rather than `EVP_PKEY_get1_EC_KEY`: the
    /// latter is deprecated as of OpenSSL 3.0 and downgrades a provider-backed key to a
    /// legacy one just to read its curve name.
    #[cfg(ossl300)]
    fn ecdsa_scheme(&self) -> Option<SignatureScheme> {
        use crate::openssl_internal::PKeyRefExt;
        const OSSL_PKEY_PARAM_GROUP_NAME: &[u8] = b"group\0";

        let group = self
            .0
            .get_utf8_string_param(OSSL_PKEY_PARAM_GROUP_NAME)
            .ok()?;

        ecdsa_scheme_for_group(&group)
    }

    /// As above, for OpenSSL before 3.0, which has no `OSSL_PARAM` accessors.
    ///
    /// This reads the curve out of the key rather than performing any cryptography, and
    /// there is no provider layer to bypass on 1.1.1 in any case.
    #[cfg(not(ossl300))]
    fn ecdsa_scheme(&self) -> Option<SignatureScheme> {
        ecdsa_scheme_for_nid(self.0.ec_key().ok()?.group().curve_name()?)
    }
}

/// The signature scheme this crate signs with for an ECDSA key on the curve OpenSSL reports
/// under `group`.
///
/// `None` for a curve this provider signs with differently, or not at all: an unknown curve has
/// to be refused here rather than signed with and left for the peer to reject.
#[cfg(ossl300)]
fn ecdsa_scheme_for_group(group: &str) -> Option<SignatureScheme> {
    // OpenSSL reports a curve by its short name; the aliases are the other spellings a
    // provider is free to report, and both are accepted.
    match group {
        "prime256v1" | "P-256" => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        "secp384r1" | "P-384" => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
        "secp521r1" | "P-521" => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
        _ => None,
    }
}

/// As [`ecdsa_scheme_for_group`], for the `NID` OpenSSL before 3.0 names a curve by.
#[cfg(not(ossl300))]
fn ecdsa_scheme_for_nid(nid: openssl::nid::Nid) -> Option<SignatureScheme> {
    match nid {
        openssl::nid::Nid::X9_62_PRIME256V1 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        openssl::nid::Nid::SECP384R1 => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
        openssl::nid::Nid::SECP521R1 => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
        _ => None,
    }
}

/// Import a private key in the global library context, on OpenSSL 3.0+.
///
/// A signature is computed by the providers of the library context its key belongs to, so the
/// key is imported into the one [crate::get_global_lib_ctx] reports: the application's
/// configured providers, and in a FIPS deployment the validated module. The
/// `d2i_AutoPrivateKey` that `PKey::private_key_from_der` calls names the default context
/// instead.
#[cfg(ossl300)]
fn import_private_key(der: &[u8]) -> Result<openssl::pkey::PKey<Private>, ErrorStack> {
    use crate::openssl_internal::PKeyPrivateExt;
    openssl::pkey::PKey::<Private>::private_key_from_der_ex(crate::get_global_lib_ctx(), der, None)
}

/// As above, for OpenSSL before 3.0, which has no `OSSL_LIB_CTX` and no provider layer to
/// keep the key inside of.
#[cfg(not(ossl300))]
fn import_private_key(der: &[u8]) -> Result<openssl::pkey::PKey<Private>, ErrorStack> {
    openssl::pkey::PKey::private_key_from_der(der)
}

impl rustls::crypto::KeyProvider for KeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        let pkey = import_private_key(key_der.secret_der())
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        Ok(Arc::new(PKey(Arc::new(pkey))))
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl SigningKey for PKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        match self.algorithm() {
            SignatureAlgorithm::RSA => RSA_SCHEMES
                .iter()
                .find(|scheme| offered.contains(scheme))
                .map(|scheme| Box::new(self.signer(*scheme)) as Box<dyn rustls::sign::Signer>),

            SignatureAlgorithm::ED25519 => {
                if crate::verify::ed25519_available() && offered.contains(&SignatureScheme::ED25519)
                {
                    Some(Box::new(Signer {
                        key: Arc::clone(&self.0),
                        scheme: SignatureScheme::ED25519,
                    }))
                } else {
                    None
                }
            }
            SignatureAlgorithm::ED448 => {
                if offered.contains(&SignatureScheme::ED448) {
                    Some(Box::new(Signer {
                        key: Arc::clone(&self.0),
                        scheme: SignatureScheme::ED448,
                    }))
                } else {
                    None
                }
            }
            SignatureAlgorithm::ECDSA => {
                // First determine our scheme, then see if that was offered.
                self.ecdsa_scheme().and_then(|scheme| {
                    if offered.contains(&scheme) {
                        Some(Box::new(self.signer(scheme)) as Box<dyn rustls::sign::Signer>)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    /// Return the RFC 5280 SubjectPublicKeyInfo for this key.
    ///
    /// The `SigningKey` trait opts out of this by default, returning `None`.
    /// Leaving it at the default is not harmless: it makes
    /// [`rustls::sign::CertifiedKey::keys_match`] fail with
    /// `InconsistentKeys::Unknown` rather than succeed, because that check
    /// starts by asking the key for its SPKI and gives up when none is
    /// available. A caller that verifies its certificate and private key
    /// agree before serving — a reasonable thing to do at startup — can
    /// therefore load no certificate at all with this provider.
    ///
    /// OpenSSL already holds the public half, so producing the SPKI is a
    /// direct call. Errors map to `None` to match the trait's "unavailable"
    /// contract, which has no fallible variant.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key_to_der().ok().map(Into::into)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.0.id() {
            Id::RSA => SignatureAlgorithm::RSA,
            Id::EC => SignatureAlgorithm::ECDSA,
            Id::ED448 => SignatureAlgorithm::ED448,
            Id::ED25519 => SignatureAlgorithm::ED25519,
            _ => SignatureAlgorithm::Unknown(self.0.id().as_raw().try_into().unwrap_or_default()),
        }
    }
}

impl rustls::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match message_digest(self.scheme) {
            Some(algorithm) => {
                let digest = algorithm
                    .digest(message)
                    .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;

                PkeyCtx::new(&self.key)
                    .and_then(|mut ctx| {
                        ctx.sign_init()?;
                        ctx.set_signature_md(algorithm.mdref()?)?;

                        if let Some(padding) = rsa_padding(self.scheme) {
                            ctx.set_rsa_padding(padding)?;
                        }
                        if let Some(mgf1) = mgf1(self.scheme) {
                            ctx.set_rsa_mgf1_md(mgf1.mdref()?)?;
                        }
                        if let Some(len) = pss_salt_len(self.scheme) {
                            ctx.set_rsa_pss_saltlen(len)?;
                        }

                        let mut signature = Vec::new();
                        ctx.sign_to_vec(digest.as_ref(), &mut signature)?;
                        Ok(signature)
                    })
                    .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
            }

            // Ed25519 and Ed448 have no separate digest step: the signature is over the
            // message. They also have no `EVP_PKEY_sign` support at all -- OpenSSL 3.0
            // rejects `EVP_PKEY_sign_init` for both with
            // `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`, since they can only be used
            // one-shot -- so they use the digest-signature API.
            None => openssl::sign::Signer::new_without_digest(&self.key)
                .and_then(|mut signer| signer.sign_oneshot_to_vec(message))
                .map_err(|e| Error::General(format!("OpenSSL error: {e}"))),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::SignatureScheme;

    /// The curve-name table decides which signature scheme a key is offered under, and an
    /// entry that is missing or wrong does not fail: `choose_scheme` simply returns `None`,
    /// and the handshake fails much later with a message about signature schemes.
    #[cfg(ossl300)]
    #[test]
    fn every_curve_name_maps_to_a_scheme() {
        for (name, expected) in [
            ("prime256v1", SignatureScheme::ECDSA_NISTP256_SHA256),
            ("P-256", SignatureScheme::ECDSA_NISTP256_SHA256),
            ("secp384r1", SignatureScheme::ECDSA_NISTP384_SHA384),
            ("P-384", SignatureScheme::ECDSA_NISTP384_SHA384),
            ("secp521r1", SignatureScheme::ECDSA_NISTP521_SHA512),
            ("P-521", SignatureScheme::ECDSA_NISTP521_SHA512),
        ] {
            assert_eq!(
                ecdsa_scheme_for_group(name),
                Some(expected),
                "{name} should map to {expected:?}"
            );
        }
    }

    /// A curve this crate does not sign with has to be refused, including the lookalikes: a
    /// name that is merely close to a supported one is not that one.
    #[cfg(ossl300)]
    #[test]
    fn unsupported_curve_names_are_refused() {
        for name in [
            "secp256k1",  // supported by the verification side, not the signing side
            "P-256K",     //
            "prime256v2", // not a curve
            "brainpoolP256r1",
            "x25519",     // not an ECDSA curve at all
            "",           //
            "PRIME256V1", // matching is case-sensitive
            " prime256v1",
            "prime256v1 ",
            "prime256v1\0",
        ] {
            assert_eq!(
                ecdsa_scheme_for_group(name),
                None,
                "{name:?} should not map to a scheme"
            );
        }
    }

    /// The `NID` table has to agree with the name table above: both answer the same question,
    /// and only one of them is compiled on any given OpenSSL version.
    #[cfg(not(ossl300))]
    #[test]
    fn every_curve_nid_maps_to_a_scheme() {
        use openssl::nid::Nid;

        assert_eq!(
            ecdsa_scheme_for_nid(Nid::X9_62_PRIME256V1),
            Some(SignatureScheme::ECDSA_NISTP256_SHA256)
        );
        assert_eq!(
            ecdsa_scheme_for_nid(Nid::SECP384R1),
            Some(SignatureScheme::ECDSA_NISTP384_SHA384)
        );
        assert_eq!(
            ecdsa_scheme_for_nid(Nid::SECP521R1),
            Some(SignatureScheme::ECDSA_NISTP521_SHA512)
        );
        for nid in [Nid::SECP256K1, Nid::UNDEF] {
            assert_eq!(ecdsa_scheme_for_nid(nid), None, "{nid:?} has no scheme");
        }
    }

    /// Round trip: a real key's curve name, read through the provider, selects a scheme, and
    /// what that scheme signs verifies. This is the chain the table sits in.
    #[cfg(ossl300)]
    #[test]
    fn a_generated_key_signs_with_the_scheme_its_curve_maps_to() {
        use crate::openssl_internal::{PKeyRefExt as _, PkeyCtxExt as _};
        use openssl::pkey::{PKey, Private};
        use openssl::pkey_ctx::PkeyCtx;
        use rustls::sign::Signer as _;

        for (nid, expected) in [
            (
                openssl::nid::Nid::X9_62_PRIME256V1,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                openssl::nid::Nid::SECP384R1,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
            (
                openssl::nid::Nid::SECP521R1,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ),
        ] {
            let mut ctx = PkeyCtx::<()>::new_from_name(crate::get_global_lib_ctx(), b"EC\0")
                .expect("no EC in the configured library context");
            ctx.keygen_init().unwrap();
            ctx.set_ec_paramgen_curve_nid(nid).unwrap();
            let key: PKey<Private> = ctx.keygen().unwrap();

            let key = super::PKey(Arc::new(key));
            let scheme = key
                .ecdsa_scheme()
                .unwrap_or_else(|| panic!("{nid:?} should map to a scheme"));
            assert_eq!(scheme, expected);

            let message = b"a message to sign";
            let signature = key.signer(scheme).sign(message).expect("signing failed");

            let public = key.0.get_octet_string_param(b"encoded-pub-key\0").unwrap();
            let algorithms = crate::verify::SUPPORTED_SIG_ALGS
                .mapping
                .iter()
                .find(|(s, _)| *s == scheme)
                .map(|(_, v)| *v)
                .expect("the scheme is in the verification algorithms");
            assert!(
                algorithms
                    .iter()
                    .any(|alg| alg.verify_signature(&public, message, &signature).is_ok()),
                "{nid:?} signed a signature nothing accepts"
            );
        }
    }
}
