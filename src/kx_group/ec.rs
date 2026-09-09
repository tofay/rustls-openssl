use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

#[cfg(ossl300)]
use crate::openssl_internal::kem::PKeyRefExt;

/// `KXGroup`'s that use NIST curves for key exchange.
#[derive(Debug)]
struct EcKxGroup {
    name: NamedGroup,
    nid: Nid,
}

struct EcKeyExchange {
    priv_key: PKey<Private>,
    name: NamedGroup,
    group: EcGroup,
    pub_key: Vec<u8>,
}

/// secp256r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP256R1: &dyn SupportedKxGroup = &EcKxGroup {
    name: NamedGroup::secp256r1,
    nid: Nid::X9_62_PRIME256V1,
};
/// secp384r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP384R1: &dyn SupportedKxGroup = &EcKxGroup {
    name: NamedGroup::secp384r1,
    nid: Nid::SECP384R1,
};

/// Generate an ephemeral keypair on the curve `nid`, via `EVP_PKEY_keygen`.
///
/// Generation must go through EVP rather than `EC_KEY_generate_key`: only the EVP path is
/// dispatched through OpenSSL's provider layer, so only it runs inside the FIPS provider --
/// and so gets that provider's SP 800-56A generation path and its pairwise consistency test --
/// when one is in use.
fn generate(nid: Nid) -> Result<PKey<Private>, ErrorStack> {
    let mut ctx = PkeyCtx::new_id(Id::EC)?;
    ctx.keygen_init()?;
    ctx.set_ec_paramgen_curve_nid(nid)?;
    ctx.keygen()
}

/// The public part of `key` as an uncompressed SEC1 point, the encoding TLS key shares use.
#[cfg(ossl300)]
fn encoded_public_key(key: &PKey<Private>, _group: &EcGroup) -> Result<Vec<u8>, ErrorStack> {
    const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: &[u8] = b"encoded-pub-key\0";
    key.get_octet_string_param(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)
}

/// As above, for OpenSSL before 3.0, which has no `OSSL_PARAM` accessors.
///
/// This reads the public point out of the key rather than performing any cryptography, and
/// there is no provider layer to bypass on 1.1.1 in any case.
#[cfg(not(ossl300))]
fn encoded_public_key(key: &PKey<Private>, group: &EcGroup) -> Result<Vec<u8>, ErrorStack> {
    use openssl::ec::PointConversionForm;

    let mut ctx = BigNumContext::new()?;
    key.ec_key()?
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
}

impl SupportedKxGroup for EcKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        EcGroup::from_curve_name(self.nid)
            .and_then(|group| {
                let priv_key = generate(self.nid)?;
                let pub_key = encoded_public_key(&priv_key, &group)?;
                Ok(Box::new(EcKeyExchange {
                    priv_key,
                    name: self.name,
                    group,
                    pub_key,
                }) as Box<dyn ActiveKeyExchange>)
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl EcKeyExchange {
    fn load_peer_key(&self, peer_pub_key: &[u8]) -> Result<PKey<Public>, ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&self.group, peer_pub_key, &mut ctx)?;
        let peer_key = EcKey::from_public_key(&self.group, &point)?;
        peer_key.check_key()?;
        let peer_key: PKey<_> = peer_key.try_into()?;
        Ok(peer_key)
    }
}

impl ActiveKeyExchange for EcKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // Reject public keys that are not in uncompressed form
        if peer_pub_key.first() != Some(&0x04) {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        self.load_peer_key(peer_pub_key)
            .and_then(|peer_key| {
                let mut deriver = Deriver::new(&self.priv_key)?;
                deriver.set_peer(&peer_key)?;
                let secret = deriver.derive_to_vec()?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[cfg(test)]
mod test {
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey, EcPoint},
        nid::Nid,
        pkey::PKey,
    };
    use rustls::{
        NamedGroup,
        crypto::{ActiveKeyExchange, SupportedKxGroup},
    };
    use wycheproof::{TestResult, ecdh::TestName};

    use super::EcKeyExchange;

    #[rstest::rstest]
    #[case::secp256r1(TestName::EcdhSecp256r1, NamedGroup::secp256r1, Nid::X9_62_PRIME256V1)]
    #[case::secp384r1(TestName::EcdhSecp384r1, NamedGroup::secp384r1, Nid::SECP384R1)]
    fn test_ec_kx(#[case] test_name: TestName, #[case] rustls_group: NamedGroup, #[case] nid: Nid) {
        let test_set = wycheproof::ecdh::TestSet::load(test_name).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                let group = EcGroup::from_curve_name(nid).unwrap();
                let private_num = BigNum::from_slice(&test.private_key).unwrap();
                let mut point = EcPoint::new(&group).unwrap();
                point
                    .mul_generator2(&group, &private_num, &mut ctx)
                    .unwrap();
                let ec_key = EcKey::from_private_components(&group, &private_num, &point).unwrap();

                let kx = EcKeyExchange {
                    // These vectors pin a specific private key, so they exercise `complete()`
                    // rather than generation; import it directly.
                    priv_key: PKey::from_ec_key(ec_key).unwrap(),
                    name: rustls_group,
                    group: EcGroup::from_curve_name(nid).unwrap(),
                    pub_key: Vec::new(),
                };

                let res = Box::new(kx).complete(&test.public_key);
                let pub_key_uncompressed = test.public_key.first() == Some(&0x04);

                match (&test.result, pub_key_uncompressed) {
                    (TestResult::Acceptable, true) | (TestResult::Valid, true) => {
                        assert!(res.is_ok(), "Test failed: {:?}", test);
                        assert_eq!(
                            res.unwrap().secret_bytes(),
                            &test.shared_secret[..],
                            "Derived incorrect secret: {:?}",
                            test
                        );
                    }
                    _ => {
                        assert!(res.is_err(), "Expected error: {:?}", test);
                    }
                }
            }
        }
    }

    /// Exercises `start()`, i.e. the `EVP_PKEY_keygen` path and the public key encoding.
    /// The wycheproof vectors above cannot: they pin a private key and only test `complete()`.
    #[rstest::rstest]
    #[case::secp256r1(crate::kx_group::SECP256R1, 65)]
    #[case::secp384r1(crate::kx_group::SECP384R1, 97)]
    fn generated_keys_agree(
        #[case] group: &'static dyn SupportedKxGroup,
        #[case] pub_key_len: usize,
    ) {
        let a = group.start().unwrap();
        let b = group.start().unwrap();

        let a_pub = a.pub_key().to_vec();
        let b_pub = b.pub_key().to_vec();

        // Uncompressed SEC1 point of the expected width for the curve.
        assert_eq!(a_pub.len(), pub_key_len);
        assert_eq!(b_pub.len(), pub_key_len);
        assert_eq!(a_pub.first(), Some(&0x04));
        assert_eq!(b_pub.first(), Some(&0x04));

        // Ephemeral: each `start()` must produce a fresh key.
        assert_ne!(a_pub, b_pub);

        let secret_a = a.complete(&b_pub).unwrap();
        let secret_b = b.complete(&a_pub).unwrap();
        assert_eq!(secret_a.secret_bytes(), secret_b.secret_bytes());
    }
}
