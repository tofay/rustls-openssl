use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
#[cfg(not(feature = "fips"))]
use openssl::pkey::Id;
use openssl::pkey::{PKey, Private, Public};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

/// [Supported KeyExchange groups](SupportedKxGroup).
/// * [SECP384R1]
/// * [SECP256R1]
/// * [X25519]
///
/// If the `fips` feature is enabled, only [SECP384R1] and [SECP256R1] are available.
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    SECP256R1,
    SECP384R1,
    #[cfg(not(feature = "fips"))]
    X25519,
];

/// `KXGroup`'s that use `openssl::ec` module with Nid's for key exchange.
#[derive(Debug)]
struct EcKxGroup {
    name: NamedGroup,
    nid: Nid,
}

struct EcKeyExchange {
    priv_key: EcKey<Private>,
    name: NamedGroup,
    group: EcGroup,
    pub_key: Vec<u8>,
}

#[cfg(not(feature = "fips"))]
/// `KXGroup`` for X25519
#[derive(Debug)]
struct X25519KxGroup {}

#[cfg(not(feature = "fips"))]
#[derive(Debug)]
struct X25519KeyExchange {
    private_key: PKey<Private>,
    public_key: Vec<u8>,
}

#[cfg(not(feature = "fips"))]
/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &X25519KxGroup {};
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

impl SupportedKxGroup for EcKxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        EcGroup::from_curve_name(self.nid)
            .and_then(|group| {
                let priv_key = EcKey::generate(&group)?;
                let mut ctx = BigNumContext::new()?;
                let pub_key = priv_key.public_key().to_bytes(
                    &group,
                    PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )?;
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
                let key: PKey<_> = self.priv_key.try_into()?;
                let mut deriver = Deriver::new(&key)?;
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

#[cfg(not(feature = "fips"))]
impl SupportedKxGroup for X25519KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        PKey::generate_x25519()
            .and_then(|private_key| {
                let public_key = private_key.raw_public_key()?;
                Ok(Box::new(X25519KeyExchange {
                    private_key,
                    public_key,
                }) as Box<dyn ActiveKeyExchange>)
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[cfg(not(feature = "fips"))]
impl ActiveKeyExchange for X25519KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        PKey::public_key_from_raw_bytes(peer_pub_key, Id::X25519)
            .and_then(|peer_pub_key| {
                let mut deriver = Deriver::new(&self.private_key)?;
                deriver.set_peer(&peer_pub_key)?;
                let secret = deriver.derive_to_vec()?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[cfg(test)]
mod test {
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey, EcPoint},
        nid::Nid,
        pkey::{Id, PKey},
    };
    use rustls::{crypto::ActiveKeyExchange, NamedGroup};
    use wycheproof::{ecdh::TestName, TestResult};

    use crate::kx::EcKeyExchange;

    use super::X25519KeyExchange;

    #[rstest::rstest]
    #[case::secp256r1(TestName::EcdhSecp256r1, NamedGroup::secp256r1, Nid::X9_62_PRIME256V1)]
    #[case::secp384r1(TestName::EcdhSecp384r1, NamedGroup::secp384r1, Nid::SECP384R1)]
    fn ec(#[case] test_name: TestName, #[case] rustls_group: NamedGroup, #[case] nid: Nid) {
        let test_set = wycheproof::ecdh::TestSet::load(test_name).unwrap();
        let ctx = openssl::bn::BigNumContext::new().unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                let group = EcGroup::from_curve_name(nid).unwrap();
                let private_num = BigNum::from_slice(&test.private_key).unwrap();
                let mut point = EcPoint::new(&group).unwrap();
                point.mul_generator(&group, &private_num, &ctx).unwrap();
                let ec_key = EcKey::from_private_components(&group, &private_num, &point).unwrap();

                let kx = EcKeyExchange {
                    priv_key: ec_key,
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

    #[test]
    fn x25519() {
        let test_set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();
        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                let kx = X25519KeyExchange {
                    private_key: PKey::private_key_from_raw_bytes(&test.private_key, Id::X25519)
                        .unwrap(),
                    public_key: Vec::new(),
                };

                let res = Box::new(kx).complete(&test.public_key);

                // OpenSSL does not support producing a zero shared secret
                let zero_shared_secret = test
                    .flags
                    .contains(&wycheproof::xdh::TestFlag::ZeroSharedSecret);

                match (&test.result, zero_shared_secret) {
                    (TestResult::Acceptable, false) | (TestResult::Valid, _) => match res {
                        Ok(sharedsecret) => {
                            assert_eq!(
                                sharedsecret.secret_bytes(),
                                &test.shared_secret[..],
                                "Derived incorrect secret: {:?}",
                                test
                            );
                        }
                        Err(e) => {
                            panic!("Test failed: {:?}. Error {:?}", test, e);
                        }
                    },
                    _ => {
                        assert!(res.is_err(), "Expected error: {:?}", test);
                    }
                }
            }
        }
    }
}
