use openssl::derive::Deriver;
use openssl::pkey::Id;
use openssl::pkey::{PKey, Private};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

/// `KXGroup`` for X25519
#[derive(Debug)]
struct X25519KxGroup {}

#[derive(Debug)]
struct X25519KeyExchange {
    private_key: PKey<Private>,
    public_key: Vec<u8>,
}

/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &X25519KxGroup {};

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
    use openssl::pkey::{Id, PKey};
    use rustls::crypto::ActiveKeyExchange;
    use wycheproof::TestResult;

    use super::X25519KeyExchange;

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
