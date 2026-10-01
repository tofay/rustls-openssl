use openssl::derive::Deriver;
use openssl::error::ErrorStack;
#[cfg(ossl300)]
use openssl::pkey::KeyType;
use openssl::pkey::{PKey, Private, Public};
#[cfg(ossl300)]
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

#[cfg(ossl300)]
use crate::openssl_internal::PkeyCtxExt as _;

/// `KXGroup`` for X25519
#[derive(Debug)]
struct X25519KxGroup {}

#[derive(Debug)]
struct X25519KeyExchange {
    private_key: PKey<Private>,
    public_key: Vec<u8>,
}

/// Generate an ephemeral X25519 keypair, via `EVP_PKEY_keygen`.
///
/// As with the NIST curves, generation goes through EVP in the global library context, so it
/// reaches the same providers as the rest of this crate's key operations. `PKey::generate_x25519`
/// names the default context, which is where the application's providers may not be.
#[cfg(ossl300)]
fn generate() -> Result<PKey<Private>, ErrorStack> {
    let mut ctx = PkeyCtx::<()>::new_from_name(crate::get_global_lib_ctx(), b"X25519\0")?;
    ctx.keygen_init()?;
    ctx.keygen()
}

/// As above, for OpenSSL before 3.0, which has no library context to generate in.
#[cfg(not(ossl300))]
fn generate() -> Result<PKey<Private>, ErrorStack> {
    PKey::generate_x25519()
}

/// Import a peer's X25519 public key from its 32 raw bytes, in the global library context.
#[cfg(ossl300)]
pub(crate) fn import_public_key(peer_pub_key: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    PKey::<Public>::public_key_from_raw_bytes_ex(
        crate::get_global_lib_ctx(),
        KeyType::X25519,
        None,
        peer_pub_key,
    )
}

/// As above, for OpenSSL before 3.0, which names key types by `NID`.
#[cfg(not(ossl300))]
pub(crate) fn import_public_key(peer_pub_key: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    use openssl::pkey::Id;

    PKey::public_key_from_raw_bytes(peer_pub_key, Id::X25519)
}

/// Import an X25519 private key from its 32 raw bytes, in the global library context.
///
/// The hybrid groups need this for the classical component of a key, which the KEM key holds
/// rather than the `X25519` group. OpenSSL 3.0 and later only, because nothing on OpenSSL
/// before 3.0 builds a hybrid group.
#[cfg(ossl300)]
pub(crate) fn import_private_key(raw_key: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    PKey::private_key_from_raw_bytes_ex(crate::get_global_lib_ctx(), KeyType::X25519, None, raw_key)
}

/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &X25519KxGroup {};

impl SupportedKxGroup for X25519KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        generate()
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
        import_public_key(peer_pub_key)
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
    use openssl::pkey::PKey;
    use rustls::crypto::ActiveKeyExchange;
    use wycheproof::TestResult;

    use super::X25519KeyExchange;

    /// The test vector's private key, imported the way the runtime code imports a peer's
    /// public one: in the context this crate works in.
    fn private_key(seed: &[u8]) -> PKey<openssl::pkey::Private> {
        #[cfg(ossl300)]
        let key = PKey::private_key_from_raw_bytes_ex(
            crate::get_global_lib_ctx(),
            openssl::pkey::KeyType::X25519,
            None,
            seed,
        );
        #[cfg(not(ossl300))]
        let key = PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::X25519);
        key.expect("failed to import an X25519 private key")
    }

    #[test]
    fn x25519() {
        // X25519 is not FIPS-approved for key agreement at any provider version, so with
        // OpenSSL in FIPS mode it cannot be fetched at all. Skip rather than fail: the
        // provider already drops this group from `available_groups()` for the same reason.
        if super::generate().is_err() {
            println!("skipping: OpenSSL cannot supply X25519 in this configuration");
            return;
        }

        let test_set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();
        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                let kx = X25519KeyExchange {
                    private_key: private_key(&test.private_key),
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
