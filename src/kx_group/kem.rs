//! Key Encapsulation Mechanism (KEM) key exchange groups.
use crate::openssl_internal::kem::{PKeyRefExt, PkeyCtxExt, PkeyCtxRefKemExt, PkeyExt};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};
use zeroize::Zeroize;

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub const MLKEM768: &dyn SupportedKxGroup = &KxGroup {
    named_group: NamedGroup::MLKEM768,
    algorithm_name: b"mlkem768\0",
};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup = &X25519HybridKxGroup(KxGroup {
    named_group: NamedGroup::X25519MLKEM768,
    algorithm_name: b"X25519MLKEM768\0",
});

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
struct KxGroup {
    named_group: NamedGroup,
    algorithm_name: &'static [u8],
}

struct KeyExchange {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
    group: KxGroup,
}

impl KxGroup {
    /// [KxGroup::start] but returns a concrete `KeyExchange` instead of a trait object.
    fn start_internal(&self) -> Result<KeyExchange, Error> {
        PkeyCtx::<()>::new_from_name(self.algorithm_name)
            .and_then(|mut pkey_ctx| {
                pkey_ctx.keygen_init()?;
                let priv_key = pkey_ctx.keygen()?;
                const OSSL_PKEY_PARAM_ENCODED_PUB_KEY: &[u8] = b"encoded-pub-key\0";
                let pub_key = priv_key.get_octet_string_param(OSSL_PKEY_PARAM_ENCODED_PUB_KEY)?;
                Ok(KeyExchange {
                    priv_key,
                    pub_key,
                    group: *self,
                })
            })
            .map_err(|e| Error::General(format!("OpenSSL keygen error: {e}")))
    }
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        self.start_internal()
            .map(|kx| Box::new(kx) as Box<dyn ActiveKeyExchange>)
    }

    fn name(&self) -> NamedGroup {
        self.named_group
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
        PKey::from_encoded_public_key(peer_pub_key, self.algorithm_name)
            .and_then(|key| {
                let mut ctx = PkeyCtx::new(&key)?;
                ctx.encapsulate_init()?;
                let (out, secret) = ctx.encapsulate_to_vec()?;
                Ok(CompletedKeyExchange {
                    group: self.named_group,
                    pub_key: out,
                    secret: SharedSecret::from(secret.as_slice()),
                })
            })
            .map_err(|e| Error::General(format!("OpenSSL encapsulation error: {e}")))
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        PkeyCtx::new(&self.priv_key)
            .and_then(|ctx| {
                ctx.decapsulate_init()?;
                let secret = ctx.decapsulate_to_vec(peer_pub_key)?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL decapsulation error: {e}")))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.group.named_group
    }
}

#[derive(Debug, Copy, Clone)]
struct X25519HybridKxGroup(KxGroup);

struct X25519HybridKeyExchange {
    inner: KeyExchange,
    classical_pub_key: Vec<u8>,
}

impl SupportedKxGroup for X25519HybridKxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        self.0.start_internal().map(|inner| {
            let pub_key = inner.pub_key();
            let classical_pub_key = pub_key[pub_key.len() - 32..].to_vec();
            Box::new(X25519HybridKeyExchange {
                inner,
                classical_pub_key,
            }) as Box<dyn ActiveKeyExchange>
        })
    }

    fn name(&self) -> NamedGroup {
        self.0.named_group
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        self.0.usable_for_version(version)
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        self.0.start_and_complete(peer_pub_key)
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl ActiveKeyExchange for X25519HybridKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Box::new(self.inner).complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.inner.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.inner.group.named_group
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, &self.classical_pub_key))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        PKey::public_key_from_raw_bytes(peer_pub_key, Id::X25519)
            .and_then(|peer_pub_key| {
                // does openssl provide a way to get the classical private key like liboqs?
                // // get the private part of the key
                // const OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY: &[u8] =
                //     b"hybrid_classical_priv\0";
                // let mut private_bytes = self
                //     .priv_key
                //     .get_octet_string_param(OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY)?;
                let mut private_bytes = self.inner.priv_key.raw_private_key()?;
                let priv_key = PKey::private_key_from_raw_bytes(
                    &private_bytes[private_bytes.len() - 32..],
                    Id::X25519,
                )?;
                private_bytes.zeroize();

                let mut deriver = Deriver::new(&priv_key)?;
                deriver.set_peer(&peer_pub_key)?;
                let secret = deriver.derive_to_vec()?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }
}
