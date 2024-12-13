use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};

use crate::openssl_internal::kem::{decapsulate_init, decapsulate_to_vec, new_pkey_ctx_from_name};

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
pub struct KxGroup {
    named_group: NamedGroup,
    algorithm_name: &'static [u8],
}

impl KxGroup {
    /// Create a new key exchange group with the specified named group and OpenSSL algorithm name.
    /// The name should be a null terminated string, e.g `b"kyber768\0"`.
    pub const fn new(named_group: NamedGroup, algorithm_name: &'static [u8]) -> Self {
        Self {
            named_group,
            algorithm_name,
        }
    }
}

struct KeyExchange {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
    mlkem: KxGroup,
}

// pub const MLKEM768: &dyn SupportedKxGroup = &KxGroup {
//     named_group: NamedGroup::MLKEM768,
//     algorithm_id: 513,
// };

// pub const X25519MLKEM768: &dyn SupportedKxGroup = &KxGroup {
//     named_group: NamedGroup::X25519MLKEM768,
//     algorithm_id: 0x11ec,
// };

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        new_pkey_ctx_from_name(self.algorithm_name)
            .and_then(|mut pkey_ctx| {
                pkey_ctx.keygen_init()?;
                let priv_key = pkey_ctx.keygen()?;
                let pub_key = priv_key.raw_public_key()?;
                Ok(Box::new(KeyExchange {
                    priv_key,
                    pub_key,
                    mlkem: *self,
                }) as Box<dyn ActiveKeyExchange>)
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn name(&self) -> NamedGroup {
        self.named_group
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        PkeyCtx::new(&self.priv_key)
            .and_then(|mut ctx| {
                decapsulate_init(&mut ctx)?;
                let secret = decapsulate_to_vec(&mut ctx, peer_pub_key)?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.mlkem.named_group
    }
}
