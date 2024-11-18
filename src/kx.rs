use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
#[cfg(feature = "x25519")]
use openssl::pkey::Id;
use openssl::pkey::{PKey, Private, Public};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

/// Supported `KeyExchange` groups.
/// ```ignore
/// SECP384R1
/// SECP256R1
/// X25519 // Enabled with the `x25519` feature
/// ```
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    SECP256R1,
    SECP384R1,
    #[cfg(feature = "x25519")]
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

#[cfg(feature = "x25519")]
/// KXGroup for X25519
#[derive(Debug)]
struct X25519KxGroup {}

#[cfg(feature = "x25519")]
#[derive(Debug)]
struct X25519KeyExchange {
    private_key: PKey<Private>,
    public_key: Vec<u8>,
}

#[cfg(feature = "x25519")]
pub const X25519: &dyn SupportedKxGroup = &X25519KxGroup {};

pub const SECP256R1: &dyn SupportedKxGroup = &EcKxGroup {
    name: NamedGroup::secp256r1,
    nid: Nid::X9_62_PRIME256V1,
};

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

#[cfg(feature = "x25519")]
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

#[cfg(feature = "x25519")]
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
