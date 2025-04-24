//! Util for creating test servers, adapted from https://github.com/rustls/rustls/blob/20de56876d8bc45224c351339337c61126c1c954/provider-example/examples/server.rs#L58
use std::io::Write;
use std::sync::Arc;

use openssl::pkey::PKey;
use rcgen::SignatureAlgorithm;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::ServerConfig;

/// Algorithm to use for the server keypair. Required to workaround
/// https://github.com/openssl/openssl/issues/10468 and rcgen::SignatureAlgorithm not
/// being PartialEq, as we use openssl to generate the keypair for ed25519
#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Alg {
    PKCS_ED25519,
    PKCS_RSA_SHA512,
    PKCS_RSA_SHA384,
    PKCS_ECDSA_P256_SHA256,
}

/// Start a server that uses [rustls_openssl::default_provider] on a random port,
/// generating a certificate for `localhost` with the specified algorithm.
///
/// The server will handle a single connection.
///
/// Returns the port the server is listening on and the CA certificate used to sign the server certificate.
pub fn start_server(alg: Alg, provider: Option<CryptoProvider>) -> (u16, CertificateDer<'static>) {
    #[cfg(feature = "fips")]
    {
        rustls_openssl::fips::enable();
    }

    let pki = TestPki::for_algorithm(alg);
    let ca_cert_der = pki.ca_cert_der.clone();
    let server_config = pki.with_provider(provider.unwrap_or(rustls_openssl::default_provider()));

    let listener = std::net::TcpListener::bind("[::]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut stream = listener.incoming().next().unwrap().unwrap();
        let mut acceptor = Acceptor::default();

        loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                let mut conn = accepted.into_connection(server_config.clone()).unwrap();
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
        }
    });
    (port, ca_cert_der)
}

struct TestPki {
    ca_cert_der: CertificateDer<'static>,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl Alg {
    fn to_rcgen_algorithm(self) -> &'static SignatureAlgorithm {
        match self {
            Alg::PKCS_ED25519 => &rcgen::PKCS_ED25519,
            Alg::PKCS_RSA_SHA512 => &rcgen::PKCS_RSA_SHA512,
            Alg::PKCS_RSA_SHA384 => &rcgen::PKCS_RSA_SHA384,
            Alg::PKCS_ECDSA_P256_SHA256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }
}

impl TestPki {
    fn for_algorithm(alg: Alg) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "rustls-openssl tests");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        let ca_key = generate_for(alg);

        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = generate_for(alg);
        let server_cert = server_ee_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        Self {
            ca_cert_der: ca_cert.into(),
            server_cert_der: server_cert.into(),
            server_key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        }
    }

    fn with_provider(self, provider: CryptoProvider) -> Arc<ServerConfig> {
        let mut server_config = ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![self.server_cert_der], self.server_key_der)
            .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}

fn generate_for(alg: Alg) -> rcgen::KeyPair {
    if alg == Alg::PKCS_ED25519 {
        // use openssl as openssl doesn't support the PKCS8v2 format which
        // rcgen/ring produces: https://github.com/openssl/openssl/issues/10468
        let key = PKey::generate_ed25519().unwrap();
        let pem = key.private_key_to_pkcs8().unwrap();
        let key = PrivatePkcs8KeyDer::from(&pem[..]);

        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, alg.to_rcgen_algorithm()).unwrap()
    } else {
        rcgen::KeyPair::generate_for(alg.to_rcgen_algorithm()).unwrap()
    }
}
