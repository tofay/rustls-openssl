//! Integration tests
use crate::server::start_server;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
#[cfg(not(feature = "fips"))]
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rstest::rstest;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};
use rustls_openssl::{custom_provider, default_provider};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use webpki::types::CertificateDer;

pub mod server;

fn test_with_provider(
    provider: CryptoProvider,
    port: u16,
    root_ca_certs: Vec<CertificateDer<'static>>,
) -> CipherSuite {
    #[cfg(feature = "fips")]
    {
        rustls_openssl::enable_fips();
    }

    // Add default webpki roots to the root store
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    root_store.add_parsable_certificates(root_ca_certs);

    #[allow(unused_mut)]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    #[cfg(feature = "fips")]
    {
        config.require_ems = true;
        assert!(config.fips());
    }

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect(format!("localhost:{port}")).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "q" is a single byte command
    exit_buffer[0] = b'q'; // Assign the ASCII value of "q" to the buffer

    // Write the "q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    ciphersuite.suite()
}

fn test_with_custom_config_to_internet(
    suite: SupportedCipherSuite,
    group: &'static dyn SupportedKxGroup,
) -> CipherSuite {
    #[cfg(feature = "fips")]
    {
        rustls_openssl::enable_fips();
    }

    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    #[allow(unused_mut)]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_provider(
        cipher_suites,
        kx_group,
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    #[cfg(feature = "fips")]
    {
        config.require_ems = true;
        assert!(config.fips());
    }

    let server_name = "index.crates.io".try_into().unwrap();
    let mut sock = TcpStream::connect("index.crates.io:443").unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        concat!(
            "GET /config.json HTTP/1.1\r\n",
            "Host: index.crates.io\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("https://static.crates.io/crates"));

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
    exit_buffer[0] = b'q'; // Assign the ASCII value of "Q" to the buffer

    // Write the "Q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    ciphersuite.suite()
}

#[rstest]
#[case::tls13_aes_128_gcm_sha256(
    rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls_openssl::kx_group::SECP384R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case::tls13_aes_256_gcm_sha384(
    rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_openssl::kx_group::SECP256R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    all(chacha, not(feature = "fips")),
    case::tls13_chacha20_poly1305_sha256(
        rustls_openssl::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_ECDSA_P256_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    )
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_aes_256_gcm_sha384(
        rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_aes_128_gcm_sha256(
        rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )
)]
#[cfg_attr(
    not(feature = "fips"),
    case::tls13_aes_256_gcm_sha384_x25519(
        rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls_openssl::kx_group::X25519,
        server::Alg::PKCS_ECDSA_P256_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384
    )
)]
#[case::tls13_aes_256_gcm_sha384_secp384r1(
    rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_openssl::kx_group::SECP384R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    all(feature = "tls12", chacha, not(feature = "fips")),
    case::tls_ecdhe_rsa_with_chacha20_poly1305_sha256(
        rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_ecdsa_with_aes_128_gcm_sha256(
        rustls_openssl::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_ECDSA_P256_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    )
)]
#[cfg_attr(
    all(feature = "tls12", not(feature = "fips")),
    case::ed25519_tls12(
        rustls_openssl::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls_openssl::kx_group::SECP256R1,
        server::Alg::PKCS_ED25519,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    )
)]
#[cfg_attr(
    all(feature = "tls12", not(feature = "fips")),
    case::tls_ecdhe_rsa_with_aes_256_gcm_sha384(
        rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls_openssl::kx_group::X25519,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )
)]
#[case::tls13_aes_256_gcm_sha384_secp384r1(
    rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_openssl::kx_group::SECP384R1,
    server::Alg::PKCS_RSA_SHA512,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
fn test_client_and_server(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] alg: server::Alg,
    #[case] expected: CipherSuite,
) {
    // Run against a server using our default provider
    let (port, certificate) = start_server(alg);
    let provider = custom_provider(vec![suite], vec![group]);
    let actual_suite = test_with_provider(provider, port, vec![certificate]);
    assert_eq!(actual_suite, expected);
}

#[rstest]
#[cfg_attr(
    all(feature = "tls12", chacha, not(feature = "fips")),
    case(
        rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls_openssl::kx_group::SECP384R1,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
)]
#[case::tls13_aes_256_gcm_sha384(
    rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_openssl::kx_group::SECP384R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
fn test_to_internet(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] expected: CipherSuite,
) {
    let actual = test_with_custom_config_to_internet(suite, group);
    assert_eq!(actual, expected);
}

/// Test that the default provider returns the highest priority cipher suite
#[test]
fn test_default_client() {
    #[cfg(feature = "fips")]
    {
        rustls_openssl::enable_fips();
    }

    let (port, certificate) = start_server(server::Alg::PKCS_RSA_SHA512);
    let actual_suite = test_with_provider(default_provider(), port, vec![certificate]);
    assert_eq!(actual_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
}

static RSA_SIGNING_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

#[test]
fn test_rsa_sign_and_verify() {
    let ours = rustls_openssl::default_provider();
    let theirs = rustls::crypto::aws_lc_rs::default_provider();

    let private_key = Rsa::generate(2048).unwrap();
    let rustls_private_key =
        PrivateKeyDer::from_pem_slice(&private_key.private_key_to_pem().unwrap()).unwrap();
    let pub_key = private_key.public_key_to_der_pkcs1().unwrap();

    for scheme in RSA_SIGNING_SCHEMES {
        eprintln!("Testing scheme {scheme:?}");

        sign_and_verify(
            &ours,
            &theirs,
            *scheme,
            rustls_private_key.clone_key(),
            &pub_key,
        );
        sign_and_verify(
            &theirs,
            &ours,
            *scheme,
            rustls_private_key.clone_key(),
            &pub_key,
        );
    }
}

#[rstest]
#[case::ecdsa_nistp256_sha256(SignatureScheme::ECDSA_NISTP256_SHA256, Nid::X9_62_PRIME256V1)]
#[case::ecdsa_nistp384_sha384(SignatureScheme::ECDSA_NISTP384_SHA384, Nid::SECP384R1)]
#[case::ecdsa_nistp521_sha512(SignatureScheme::ECDSA_NISTP521_SHA512, Nid::SECP521R1)]

fn test_ec_sign_and_verify(#[case] scheme: SignatureScheme, #[case] curve: Nid) {
    let ours = rustls_openssl::default_provider();
    let theirs = rustls::crypto::aws_lc_rs::default_provider();

    let group = EcGroup::from_curve_name(curve).unwrap();

    let private_key = EcKey::generate(&group).unwrap();
    let rustls_private_key =
        PrivateKeyDer::from_pem_slice(&private_key.private_key_to_pem().unwrap()).unwrap();

    eprintln!("private_key: {rustls_private_key:?}");

    let mut ctx = BigNumContext::new().unwrap();
    let pub_key = private_key
        .public_key()
        // ring doesn't work if PointConversionForm::Compression, aws_lc_rs does
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();

    eprintln!("verifying using theirs");
    sign_and_verify(
        &ours,
        &theirs,
        scheme,
        rustls_private_key.clone_key(),
        &pub_key,
    );
    eprintln!("verifying using ours");
    sign_and_verify(
        &theirs,
        &ours,
        scheme,
        rustls_private_key.clone_key(),
        &pub_key,
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn test_ed25119_sign_and_verify() {
    let ours = rustls_openssl::default_provider();
    let theirs = rustls::crypto::aws_lc_rs::default_provider();
    let scheme = SignatureScheme::ED25519;

    let private_key = PKey::generate_ed25519().unwrap();
    let pub_key = private_key.raw_public_key().unwrap();
    let rustls_private_key =
        PrivateKeyDer::from_pem_slice(&private_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    eprintln!("verifying using theirs");
    sign_and_verify(
        &ours,
        &theirs,
        scheme,
        rustls_private_key.clone_key(),
        &pub_key,
    );
    eprintln!("verifying using ours");
    sign_and_verify(
        &theirs,
        &ours,
        scheme,
        rustls_private_key.clone_key(),
        &pub_key,
    );
}

fn sign_and_verify(
    signing_provider: &rustls::crypto::CryptoProvider,
    verifying_provider: &rustls::crypto::CryptoProvider,
    scheme: SignatureScheme,
    rustls_private_key: PrivateKeyDer<'static>,
    pub_key: &[u8],
) {
    let data = b"hello, world!";

    // sign
    let signing_key = signing_provider
        .key_provider
        .load_private_key(rustls_private_key)
        .unwrap();
    let signer = signing_key
        .choose_scheme(&[scheme])
        .expect("signing provider supports this scheme");
    let signature = signer.sign(data).unwrap();

    // verify
    let algs = verifying_provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(k, _v)| *k == scheme)
        .map(|(_k, v)| *v)
        .expect("verifying provider supports this scheme");
    assert!(!algs.is_empty());
    assert!(algs
        .iter()
        .any(|alg| { alg.verify_signature(pub_key, data, &signature).is_ok() }));
}

#[cfg(feature = "fips")]
#[test]
fn provider_is_fips() {
    rustls_openssl::enable_fips();
    let provider = rustls_openssl::default_provider();
    assert!(provider.fips());
}
