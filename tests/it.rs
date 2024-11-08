//! Integration tests, based on rustls-symcrypt integration tests
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rstest::rstest;
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};
use rustls_openssl::{
    custom_provider, default_provider, SECP256R1, SECP384R1, TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
#[cfg(feature = "chacha")]
use rustls_openssl::{TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256};
use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;

static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("certs");
    path
});

static OPENSSL_SERVER_PROCESS: once_cell::sync::Lazy<antidote::Mutex<Option<Child>>> =
    once_cell::sync::Lazy::new(|| antidote::Mutex::new(maybe_start_server()));

const PORT: u32 = 4443;

fn maybe_start_server() -> Option<Child> {
    if TcpStream::connect(format!("localhost:{}", PORT)).is_ok() {
        eprintln!("Server already running");
        return None;
    }

    eprintln!("Starting openssl server...");

    // Spawn openssl server
    // openssl s_server -accept 4443 -cert localhost.crt  -key localhost.key

    let cert_path = TEST_CERT_PATH
        .join("localhost.pem")
        .into_os_string()
        .into_string()
        .unwrap();
    let key_path = TEST_CERT_PATH
        .join("localhost.key")
        .into_os_string()
        .into_string()
        .unwrap();

    let child = Command::new("openssl")
        .arg("s_server")
        .arg("-accept")
        .arg(PORT.to_string())
        .arg("-cert")
        .arg(cert_path)
        .arg("-key")
        .arg(key_path)
        .arg("-quiet")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("Failed to start OpenSSL server.");
    // sleep to allow the server to start
    std::thread::sleep(std::time::Duration::from_secs(1));
    Some(child)
}

fn test_with_config(
    suite: SupportedCipherSuite,
    group: &'static dyn SupportedKxGroup,
) -> CipherSuite {
    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let cert_path = TEST_CERT_PATH
        .join("RootCA.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    root_store.add_parsable_certificates(certs);

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect(format!("localhost:{}", PORT)).unwrap();

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
    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

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
    TLS13_AES_128_GCM_SHA256,
    SECP384R1,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case::tls13_aes_256_gcm_sha384(
    TLS13_AES_256_GCM_SHA384,
    SECP256R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    feature = "chacha",
    case::tls13_chacha20_poly1305_sha256(
        TLS13_CHACHA20_POLY1305_SHA256,
        SECP256R1,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    )
)]
#[case::tls_ecdhe_rsa_with_aes_256_gcm_sha384(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SECP256R1,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
)]
#[case::tls_ecdhe_rsa_with_aes_128_gcm_sha256(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SECP256R1,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
)]
#[cfg_attr(
    feature = "x25519",
    case::tls13_aes_256_gcm_sha384(
        TLS13_AES_256_GCM_SHA384,
        rustls_openssl::X25519,
        CipherSuite::TLS13_AES_256_GCM_SHA384
    )
)]
#[case::tls13_aes_256_gcm_sha384(
    TLS13_AES_256_GCM_SHA384,
    SECP384R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
// TODO: setup ECDSA certs
// #[case::tls_ecdhe_ecdsa_with_aes_256_gcm_sha384(
//     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//     SECP384R1,
//     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
// )]
// #[case::tls_ecdhe_ecdsa_with_aes_128_gcm_sha256(
//     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//     SECP256R1,
//     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// )]
fn test_tls(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] expected: CipherSuite,
) {
    let lock = OPENSSL_SERVER_PROCESS.lock();
    let actual_suite = test_with_config(suite, group);
    assert_eq!(actual_suite, expected);
    drop(lock);
}

#[rstest]
#[cfg_attr(
    feature = "chacha",
    case(
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        SECP384R1,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
)]
#[case(
    TLS13_AES_256_GCM_SHA384,
    SECP384R1,
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

#[test]
fn test_default_client() {
    let lock = OPENSSL_SERVER_PROCESS.lock();
    // Add default webpki roots to the root store
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let cert_path = TEST_CERT_PATH
        .join("RootCA.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    root_store.add_parsable_certificates(certs);

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect(format!("localhost:{}", PORT)).unwrap();

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

    let exit_buffer: [u8; 1] = [b'q'];
    tls.write_all(&exit_buffer).unwrap();

    assert_eq!(ciphersuite.suite(), CipherSuite::TLS13_AES_256_GCM_SHA384);
    drop(lock);
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
        eprintln!("Testing scheme {:?}", scheme);

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

    eprintln!("private_key: {:?}", rustls_private_key);

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
