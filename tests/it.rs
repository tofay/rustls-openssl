//! Integration tests, based on rustls-symcrypt integration tests

use once_cell::sync::OnceCell;
use rstest::rstest;
use rustls::crypto::SupportedKxGroup;
use rustls::{CipherSuite, SupportedCipherSuite};
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

const PORT: u32 = 4443;

static OPENSSL_SERVER_PROCESS: OnceCell<Option<Child>> = OnceCell::new();

fn maybe_start_openssl_server() {
    OPENSSL_SERVER_PROCESS.get_or_init(|| {
        if TcpStream::connect(format!("localhost:{}", PORT)).is_ok() {
            return None;
        }

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
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start OpenSSL server.");
        // sleep for 1 second to allow the server to start
        std::thread::sleep(std::time::Duration::from_secs(1));
        Some(child)
    });
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
#[case(
    TLS13_AES_128_GCM_SHA256,
    SECP384R1,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case(
    TLS13_AES_256_GCM_SHA384,
    SECP256R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    feature = "chacha",
    case(
        TLS13_CHACHA20_POLY1305_SHA256,
        SECP256R1,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    )
)]
#[case(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SECP256R1,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
)]
#[case(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SECP256R1,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
)]
#[cfg_attr(
    feature = "x25519",
    case(
        TLS13_AES_256_GCM_SHA384,
        rustls_openssl::X25519,
        CipherSuite::TLS13_AES_256_GCM_SHA384
    )
)]
#[case(
    TLS13_AES_256_GCM_SHA384,
    SECP384R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
// #[case(
//     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//     SECP384R1,
//     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
// )]
fn test_tls(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] expected: CipherSuite,
) {
    maybe_start_openssl_server();
    let actual_suite = test_with_config(suite, group);
    assert_eq!(actual_suite, expected);
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
    maybe_start_openssl_server();
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
}
