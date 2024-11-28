//! Example of creating Quinn client and server endpoints.
//!
//! Adapted from https://github.com/quinn-rs/quinn/blob/main/quinn/examples/single_socket.rs
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::{error::Error, sync::Arc};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{default_runtime, ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls_openssl::quinn::reset_key;

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
/// - bind_addr: address to bind to.
/// - server_certs: list of trusted certificates.
fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let client_cfg = configure_client(server_certs)?;
    let endpoint_config = EndpointConfig::new(reset_key());
    let socket = UdpSocket::bind(bind_addr).unwrap();
    let mut endpoint =
        Endpoint::new(endpoint_config, None, socket, default_runtime().unwrap()).unwrap();
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint_config = EndpointConfig::new(reset_key());
    let socket = UdpSocket::bind(bind_addr).unwrap();
    let endpoint = Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        default_runtime().unwrap(),
    )?;
    Ok((endpoint, server_cert))
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client(
    server_certs: &[&[u8]],
) -> Result<ClientConfig, Box<dyn Error + Send + Sync + 'static>> {
    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(CertificateDer::from(*cert))?;
    }

    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(certs),
        Arc::new(rustls_openssl::default_provider()),
    )
    .build()
    .unwrap();

    let mut rustls_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_openssl::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    rustls_config.enable_early_data = true;

    let suite = TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap();
    let quic_client_config =
        QuicClientConfig::with_initial(Arc::new(rustls_config), suite).unwrap();
    Ok(ClientConfig::new(Arc::new(quic_client_config)))
}

/// Returns default server configuration along with its certificate.
fn configure_server(
) -> Result<(ServerConfig, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut rustls_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_openssl::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], priv_key.into())?;
    rustls_config.max_early_data_size = u32::MAX;

    let quic_server_config = QuicServerConfig::with_initial(
        Arc::new(rustls_config),
        TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap(),
    )
    .unwrap();

    let mut server_config = ServerConfig::new(
        Arc::new(quic_server_config),
        rustls_openssl::quinn::handshake_token_key(),
    );

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    env_logger::init();
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002);
    let server1_cert = run_server(addr1)?;
    let server2_cert = run_server(addr2)?;
    let server3_cert = run_server(addr3)?;

    let client = make_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[&server1_cert, &server2_cert, &server3_cert],
    )?;

    // connect to multiple endpoints using the same socket/endpoint
    tokio::join!(
        run_client(&client, addr1),
        run_client(&client, addr2),
        run_client(&client, addr3),
    );

    // Make sure the server has a chance to clean up
    client.wait_idle().await;

    Ok(())
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server(
    addr: SocketAddr,
) -> Result<CertificateDer<'static>, Box<dyn Error + Send + Sync + 'static>> {
    let (endpoint, server_cert) = make_server_endpoint(addr)?;
    // accept a single connection
    tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        println!(
            "[server] incoming connection: addr={}",
            connection.remote_address()
        );
    });

    Ok(server_cert)
}

/// Attempt QUIC connection with the given server address.
async fn run_client(endpoint: &Endpoint, server_addr: SocketAddr) {
    let connect = endpoint.connect(server_addr, "localhost").unwrap();
    let connection = connect.await.unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
}
