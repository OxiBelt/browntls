use browntls_core::{dtls, quic};

use super::*;

fn configs() -> (
    Arc<ClientConfig>,
    Arc<ServerConfig>,
    Arc<SchemeRecordingServerVerifier>,
) {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (credential, delegated_key) = issue(&chain, SignatureScheme::ED25519, shifted(3600));
    let certified = certified_key(&chain)
        .with_delegated_credential(credential, delegated_key, &provider())
        .unwrap();
    let verifier = SchemeRecordingServerVerifier::new(
        PinnedServerVerifier::new(&chain),
        &prov::SUPPORTED_SIG_ALGS.supported_schemes(),
    );
    let mut client = dc_client(&chain);
    client.alpn_protocols = vec![b"credential-test".to_vec()];
    client
        .dangerous()
        .set_certificate_verifier(verifier.clone());
    let mut server = server_with(certified);
    server.alpn_protocols = client.alpn_protocols.clone();
    (Arc::new(client), Arc::new(server), verifier)
}

#[test]
fn quic_tls_presents_the_verified_delegated_credential() {
    let (client_config, server_config, verifier) = configs();
    let mut client =
        quic::ClientConnection::new(client_config, quic::Version::V1, server_name(), vec![0])
            .unwrap();
    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, vec![0]).unwrap();
    let mut handshake = Vec::new();
    for _ in 0..20 {
        client.write_hs(&mut handshake);
        if !handshake.is_empty() {
            server.read_hs(&handshake).unwrap();
            handshake.clear();
        }
        server.write_hs(&mut handshake);
        if !handshake.is_empty() {
            client.read_hs(&handshake).unwrap();
            handshake.clear();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(
        verifier.seen(),
        [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519
        ]
    );
}

#[test]
fn dtls13_presents_the_verified_delegated_credential_with_record_limits() {
    let (client_config, server_config, verifier) = configs();
    let settings = || {
        dtls::Settings::default()
            .with_record_size_limit(Some(128))
            .unwrap()
    };
    let mut client =
        dtls::ClientConnection::new_with_settings(client_config, server_name(), settings())
            .unwrap();
    let mut server = dtls::ServerConnection::new_without_cookie_exchange_with_settings(
        server_config,
        b"peer",
        settings(),
    )
    .unwrap();
    let now = Duration::from_secs(1);
    let mut datagram = Vec::new();
    for _ in 0..20 {
        while client.write_datagram(&mut datagram, now).unwrap() {
            server.read_datagram(&mut datagram, now).unwrap();
            datagram.clear();
        }
        while server.write_datagram(&mut datagram, now).unwrap() {
            client.read_datagram(&mut datagram, now).unwrap();
            datagram.clear();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(client.max_application_data(), Some(127));
    assert_eq!(
        verifier.seen(),
        [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519
        ]
    );
}
