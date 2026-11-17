// Shared cases, included by `tests/kernel.rs` (RustCrypto provider) and
// `tests/kernel_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::sync::Arc;

use browntls::{
    ClientConfig, ClientConnection, ConnectionTrafficSecrets, ServerConfig, ServerConnection,
    SupportedCipherSuite, version,
};
use common::*;

/// A client and a server restricted to `suite` with secret extraction
/// enabled, handshake completed.
fn pair(suite: SupportedCipherSuite, chain: &Chain) -> (ClientConnection, ServerConnection) {
    let mut provider = prov::default_provider();
    provider.cipher_suites = vec![suite];
    let provider = Arc::new(provider);
    let versions: &[&'static browntls::SupportedProtocolVersion] = match suite {
        SupportedCipherSuite::Tls12(_) => &[&version::TLS12],
        SupportedCipherSuite::Tls13(_) => &[&version::TLS13],
    };
    let mut client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    client_config.enable_secret_extraction = true;
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.enable_secret_extraction = true;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    (client, server)
}

/// The records in `wire` (header type and body), in order.
fn records(mut wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while wire.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        out.push((wire[0], wire[5..5 + len].to_vec()));
        wire = &wire[5 + len..];
    }
    assert!(wire.is_empty(), "truncated record");
    out
}

fn gcm_iv(secrets: &ConnectionTrafficSecrets) -> [u8; 12] {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { iv, .. }
        | ConnectionTrafficSecrets::Aes256Gcm { iv, .. } => iv.as_ref().try_into().unwrap(),
        other => panic!("not AES-GCM: {other:?}"),
    }
}

/// Linux kernel TLS continues a TLS 1.2 AES-GCM connection with the explicit
/// nonce it is given, counting up by one per record. The extracted IV must
/// therefore carry the explicit nonce of the next record, and no nonce the
/// kernel goes on to use may repeat one the library already sent.
#[test]
fn tls12_gcm_extraction_continues_the_explicit_nonce_sequence() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in [
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ] {
        // Capture five application data records after the handshake (whose
        // Finished used sequence number 0).
        let (mut client, mut server) = pair(suite, &chain);
        let mut wire = Vec::new();
        for i in 0..5u8 {
            use std::io::Write;
            client.writer().write_all(&[i; 100]).unwrap();
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
        }
        server.read_tls(&mut &wire[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut sink = Vec::new();
        std::io::Read::read_to_end(&mut server.reader(), &mut sink).unwrap_err();
        assert_eq!(sink.len(), 500);

        let sent: Vec<u64> = records(&wire)
            .into_iter()
            .map(|(typ, body)| {
                assert_eq!(typ, 23);
                u64::from_be_bytes(body[..8].try_into().unwrap())
            })
            .collect();
        // Consecutive records count up from the previous one.
        for pair in sent.windows(2) {
            assert_eq!(pair[1], pair[0].wrapping_add(1), "{suite:?}");
        }

        let client_secrets = client.dangerous_extract_secrets().unwrap();
        let server_secrets = server.dangerous_extract_secrets().unwrap();
        let (seq, tx) = &client_secrets.tx;
        // The Finished (sequence number 0) plus five records.
        assert_eq!(*seq, 6, "{suite:?}");
        let next = u64::from_be_bytes(gcm_iv(tx)[4..].try_into().unwrap());
        assert_eq!(next, sent.last().unwrap().wrapping_add(1), "{suite:?}");
        // The kernel's nonces never meet the library's: they start where the
        // library would have continued and count up from there.
        for k in 0..4096u64 {
            assert!(!sent.contains(&next.wrapping_add(k)), "{suite:?}");
        }
        // The server's view of the client direction agrees.
        let (rx_seq, rx) = &server_secrets.rx;
        assert_eq!(rx_seq, seq);
        assert_eq!(gcm_iv(rx), gcm_iv(tx), "{suite:?}");
        // Both salts are the fixed IV, the same in both views.
        assert_eq!(gcm_iv(&server_secrets.tx.1)[..4], gcm_iv(&client_secrets.rx.1)[..4]);
    }
}
