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
        assert_eq!(
            gcm_iv(&server_secrets.tx.1)[..4],
            gcm_iv(&client_secrets.rx.1)[..4]
        );
    }
}

// ------------------------------------------------- kernel connection

#[path = "kernel/sim.rs"]
mod sim;

use browntls::kernel::{KernelHandoffBlocker, KernelOutput};
use browntls::{ContentType, Error, SideData};
use sim::Offloaded;

/// The suites with a kernel TLS form, both versions.
fn kernel_suites() -> Vec<SupportedCipherSuite> {
    vec![
        prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS13_AES_256_GCM_SHA384,
        prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Moves the userspace peer's queued records to the offloaded side.
fn peer_to_kernel<A: SideData, B: SideData>(
    peer: &mut browntls::ConnectionCommon<A>,
    off: &mut Offloaded<B>,
) -> Result<(), Error> {
    let mut wire = Vec::new();
    while peer.wants_write() {
        peer.write_tls(&mut wire).unwrap();
    }
    off.receive(&wire)
}

/// Moves the offloaded side's records to the userspace peer and returns
/// the plaintext it read.
fn kernel_to_peer<A: SideData, B: SideData>(
    off: &mut Offloaded<A>,
    peer: &mut browntls::ConnectionCommon<B>,
) -> Vec<u8> {
    let wire = off.take_wire();
    let mut offset = 0;
    let mut out = Vec::new();
    while offset < wire.len() {
        offset += peer.read_tls(&mut &wire[offset..]).unwrap();
        peer.process_new_packets().unwrap();
        match std::io::Read::read_to_end(&mut peer.reader(), &mut out) {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        }
    }
    out
}

/// Data both ways, a KeyUpdate from each side (TLS 1.3), and closure, with
/// one side offloaded and the other in userspace.
fn exercise<A: SideData, B: SideData>(
    off: &mut Offloaded<A>,
    peer: &mut browntls::ConnectionCommon<B>,
    suite: SupportedCipherSuite,
) {
    use std::io::Write;
    let big: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    off.send(&big);
    assert_eq!(kernel_to_peer(off, peer), big, "{suite:?} kernel to peer");
    peer.writer().write_all(&big).unwrap();
    peer_to_kernel(peer, off).unwrap();
    assert_eq!(
        std::mem::take(&mut off.app_in),
        big,
        "{suite:?} peer to kernel"
    );

    if off.conn.protocol_version() == browntls::ProtocolVersion::TLSv1_3 {
        // The peer rotates and asks us to: new receive keys, then our
        // KeyUpdate under the old transmit key, then new transmit keys.
        peer.refresh_traffic_keys().unwrap();
        peer.writer().write_all(b"after peer update").unwrap();
        peer_to_kernel(peer, off).unwrap();
        assert_eq!(std::mem::take(&mut off.app_in), b"after peer update");
        assert_eq!((off.rx_rekeys, off.tx_rekeys), (1, 1), "{suite:?}");
        off.send(b"answer");
        assert_eq!(kernel_to_peer(off, peer), b"answer");

        // We rotate and ask the peer to.
        off.conn.refresh_traffic_keys().unwrap();
        off.send(b"after our update");
        assert_eq!(kernel_to_peer(off, peer), b"after our update");
        assert_eq!(off.tx_rekeys, 2);
        peer.writer().write_all(b"peer answer").unwrap();
        peer_to_kernel(peer, off).unwrap();
        assert_eq!(std::mem::take(&mut off.app_in), b"peer answer");
        assert_eq!(off.rx_rekeys, 2);
    } else {
        assert!(off.conn.refresh_traffic_keys().is_err());
    }

    // Closure from both sides.
    off.conn.send_close_notify();
    off.flush();
    assert!(!off.conn.may_send_application_data());
    let _ = kernel_to_peer(off, peer);
    assert!(peer.process_new_packets().unwrap().peer_has_closed());
    peer.send_close_notify();
    peer_to_kernel(peer, off).unwrap();
    assert!(off.conn.peer_has_closed());
}

#[test]
fn offloaded_client_talks_to_a_userspace_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in kernel_suites() {
        let (client, mut server) = pair(suite, &chain);
        assert_eq!(client.kernel_handoff_blocker(), None);
        let (secrets, conn) = client.dangerous_into_kernel_connection().unwrap();
        assert_eq!(conn.negotiated_cipher_suite().suite(), suite.suite());
        assert_eq!(conn.max_tx_payload_len(), None);
        let mut off = Offloaded::new(conn, secrets);
        exercise(&mut off, &mut server, suite);
    }
}

#[test]
fn offloaded_server_talks_to_a_userspace_client() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in kernel_suites() {
        let (mut client, server) = pair(suite, &chain);
        let (secrets, conn) = server.dangerous_into_kernel_connection().unwrap();
        let mut off = Offloaded::new(conn, secrets);
        exercise(&mut off, &mut client, suite);
    }
}

/// A TLS 1.3 client handed over before the server's NewSessionTickets
/// arrive stores them from the records the kernel passes back.
#[test]
fn tickets_arriving_after_the_handover_are_stored() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let (mut client, mut server) = unfinished_pair(suite, &chain);
    // Drive until the client is done; its Finished reaches the server,
    // whose tickets stay on the server's side for now.
    while client.is_handshaking() {
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
    }
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(server.wants_write(), "tickets queued");
    let before = client.tls13_tickets_received();
    let (secrets, conn) = client.dangerous_into_kernel_connection().unwrap();
    let mut off = Offloaded::new(conn, secrets);
    peer_to_kernel(&mut server, &mut off).unwrap();
    assert!(off.conn.tls13_tickets_received() > before);
    assert!(off.control_sent.is_empty());
}

#[test]
fn ticket_limit_continues_across_handover() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 2);

    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    let (head, tail) = split_ticket(0);
    for _ in 0..9 {
        conn.handle_record(ContentType::Handshake, &head).unwrap();
        conn.handle_record(ContentType::Handshake, &tail).unwrap();
    }
    assert_eq!(conn.tls13_tickets_received(), 8);
    assert!(!conn.has_output());
    // The cap does not turn malformed later messages into accepted input.
    assert!(
        conn.handle_record(ContentType::Handshake, &[4, 0, 0, 0])
            .is_err()
    );
}

/// The client and server of `pair` before their handshake.
fn unfinished_pair(
    suite: SupportedCipherSuite,
    chain: &Chain,
) -> (ClientConnection, ServerConnection) {
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
    (
        ClientConnection::new(Arc::new(client_config), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server_config)).unwrap(),
    )
}

#[test]
fn handoff_waits_for_everything_in_flight() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256;

    // Before and during the handshake.
    let (mut client, mut server) = unfinished_pair(suite, &chain);
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::HandshakeIncomplete)
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.kernel_handoff_blocker(), None);

    // Unwritten records.
    client.writer().write_all(b"queued").unwrap();
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::UnsentRecords)
    );
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    // Unread plaintext.
    assert_eq!(
        server.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::UnreadPlaintext)
    );
    let mut sink = Vec::new();
    std::io::Read::read_to_end(&mut server.reader(), &mut sink).unwrap_err();
    assert_eq!(server.kernel_handoff_blocker(), None);

    // Half a record, then all of it unprocessed.
    server.writer().write_all(b"partial").unwrap();
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    client.read_tls(&mut &wire[..3]).unwrap();
    client.process_new_packets().unwrap();
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::UnprocessedInput)
    );
    client.read_tls(&mut &wire[3..]).unwrap();
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::UnprocessedInput)
    );
    client.process_new_packets().unwrap();
    std::io::Read::read_to_end(&mut client.reader(), &mut sink).unwrap_err();
    assert_eq!(client.kernel_handoff_blocker(), None);

    // A blocked handover fails rather than losing data, and so does secret
    // extraction.
    client.writer().write_all(b"queued").unwrap();
    let err = client.dangerous_into_kernel_connection().unwrap_err();
    assert!(
        matches!(err, Error::General(ref m) if m.contains("written")),
        "{err:?}"
    );

    // After our close_notify.
    let (mut client, mut server) = pair(suite, &chain);
    client.send_close_notify();
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::Closed)
    );
    transfer(&mut client, &mut server);
    assert!(client.dangerous_into_kernel_connection().is_err());

    // Extraction disabled.
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::SecretExtractionDisabled)
    );
}

/// Secret extraction refuses what is still in flight after our own
/// `close_notify` too, although the handover reports `Closed` first, and
/// succeeds once it is drained.
#[test]
fn extraction_after_close_notify_still_waits_for_data_in_flight() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in kernel_suites() {
        // Queued records, our close_notify among them.
        let (mut client, mut server) = pair(suite, &chain);
        client.writer().write_all(b"queued").unwrap();
        client.send_close_notify();
        assert_eq!(
            client.kernel_handoff_blocker(),
            Some(KernelHandoffBlocker::Closed)
        );
        let err = client.dangerous_extract_secrets().unwrap_err();
        assert!(
            matches!(err, Error::General(ref m) if m.contains("written")),
            "{suite:?}: {err:?}"
        );

        // Received data not read yet.
        let (mut client, mut server2) = pair(suite, &chain);
        client.writer().write_all(b"unread").unwrap();
        transfer(&mut client, &mut server2);
        server2.process_new_packets().unwrap();
        server2.send_close_notify();
        assert_eq!(
            server2.kernel_handoff_blocker(),
            Some(KernelHandoffBlocker::Closed)
        );
        let err = server2.dangerous_extract_secrets().unwrap_err();
        assert!(
            matches!(err, Error::General(ref m) if m.contains("read")),
            "{suite:?}: {err:?}"
        );

        // Drained: the close_notify written, nothing left to read.
        server.send_close_notify();
        transfer(&mut server, &mut client);
        assert!(!server.wants_write());
        server.dangerous_extract_secrets().unwrap();
    }
}

/// The KeyUpdate message `update_requested` (1) or not (0).
fn key_update(request: u8) -> Vec<u8> {
    vec![24, 0, 0, 1, request]
}

#[test]
fn a_key_update_must_end_its_record() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let (client, _server) = pair(suite, &chain);
    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    let mut record = key_update(0);
    record.extend_from_slice(&[4, 0, 0]);
    assert!(conn.handle_record(ContentType::Handshake, &record).is_err());
    // The fatal alert is queued for the kernel, and the connection is over.
    match conn.pop_output() {
        Some(KernelOutput::Record { typ, payload }) => {
            assert_eq!(typ, ContentType::Alert);
            assert_eq!(payload, [2, 10], "fatal unexpected_message");
        }
        other => panic!("{other:?}"),
    }
    assert!(!conn.may_send_application_data());
    assert!(
        conn.handle_record(ContentType::Handshake, &key_update(0))
            .is_err()
    );
}

#[test]
fn records_the_kernel_handles_itself_are_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client, _server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    assert!(
        conn.handle_record(ContentType::ApplicationData, b"x")
            .is_err()
    );
    // The connection is still usable.
    assert!(conn.may_send_application_data());
    conn.handle_record(ContentType::Handshake, &key_update(0))
        .unwrap();
    assert!(matches!(conn.pop_output(), Some(KernelOutput::RxKeys(_))));
    assert!(!conn.has_output(), "no answer to update_not_requested");
}

/// A NewSessionTicket (lifetime first byte `lifetime0`) split after its
/// four-byte header.
fn split_ticket(lifetime0: u8) -> (Vec<u8>, Vec<u8>) {
    let body = [lifetime0, 0, 0, 60, 1, 2, 3, 4, 1, 0, 0, 1, 0xaa, 0, 0];
    (vec![4, 0, 0, body.len() as u8], body.to_vec())
}

#[test]
fn a_handshake_message_split_across_records_is_joined() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client, _server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    let before = conn.tls13_tickets_received();
    let (head, tail) = split_ticket(0);
    conn.handle_record(ContentType::Handshake, &head).unwrap();
    conn.handle_record(ContentType::Handshake, &tail).unwrap();
    assert_eq!(conn.tls13_tickets_received(), before + 1);
    assert!(!conn.has_output());

    let (_, mut conn) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain)
        .0
        .dangerous_into_kernel_connection()
        .unwrap();
    conn.handle_record(ContentType::Handshake, &head).unwrap();
    // No other record may come between the parts (RFC 8446 §5.1).
    assert!(conn.handle_record(ContentType::Alert, &[1, 0]).is_err());
}

/// Linux pauses reception after any handshake record that starts with the
/// KeyUpdate type: anything but one whole KeyUpdate in its own record would
/// stall the connection, so it fails instead (with an alert), as do empty
/// handshake records.
#[test]
fn records_that_would_stall_kernel_tls_are_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let refused = |records: &[&[u8]]| {
        let (_, mut conn) = pair(suite, &chain)
            .0
            .dangerous_into_kernel_connection()
            .unwrap();
        let (last, first) = records.split_last().unwrap();
        for record in first {
            conn.handle_record(ContentType::Handshake, record).unwrap();
        }
        assert!(conn.handle_record(ContentType::Handshake, last).is_err());
        match conn.pop_output() {
            Some(KernelOutput::Record { typ, payload }) => {
                assert_eq!(typ, ContentType::Alert);
                assert_eq!(payload[0], 2, "fatal");
            }
            other => panic!("{other:?}"),
        }
    };
    let msg = key_update(1);
    refused(&[&msg[..2]]);
    // A KeyUpdate after another message in its record: Linux would not
    // pause, and could read on under the old key.
    let (head, tail) = split_ticket(0);
    refused(&[&[&head[..], &tail[..], &msg[..]].concat()]);
    let (head, tail) = split_ticket(24);
    refused(&[&head, &tail]);
    refused(&[&[]]);

    // TLS 1.2 has no KeyUpdate, so such a record always stalls.
    let (_, mut conn) = pair(
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &chain,
    )
    .0
    .dangerous_into_kernel_connection()
    .unwrap();
    assert!(conn.handle_record(ContentType::Handshake, &msg).is_err());
}

/// Repeated `update_requested` without application data in between is
/// refused, as in userspace; application data renews the budget.
#[test]
fn key_update_requests_are_bounded_by_application_data() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client, _server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    let mut accepted = 0;
    loop {
        match conn.handle_record(ContentType::Handshake, &key_update(1)) {
            Ok(()) => accepted += 1,
            Err(_) => break,
        }
        while conn.pop_output().is_some() {}
        assert!(accepted < 1000, "no bound");
    }
    assert!(accepted >= 1);

    let (client, _server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
    for _ in 0..(accepted * 3) {
        conn.handle_record(ContentType::Handshake, &key_update(1))
            .unwrap();
        while conn.pop_output().is_some() {}
        conn.application_data_received();
    }
}

#[test]
fn the_confidentiality_limit_refreshes_or_closes() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in [
        prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ] {
        let (client, _server) = pair(suite, &chain);
        let (_, mut conn) = client.dangerous_into_kernel_connection().unwrap();
        let limit = match suite {
            SupportedCipherSuite::Tls13(s) => s.common.confidentiality_limit,
            SupportedCipherSuite::Tls12(s) => s.common.confidentiality_limit,
        };
        conn.records_sent(limit - 10).unwrap();
        assert!(!conn.has_output());
        conn.records_sent(10).unwrap();
        let outputs: Vec<_> = std::iter::from_fn(|| conn.pop_output()).collect();
        match suite {
            SupportedCipherSuite::Tls13(_) => {
                assert!(matches!(
                    &outputs[0],
                    KernelOutput::Record { typ: ContentType::Handshake, payload } if payload[0] == 24
                ));
                assert!(matches!(outputs[1], KernelOutput::TxKeys(_)));
                assert!(conn.may_send_application_data());
            }
            SupportedCipherSuite::Tls12(_) => {
                assert!(matches!(
                    &outputs[0],
                    KernelOutput::Record { typ: ContentType::Alert, payload } if payload[..] == [1, 0]
                ));
                assert!(!conn.may_send_application_data());
            }
        }
    }
}

#[test]
fn a_smaller_peer_record_size_limit_is_reported() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let (mut client, server) = unfinished_pair(suite, &chain);
    // Rebuild the server with a record size limit of 1000.
    drop(server);
    let mut provider = prov::default_provider();
    provider.cipher_suites = vec![suite];
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.record_size_limit = Some(1000);
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    // Known before the handover, so a driver can check kernel support.
    assert_eq!(client.max_tx_payload_len(), Some(999));
    let (secrets, conn) = client.dangerous_into_kernel_connection().unwrap();
    // RFC 8449: the limit counts the TLS 1.3 content type byte.
    assert_eq!(conn.max_tx_payload_len(), Some(999));
    let mut off = Offloaded::new(conn, secrets);
    off.send(&[7u8; 5000]);
    assert_eq!(kernel_to_peer(&mut off, &mut server), [7u8; 5000]);
}

/// Post-handshake client authentication across the handover, with either
/// side offloaded: the CertificateRequest and the client's Certificate,
/// CertificateVerify and Finished travel as kernel records.
#[test]
fn post_handshake_auth_through_the_kernel() {
    use browntls::server::PostHandshakeAuthStatus;
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let configs = || {
        let mut client = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap();
        client.enable_post_handshake_auth = true;
        client.enable_secret_extraction = true;
        let mut server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        server.request_client_auth_after_handshake = true;
        server.enable_secret_extraction = true;
        (
            ClientConnection::new(Arc::new(client), server_name()).unwrap(),
            ServerConnection::new(Arc::new(server)).unwrap(),
        )
    };

    // The server offloaded asks a userspace client.
    let (mut client, mut server) = configs();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let (secrets, conn) = server.dangerous_into_kernel_connection().unwrap();
    let mut off = Offloaded::new(conn, secrets);
    off.conn.request_client_auth().unwrap();
    off.flush();
    let _ = kernel_to_peer(&mut off, &mut client);
    assert_eq!(client.post_handshake_auth_responses(), 1);
    peer_to_kernel(&mut client, &mut off).unwrap();
    assert_eq!(
        off.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(
        off.conn.common_state().peer_certificates().unwrap(),
        client_chain.cert_chain()
    );

    // The client offloaded answers a userspace server.
    let (mut client, mut server) = configs();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let (secrets, conn) = client.dangerous_into_kernel_connection().unwrap();
    let mut off = Offloaded::new(conn, secrets);
    server.request_client_auth().unwrap();
    peer_to_kernel(&mut server, &mut off).unwrap();
    let kinds: Vec<_> = off.control_sent.iter().map(|(t, p)| (*t, p[0])).collect();
    // Certificate (11, or 25 compressed), CertificateVerify (15), Finished (20).
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    assert!(kinds.iter().all(|(t, _)| *t == ContentType::Handshake));
    assert!(matches!(kinds[0].1, 11 | 25), "{kinds:?}");
    assert_eq!((kinds[1].1, kinds[2].1), (15, 20));
    let _ = kernel_to_peer(&mut off, &mut server);
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
}

#[test]
fn the_bytes_to_the_next_record_boundary_are_reported() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = pair(prov::cipher_suite::TLS13_AES_128_GCM_SHA256, &chain);
    assert_eq!(client.bytes_to_record_boundary(), 0);
    server.writer().write_all(b"one").unwrap();
    server.writer().write_all(b"two").unwrap();
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    let first = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    // Inside the first header, inside its body, at the boundary, inside the
    // second record's header.
    let mut fed = 0;
    for step in [2, 5, first - 7, 1] {
        client.read_tls(&mut &wire[fed..fed + step]).unwrap();
        fed += step;
        let expected = match fed {
            2 => 3,
            7 => first - 7,
            f if f == first => 0,
            _ => 4,
        };
        assert_eq!(client.bytes_to_record_boundary(), expected, "after {fed}");
    }
    client.read_tls(&mut &wire[fed..]).unwrap();
    assert_eq!(client.bytes_to_record_boundary(), 0);
    client.process_new_packets().unwrap();
    assert_eq!(client.bytes_to_record_boundary(), 0);
}

/// Linux takes no record payload limit below 64 bytes (63 for TLS 1.3), so
/// a smaller configured `max_fragment_size` blocks the handover.
#[test]
fn a_fragment_size_below_the_kernel_floor_blocks_the_handover() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    client_config.enable_secret_extraction = true;
    client_config.max_fragment_size = Some(32);
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.max_tx_payload_len().is_some_and(|len| len < 63));
    assert_eq!(
        client.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::FragmentTooSmall)
    );
    // Extracting the secrets alone is still allowed.
    client.dangerous_extract_secrets().unwrap();
}
