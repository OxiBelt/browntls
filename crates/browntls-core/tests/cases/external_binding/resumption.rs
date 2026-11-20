// Resumption and 0-RTT with a binding configured. RFC 8844 §5: information
// from one TLS connection is not used in another, even one of the same
// signaling session. A bound connection does a full handshake on both sides,
// keeps no session for later, and sends no early data. External PSKs are
// provisioned by the application, not left by a connection, and still work.

type Kinds = (Option<HandshakeKind>, Option<HandshakeKind>);

const FULL: Kinds = (Some(HandshakeKind::Full), Some(HandshakeKind::Full));
const RESUMED: Kinds = (Some(HandshakeKind::Resumed), Some(HandshakeKind::Resumed));

/// Copies of `client` and `server` with the given bindings, sharing their
/// session stores, ticketer and cache (cloned `Arc`s).
fn with_bindings(
    client: &ClientConfig,
    server: &ServerConfig,
    c: Option<ExternalBinding>,
    s: Option<ExternalBinding>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut client = client.clone();
    client.external_binding = c;
    let mut server = server.clone();
    server.external_binding = s;
    (Arc::new(client), Arc::new(server))
}

/// A handshake, then the delivery of the TLS 1.3 tickets: how each side
/// shook hands.
fn shake((client, server): &(Arc<ClientConfig>, Arc<ServerConfig>)) -> Kinds {
    let (mut c, mut s) = connect_arc(client, server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(send_and_receive(&mut *s, &mut *c, b"t"), b"t");
    (c.handshake_kind(), s.handshake_kind())
}

/// The base configurations: session IDs (the server's cache) or tickets in
/// TLS 1.2; stateful or stateless tickets in TLS 1.3.
fn bases(chain: &Chain, v: ProtocolVersion, tickets: bool) -> (ClientConfig, ServerConfig) {
    let mut server = server_for(chain, v, None);
    if tickets {
        server.ticketer = prov::Ticketer::new().unwrap();
    }
    (client_for(chain, v, None), server)
}

#[test]
fn a_bound_connection_neither_resumes_nor_is_resumed() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        for tickets in [false, true] {
            let (c, s) = pair();
            let (client, server) = bases(&chain, v, tickets);
            let plain = with_bindings(&client, &server, None, None);
            let client_bound = with_bindings(&client, &server, Some(c.clone()), None);
            let server_bound = with_bindings(&client, &server, None, Some(s.clone()));
            let both_bound = with_bindings(&client, &server, Some(c), Some(s));
            let case = format!("{v:?}, tickets: {tickets}");

            assert_eq!(shake(&plain), FULL, "{case}");
            // The stores hold a usable session: a bound client does not
            // offer it (nor take it from the store)...
            assert_eq!(shake(&client_bound), FULL, "{case}");
            assert_eq!(shake(&plain), RESUMED, "{case}");
            // ...and a bound server does not accept the one offered.
            assert_eq!(shake(&server_bound), FULL, "{case}");
            assert_eq!(shake(&both_bound), FULL, "{case}");
        }
    }
}

#[test]
fn a_bound_connection_leaves_no_session_behind() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        for tickets in [false, true] {
            let (c, s) = pair();
            let case = format!("{v:?}, tickets: {tickets}");

            // A bound client keeps nothing the server issues...
            let (client, server) = bases(&chain, v, tickets);
            let plain = with_bindings(&client, &server, None, None);
            let client_bound = with_bindings(&client, &server, Some(c), None);
            assert_eq!(shake(&client_bound), FULL, "{case}");
            assert_eq!(shake(&plain), FULL, "{case}");

            // ...and a bound server issues nothing: no ticket, no session ID.
            let (client, server) = bases(&chain, v, tickets);
            let plain = with_bindings(&client, &server, None, None);
            let server_bound = with_bindings(&client, &server, None, Some(s));
            let (mut cc, mut sc) = connect_arc(&server_bound.0, &server_bound.1);
            do_handshake(&mut cc, &mut sc).unwrap();
            assert_eq!(send_and_receive(&mut *sc, &mut *cc, b"t"), b"t");
            assert_eq!(cc.tls13_tickets_received(), 0, "{case}");
            assert_eq!(shake(&plain), FULL, "{case}");
        }
    }
}

/// The reviewer's case: a ticket that allows 0-RTT, then a bound client
/// whose server answers another session identifier. The client would fail
/// only at EncryptedExtensions, after the server read its early data: it
/// offers none.
#[test]
fn a_bound_client_sends_no_early_data_with_a_ticket() {
    use std::io::{Read, Write};
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_3;
    let (c, s) = pair();
    let mut client = client_for(&chain, v, None);
    client.enable_early_data = true;
    let mut server = server_for(&chain, v, None);
    server.max_early_data_size = 1024;
    let plain = with_bindings(&client, &server, None, None);
    assert_eq!(shake(&plain), FULL);

    // Without a binding, the ticket carries early data to the server.
    let (mut cc, mut sc) = connect_arc(&plain.0, &plain.1);
    cc.early_data()
        .expect("the ticket allows early data")
        .write_all(b"early")
        .unwrap();
    do_handshake(&mut cc, &mut sc).unwrap();
    let mut got = Vec::new();
    sc.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early");
    assert_eq!(send_and_receive(&mut *sc, &mut *cc, b"t"), b"t");

    let mut other = s;
    other.session_id = Some(tls_id("someone else"));
    let bound = with_bindings(&client, &server, Some(c), Some(other));
    let (mut cc, mut sc) = connect_arc(&bound.0, &bound.1);
    assert!(cc.early_data().is_none());
    let hello = flight(&mut cc);
    assert_eq!(extension(&hello, EXT_EARLY_DATA), None);
    assert_eq!(extension(&hello, EXT_PRE_SHARED_KEY), None);
    feed(&mut sc, &hello);
    let (client_res, server_res) = do_handshake_until_error(&mut cc, &mut sc);
    assert_eq!(server_res, Err(alert_for(v, false)));
    assert_eq!(
        client_res,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::ExternalSessionIdMismatch
        ))
    );
    assert!(sc.early_data().is_none());
    assert!(!cc.is_early_data_accepted());
}

/// An external PSK that allows 0-RTT: a bound client still sends no early
/// data, but the PSK itself is used.
#[test]
fn a_bound_client_uses_external_psks_without_early_data() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_3;
    let psk = || {
        Arc::new(
            ExternalPsk::new(b"early".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256)
                .unwrap()
                .with_cipher_suite(browntls_core::CipherSuite::TLS13_AES_128_GCM_SHA256)
                .with_early_data(1024),
        )
    };
    let mut client = client_for(&chain, v, None);
    client.external_psks = vec![psk()];
    client.enable_early_data = true;
    let mut server = server_for(&chain, v, None);
    server.external_psks = Some(Arc::new(vec![psk()]));
    server.max_early_data_size = 1024;

    // Without a binding the PSK carries early data.
    let (mut cc, _) = connect(client.clone(), server.clone());
    assert!(cc.early_data().is_some());

    for server_session in ["server", "someone else"] {
        let (c, mut s) = pair();
        s.session_id = Some(tls_id(server_session));
        let bound = with_bindings(&client, &server, Some(c), Some(s));
        let (mut cc, mut sc) = connect_arc(&bound.0, &bound.1);
        assert!(cc.early_data().is_none());
        let hello = flight(&mut cc);
        assert_eq!(extension(&hello, EXT_EARLY_DATA), None);
        assert!(extension(&hello, EXT_PRE_SHARED_KEY).is_some());
        feed(&mut sc, &hello);
        let (client_res, server_res) = do_handshake_until_error(&mut cc, &mut sc);
        assert!(sc.early_data().is_none());
        if server_session == "server" {
            assert_eq!((client_res, server_res), (Ok(()), Ok(())));
            assert_eq!(cc.external_psk_identity(), Some(&b"early"[..]));
            assert_eq!(sc.external_psk_identity(), Some(&b"early"[..]));
        } else {
            assert_eq!(
                client_res,
                Err(Error::PeerMisbehaved(
                    PeerMisbehaved::ExternalSessionIdMismatch
                ))
            );
            assert_eq!(server_res, Err(alert_for(v, false)));
        }
    }
}

#[cfg(feature = "tls12")]
#[test]
fn a_bound_tls12_client_does_not_offer_a_session_ticket() {
    init_logging();
    const SESSION_TICKET: u16 = 0x0023;
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_2;
    let (c, _) = pair();
    let (client, server) = bases(&chain, v, true);
    for (binding, offered) in [(None, true), (Some(c), false)] {
        let (client, server) = with_bindings(&client, &server, binding, None);
        let (mut client, _server) = connect_arc(&client, &server);
        let hello = flight(&mut client);
        assert_eq!(
            extension(&hello, SESSION_TICKET).is_some(),
            offered,
            "bound: {}",
            !offered
        );
    }
}
