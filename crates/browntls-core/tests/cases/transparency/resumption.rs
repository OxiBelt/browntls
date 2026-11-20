// Session resumption: a resumed handshake carries no `transparency_info`
// and does not evaluate the certificate again (RFC 9162 §6.5). Included by
// `cases/transparency.rs`.

/// A full handshake with the policy met, then a resumed one: the resumed
/// connection has neither items nor a status.
fn resume_twice(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) {
    let (c, _s, cr, sr) = connect(client, server);
    cr.unwrap();
    sr.unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
    assert!(c.peer_transparency_status().is_some());
    assert!(c.peer_transparency_info().is_some());

    let (c, s, cr, sr) = connect(client, server);
    cr.unwrap();
    sr.unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(c.peer_transparency_info(), None);
    assert_eq!(c.peer_transparency_status(), None);
    assert!(c.peer_certificates().is_some());
}

#[test]
fn tls13_ticket_resumption() {
    let fx = Fixture::new();
    let v = &version::TLS13;
    let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
    let list = list(&[fx.sct(&fx.log_a)]);
    resume_twice(&client, &server(&fx.chain, Some(list), None, v));
}

#[test]
fn tls12_session_id_and_ticket_resumption() {
    use browntls_core::client::{Resumption, Tls12Resumption};

    let fx = Fixture::new();
    let v = &version::TLS12;
    let list = list(&[fx.sct(&fx.log_a)]);

    // Session ID (the server's memory cache).
    let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
    resume_twice(&client, &server(&fx.chain, Some(list.clone()), None, v));

    // Ticket (RFC 5077).
    let mut config = client_with(&fx.pki, Some(fx.requirements(&[&fx.log_a])), v);
    config.resumption =
        Resumption::in_memory_sessions(4).tls12_resumption(Tls12Resumption::SessionIdOrTickets);
    let mut server_config = (*server(&fx.chain, Some(list), None, v)).clone();
    server_config.ticketer = prov::Ticketer::new().unwrap();
    server_config.session_storage = Arc::new(browntls_core::server::NoServerSessionStorage {});
    resume_twice(&Arc::new(config), &Arc::new(server_config));
}
