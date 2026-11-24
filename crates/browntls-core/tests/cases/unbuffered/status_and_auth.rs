// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: what an unbuffered connection reports about Encrypted
// Client Hello and delegated credentials, and TLS 1.3 post-handshake client
// authentication (RFC 9846 §4.7.2) started by an unbuffered server or
// answered by an unbuffered client.

use browntls_core::client::ResolvesClientCert;
use browntls_core::server::PostHandshakeAuthStatus;

/// Has certificates (so `post_handshake_auth` is offered) but never finds
/// one for a request.
#[derive(Debug)]
struct DeclinesEveryRequest;

impl ResolvesClientCert for DeclinesEveryRequest {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[browntls_core::SignatureScheme],
    ) -> Option<Arc<browntls_core::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A TLS 1.3 client that offers `post_handshake_auth`, answering with
/// `client`'s certificate, or declining every request without one.
fn pha_client(server: &Chain, client: Option<&Chain>) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server));
    let mut config = match client {
        Some(client) => builder
            .with_client_auth_cert(client.cert_chain(), client.private_key())
            .unwrap(),
        None => builder.with_client_cert_resolver(Arc::new(DeclinesEveryRequest)),
    };
    config.enable_post_handshake_auth = true;
    Arc::new(config)
}

/// A server that verifies client certificates against `client` only after
/// the handshake, on request.
fn pha_server(server: &Chain, client: &Chain, mandatory: bool) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client, mandatory))
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    config.request_client_auth_after_handshake = true;
    Arc::new(config)
}

/// Requests client authentication from an unbuffered server, checks the
/// request is refused while it is outstanding, and runs the exchange.
fn ub_request_client_auth(client: &mut dyn Endpoint, server: &mut UbServer) {
    assert!(server.conn.post_handshake_auth_offered());
    server.conn.request_client_auth().unwrap();
    assert_eq!(
        server.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Requested)
    );
    assert!(server.conn.request_client_auth().is_err(), "one at a time");
    pump(client, server);
}

#[test]
fn unbuffered_server_requests_client_auth_after_the_handshake() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let cc = pha_client(&server_chain, Some(&client_chain));
    let sc = pha_server(&server_chain, &client_chain, true);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        // buffered client, unbuffered server
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert!(s.conn.peer_certificates().is_none(), "deferred");
        assert_eq!(s.conn.post_handshake_auth_status(), None);
        ub_request_client_auth(&mut c, &mut s);
        assert!(!s.failed(), "{feed:?}: {}", s.describe());
        assert_eq!(c.conn.post_handshake_auth_responses(), 1);
        assert_eq!(
            s.conn.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(
            s.conn.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
        exchange(&mut c, &mut s, b"after authentication");

        // both unbuffered, twice: each request has its own context
        let mut c = ub_client(&cc, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        for round in 1..=2 {
            ub_request_client_auth(&mut c, &mut s);
            assert!(!s.failed() && !c.failed(), "{feed:?} round {round}");
            assert_eq!(c.conn.post_handshake_auth_responses(), round);
            assert_eq!(
                s.conn.post_handshake_auth_status(),
                Some(PostHandshakeAuthStatus::Authenticated)
            );
            exchange(&mut c, &mut s, b"still talking");
        }
        assert!(c.states.contains(&"EncodeTlsData"));
    }
}

#[test]
fn certificate_request_is_offered_before_pending_input() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let cc = pha_client(&server_chain, Some(&client_chain));
    let sc = pha_server(&server_chain, &client_chain, true);
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);

    // Client data waits, unprocessed, in the server's input buffer.
    c.send(b"waiting");
    let data = c.take_output();
    assert!(!data.is_empty());
    s.incoming.extend_from_slice(&data);
    s.conn.request_client_auth().unwrap();
    let status = s.conn.process_tls_records(&mut s.incoming);
    assert_eq!(status.discard, 0, "nothing read before the request is out");
    match status.state {
        Ok(ConnectionState::EncodeTlsData(mut e)) => {
            let mut buf = vec![0u8; 4096];
            let n = e.encode(&mut buf).unwrap();
            s.outgoing.extend_from_slice(&buf[..n]);
        }
        other => panic!("{other:?}"),
    }
    pump(&mut c, &mut s);
    assert!(!s.failed(), "{}", s.describe());
    assert_eq!(s.take_received(), b"waiting");
    assert_eq!(
        s.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(c.conn.post_handshake_auth_responses(), 1);
}

#[test]
fn unbuffered_client_answers_a_buffered_server() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let cc = pha_client(&server_chain, Some(&client_chain));
    let sc = pha_server(&server_chain, &client_chain, true);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = ub_client(&cc, feed);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.post_handshake_auth_responses(), 0);
        s.conn.request_client_auth().unwrap();
        pump(&mut c, &mut s);
        assert!(!c.failed() && !s.failed(), "{feed:?}: {}", c.describe());
        assert_eq!(c.conn.post_handshake_auth_responses(), 1);
        assert_eq!(
            s.conn.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        exchange(&mut c, &mut s, b"answered");
    }
}

#[test]
fn unbuffered_post_handshake_auth_declined_or_refused() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let no_cert = pha_client(&server_chain, None);

    // Optional client authentication: an empty Certificate is a decline.
    let mut c = ub_client(&no_cert, Feed::Whole);
    let mut s = ub_server(
        &pha_server(&server_chain, &client_chain, false),
        Feed::Whole,
    );
    handshake(&mut c, &mut s);
    ub_request_client_auth(&mut c, &mut s);
    assert!(!s.failed(), "{}", s.describe());
    assert_eq!(c.conn.post_handshake_auth_responses(), 1);
    assert_eq!(
        s.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Declined)
    );
    assert!(s.conn.peer_certificates().is_none());
    exchange(&mut c, &mut s, b"anonymous");

    // Mandatory client authentication: the decline ends the connection.
    let mut c = ub_client(&no_cert, Feed::Whole);
    let mut s = ub_server(&pha_server(&server_chain, &client_chain, true), Feed::Whole);
    handshake(&mut c, &mut s);
    ub_request_client_auth(&mut c, &mut s);
    assert!(s.failed(), "a mandatory certificate was not presented");
    assert_eq!(
        s.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Requested)
    );
}

#[test]
fn unbuffered_request_client_auth_refusals() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let sc = pha_server(&server_chain, &client_chain, false);

    // Before the handshake has completed.
    let mut s = UnbufferedServerConnection::new(sc.clone()).unwrap();
    assert_eq!(s.request_client_auth(), Err(Error::HandshakeNotComplete));
    assert!(!s.post_handshake_auth_offered());
    assert_eq!(s.post_handshake_auth_status(), None);

    // The client did not offer `post_handshake_auth`.
    let mut c = ub_client(&Arc::new(client_config(&server_chain)), Feed::Whole);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    assert!(!s.conn.post_handshake_auth_offered());
    assert!(s.conn.request_client_auth().is_err());
    assert_eq!(s.conn.post_handshake_auth_status(), None);
    exchange(&mut c, &mut s, b"nothing was queued");

    // After our close_notify, and after the client's (RFC 9846 §6.1: the
    // client would never answer).
    let cc = pha_client(&server_chain, Some(&client_chain));
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    s.close_requested = true;
    pump(&mut c, &mut s);
    assert!(
        s.conn.request_client_auth().is_err(),
        "after our close_notify"
    );
    assert_eq!(s.conn.post_handshake_auth_status(), None);
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    c.conn.send_close_notify();
    pump(&mut c, &mut s);
    assert!(s.peer_closed);
    assert!(
        s.conn.request_client_auth().is_err(),
        "after the client's close_notify"
    );
    assert_eq!(s.conn.post_handshake_auth_status(), None);
    assert!(s.take_output().is_empty(), "nothing was queued");

    // TLS 1.2 has no post-handshake authentication.
    #[cfg(feature = "tls12")]
    {
        let cc = Arc::new(versioned_client(&server_chain, ProtocolVersion::TLSv1_2));
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        assert!(s.conn.request_client_auth().is_err());
        assert_eq!(s.conn.post_handshake_auth_status(), None);
        exchange(&mut c, &mut s, b"tls12");
    }
}

#[test]
fn unbuffered_client_reports_its_delegated_credential() {
    use std::time::Duration;

    use browntls_core::delegated_credential::{Credential, DelegatedCredential, valid_time_until};
    use browntls_core::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
    use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
    use browntls_core::{Side, SignatureScheme};

    init_logging();
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let dc_key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pair.serialize_der(),
        )))
        .unwrap();
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let expiry = browntls_core::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(
        browntls_core::pki_types::UnixTime::now().as_secs() + 24 * 3600,
    ));
    let dc = DelegatedCredential::issue(
        Side::Server,
        &chain.end_entity,
        &*cert_key,
        chain.key_type.schemes(),
        Credential {
            valid_time: valid_time_until(&chain.end_entity, expiry).unwrap(),
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: SubjectPublicKeyInfoDer::from(
                rcgen::PublicKeyData::subject_public_key_info(&pair),
            ),
        },
    )
    .unwrap();
    let ck = CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider())
        .unwrap()
        .with_delegated_credential(dc.clone(), dc_key, &provider())
        .unwrap();
    let sc = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(ck))),
    );
    // Resumed handshakes carry no Certificate, so no credential: every
    // connection here is a full handshake.
    let client = |delegated: bool| {
        let mut config = versioned_client(&chain, ProtocolVersion::TLSv1_3);
        config.resumption = browntls_core::client::Resumption::disabled();
        config.enable_delegated_credentials = delegated;
        Arc::new(config)
    };
    let plain = client(false);
    let opted_in = client(true);

    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = ub_client(&opted_in, feed);
        assert_eq!(c.conn.delegated_credential(), None);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.delegated_credential(), Some(&dc), "{feed:?}");
        exchange(&mut c, &mut s, b"delegated");

        let mut c = ub_client(&opted_in, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.delegated_credential(), Some(&dc), "{feed:?}");

        // Without the client's opt-in the certificate key signs.
        let mut c = ub_client(&plain, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.delegated_credential(), None);
    }
}

/// An unbuffered server reports the delegated credential (RFC 9345 §4.1.2)
/// a client authenticated with, in the handshake or after it, and so does
/// the kernel connection it is handed over to.
#[test]
fn unbuffered_server_reports_the_client_delegated_credential() {
    use std::time::Duration;

    use browntls_core::delegated_credential::{Credential, DelegatedCredential, valid_time_until};
    use browntls_core::pki_types::{
        PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
    };
    use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
    use browntls_core::{Side, SignatureScheme};

    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let dc_key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pair.serialize_der(),
        )))
        .unwrap();
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let expiry =
        UnixTime::since_unix_epoch(Duration::from_secs(UnixTime::now().as_secs() + 24 * 3600));
    let dc = DelegatedCredential::issue(
        Side::Client,
        &chain.end_entity,
        &*cert_key,
        chain.key_type.schemes(),
        Credential {
            valid_time: valid_time_until(&chain.end_entity, expiry).unwrap(),
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: SubjectPublicKeyInfoDer::from(
                rcgen::PublicKeyData::subject_public_key_info(&pair),
            ),
        },
    )
    .unwrap();
    let ck = CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider())
        .unwrap()
        .with_client_delegated_credential(dc.clone(), dc_key, &provider())
        .unwrap();
    let mut cc = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(ck)));
    cc.enable_post_handshake_auth = true;
    // Resumed handshakes carry no Certificate, so no credential: every
    // connection here is a full handshake.
    cc.resumption = browntls_core::client::Resumption::disabled();
    let cc = Arc::new(cc);
    let server = |defer: bool| {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&chain, !defer))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        config.enable_delegated_credentials = true;
        config.request_client_auth_after_handshake = defer;
        config.enable_secret_extraction = true;
        Arc::new(config)
    };
    let (in_handshake, deferred) = (server(false), server(true));

    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = b_client(&cc);
        let mut s = ub_server(&in_handshake, feed);
        assert_eq!(s.conn.client_delegated_credential(), None);
        handshake(&mut c, &mut s);
        assert_eq!(s.conn.client_delegated_credential(), Some(&dc), "{feed:?}");
        assert_eq!(s.conn.peer_certificates().unwrap()[0], chain.end_entity);
        exchange(&mut c, &mut s, b"delegated");
        let (_, kernel) = s.conn.dangerous_into_kernel_connection().unwrap();
        assert_eq!(kernel.client_delegated_credential(), Some(&dc));

        let mut c = b_client(&cc);
        let mut s = ub_server(&deferred, feed);
        handshake(&mut c, &mut s);
        assert_eq!(s.conn.client_delegated_credential(), None);
        ub_request_client_auth(&mut c, &mut s);
        assert!(!s.failed(), "{feed:?}: {}", s.describe());
        assert_eq!(
            s.conn.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(s.conn.client_delegated_credential(), Some(&dc), "{feed:?}");
        exchange(&mut c, &mut s, b"authenticated later");
        let (_, kernel) = s.conn.dangerous_into_kernel_connection().unwrap();
        assert_eq!(
            kernel.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(kernel.client_delegated_credential(), Some(&dc));
    }
}

/// ECH needs HPKE, which only the native provider implements; the suites
/// work with either provider's handshake.
#[cfg(feature = "native")]
#[test]
fn unbuffered_connections_report_ech_status() {
    use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    use browntls_core::ech::{EchConfig, EchMode, EchServerConfig, EchServerKey, EchStatus};

    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let key = |id| EchServerKey::generate(id, "public.example", 32, ALL_SUPPORTED_SUITES).unwrap();
    let current = Arc::new(EchServerConfig::new(vec![key(7)]).unwrap());
    let stale = EchServerConfig::new(vec![key(8)]).unwrap();
    let mut sc = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    sc.ech = Some(current.clone());
    let sc = Arc::new(sc);
    let ech_client = |list: &[u8]| {
        let mut config = versioned_client(&chain, ProtocolVersion::TLSv1_3);
        config.ech_mode = Some(EchMode::Enable(
            EchConfig::new(list, ALL_SUPPORTED_SUITES).unwrap(),
        ));
        Arc::new(config)
    };
    let cc = ech_client(current.ech_config_list());

    for feed in [Feed::Whole, Feed::ByteByByte] {
        // Accepted: unbuffered client, buffered server.
        let mut c = ub_client(&cc, feed);
        assert_eq!(c.conn.ech_status(), EchStatus::Offered);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.ech_status(), EchStatus::Accepted);
        assert_eq!(s.conn.ech_status(), EchStatus::Accepted);
        exchange(&mut c, &mut s, b"hidden");

        // Accepted: buffered client, unbuffered server.
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, feed);
        assert_eq!(s.conn.ech_status(), EchStatus::NotOffered);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.ech_status(), EchStatus::Accepted);
        assert_eq!(s.conn.ech_status(), EchStatus::Accepted);
        assert_eq!(s.conn.server_name(), Some("localhost"));

        // Accepted: both unbuffered.
        let mut c = ub_client(&cc, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.ech_status(), EchStatus::Accepted);
        assert_eq!(s.conn.ech_status(), EchStatus::Accepted);

        // Not offered.
        let plain = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
        let mut c = ub_client(&plain, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.ech_status(), EchStatus::NotOffered);
        assert_eq!(s.conn.ech_status(), EchStatus::NotOffered);

        // Rejected: the client offers a configuration the server lost.
        let mut c = ub_client(&ech_client(stale.ech_config_list()), feed);
        let mut s = ub_server(&sc, feed);
        pump(&mut c, &mut s);
        assert_eq!(c.conn.ech_status(), EchStatus::Rejected);
        assert_eq!(s.conn.ech_status(), EchStatus::Rejected);
        let Some(Error::RejectedEch(rejected)) = &c.error else {
            panic!("{feed:?}: {}", c.describe());
        };
        assert_eq!(rejected.retry_configs(), Some(current.ech_config_list()));
    }
}
