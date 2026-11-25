// Cases included by `tests/rsa_pkcs1_legacy_native.rs` after
// `cases/rsa_pkcs1_legacy.rs`, whose imports and helpers they use: the
// native provider's own RSA keys, which the RustCrypto provider does not
// have (its key loader does not sign with RSA). `any_rsa_pkcs1_legacy_type`
// loads a key that signs with RSASSA-PKCS1-v1_5 only; the default key
// loader's RSA keys sign with RSASSA-PSS in TLS 1.3.

use browntls_core::PeerIncompatible;

/// [`rsa_client`]'s key loaded by `native::sign::any_rsa_pkcs1_legacy_type`.
fn native_legacy_key(chain: &Chain) -> Arc<dyn SigningKey> {
    prov::sign::any_rsa_pkcs1_legacy_type(&chain.private_key()).unwrap()
}

/// The native legacy key authenticates a TLS 1.3 client to an opted-in
/// server with `rsa_pkcs1_sha512_legacy`, its first choice of the legacy
/// schemes (the request lists all three), and to a default
/// server not at all: the client then sends an empty Certificate, and
/// mandatory client authentication fails with `certificate_required`.
#[test]
fn native_legacy_key_authenticates_a_tls13_client() {
    let mut outcome = authenticate(
        prov::provider_with_rsa_pkcs1_legacy(),
        true,
        rsa_client(),
        native_legacy_key(rsa_client()),
    );
    outcome.completed();
    assert_eq!(outcome.verifier.seen(), [S::RSA_PKCS1_SHA512_LEGACY]);
    assert_eq!(
        outcome.server.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );

    let outcome = authenticate(
        prov::provider(),
        true,
        rsa_client(),
        native_legacy_key(rsa_client()),
    );
    outcome.refused(
        Error::NoCertificatesPresented,
        AlertDescription::CertificateRequired,
        "default server",
    );
    assert!(outcome.verifier.seen().is_empty());
}

/// The same key in a TLS 1.2 handshake with an opted-in server signs with
/// `rsa_pkcs1_sha512`: TLS 1.2 has no legacy scheme, and RSASSA-PKCS1-v1_5
/// is its own.
#[cfg(feature = "tls12")]
#[test]
fn native_legacy_key_in_tls12() {
    let (request, mut outcome) = authenticate_tls12(
        prov::provider_with_rsa_pkcs1_legacy(),
        rsa_client(),
        native_legacy_key(rsa_client()),
    );
    outcome.completed();
    assert!(
        request
            .iter()
            .all(|s| !matches!(s, 0x0420 | 0x0520 | 0x0620))
    );
    assert_eq!(outcome.verifier.seen(), [S::RSA_PKCS1_SHA512]);
    assert_eq!(
        outcome.client.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
}

/// The native legacy key as a TLS 1.3 server's key, against a client that
/// opted in everywhere: no ClientHello offers a legacy scheme and TLS 1.3
/// allows no other RSASSA-PKCS1-v1_5 scheme, so the key cannot sign. The
/// server fails cleanly with no scheme in common and `handshake_failure`.
#[test]
fn native_legacy_key_cannot_authenticate_a_tls13_server() {
    let verifier = server_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_server());
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(prov::provider_with_rsa_pkcs1_legacy()))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(prov::provider_with_rsa_pkcs1_legacy()))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .with_no_client_auth()
            .with_single_certified_key(CertifiedKey::new(
                rsa_server().cert_chain(),
                native_legacy_key(rsa_server()),
            ));
    let mut client = ClientConnection::new(Arc::new(client_config), common::server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoSignatureSchemesInCommon
        ))
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
    assert!(verifier.seen().is_empty());
}

/// An ordinary RSA client key (the default key loader's) against an
/// opted-in server: it is offered the legacy schemes too and still signs
/// with `rsa_pss_rsae_sha512`, as RFC 9963 §3 says a key that can make
/// RSASSA-PSS signatures should.
#[test]
fn native_rsa_key_keeps_signing_with_pss() {
    let key = prov::provider()
        .key_provider
        .load_private_key(rsa_client().private_key())
        .unwrap();
    let mut outcome = authenticate(
        prov::provider_with_rsa_pkcs1_legacy(),
        true,
        rsa_client(),
        key,
    );
    outcome.completed();
    assert_eq!(outcome.verifier.seen(), [S::RSA_PSS_SHA512]);
    let offered = outcome.resolver.seen();
    assert_eq!(offered.len(), 1);
    assert!(OPT_IN_ORDER.iter().all(|s| offered[0].contains(s)));
}

/// Both sides opted in everywhere, with an RSA server certificate whose
/// key the native provider loads: the server authenticates with
/// `rsa_pss_rsae_sha512` and the token key client with a legacy scheme.
#[test]
fn native_rsa_server_and_legacy_client_with_the_opt_in_everywhere() {
    let client_verifier =
        client_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_client(), true);
    let server_verifier = server_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_server());
    let key = TokenKey::legacy(S::RSA_PKCS1_SHA256_LEGACY, Sig::Pkcs1);
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(prov::provider_with_rsa_pkcs1_legacy()))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier.clone())
            .with_client_auth_certified_key(CertifiedKey::new(rsa_client().cert_chain(), key));
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(prov::provider_with_rsa_pkcs1_legacy()))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .with_client_cert_verifier(client_verifier.clone())
            .with_single_cert(rsa_server().cert_chain(), rsa_server().private_key())
            .unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), common::server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    common::do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server_verifier.seen(), [S::RSA_PSS_SHA512]);
    assert_eq!(client_verifier.seen(), [S::RSA_PKCS1_SHA256_LEGACY]);
    assert_eq!(send_and_receive(&mut client, &mut server, b"ping"), b"ping");
}
