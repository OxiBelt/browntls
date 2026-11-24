// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: where the opt-in puts the ML-DSA schemes in the
// `signature_algorithms` a peer sends, with the library's own verifiers.

/// The `signature_algorithms` (extension 13) of a list of extensions.
fn listed_schemes(exts: &[(u16, Vec<u8>)]) -> Vec<SignatureScheme> {
    let (_, body) = exts.iter().find(|(typ, _)| *typ == 13).unwrap();
    common::grease_wire::signature_schemes(body)
        .into_iter()
        .map(SignatureScheme::from)
        .collect()
}

/// The `signature_algorithms` of a TLS 1.3-only ClientHello whose
/// certificate verifier is the library's `WebPkiServerVerifier` built with
/// `provider`.
fn client_hello_schemes(provider: CryptoProvider, server: &Identity) -> Vec<SignatureScheme> {
    let verifier =
        WebPkiServerVerifier::builder_with_provider(server.roots(), arc(provider.clone()))
            .build()
            .unwrap();
    let mut c = ClientConnection::new(
        Arc::new(client_config(provider, verifier, None)),
        server_name(),
    )
    .unwrap();
    let hello = common::hello_wire::take_flight(&mut c);
    listed_schemes(&common::hello_wire::hello_extensions(&hello, true))
}

/// The `signature_algorithms` of the TLS 1.3 CertificateRequest of a server
/// whose client verifier is the library's `WebPkiClientVerifier` built with
/// `provider`. The handshake runs over QUIC (RFC 9001), whose handshake
/// messages leave the connection unprotected (as CRYPTO data), so the
/// request is read as sent rather than as the client's resolver sees it.
fn certificate_request_schemes(
    provider: CryptoProvider,
    server: &Identity,
    client: &Identity,
) -> Vec<SignatureScheme> {
    use browntls_core::quic;

    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(client.roots(), arc(provider.clone()))
            .build()
            .unwrap();
    let server_config = server_config(provider.clone(), server, Some(client_verifier));
    let client_config = client_config(provider.clone(), server_verifier(provider, server), None);
    let mut c = quic::ClientConnection::new(
        Arc::new(client_config),
        quic::Version::V1,
        server_name(),
        b"c".to_vec(),
    )
    .unwrap();
    let mut s =
        quic::ServerConnection::new(Arc::new(server_config), quic::Version::V1, b"s".to_vec())
            .unwrap();
    let mut hello = Vec::new();
    while c.write_hs(&mut hello).is_some() {}
    s.read_hs(&hello).unwrap();
    // ServerHello, then (after the change to Handshake keys) the rest of
    // the server's flight.
    let mut sent = Vec::new();
    while s.write_hs(&mut sent).is_some() {}
    let messages = common::grease_wire::handshake_messages(&sent);
    let (_, request) = messages
        .iter()
        .find(|(typ, _)| *typ == 13)
        .expect("a CertificateRequest");
    listed_schemes(&common::grease_wire::certificate_request_extensions(
        request,
    ))
}

/// With the opt-in, the library's verifiers list the three ML-DSA schemes
/// last, in code point order (0x0904, 0x0905, 0x0906), after exactly the
/// schemes they list without it: in a ClientHello and in a TLS 1.3
/// CertificateRequest.
#[test]
fn ml_dsa_schemes_come_last_on_the_wire() {
    let server = server_id(Alg::P256);
    let client = client_id(Alg::P256);
    for (what, opt_in, default) in [
        (
            "ClientHello",
            client_hello_schemes(prov::provider_with_ml_dsa(), &server),
            client_hello_schemes(prov::provider(), &server),
        ),
        (
            "CertificateRequest",
            certificate_request_schemes(prov::provider_with_ml_dsa(), &server, &client),
            certificate_request_schemes(prov::provider(), &server, &client),
        ),
    ] {
        assert!(opt_in.len() > ML_DSA_SCHEMES.len(), "{what}: {opt_in:?}");
        let (head, tail) = opt_in.split_at(opt_in.len() - ML_DSA_SCHEMES.len());
        assert_eq!(tail, ML_DSA_SCHEMES, "{what}");
        assert_eq!(
            tail.iter().map(|s| u16::from(*s)).collect::<Vec<_>>(),
            [0x0904, 0x0905, 0x0906],
            "{what}"
        );
        assert_eq!(head, default, "{what}");
        assert!(
            !default.iter().any(|s| ML_DSA_SCHEMES.contains(s)),
            "{what}: {default:?}"
        );
    }
}
