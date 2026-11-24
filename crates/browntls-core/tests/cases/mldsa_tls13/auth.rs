// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: server, client and mutual authentication with ML-DSA end
// entities, and the size of ML-DSA flights.

/// Each parameter set authenticates a server under a CA of the same set:
/// the handshake completes, application data flows, and the
/// `CertificateVerify` scheme is exactly the one of the key's parameter set
/// (§3.2 of the draft).
#[test]
fn server_authenticates_with_each_parameter_set() {
    for set in ml_dsa::SETS {
        let server = server_id(Alg::Ml(set));
        let (mut c, mut s, seen, _) = ml_dsa_handshake(&server, None);
        assert_eq!(seen.seen(), [scheme_of(set)], "{set:?}");
        assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(c.peer_certificates().unwrap(), server.chain);
        exchange(&mut c, &mut s);
    }
}

/// The server needs only the key loader opt-in to sign; the client needs
/// only the verification opt-in to verify.
#[test]
fn each_side_needs_only_its_own_opt_in() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let mut client_provider = prov::provider();
    client_provider.signature_verification_algorithms =
        prov::provider_with_ml_dsa().signature_verification_algorithms;
    let verifier = server_verifier(client_provider.clone(), &server);
    let (mut c, mut s) = connect(
        client_config(client_provider, verifier.clone(), None),
        server_config(provider_with_ml_dsa_keys_only(), &server, None),
    );
    handshake(&mut c, &mut s).unwrap();
    assert_eq!(verifier.seen(), [SignatureScheme::ML_DSA_65]);
    exchange(&mut c, &mut s);
}

/// An ML-DSA end entity under an ECDSA CA, and an ECDSA end entity under
/// an ML-DSA CA: the `CertificateVerify` scheme follows the end entity.
#[test]
fn mixed_chains() {
    for (ee, ca) in [
        (Alg::Ml(Set::MlDsa65), Alg::P256),
        (Alg::P256, Alg::Ml(Set::MlDsa44)),
        (Alg::Ml(Set::MlDsa87), Alg::Ml(Set::MlDsa44)),
    ] {
        let server = identity(ee, &[ca], Purpose::Server, "mixed");
        let (mut c, mut s, seen, _) = ml_dsa_handshake(&server, None);
        assert_eq!(seen.seen(), [server.scheme()], "{ee:?} under {ca:?}");
        exchange(&mut c, &mut s);
    }
}

/// Client authentication with ML-DSA on one side or both, with different
/// parameter sets per side: each `CertificateVerify` has its key's scheme.
#[test]
fn client_and_mutual_authentication() {
    for (server_alg, client_alg) in [
        (Alg::P256, Alg::Ml(Set::MlDsa44)),
        (Alg::Ml(Set::MlDsa65), Alg::P256),
        (Alg::Ml(Set::MlDsa65), Alg::Ml(Set::MlDsa65)),
        (Alg::Ml(Set::MlDsa87), Alg::Ml(Set::MlDsa44)),
        (Alg::Ml(Set::MlDsa44), Alg::Ml(Set::MlDsa87)),
    ] {
        let server = server_id(server_alg);
        let client = client_id(client_alg);
        let (mut c, mut s, server_seen, client_seen) = ml_dsa_handshake(&server, Some(&client));
        let what = format!("server {server_alg:?}, client {client_alg:?}");
        assert_eq!(server_seen.seen(), [server.scheme()], "{what}");
        assert_eq!(client_seen.unwrap().seen(), [client.scheme()], "{what}");
        assert_eq!(s.peer_certificates().unwrap(), client.chain, "{what}");
        assert_eq!(c.peer_certificates().unwrap(), server.chain, "{what}");
        exchange(&mut c, &mut s);
    }
}

/// The records of `flight`, as `(content type, record length)`.
fn records(flight: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < flight.len() {
        let len = usize::from(u16::from_be_bytes([flight[at + 3], flight[at + 4]]));
        out.push((flight[at], 5 + len));
        at += 5 + len;
    }
    assert_eq!(at, flight.len());
    out
}

/// Three-certificate ML-DSA-87 chains (the root not sent: about 15 KB of
/// certificates and a 4627-byte signature per side) complete in both
/// directions, also with a 512-byte `max_fragment_size` on both sides,
/// where the server's flight is split into records of at most that size
/// (plus the TLS 1.3 content type and AEAD tag).
#[test]
fn ml_dsa_87_chains_fit_and_fragment() {
    const MAX: usize = 512;
    let ml87 = Alg::Ml(Set::MlDsa87);
    let server = identity(ml87, &[ml87, ml87], Purpose::Server, "large");
    let client = identity(ml87, &[ml87, ml87], Purpose::Client, "large");
    assert_eq!(server.chain.len(), 2);
    let sent: usize = server.chain.iter().map(|c| c.as_ref().len()).sum();
    assert!(sent > 14_000, "{sent}");

    for max_fragment_size in [None, Some(MAX)] {
        let server_verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
        let client_verifier = client_verifier(prov::provider_with_ml_dsa(), &client, true);
        let mut client_config = client_config(
            prov::provider_with_ml_dsa(),
            server_verifier.clone(),
            Some(&client),
        );
        client_config.max_fragment_size = max_fragment_size;
        let mut server_config =
            server_config(prov::provider_with_ml_dsa(), &server, Some(client_verifier.clone()));
        server_config.max_fragment_size = max_fragment_size;
        let (mut c, mut s) = connect(client_config, server_config);

        pump(&mut c, &mut s).unwrap();
        let flight = common::hello_wire::take_flight(&mut s);
        let records = records(&flight);
        if max_fragment_size.is_some() {
            // Encrypted handshake records: inner type and 16-byte tag.
            assert!(records.iter().all(|(_, len)| *len <= MAX + 17), "{records:?}");
            assert!(records.len() > (sent + 4627) / MAX, "{}", records.len());
        }
        assert!(flight.len() > sent + 4627);
        feed(&mut c, &flight).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(server_verifier.seen(), [SignatureScheme::ML_DSA_87]);
        assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_87]);
        assert_eq!(s.peer_certificates().unwrap(), client.chain);
        exchange(&mut c, &mut s);
    }
}
