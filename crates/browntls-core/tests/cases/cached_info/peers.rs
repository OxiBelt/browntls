// Misbehaving servers: the client is fed a server flight edited on the
// wire (TLS 1.2 sends everything up to ChangeCipherSpec unprotected).

/// Fills a store with the server's Certificate, then starts a second
/// connection to a server with `second`: returns its client and the
/// server's first flight, split into handshake messages (ServerHello,
/// Certificate, ServerKeyExchange, ServerHelloDone).
fn second_flight(second: ServerCachedInfoPolicy) -> (ClientConnection, Vec<Vec<u8>>, [u8; 32]) {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let cc = client(&chain, &store, None, &TLS12);
    let (mut c, mut s) = connect(&cc, &server(&chain, policy(true, false), None, &TLS12));
    run(&mut c, &mut s).unwrap();
    let (mut c, mut s) = connect(&cc, &server(&chain, second, None, &TLS12));
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let flight = messages(&output(&mut s));
    assert_eq!(flight.len(), 4);
    (c, flight, cached(&store, CERT)[0])
}

/// Delivers `edited` and returns the client's error, checking its alert.
fn refused(mut client: ClientConnection, edited: &[Vec<u8>], expect: AlertDescription) -> Error {
    let err = deliver(&mut client, &flight(edited)).unwrap_err();
    assert_eq!(alert(&mut client), Some(expect), "{err:?}");
    err
}

#[test]
fn acknowledgements_of_what_was_not_offered() {
    // Only `cert` was offered (the store has no CertificateRequest).
    for answer in [&[0, 1, 2][..], &[0, 2, 1, 1], &[0, 1, 7], &[0, 2, 1, 2]] {
        let (c, mut f, _) = second_flight(policy(true, false));
        f[0] = with_cached_info(&f[0], Some(answer));
        let err = refused(c, &f, AlertDescription::IllegalParameter);
        assert_eq!(
            err,
            Error::PeerMisbehaved(browntls_core::PeerMisbehaved::SelectedUnofferedCachedInfo),
            "{answer:?}"
        );
    }
    // A malformed answer.
    for answer in [&[0, 0][..], &[0, 2, 1], &[0]] {
        let (c, mut f, _) = second_flight(policy(true, false));
        f[0] = with_cached_info(&f[0], Some(answer));
        let err = refused(c, &f, AlertDescription::DecodeError);
        assert!(
            matches!(err, Error::InvalidMessage(_)),
            "{answer:?}: {err:?}"
        );
    }
}

#[test]
fn unsolicited_acknowledgement() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = (*client(&chain, &new_store(), None, &TLS12)).clone();
    config.cached_info = None;
    let (mut c, mut s) = connect(
        &Arc::new(config),
        &server(&chain, policy(true, true), None, &TLS12),
    );
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut f = messages(&output(&mut s));
    f[0] = with_cached_info(&f[0], Some(&[0, 1, 1]));
    let err = refused(c, &f, AlertDescription::UnsupportedExtension);
    assert!(matches!(err, Error::PeerMisbehaved(_)), "{err:?}");
}

#[test]
fn hash_forms_that_match_no_offer() {
    let (_, f, ours) = second_flight(policy(true, false));
    assert_eq!(
        f[1],
        message(11, &hash_form(&ours)),
        "the server's hash form"
    );

    let mut flipped = ours;
    flipped[31] ^= 1;
    let mut longer = ours.to_vec();
    longer.push(0);
    for hash in [&flipped[..], &ours[..31], &longer, &ours[..1]] {
        let (c, mut f, _) = second_flight(policy(true, false));
        f[1] = message(11, &hash_form(hash));
        let err = refused(c, &f, AlertDescription::IllegalParameter);
        assert_eq!(
            err,
            Error::PeerMisbehaved(browntls_core::PeerMisbehaved::UnofferedCachedInfoFingerprint)
        );
    }
}

#[test]
fn malformed_hash_forms() {
    let (_, _, ours) = second_flight(policy(true, false));
    let mut trailing = hash_form(&ours);
    trailing.push(0);
    for body in [vec![], vec![0], vec![32, 1, 2, 3], trailing] {
        let (c, mut f, _) = second_flight(policy(true, false));
        f[1] = message(11, &body);
        let err = refused(c, &f, AlertDescription::DecodeError);
        assert!(matches!(err, Error::InvalidMessage(_)), "{err:?}");
    }
}

#[test]
fn hash_form_without_acknowledgement() {
    let (c, mut f, _) = second_flight(policy(true, false));
    f[0] = with_cached_info(&f[0], None);
    let err = refused(c, &f, AlertDescription::DecodeError);
    assert!(matches!(err, Error::InvalidMessage(_)), "{err:?}");
}

#[test]
fn acknowledgement_with_a_full_certificate() {
    // The server sends its Certificate in full; the edit claims it is a
    // hash form, so the client reads its body as one.
    let (c, mut f, _) = second_flight(ServerCachedInfoPolicy::default());
    assert!(f[1].len() > 37);
    f[0] = with_cached_info(&f[0], Some(&[0, 1, 1]));
    let err = refused(c, &f, AlertDescription::DecodeError);
    assert!(matches!(err, Error::InvalidMessage(_)), "{err:?}");
}

/// RFC 7924 §5: a fingerprint of a certificate the client trusts, injected
/// by a server holding another key, fails at the ServerKeyExchange
/// signature, which is checked against the restored certificate's key.
#[test]
fn injected_fingerprint_fails_the_signature_check() {
    let a = server_chain(KeyType::EcdsaP256);
    let b = server_chain(KeyType::EcdsaP256);
    let mut roots = browntls_core::RootCertStore::empty();
    roots.add(a.ca.clone()).unwrap();
    roots.add(b.ca.clone()).unwrap();
    let store = new_store();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&TLS12)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.cached_info = Some(store.clone());
    let cc = Arc::new(config);
    let (mut c, mut s) = connect(&cc, &server(&a, policy(true, false), None, &TLS12));
    run(&mut c, &mut s).unwrap();
    let a_fp = cached(&store, CERT)[0];

    // Both chains are trusted: B alone would be accepted.
    let sb = server(&b, ServerCachedInfoPolicy::default(), None, &TLS12);
    let (mut c, mut s) = connect(&cc, &sb);
    run(&mut c, &mut s).unwrap();

    let (mut c, mut s) = connect(&cc, &sb);
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut f = messages(&output(&mut s));
    f[0] = with_cached_info(&f[0], Some(&[0, 1, 1]));
    f[1] = message(11, &hash_form(&a_fp));
    let err = refused(c, &f, AlertDescription::DecryptError);
    assert!(matches!(err, Error::InvalidCertificate(_)), "{err:?}");
}
