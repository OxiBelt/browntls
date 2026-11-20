// Client certificate URL failures, included by
// `cases/client_certificate_url.rs`.

/// Runs a handshake from a client without a chain that sends `urls`.
fn failing_run(
    s: &Setup,
    urls: CertificateUrl,
    mandatory: bool,
    policy: Option<ClientCertificateUrlPolicy>,
    answer: impl FnMut(&ClientCertificateUrlQuery) -> ClientCertificateUrlResponse,
) -> Outcome {
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(urls), false), true),
        s.server(&TLS12, mandatory, policy),
    );
    let outcome = run(&mut client, &mut server, answer);
    if outcome.server.is_err() {
        assert!(server.peer_certificates().is_none());
    }
    outcome
}

/// Checks the server failed with `err` and alert `alert`, which ended the
/// client's handshake too.
fn assert_failed(outcome: &Outcome, err: Error, alert: u8) {
    assert_eq!(outcome.server, Err(err), "{outcome:?}");
    assert_eq!(outcome.alert, Some(alert), "{outcome:?}");
    assert_eq!(
        outcome.client,
        Err(Error::AlertReceived(AlertDescription::from(alert))),
        "{outcome:?}"
    );
}

#[test]
fn a_hash_mismatch_is_bad_certificate_hash_value() {
    init_logging();
    let s = Setup::new();
    // The objects swapped: each has the other's hash.
    let outcome = failing_run(&s, s.individual(), true, policy(), |q| {
        let mut objects = match s.fetch(q) {
            ClientCertificateUrlResponse::Fetched(objects) => objects,
            _ => unreachable!(),
        };
        objects.reverse();
        ClientCertificateUrlResponse::Fetched(objects)
    });
    assert_failed(
        &outcome,
        CertificateUrlError::HashMismatch.into(),
        ALERT_BAD_CERTIFICATE_HASH_VALUE,
    );
}

/// Always fatal, also when client authentication is optional: the client's
/// CertificateVerify could not be checked.
#[test]
fn unobtainable_is_fatal_with_mandatory_and_optional_client_auth() {
    init_logging();
    let s = Setup::new();
    for mandatory in [true, false] {
        let outcome = failing_run(&s, s.individual(), mandatory, policy(), |_| {
            ClientCertificateUrlResponse::Unobtainable
        });
        assert_eq!(outcome.queries.len(), 1);
        assert_failed(
            &outcome,
            CertificateUrlError::Unobtainable.into(),
            ALERT_CERTIFICATE_UNOBTAINABLE,
        );
    }
}

#[test]
fn a_wrong_object_count_is_unobtainable() {
    init_logging();
    let s = Setup::new();
    for objects in [vec![], vec![s.web[EE_URL].clone()]] {
        let outcome = failing_run(&s, s.individual(), true, policy(), |_| {
            ClientCertificateUrlResponse::Fetched(objects.clone())
        });
        assert_failed(
            &outcome,
            CertificateUrlError::WrongObjectCount.into(),
            ALERT_CERTIFICATE_UNOBTAINABLE,
        );
    }
}

#[test]
fn oversized_objects_are_unobtainable() {
    init_logging();
    let s = Setup::new();
    let total = s.web[EE_URL].len() + s.web[CA_URL].len();
    let mut small = ClientCertificateUrlPolicy::new(prov::sha1);
    small.max_fetched_len = total - 1;
    let outcome = failing_run(&s, s.individual(), true, Some(small.clone()), |q| {
        s.fetch(q)
    });
    assert_failed(
        &outcome,
        CertificateUrlError::FetchedTooLarge.into(),
        ALERT_CERTIFICATE_UNOBTAINABLE,
    );
    // Exactly at the limit is fine.
    small.max_fetched_len = total;
    let outcome = failing_run(&s, s.individual(), false, Some(small), |q| s.fetch(q));
    assert!(outcome.server.is_ok(), "{outcome:?}");
}

/// URLs the policy refuses end the handshake before any query.
#[test]
fn urls_the_policy_refuses_are_never_surfaced() {
    init_logging();
    let s = Setup::new();
    let one = |url: &str| CertificateUrl::individual_certs(vec![s.entry_for(url)]).unwrap();
    let mut cases: Vec<(CertificateUrl, Option<ClientCertificateUrlPolicy>)> = [
        "https://certs.example/client.der",
        "ftp://certs.example/client.der",
        "certs.example/client.der",
        "http:certs.example",
        "http:///client.der",
        "http://user@certs.example/client.der",
        "http://certs.example/client.der#x",
        "http://certs.example\\client.der",
    ]
    .into_iter()
    .map(|url| (one(url), policy()))
    .collect();
    let mut short = ClientCertificateUrlPolicy::new(prov::sha1);
    short.max_url_len = EE_URL.len() - 1;
    cases.push((one(EE_URL), Some(short)));
    let mut few = ClientCertificateUrlPolicy::new(prov::sha1);
    few.max_urls = 1;
    cases.push((s.individual(), Some(few)));
    for (urls, policy) in cases {
        let outcome = failing_run(&s, urls.clone(), true, policy, |_| {
            panic!("query surfaced for {urls:?}")
        });
        assert!(outcome.queries.is_empty());
        assert_failed(
            &outcome,
            CertificateUrlError::RefusedByPolicy.into(),
            ALERT_CERTIFICATE_UNOBTAINABLE,
        );
    }
    // A scheme enabled by the policy, in any case.
    let mut https = ClientCertificateUrlPolicy::new(prov::sha1);
    https.allowed_schemes = vec!["HTTPS".into()];
    let urls = one("https://certs.example/client.der");
    let outcome = failing_run(&s, urls, true, Some(https), |_| {
        ClientCertificateUrlResponse::Unobtainable
    });
    assert_eq!(outcome.queries.len(), 1);
}

#[test]
fn a_malformed_pkipath_is_bad_certificate() {
    init_logging();
    let mut s = Setup::new();
    let mut bad = s.web[PATH_URL].clone();
    bad.push(0);
    s.web.insert(PATH_URL.into(), bad);
    let outcome = failing_run(&s, s.pkipath(), true, policy(), |q| s.fetch(q));
    assert_failed(
        &outcome,
        CertificateUrlError::MalformedPkiPath.into(),
        ALERT_BAD_CERTIFICATE,
    );
}

/// A fetched chain is verified like a sent one.
#[test]
fn a_fetched_chain_that_fails_verification() {
    init_logging();
    let mut s = Setup::new();
    let other = client_chain(KeyType::EcdsaP256);
    s.web.insert(EE_URL.into(), other.end_entity.to_vec());
    let outcome = failing_run(&s, s.individual(), true, policy(), |q| s.fetch(q));
    assert_failed(
        &outcome,
        CertificateError::UnknownIssuer.into(),
        ALERT_UNKNOWN_CA,
    );
}

/// A wrong id changes nothing; nothing buffered is processed while the
/// query is outstanding.
#[test]
fn the_pause_holds_until_the_right_answer() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.individual()), false), true),
        s.server(&TLS12, true, policy()),
    );
    let (_, flight) = hello_round(&mut client, &mut server);
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    // CertificateURL, ClientKeyExchange, CertificateVerify,
    // ChangeCipherSpec and Finished arrive together.
    give(&mut server, &take_flight(&mut client));
    let io = server.process_new_packets().unwrap();
    assert!(io.client_certificate_url_pending());
    assert!(!io.revocation_pending());
    let id = server.pending_client_certificate_url().unwrap().id();
    assert!(!server.wants_read() && !server.wants_write());
    let err = server.read_tls(&mut &[22u8, 3, 3, 0, 0][..]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    assert!(
        server
            .process_new_packets()
            .unwrap()
            .client_certificate_url_pending()
    );

    let fetched = s.fetch(server.pending_client_certificate_url().unwrap());
    assert!(
        server
            .resolve_client_certificate_url(id + 1, ClientCertificateUrlResponse::Unobtainable)
            .is_err()
    );
    assert_eq!(server.pending_client_certificate_url().unwrap().id(), id);
    assert!(server.is_handshaking() && !server.wants_write());

    // The answer processes the rest of the flight at once.
    server.resolve_client_certificate_url(id, fetched).unwrap();
    assert!(server.pending_client_certificate_url().is_none());
    assert!(!server.is_handshaking());
    assert!(server.wants_write());
    give(&mut client, &take_flight(&mut server));
    client.process_new_packets().unwrap();
    assert!(!client.is_handshaking());
    assert!(
        server
            .resolve_client_certificate_url(id, ClientCertificateUrlResponse::Unobtainable)
            .is_err()
    );
    // Client connections never pause.
    assert!(client.pending_client_certificate_url().is_none());
}

/// RFC 6066 §5: a client logs a warning-level certificate_unobtainable and
/// goes on; a fatal one ends its handshake.
#[test]
fn the_client_survives_a_warning_certificate_unobtainable() {
    init_logging();
    let s = Setup::new();
    for (level, fatal) in [(1u8, false), (2, true)] {
        let (mut client, mut server) = connect(
            s.client(&TLS12, s.key(Some(s.individual()), false), true),
            s.server(&TLS12, false, policy()),
        );
        let (_, flight) = hello_round(&mut client, &mut server);
        give(&mut client, &flight);
        client.process_new_packets().unwrap();
        give(&mut server, &take_flight(&mut client));
        server.process_new_packets().unwrap();
        let alert = [21, 3, 3, 0, 2, level, ALERT_CERTIFICATE_UNOBTAINABLE];
        give(&mut client, &alert);
        let result = client.process_new_packets();
        if fatal {
            assert_eq!(
                result.unwrap_err(),
                Error::AlertReceived(AlertDescription::CertificateUnobtainable)
            );
            continue;
        }
        result.unwrap();
        let outcome = run(&mut client, &mut server, |q| s.fetch(q));
        assert!(
            outcome.server.is_ok() && outcome.client.is_ok(),
            "{outcome:?}"
        );
    }
}

/// RFC 6066 §5: bad_certificate_hash_value is always fatal, so a
/// warning-level one ends the client's handshake too.
#[test]
fn a_warning_bad_certificate_hash_value_is_fatal() {
    init_logging();
    let s = Setup::new();
    for level in [1u8, 2] {
        let (mut client, mut server) = connect(
            s.client(&TLS12, s.key(Some(s.individual()), false), true),
            s.server(&TLS12, false, policy()),
        );
        let (_, flight) = hello_round(&mut client, &mut server);
        give(&mut client, &flight);
        client.process_new_packets().unwrap();
        give(&mut server, &take_flight(&mut client));
        server.process_new_packets().unwrap();
        let alert = [21, 3, 3, 0, 2, level, ALERT_BAD_CERTIFICATE_HASH_VALUE];
        give(&mut client, &alert);
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::AlertReceived(AlertDescription::BadCertificateHashValue),
            "level {level}"
        );
    }
}
