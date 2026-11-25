// Cases included by `cases/rsa_pkcs1_legacy.rs` with the `tls12` feature,
// which holds the imports and the shared helpers: an opted-in server in
// TLS 1.2, where the legacy schemes do not exist (RFC 9963 §3).

static TLS12: [&SupportedProtocolVersion; 1] = [&version::TLS12];

/// The `supported_signature_algorithms` of the TLS 1.2 CertificateRequest
/// in `flight`, the server's first flight (unprotected handshake records).
fn tls12_request_schemes(flight: &[u8]) -> Vec<u16> {
    let mut messages = Vec::new();
    let mut at = 0;
    while at < flight.len() {
        assert_eq!(flight[at], 22, "a handshake record");
        let len = usize::from(u16::from_be_bytes([flight[at + 3], flight[at + 4]]));
        messages.extend_from_slice(&flight[at + 5..at + 5 + len]);
        at += 5 + len;
    }
    let messages = common::grease_wire::handshake_messages(&messages);
    let (_, request) = messages
        .iter()
        .find(|(typ, _)| *typ == 13)
        .expect("a CertificateRequest");
    // certificate_types<1..2^8-1>, supported_signature_algorithms<2..2^16-2>
    let schemes = &request[1 + usize::from(request[0])..];
    let len = usize::from(u16::from_be_bytes([schemes[0], schemes[1]]));
    common::grease_wire::signature_schemes(&schemes[..2 + len])
}

/// A TLS 1.2 handshake of a default client presenting `chain` with `key`
/// against a server requiring client authentication whose verifier and
/// configuration are built with `server_provider`. Returns the schemes of
/// the CertificateRequest as sent, and the outcome.
fn authenticate_tls12(
    server_provider: CryptoProvider,
    chain: &Chain,
    key: Arc<dyn SigningKey>,
) -> (Vec<u16>, Outcome) {
    let verifier = client_verifier(server_provider.clone(), chain, true);
    let resolver = Recording::new(Some(CertifiedKey::new(chain.cert_chain(), key)));
    let mut client = ClientConnection::new(
        Arc::new(client_config_for(
            prov::provider(),
            &TLS12,
            resolver.clone(),
        )),
        common::server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config_for(
        server_provider,
        &TLS12,
        verifier.clone(),
    )))
    .unwrap();
    let hello = common::hello_wire::take_flight(&mut client);
    common::hello_wire::give(&mut server, &hello);
    server.process_new_packets().unwrap();
    let flight = common::hello_wire::take_flight(&mut server);
    let request = tls12_request_schemes(&flight);
    common::hello_wire::give(&mut client, &flight);
    client.process_new_packets().unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    let outcome = Outcome {
        client,
        server,
        client_res,
        server_res,
        verifier,
        resolver,
    };
    (request, outcome)
}

/// An opted-in server's TLS 1.2 CertificateRequest is that of a default
/// server, with no legacy scheme, and client authentication with a key of
/// the provider's key loader works as without the opt-in: an RSA key
/// signs with `rsa_pss_rsae_sha512` (native provider), an ECDSA key with
/// `ecdsa_secp256r1_sha256` (RustCrypto provider, which cannot sign with
/// RSA).
#[test]
fn tls12_certificate_request_lists_no_legacy_scheme() {
    let (chain, expected) = if prov::SIGNS_RSA {
        (rsa_client().clone(), S::RSA_PSS_SHA512)
    } else {
        (
            common::client_chain(KeyType::EcdsaP256),
            S::ECDSA_NISTP256_SHA256,
        )
    };
    let key = prov::provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let (default_request, mut default) = authenticate_tls12(prov::provider(), &chain, key.clone());
    default.completed();
    let (request, mut opt_in) =
        authenticate_tls12(prov::provider_with_rsa_pkcs1_legacy(), &chain, key);
    opt_in.completed();
    assert_eq!(request, default_request);
    assert!(
        request
            .iter()
            .all(|s| !matches!(s, 0x0420 | 0x0520 | 0x0620)),
        "{request:x?}"
    );
    let resolved: Vec<u16> = opt_in.resolver.seen()[0]
        .iter()
        .map(|s| u16::from(*s))
        .collect();
    assert_eq!(resolved, request);
    assert_eq!(
        opt_in.client.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
    assert_eq!(opt_in.verifier.seen(), [expected]);
    assert_eq!(default.verifier.seen(), [expected]);
}

/// The token key in TLS 1.2 against an opted-in server: it is offered no
/// legacy scheme and signs with `rsa_pkcs1_sha256`, which TLS 1.2 allows.
#[test]
fn tls12_token_key_signs_with_rsa_pkcs1() {
    let key = TokenKey::choosing(
        rsa_client(),
        &[S::RSA_PKCS1_SHA256_LEGACY, S::RSA_PKCS1_SHA256],
        Sig::Pkcs1,
    );
    let (request, mut outcome) = authenticate_tls12(
        prov::provider_with_rsa_pkcs1_legacy(),
        rsa_client(),
        key.clone(),
    );
    outcome.completed();
    assert!(request.contains(&0x0401));
    assert_eq!(outcome.verifier.seen(), [S::RSA_PKCS1_SHA256]);
    assert_eq!(key.offered().len(), 1);
    assert!(key.offered()[0].iter().all(|s| !is_legacy(s)));
}
