//! Split mode: the back-end server behind the client-facing server, and
//! trial decryption in both modes.

use super::*;

/// The offset of the body of the first `inner` ECH extension (type,
/// length 1, value 1) in `buf`.
fn inner_extension_offset(buf: &[u8]) -> usize {
    buf.windows(5)
        .position(|w| w == [0xfe, 0x0d, 0, 1, 1])
        .expect("an inner ECH extension")
}

#[test]
fn backend_checks_the_forwarded_hellos() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // The second inner ClientHello loses its `inner` extension, or gets
    // one of another type.
    for (value, expected) in [
        (
            None,
            browntls::PeerMisbehaved::MissingEchExtensionInSecondClientHello,
        ),
        (
            Some(5u8),
            browntls::PeerMisbehaved::IllegalEchClientHelloType,
        ),
    ] {
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(ech.ech_config_list())),
            &ech,
            backend_config(&certs, Some(&[prov::kx_group::SECP256R1])),
        );
        let mut batches = 0;
        split.edit_forwarded = Some(Box::new(move |buf: &mut Vec<u8>| {
            batches += 1;
            if batches == 2 {
                let at = inner_extension_offset(buf);
                match value {
                    None => buf[at + 1] = 0x0e,
                    Some(v) => buf[at + 4] = v,
                }
            }
        }));
        split.pump();
        assert_eq!(
            split.errors.server,
            Some(Error::PeerMisbehaved(expected.clone())),
            "{:?}",
            split.errors
        );
        assert!(split.errors.client.is_some());
    }

    // An inner ClientHello offering TLS 1.2 (supported_versions rewritten
    // in place: TLS 1.3 becomes TLS 1.2).
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend_config(&certs, None),
    );
    split.edit_forwarded = Some(Box::new(|buf: &mut Vec<u8>| {
        if let Some(at) = buf.windows(7).position(|w| w == [0, 43, 0, 3, 2, 3, 4]) {
            buf[at + 6] = 3;
        }
    }));
    split.pump();
    assert_eq!(
        split.errors.server,
        Some(Error::PeerMisbehaved(
            browntls::PeerMisbehaved::IllegalEchInnerClientHello
        ))
    );
}

#[test]
fn backend_refuses_outer_extensions() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    // A client reaching the back-end server directly with ECH or GREASE.
    for mode in [enable(ech.ech_config_list()), Some(EchMode::Grease(grease))] {
        let (mut client, mut server) =
            connect(client_config(&certs, mode), backend_config(&certs, None));
        let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_res,
            Err(Error::PeerMisbehaved(
                browntls::PeerMisbehaved::IllegalEchClientHelloType
            ))
        );
    }
    // Without ECH, the back-end server is an ordinary server.
    let (mut client, mut server) =
        connect(client_config(&certs, None), backend_config(&certs, None));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.ech_status(), EchStatus::NotOffered);
    assert_eq!(client.ech_status(), EchStatus::NotOffered);
}

#[test]
fn backend_and_shared_mode_exclude_each_other() {
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut config = server_config(&certs, Some(&ech), None);
    config.ech_backend = true;
    let config = Arc::new(config);
    assert!(ServerConnection::new(config.clone()).is_err());
    // Also through the acceptor.
    let client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    );
    let mut client = client.unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    let flight = drain(&mut client);
    acceptor.read_tls(&mut &flight[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(accepted.into_connection(config).is_err());
}

#[test]
fn backend_through_the_acceptor() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let mut front = ClientFacing::new(ech);
    front.read_client(&drain(&mut client)).unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    acceptor
        .read_tls(&mut &front.take_for_backend()[..])
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert_eq!(accepted.client_hello().server_name(), Some(SECRET));
    let mut backend = accepted
        .into_connection(Arc::new(backend_config(&certs, None)))
        .unwrap();
    assert_eq!(backend.ech_status(), EchStatus::Accepted);
    front.read_backend(&drain(&mut backend)).unwrap();
    assert!(front.is_relaying());
    feed(&mut client, &front.take_for_client());
    client.process_new_packets().unwrap();
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    do_handshake(&mut client, &mut backend).unwrap();
    assert_eq!(send_and_receive(&mut client, &mut backend, b"y"), b"y");
}

#[test]
fn backend_alert_reaches_the_client() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // A back-end server without the hidden name's certificate.
    let mut backend = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()));
    backend.ech_backend = true;
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend,
    );
    split.pump();
    assert!(split.errors.server.is_some());
    assert!(
        matches!(split.errors.client, Some(Error::AlertReceived(_))),
        "{:?}",
        split.errors
    );
    assert!(split.front().is_relaying());
}

#[test]
fn trial_decryption_with_random_config_ids() {
    init_logging();
    let certs = Certs::new();
    let key = server_key(7);
    let ech = Arc::new(
        EchServerConfig::new(vec![server_key(1), key.clone()])
            .unwrap()
            .with_trial_decryption()
            .with_public_name_check(),
    );
    assert!(ech.trial_decryption() && ech.public_name_check());
    let one = EchServerConfig::new(vec![key]).unwrap();
    let config = EchConfig::new(one.ech_config_list(), ALL_SUPPORTED_SUITES)
        .unwrap()
        .with_random_config_id();
    assert!(config.random_config_id());
    let mut ids = Vec::new();
    for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
        for _ in 0..4 {
            // Shared mode.
            let (mut client, mut server) = connect(
                client_config(&certs, Some(EchMode::Enable(config.clone()))),
                server_config(&certs, Some(&ech), groups),
            );
            let flight = drain(&mut client);
            ids.push(flight[ech_extension_offset(&flight) + 5]);
            feed(&mut server, &flight);
            server.process_new_packets().unwrap();
            assert_accepted(&mut client, &mut server);

            // Split mode.
            let mut split = Split::new(
                &certs,
                client_config(&certs, Some(EchMode::Enable(config.clone()))),
                &ech,
                backend_config(&certs, groups),
            );
            split.pump();
            split.assert_forwarded();
        }
    }
    // The identifiers sent are random (eight equal to 7 by chance:
    // probability 2^-64).
    assert!(ids.iter().any(|id| *id != 7), "{ids:?}");
}

#[cfg(feature = "rustcrypto")]
#[test]
fn backend_on_the_rustcrypto_provider() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // The back-end server needs no HPKE: only HKDF for the confirmations.
    let provider = Arc::new(browntls::crypto::rustcrypto::default_provider());
    let resolver = {
        let mut resolver = ResolvesServerCertUsingSni::new();
        resolver
            .add(
                SECRET,
                CertifiedKey::from_der(
                    certs.secret.cert_chain(),
                    certs.secret.private_key(),
                    &provider,
                )
                .unwrap(),
            )
            .unwrap();
        Arc::new(resolver)
    };
    for groups in [false, true] {
        let mut prov = (*provider).clone();
        if groups {
            prov.kx_groups = vec![browntls::crypto::rustcrypto::kx_group::SECP256R1];
        }
        let mut backend = ServerConfig::builder_with_provider(Arc::new(prov))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        backend.alpn_protocols = vec![b"h2".to_vec()];
        backend.ech_backend = true;
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(ech.ech_config_list())),
            &ech,
            backend,
        );
        split.pump();
        split.assert_forwarded();
    }
}
