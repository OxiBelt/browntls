// Cases included by `cases/interop.rs`, which holds the imports, the
// plumbing and the configurations: the suite, group and key matrix, version
// choice, HelloRetryRequest, resumption, client authentication and
// certificate errors.

// ----------------------------------------------------------------- matrix

#[test]
fn browntls_client_to_rustls_server_every_suite_group_and_key() {
    init_logging();
    for (version, suite, keys) in suite_matrix() {
        for &key_type in keys {
            let chain = server_chain(key_type);
            for &group in COMMON_GROUPS {
                let mut client =
                    b_connect_client(b_client(&chain, version, Some(suite), Some(group)));
                let mut server =
                    rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None)))
                        .unwrap();
                let (c, s) = handshake(&mut client, &mut server);
                assert_eq!(
                    c,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(
                    s,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(client.version(), Some(version));
                assert_eq!(client.suite(), Some(suite));
                assert_eq!(server.suite(), Some(suite));
                assert_eq!(
                    client.negotiated_key_exchange_group().unwrap().name(),
                    browntls::NamedGroup::from(group)
                );
                assert_eq!(
                    client.peer_certs().unwrap(),
                    chain
                        .cert_chain()
                        .iter()
                        .map(|c| c.as_ref().to_vec())
                        .collect::<Vec<_>>()
                );
                round_trip(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn rustls_client_to_browntls_server_every_suite_group_and_key() {
    init_logging();
    let mut rsa_handshakes = 0;
    for (version, suite, keys) in suite_matrix() {
        // Only key types the provider under test can sign with (RustCrypto
        // does not sign with RSA keys, so its ECDHE_RSA suites are skipped).
        for &key_type in keys.iter().filter(|k| KeyType::SIGNING.contains(k)) {
            let chain = server_chain(key_type);
            for &group in COMMON_GROUPS {
                // The server exchanges keys over `group` only; the client
                // also lists the certificate's curve where RFC 8422 §5.3
                // requires it.
                let client_config = rustls::ClientConfig::builder_with_provider(
                    r_provider_with_groups(Some(suite), &client_groups(group, version, key_type)),
                )
                .with_protocol_versions(r_versions(version))
                .unwrap()
                .with_root_certificates(r_roots(&chain))
                .with_no_client_auth();
                let mut client = r_connect_client(client_config);
                let mut server = browntls::ServerConnection::new(Arc::new(b_server(
                    &chain,
                    version,
                    None,
                    Some(group),
                )))
                .unwrap();
                let (c, s) = handshake(&mut client, &mut server);
                assert_eq!(
                    c,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(
                    s,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(server.version(), Some(version));
                assert_eq!(server.suite(), Some(suite));
                assert_eq!(
                    server.negotiated_key_exchange_group().unwrap().name(),
                    browntls::NamedGroup::from(group)
                );
                assert_eq!(server.server_name(), Some("localhost"));
                round_trip(&mut client, &mut server);
                if key_type == KeyType::Rsa2048 {
                    rsa_handshakes += 1;
                }
            }
        }
    }
    // RSA: 3 TLS 1.3 suites and 3 ECDHE_RSA suites, 3 groups each.
    let rsa_suites = if cfg!(feature = "tls12") { 6 } else { 3 };
    assert_eq!(
        rsa_handshakes,
        if prov::SIGNS_RSA { 3 * rsa_suites } else { 0 }
    );
}

// --------------------------------------------------------- version choice

#[test]
fn default_configs_pick_tls13_and_post_quantum_free_group() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    let mut client = b_connect_client(b_client(&chain, 0, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.version(), Some(0x0304));
    // browntls offered X25519MLKEM768 first; ring does not know it, so the
    // handshake continues on the X25519 share also sent (no HelloRetryRequest).
    assert_eq!(client.handshake_kind(), Some(browntls::HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        browntls::NamedGroup::X25519
    );

    let mut client = r_connect_client(r_client(&chain, 0, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(server.version(), Some(0x0304));
    assert_eq!(server.handshake_kind(), Some(browntls::HandshakeKind::Full));
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_only_client_accepts_downgrade_sentinel_from_dual_version_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // rustls server (both versions) writes the TLS 1.2 sentinel into
    // ServerHello.random; a client that never offered 1.3 must accept it.
    let mut client = b_connect_client(b_client(&chain, 0x0303, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.version(), Some(0x0303));

    // and the browntls server does the same for a TLS 1.2-only rustls client
    let mut client = r_connect_client(r_client(&chain, 0x0303, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(server.version(), Some(0x0303));
    round_trip(&mut client, &mut server);
}

#[cfg(feature = "tls12")]
#[test]
fn version_mismatch_is_a_protocol_version_alert() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = b_connect_client(b_client(&chain, 0x0303, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    let (c, s) = handshake(&mut client, &mut server);
    assert!(s.is_err());
    assert_eq!(
        c,
        Err(format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::ProtocolVersion)
        ))
    );

    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0x0303, None, None))).unwrap();
    let (c, s) = handshake(&mut client, &mut server);
    assert_eq!(
        s,
        Err(format!(
            "{:?}",
            browntls::Error::from(browntls::PeerIncompatible::Tls12NotOfferedOrEnabled)
        ))
    );
    assert_eq!(
        c,
        Err(format!(
            "{:?}",
            rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)
        ))
    );
}

// ------------------------------------------------------- hello retry request

#[test]
fn hello_retry_request_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    // browntls client shares X25519 (its first group) but the rustls server
    // only accepts P-256, which the client also supports.
    let client_provider = {
        let mut p = prov::default_provider();
        p.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
        Arc::new(p)
    };
    let client_config = browntls::ClientConfig::builder_with_provider(client_provider)
        .with_protocol_versions(&[&browntls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut client = b_connect_client(client_config);
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, Some(0x0017))))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(browntls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
    );
    round_trip(&mut client, &mut server);

    // rustls client shares X25519; browntls server only accepts P-256.
    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0x0304, None, Some(0x0017))))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(browntls::HandshakeKind::FullWithHelloRetryRequest)
    );
    round_trip(&mut client, &mut server);
}

// ---------------------------------------------------------------- resumption

#[test]
fn resumption_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        for tickets in [false, true] {
            let client_config = Arc::new(b_client(&chain, version, None, None));
            let mut server_config = r_server(&chain, version, None, None);
            if tickets {
                server_config.ticketer = ring_provider::Ticketer::new().unwrap();
                server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            }
            let server_config = Arc::new(server_config);

            let mut client =
                browntls::ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(!client.resumed());
            // TLS 1.3 tickets arrive after the handshake
            transfer(&mut server, &mut client);
            client.process().unwrap();

            let mut client = browntls::ClientConnection::new(client_config, server_name()).unwrap();
            let mut server = rustls::ServerConnection::new(server_config).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(
                client.resumed(),
                "{version:#06x} tickets={tickets}: client not resumed"
            );
            assert!(
                server.resumed(),
                "{version:#06x} tickets={tickets}: server not resumed"
            );
            assert_eq!(client.version(), Some(version));
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn resumption_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        for tickets in [false, true] {
            let client_config = Arc::new(r_client(&chain, version, None, None));
            let mut server_config = b_server(&chain, version, None, None);
            if tickets {
                server_config.ticketer = prov::Ticketer::new().unwrap();
                server_config.session_storage =
                    Arc::new(browntls::server::NoServerSessionStorage {});
            }
            let server_config = Arc::new(server_config);

            let mut client = r_connect_client_from(client_config.clone());
            let mut server = browntls::ServerConnection::new(server_config.clone()).unwrap();
            handshake_ok(&mut client, &mut server);
            transfer(&mut server, &mut client);
            client.process().unwrap();

            let mut client = r_connect_client_from(client_config);
            let mut server = browntls::ServerConnection::new(server_config).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(
                client.resumed(),
                "{version:#06x} tickets={tickets}: client not resumed"
            );
            assert!(
                server.resumed(),
                "{version:#06x} tickets={tickets}: server not resumed"
            );
            round_trip(&mut client, &mut server);
        }
    }
}

fn r_connect_client_from(config: Arc<rustls::ClientConfig>) -> rustls::ClientConnection {
    rustls::ClientConnection::new(config, rpki::ServerName::try_from("localhost").unwrap()).unwrap()
}

// --------------------------------------------------------------- client auth

#[test]
fn client_auth_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        for &key_type in KeyType::SIGNING {
            let client_chain = client_chain(key_type);
            let mut client = b_connect_client(b_client_with_auth(&chain, &client_chain, version));
            let mut server = rustls::ServerConnection::new(Arc::new(r_server_with_client_auth(
                &chain,
                &client_chain,
                version,
            )))
            .unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(
                server.peer_certs().unwrap(),
                client_chain
                    .cert_chain()
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn client_auth_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        for key_type in KeyType::ALL {
            let client_chain = client_chain(key_type);
            let mut client = r_connect_client(r_client_with_auth(&chain, &client_chain, version));
            let mut server = browntls::ServerConnection::new(Arc::new(b_server_with_client_auth(
                &chain,
                &client_chain,
                version,
            )))
            .unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(
                server.peer_certs().unwrap(),
                client_chain
                    .cert_chain()
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn missing_client_certificate_is_rejected_by_both() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    for version in VERSIONS {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server = rustls::ServerConnection::new(Arc::new(r_server_with_client_auth(
            &chain,
            &client_chain,
            version,
        )))
        .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            s,
            Err(format!("{:?}", rustls::Error::NoCertificatesPresented))
        );
        assert!(c.is_err());

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server = browntls::ServerConnection::new(Arc::new(b_server_with_client_auth(
            &chain,
            &client_chain,
            version,
        )))
        .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            s,
            Err(format!("{:?}", browntls::Error::NoCertificatesPresented))
        );
        // certificate_required is TLS 1.3 only (RFC 8446 §6.2); TLS 1.2
        // answers a missing mandatory certificate with handshake_failure
        // (RFC 5246 §7.4.6).
        let expected = if version == 0x0304 {
            rustls::AlertDescription::CertificateRequired
        } else {
            rustls::AlertDescription::HandshakeFailure
        };
        assert_eq!(
            c,
            Err(format!("{:?}", rustls::Error::AlertReceived(expected)))
        );
    }
}

// -------------------------------------------------------- certificate errors

#[test]
fn rustls_rejects_browntls_server_with_unknown_root() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        let mut client = r_connect_client(r_client(&other, version, None, None));
        let mut server =
            browntls::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        // Both test CAs carry the same subject name, so webpki may try the
        // wrong root and report a bad signature instead of an unknown issuer.
        let unknown = format!(
            "{:?}",
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
        let bad_sig = format!(
            "{:?}",
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        );
        assert!(c == Err(unknown) || c == Err(bad_sig), "{c:?}");
        // ...with the matching alert (unknown_ca or decrypt_error) on our side.
        let unknown_ca = format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::UnknownCA)
        );
        let decrypt_error = format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::DecryptError)
        );
        assert!(s == Err(unknown_ca) || s == Err(decrypt_error), "{s:?}");
    }
}

#[test]
fn browntls_rejects_unexpected_rustls_server_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for version in VERSIONS {
        let mut client = b_connect_client(b_client(&other, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            c,
            Err(format!(
                "{:?}",
                browntls::Error::from(browntls::CertificateError::UnknownIssuer)
            ))
        );
        assert_eq!(
            s,
            Err(format!(
                "{:?}",
                rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA)
            ))
        );
    }
}
