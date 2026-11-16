// Interoperability with rustls's QUIC API.
//
// Included by `cases/quic.rs`, which holds the imports and the handshake
// plumbing.

fn r_certs(chain: &Chain) -> Vec<rustls_pki_types::CertificateDer<'static>> {
    chain
        .cert_chain()
        .iter()
        .map(|c| rustls_pki_types::CertificateDer::from(c.as_ref().to_vec()))
        .collect()
}

fn r_client_config(chain: &Chain) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            chain.ca.as_ref().to_vec(),
        ))
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = true;
    Arc::new(config)
}

fn r_server_config(chain: &Chain) -> Arc<rustls::ServerConfig> {
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        chain.end_entity_key.clone(),
    ));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(r_certs(chain), key)
    .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = u32::MAX;
    Arc::new(config)
}

fn r_client(config: &Arc<rustls::ClientConfig>) -> Peer {
    Peer::new(rq::Connection::Client(
        rq::ClientConnection::new(
            config.clone(),
            rq::Version::V1,
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            CLIENT_PARAMS.to_vec(),
        )
        .unwrap(),
    ))
}

fn r_server(config: &Arc<rustls::ServerConfig>) -> Peer {
    Peer::new(rq::Connection::Server(
        rq::ServerConnection::new(config.clone(), rq::Version::V1, SERVER_PARAMS.to_vec()).unwrap(),
    ))
}

#[test]
fn initial_keys_match_rustls() {
    let ours = quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let theirs = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|s| s.quic_suite())
        .unwrap();
    for dcid in [&hex(DCID)[..], &[], &[0xab; 20]] {
        let b: LevelKeys = ours.keys(dcid, bq::Side::Client, bq::Version::V1).into();
        let r: LevelKeys = theirs
            .keys(dcid, rustls::Side::Server, rq::Version::V1)
            .into();
        assert_dirs_match(&b.local, &r.remote, "Initial");
        assert_dirs_match(&r.local, &b.remote, "Initial");
    }
}

/// Packet and header protection agree with rustls for the 32-byte-key
/// algorithms, and ChaCha20 header protection handles every block counter
/// (a peer chooses the sample, RFC 9001 §5.4.4).
#[test]
fn header_and_packet_keys_match_rustls_from_one_key() {
    let ring = rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
    let pairs = [
        (&prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, ring),
        (
            &prov::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ),
    ];
    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    for (ours, theirs) in pairs {
        let b = quic_suite(ours).quic;
        let r = theirs.tls13().and_then(|s| s.quic_suite()).unwrap().quic;
        let b = Dir {
            packet: Box::new(b.packet_key(
                browntls::crypto::cipher::AeadKey::new(&key),
                browntls::crypto::cipher::Iv::new(iv),
            )),
            header: Box::new(b.header_protection_key(browntls::crypto::cipher::AeadKey::new(&key))),
        };
        let r = Dir {
            packet: Box::new(r.packet_key(
                rustls::crypto::cipher::AeadKey::from(key),
                rustls::crypto::cipher::Iv::new(iv),
            )),
            header: Box::new(r.header_protection_key(rustls::crypto::cipher::AeadKey::from(key))),
        };
        assert_dirs_match(&b, &r, "one key");
        assert_dirs_match(&r, &b, "one key");
        for counter in [[0; 4], [1, 0, 0, 0], [0x78, 0x56, 0x34, 0x12]] {
            let mut sample = [0x33u8; 16];
            sample[..4].copy_from_slice(&counter);
            assert_eq!(
                b.header.protect(&sample),
                r.header.protect(&sample),
                "{:?}",
                ours.suite()
            );
        }
    }

    // The ChaCha20 block counters at the top of the range, which a peer can
    // choose. ring's portable ChaCha20 (used by rustls on riscv64) overflows
    // on them in debug builds, so the expected values come from an RFC 8439
    // block function computed outside browntls, not from rustls.
    let chacha = quic_suite(&prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256).quic;
    let hp = chacha.header_protection_key(browntls::crypto::cipher::AeadKey::new(&key));
    for (counter, expected) in [
        ([0xff; 4], (0x56, [126, 206, 17, 35])),
        ([0xfe, 0xff, 0xff, 0xff], (0x44, [62, 150, 222, 234])),
    ] {
        let mut sample = [0x33u8; 16];
        sample[..4].copy_from_slice(&counter);
        assert_eq!(hp.protect(&sample), expected);
    }
}

#[test]
fn browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = b_client_config(&chain);
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    let server_config = r_server_config(&chain);

    let mut client = b_client(&client_config);
    let mut server = r_server(&server_config);
    handshake(&mut client, &mut server).unwrap();
    assert_full_handshake(&mut client, &mut server);

    // Resumption with 0-RTT.
    let mut client = b_client(&client_config);
    let client_early = client.conn.zero_rtt().expect("rustls ticket allows 0-RTT");
    let mut server = r_server(&server_config);
    pump(&mut client, &mut server).unwrap();
    let server_early = server.conn.zero_rtt().expect("rustls accepted 0-RTT");
    assert_dirs_match(&client_early, &server_early, "0-RTT");
    handshake(&mut client, &mut server).unwrap();
    assert!(client.conn.resumed() && server.conn.resumed());
    assert!(client.conn.early_accepted());
    assert_full_handshake(&mut client, &mut server);
}

#[test]
fn rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = r_client_config(&chain);
    let mut server_config = b_server_config(&chain);
    server_config.max_early_data_size = u32::MAX;
    let server_config = Arc::new(server_config);

    let mut client = r_client(&client_config);
    let mut server = b_server(&server_config);
    handshake(&mut client, &mut server).unwrap();
    assert_full_handshake(&mut client, &mut server);

    // Resumption with 0-RTT.
    let mut client = r_client(&client_config);
    let client_early = client
        .conn
        .zero_rtt()
        .expect("browntls ticket allows 0-RTT");
    let mut server = b_server(&server_config);
    pump(&mut client, &mut server).unwrap();
    let server_early = server.conn.zero_rtt().expect("browntls accepted 0-RTT");
    assert_dirs_match(&client_early, &server_early, "0-RTT");
    handshake(&mut client, &mut server).unwrap();
    assert!(client.conn.resumed() && server.conn.resumed());
    assert!(client.conn.early_accepted());
    assert_full_handshake(&mut client, &mut server);
}

#[test]
fn rustls_server_alpn_mismatch_alert() {
    // rustls applies the same RFC 9001 §8.1 rule to a browntls client.
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = b_client(&Arc::new(b_client_config(&chain)));
    let mut config = Arc::unwrap_or_clone(r_server_config(&chain));
    config.alpn_protocols = vec![b"other".to_vec()];
    let mut server = r_server(&Arc::new(config));
    assert!(matches!(
        handshake(&mut client, &mut server),
        Err(Failed::Server(_))
    ));
    assert_eq!(
        server.conn.alert(),
        Some(u8::from(AlertDescription::NoApplicationProtocol))
    );
}
