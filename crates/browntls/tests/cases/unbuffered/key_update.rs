// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: KeyUpdate and the confidentiality limit.

#[test]
fn key_update_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));

    // The unbuffered side asks; the buffered peer answers.
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    for round in 0..3 {
        c.refresh_requested = true;
        c.run();
        exchange(&mut c, &mut s, format!("after refresh {round}").as_bytes());
    }

    // The buffered side asks; the unbuffered peer answers before its next
    // application data.
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        for round in 0..3 {
            c.conn.refresh_traffic_keys().unwrap();
            exchange(&mut c, &mut s, format!("round {round}").as_bytes());
        }
    }

    // Both unbuffered, both refreshing.
    let mut c = ub_client(&cc, Feed::ByteByByte);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    c.refresh_requested = true;
    s.refresh_requested = true;
    c.run();
    s.run();
    exchange(&mut c, &mut s, b"both rotated");
}

#[test]
fn refresh_is_refused_in_tls12() {
    init_logging();
    if !VERSIONS.contains(&ProtocolVersion::TLSv1_2) {
        return;
    }
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, VERSIONS[VERSIONS.len() - 1]));
    let sc = Arc::new(versioned_server(&chain, VERSIONS[VERSIONS.len() - 1]));
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    match c.conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::WriteTraffic(w)) => assert!(w.refresh_traffic_keys().is_err()),
        other => panic!("{other:?}"),
    }
}

/// TLS_AES_128_GCM_SHA256 with a confidentiality limit of `limit` records.
fn suite_with_limit(limit: u64) -> browntls::SupportedCipherSuite {
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls::Tls13CipherSuite =
        Box::leak(Box::new(browntls::Tls13CipherSuite {
            common: browntls::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: limit,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: orig.aead_alg,
            quic: orig.quic,
        }));
    browntls::SupportedCipherSuite::Tls13(suite)
}

fn limited_configs(limit: u64) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let chain = server_chain(KeyType::Ed25519);
    let mut p = prov::default_provider();
    p.cipher_suites = vec![suite_with_limit(limit)];
    let p = Arc::new(p);
    let cc = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let sc = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    (Arc::new(cc), Arc::new(sc))
}

#[test]
fn writes_past_the_confidentiality_limit_carry_their_key_updates() {
    init_logging();
    // RFC 9846 §5.5: the KeyUpdate goes into the caller's buffer with the
    // data, so a peer reading the bytes in order can follow the keys.
    let (cc, sc) = limited_configs(4);
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    let mut wire = Vec::new();
    let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let mut buf = vec![0u8; 1024];
    for i in 0..20u8 {
        let n = w.encrypt(&[i], &mut buf).unwrap();
        wire.extend_from_slice(&buf[..n]);
    }
    // One write of more records than the limit allows in one key.
    let mut big = vec![0u8; 200_000];
    let n = w.encrypt(&[9u8; 70_000], &mut big).unwrap();
    wire.extend_from_slice(&big[..n]);
    s.give_input(&wire);
    assert!(!s.failed(), "{:?}", s.error);
    let mut expected: Vec<u8> = (0..20u8).collect();
    expected.extend_from_slice(&[9u8; 70_000]);
    assert_eq!(s.take_received(), expected);
    exchange(&mut c, &mut s, b"still in step");

    // Both unbuffered, through the driver's one-write-per-state loop.
    let mut c = ub_client(&cc, Feed::ByteByByte);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    for i in 0..12u8 {
        exchange(&mut c, &mut s, &[i; 3]);
    }
}

#[test]
fn half_rtt_data_at_the_limit_is_refused_not_misordered() {
    init_logging();
    // A server cannot send a KeyUpdate before the client's Finished: once
    // its half-RTT key is spent, writes fail and nothing is consumed.
    let (cc, sc) = limited_configs(4);
    let mut sc = (*sc).clone();
    sc.send_half_rtt_data = true;
    let sc = Arc::new(sc);
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    let hello = c.take_output();
    s.give_input(&hello);
    assert!(s.writable && s.conn.is_handshaking());
    let Ok(ConnectionState::WriteTraffic(mut w)) = s.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let mut wire = Vec::new();
    let mut taken = Vec::new();
    for i in 0..8u8 {
        // The size asked for is exactly one record: no KeyUpdate can be
        // sent before the handshake completes, so none is counted.
        let required = match w.encrypt(&[i], &mut []) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            // The key is spent; this is temporary, not fatal.
            Err(EncryptError::KeyUpdateAwaitsHandshake) => continue,
            other => panic!("{other:?}"),
        };
        let mut buf = vec![0u8; required];
        assert_eq!(w.encrypt(&[i], &mut buf), Ok(required));
        wire.extend_from_slice(&buf);
        taken.push(i);
    }
    assert!(!taken.is_empty() && taken.len() < 8, "{taken:?}");
    s.outgoing.extend_from_slice(&wire);
    handshake(&mut c, &mut s);
    assert_eq!(c.take_received(), taken);
    exchange(&mut c, &mut s, b"after the refresh");
}

/// A TLS 1.3 AEAD that understates the record length of a KeyUpdate (a
/// 5-byte plaintext) by one byte, standing in for a provider whose
/// `encrypted_payload_len` is wrong.
struct UnderstatesKeyUpdates(&'static dyn browntls::crypto::cipher::Tls13AeadAlgorithm);

struct UnderstatingEncrypter(Box<dyn browntls::crypto::cipher::MessageEncrypter>);

impl browntls::crypto::cipher::MessageEncrypter for UnderstatingEncrypter {
    fn encrypt(
        &mut self,
        msg: browntls::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<browntls::crypto::cipher::OutboundOpaqueMessage, Error> {
        self.0.encrypt(msg, seq)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        let real = self.0.encrypted_payload_len(payload_len);
        if payload_len == 5 { real - 1 } else { real }
    }
}

impl browntls::crypto::cipher::Tls13AeadAlgorithm for UnderstatesKeyUpdates {
    fn encrypter(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Box<dyn browntls::crypto::cipher::MessageEncrypter> {
        Box::new(UnderstatingEncrypter(self.0.encrypter(key, iv)))
    }

    fn decrypter(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Box<dyn browntls::crypto::cipher::MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Result<
        browntls::ConnectionTrafficSecrets,
        browntls::crypto::cipher::UnsupportedOperationError,
    > {
        self.0.extract_keys(key, iv)
    }
}

#[test]
fn trailing_key_update_that_does_not_fit_stays_queued() {
    init_logging();
    // The data records are sequenced and written; the KeyUpdate that
    // follows them must not be lost when it turns out longer than promised.
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls::Tls13CipherSuite =
        Box::leak(Box::new(browntls::Tls13CipherSuite {
            common: browntls::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: 4,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: Box::leak(Box::new(UnderstatesKeyUpdates(orig.aead_alg))),
            quic: None,
        }));
    let chain = server_chain(KeyType::Ed25519);
    let mut p = prov::default_provider();
    p.cipher_suites = vec![browntls::SupportedCipherSuite::Tls13(suite)];
    let cc = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth(),
    );
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);

    let mut wire = Vec::new();
    let mut queued_after = None;
    let mut i = 0u8;
    while i < 6 {
        let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state
        else {
            // The KeyUpdate left behind is offered first.
            let mut buf = vec![0u8; 256];
            match c.conn.process_tls_records(&mut []).state {
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    let n = e.encode(&mut buf).unwrap();
                    wire.extend_from_slice(&buf[..n]);
                }
                other => panic!("{other:?}"),
            }
            match c.conn.process_tls_records(&mut []).state {
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                other => panic!("{other:?}"),
            }
            continue;
        };
        let required = match w.encrypt(&[i], &mut []) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            other => panic!("{other:?}"),
        };
        let mut buf = vec![0u8; required];
        let n = w.encrypt(&[i], &mut buf).unwrap();
        if n < required {
            queued_after.get_or_insert(i);
        }
        wire.extend_from_slice(&buf[..n]);
        i += 1;
    }
    assert!(queued_after.is_some(), "the KeyUpdate did not fit once");
    s.give_input(&wire);
    assert!(!s.failed(), "{:?}", s.error);
    assert_eq!(s.take_received(), (0..6u8).collect::<Vec<_>>());
    exchange(&mut c, &mut s, b"still in step");
}
