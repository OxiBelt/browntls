// A KeyUpdate goes through the queue, where a failure to encrypt it is only
// noted (`encrypt_failed`) while the write key has already moved on.
// `WriteTraffic` takes no data and makes no `close_notify` after that:
// under the next key they would reach the peer with no KeyUpdate before
// them. The suites here have a confidentiality limit of a record or two,
// and an encrypter that fails for a KeyUpdate.

/// A TLS 1.3 AEAD whose encrypter fails for the 5 bytes of a KeyUpdate.
struct FailsKeyUpdates(&'static dyn browntls_core::crypto::cipher::Tls13AeadAlgorithm);

struct FailsKeyUpdatesEncrypter(Box<dyn browntls_core::crypto::cipher::MessageEncrypter>);

impl browntls_core::crypto::cipher::MessageEncrypter for FailsKeyUpdatesEncrypter {
    fn encrypt(
        &mut self,
        msg: browntls_core::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<browntls_core::crypto::cipher::OutboundOpaqueMessage, Error> {
        if msg.typ == browntls_core::ContentType::Handshake && msg.payload.len() == 5 {
            return Err(Error::EncryptError);
        }
        self.0.encrypt(msg, seq)
    }

    fn encrypt_into(
        &mut self,
        msg: browntls_core::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.0.encrypt_into(msg, seq, out)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        self.0.encrypted_payload_len(payload_len)
    }
}

impl browntls_core::crypto::cipher::Tls13AeadAlgorithm for FailsKeyUpdates {
    fn encrypter(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Box<dyn browntls_core::crypto::cipher::MessageEncrypter> {
        Box::new(FailsKeyUpdatesEncrypter(self.0.encrypter(key, iv)))
    }

    fn decrypter(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Box<dyn browntls_core::crypto::cipher::MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Result<
        browntls_core::ConnectionTrafficSecrets,
        browntls_core::crypto::cipher::UnsupportedOperationError,
    > {
        self.0.extract_keys(key, iv)
    }
}

/// A provider whose only suite refreshes its key after `limit` records and
/// cannot encrypt the KeyUpdate for it.
fn key_updates_fail(limit: u64) -> Arc<browntls_core::crypto::CryptoProvider> {
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls_core::Tls13CipherSuite =
        Box::leak(Box::new(browntls_core::Tls13CipherSuite {
            common: browntls_core::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: limit,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: Box::leak(Box::new(FailsKeyUpdates(orig.aead_alg))),
            quic: None,
        }));
    let mut p = prov::default_provider();
    p.cipher_suites = vec![browntls_core::SupportedCipherSuite::Tls13(suite)];
    Arc::new(p)
}

/// A server with that provider which sends its two tickets: they use the
/// first two records of its application key.
fn server_whose_key_updates_fail(chain: &Chain, limit: u64) -> Arc<ServerConfig> {
    let mut sc = ServerConfig::builder_with_provider(key_updates_fail(limit))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    sc.session_storage = browntls_core::server::ServerSessionMemoryCache::new(16);
    Arc::new(sc)
}

/// The length of a TLS 1.3 AES-GCM record of `plain` bytes.
const fn record_len(plain: usize) -> usize {
    5 + plain + 1 + 16
}

/// What `w` asks for to encrypt `data`.
fn size_needed<D: SideData>(
    w: &mut browntls_core::unbuffered::WriteTraffic<'_, D>,
    data: &[u8],
) -> usize {
    match w.encrypt(data, &mut []) {
        Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
            required_size
        }
        other => panic!("{other:?}"),
    }
}

/// Nothing is offered to send, and the connection reports the failure.
fn assert_finished<D: SideData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    w_closed: Result<usize, EncryptError>,
) {
    assert_eq!(w_closed, Err(EncryptError::Failed));
    assert_eq!(
        conn.process_tls_records(&mut []).state.err(),
        Some(Error::EncryptError)
    );
}

#[test]
fn no_data_follows_a_key_update_that_failed_to_encrypt() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    // The tickets reached the limit: a KeyUpdate is owed before the data.
    let sc = server_whose_key_updates_fail(&chain, 2);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);

    let Ok(ConnectionState::WriteTraffic(mut w)) = s.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let required = size_needed(&mut w, b"x");
    assert_eq!(required, record_len(5) + record_len(1));
    let mut buf = vec![0xa5u8; required + 7];
    assert_eq!(w.encrypt(b"x", &mut buf), Err(EncryptError::Failed));
    // No data was encrypted under the key that follows the lost KeyUpdate.
    assert!(buf.iter().all(|b| *b == 0xa5), "{buf:02x?}");
    assert_eq!(w.encrypt(b"y", &mut buf), Err(EncryptError::Failed));
    // Nor is an alert, however often it is asked for.
    assert_eq!(w.queue_close_notify(&mut buf), Err(EncryptError::Failed));
    let closed = w.queue_close_notify(&mut buf);
    assert!(buf.iter().all(|b| *b == 0xa5), "{buf:02x?}");
    assert_finished(&mut s.conn, closed);
}

#[test]
fn data_before_a_key_update_that_failed_to_encrypt_is_good() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    // The client's first record reaches the limit: a KeyUpdate follows it.
    let cc = Arc::new(
        ClientConfig::builder_with_provider(key_updates_fail(1))
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

    let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let required = size_needed(&mut w, b"x");
    assert_eq!(required, record_len(1) + record_len(5));
    let mut buf = vec![0xa5u8; required + 7];
    // The data went out under the old key and is reported; what the call
    // did not write is as it was.
    assert_eq!(w.encrypt(b"x", &mut buf), Ok(record_len(1)));
    assert!(buf[record_len(1)..].iter().all(|b| *b == 0xa5));
    s.give_input(&buf[..record_len(1)]);
    assert_eq!(s.error, None);
    assert_eq!(s.take_received(), b"x");

    let mut later = vec![0xa5u8; 64];
    assert_eq!(w.encrypt(b"y", &mut later), Err(EncryptError::Failed));
    let closed = w.queue_close_notify(&mut later);
    assert!(later.iter().all(|b| *b == 0xa5), "{later:02x?}");
    assert_finished(&mut c.conn, closed);
}
