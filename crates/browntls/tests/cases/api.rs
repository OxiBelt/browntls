// Shared cases, included by `tests/api.rs` (RustCrypto provider) and
// `tests/api_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use browntls::ConnectionTrafficSecrets;
use browntls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use browntls::compress::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
};
use browntls::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls::server::Acceptor;
use browntls::{
    CertificateCompressionAlgorithm, ClientConfig, ClientConnection, Connection,
    DigitallySignedStruct, Error, KeyLog, ServerConfig, ServerConnection, SignatureScheme, Stream,
    StreamOwned, version,
};
use common::*;

// ---------------------------------------------------------------- Acceptor

#[test]
fn acceptor_reads_the_client_hello_before_a_config_is_chosen() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();

    let mut acceptor = Acceptor::default();
    assert!(acceptor.accept().unwrap().is_none(), "nothing read yet");
    let mut hello_bytes = Vec::new();
    client.write_tls(&mut hello_bytes).unwrap();
    acceptor.read_tls(&mut &hello_bytes[..]).unwrap();
    let accepted = acceptor.accept().unwrap().expect("ClientHello complete");

    let hello = accepted.client_hello();
    assert_eq!(hello.server_name(), Some("localhost"));
    assert_eq!(hello.alpn().unwrap().collect::<Vec<_>>(), [&b"h2"[..]]);
    assert!(
        hello
            .cipher_suites()
            .contains(&browntls::CipherSuite::TLS13_AES_128_GCM_SHA256)
    );
    assert!(!hello.signature_schemes().is_empty());

    let mut server_config = server_config(&chain);
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let mut server = accepted
        .into_connection(Arc::new(server_config))
        .map_err(|(e, _)| e)
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.server_name(), Some("localhost"));
    assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"accepted"),
        b"accepted"
    );
}

#[test]
fn acceptor_rejects_garbage_with_an_alert() {
    init_logging();
    let mut acceptor = Acceptor::default();
    // a well-formed handshake message (ServerHelloDone) that is not a ClientHello
    acceptor
        .read_tls(&mut &[0x16u8, 3, 1, 0, 4, 0x0e, 0, 0, 0][..])
        .unwrap();
    let (err, mut alert) = acceptor.accept().unwrap_err();
    assert!(
        matches!(err, Error::InappropriateHandshakeMessage { .. }),
        "{err:?}"
    );
    let mut out = Vec::new();
    alert.write_all(&mut out).unwrap();
    // a fatal alert record: content type 21, level fatal
    assert_eq!(out[0], 0x15);
    assert_eq!(out[5], 2);
}

// ------------------------------------------------------------------ Stream

#[test]
fn stream_over_tcp_loopback() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let server_config = Arc::new(server_config(&chain));
    let client_config = Arc::new(client_config(&chain));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut stream = StreamOwned::new(conn, sock);
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap();
        stream.write_all(&buf[..n]).unwrap();
        stream.write_all(b" (echoed)").unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        let (conn, _sock) = stream.into_parts();
        conn.negotiated_cipher_suite().unwrap().suite()
    });

    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    let mut conn = ClientConnection::new(client_config, server_name()).unwrap();
    let mut stream = Stream::new(&mut conn, &mut sock);
    stream.write_all(b"over tcp").unwrap();
    stream.flush().unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"over tcp (echoed)");
    let server_suite = server_thread.join().unwrap();
    assert_eq!(
        conn.negotiated_cipher_suite().unwrap().suite(),
        server_suite
    );
    assert!(!conn.is_handshaking());
}

#[test]
fn connection_enum_wraps_either_side() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client: Connection = ClientConnection::new(Arc::new(client_config(&chain)), server_name())
        .unwrap()
        .into();
    let server: Connection = ServerConnection::new(Arc::new(server_config(&chain)))
        .unwrap()
        .into();
    assert!(client.is_handshaking() && server.is_handshaking());
    assert!(client.wants_write(), "the ClientHello is queued");
    assert!(!server.wants_write());
}

// ---------------------------------------------------------------- complete_io

/// A transport that replays fixed bytes, then reports EOF, and swallows writes.
struct ScriptedIo {
    incoming: std::io::Cursor<Vec<u8>>,
}

impl Read for ScriptedIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.incoming.read(buf)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `complete_io` on another thread and fails the test if it does not
/// return within a few seconds.
fn complete_io_with_deadline(
    mut conn: Connection,
    incoming: Vec<u8>,
) -> std::io::Result<(usize, usize)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut io = ScriptedIo {
            incoming: std::io::Cursor::new(incoming),
        };
        let _ignored = tx.send(conn.complete_io(&mut io));
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("complete_io did not return")
}

/// A plaintext `close_notify` alert record.
const CLOSE_NOTIFY_RECORD: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];

#[test]
fn complete_io_returns_when_close_notify_arrives_during_the_handshake() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let server: Connection = ServerConnection::new(Arc::new(server_config(&chain)))
        .unwrap()
        .into();
    let client: Connection = ClientConnection::new(Arc::new(client_config(&chain)), server_name())
        .unwrap()
        .into();
    for conn in [server, client] {
        let err = complete_io_with_deadline(conn, CLOSE_NOTIFY_RECORD.to_vec()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

// ---------------------------------------------------------------- key log

/// `(label, client_random, secret)` as handed to the key log.
type LoggedSecret = (String, Vec<u8>, Vec<u8>);

#[derive(Debug, Default)]
struct CapturingKeyLog(Mutex<Vec<LoggedSecret>>);

impl KeyLog for CapturingKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), client_random.to_vec(), secret.to_vec()));
    }
}

#[test]
fn key_log_receives_every_tls13_secret() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_log = Arc::new(CapturingKeyLog::default());
    let server_log = Arc::new(CapturingKeyLog::default());
    let mut client_config = client_config(&chain);
    client_config.key_log = client_log.clone();
    let mut server_config = server_config(&chain);
    server_config.key_log = server_log.clone();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();

    let client_entries = client_log.0.lock().unwrap().clone();
    let server_entries = server_log.0.lock().unwrap().clone();
    let labels: Vec<&str> = client_entries.iter().map(|(l, _, _)| l.as_str()).collect();
    for expected in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        assert!(
            labels.contains(&expected),
            "missing {expected} in {labels:?}"
        );
    }
    // both sides log the same secrets under the same client random
    let mut c = client_entries.clone();
    let mut s = server_entries.clone();
    c.sort();
    s.sort();
    assert_eq!(c, s);
    assert!(c.iter().all(|(_, random, _)| random.len() == 32));
}

#[cfg(feature = "tls12")]
#[test]
fn key_log_receives_the_tls12_master_secret() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let log = Arc::new(CapturingKeyLog::default());
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    client_config.key_log = log.clone();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    let entries = log.0.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "CLIENT_RANDOM");
    assert_eq!(entries[0].2.len(), 48);
}

// ------------------------------------------------------ max_fragment_size

/// Splits a byte stream into TLS records, returning each record's total size.
fn record_sizes(mut bytes: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();
    while bytes.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        sizes.push(5 + len);
        bytes = &bytes[5 + len..];
    }
    assert!(bytes.is_empty(), "trailing partial record");
    sizes
}

#[test]
fn max_fragment_size_bounds_every_record() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for (client_max, server_max) in [
        (Some(512usize), None),
        (None, Some(700)),
        (Some(300), Some(300)),
    ] {
        let mut client_config = client_config(&chain);
        client_config.max_fragment_size = client_max;
        let mut server_config = server_config(&chain);
        server_config.max_fragment_size = server_max;
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();

        let payload = vec![0x42u8; 5000];
        client.writer().write_all(&payload).unwrap();
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        // As in rustls, `max_fragment_size` bounds header + plaintext fragment;
        // TLS 1.3 record protection then adds a content-type byte and a 16-byte tag.
        const AEAD_OVERHEAD: usize = 17;
        let sizes = record_sizes(&wire);
        if let Some(max) = client_max {
            assert!(
                sizes.iter().all(|s| *s <= max + AEAD_OVERHEAD),
                "{sizes:?} exceed {max}"
            );
            assert!(sizes.iter().any(|s| *s == max + AEAD_OVERHEAD), "{sizes:?}");
            assert!(sizes.len() >= 5000 / max);
        } else {
            assert_eq!(sizes.len(), 1, "one record fits 5000 bytes");
        }
        server.read_tls(&mut &wire[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut got = Vec::new();
        server.reader().read_to_end(&mut got).ok();
        assert_eq!(got, payload);

        server.writer().write_all(&payload).unwrap();
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        if let Some(max) = server_max {
            assert!(
                record_sizes(&wire)
                    .iter()
                    .all(|s| *s <= max + AEAD_OVERHEAD)
            );
        }
    }
}

#[test]
fn max_fragment_size_too_small_is_refused() {
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = client_config(&chain);
    client_config.max_fragment_size = Some(10);
    assert_eq!(
        ClientConnection::new(Arc::new(client_config), server_name()).unwrap_err(),
        Error::BadMaxFragmentSize
    );
    let mut server_config = server_config(&chain);
    server_config.max_fragment_size = Some(70_000);
    assert_eq!(
        ServerConnection::new(Arc::new(server_config)).unwrap_err(),
        Error::BadMaxFragmentSize
    );
}

// ------------------------------------------------------- secret extraction

fn key_bytes(secrets: &ConnectionTrafficSecrets) -> (Vec<u8>, Vec<u8>) {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            (key.as_ref().to_vec(), iv.as_ref().to_vec())
        }
        _ => panic!("unknown secret kind"),
    }
}

#[test]
fn extracted_secrets_match_across_the_connection() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for v in browntls::ALL_VERSIONS.iter().copied() {
        let mut client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[v])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        client_config.enable_secret_extraction = true;
        let mut server_config = server_config(&chain);
        server_config.enable_secret_extraction = true;
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        // some traffic, so the sequence numbers are not all zero
        assert_eq!(send_and_receive(&mut client, &mut server, b"x"), b"x");
        assert_eq!(send_and_receive(&mut client, &mut server, b"y"), b"y");

        let c = client.dangerous_extract_secrets().unwrap();
        let s = server.dangerous_extract_secrets().unwrap();
        assert_eq!(
            key_bytes(&c.tx.1),
            key_bytes(&s.rx.1),
            "{v:?} client->server"
        );
        assert_eq!(
            key_bytes(&c.rx.1),
            key_bytes(&s.tx.1),
            "{v:?} server->client"
        );
        assert_eq!(c.tx.0, s.rx.0, "{v:?} client write seq == server read seq");
        assert_eq!(c.rx.0, s.tx.0, "{v:?}");
        assert!(c.tx.0 >= 2);
    }
}

#[test]
fn secret_extraction_must_be_enabled() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.dangerous_extract_secrets().unwrap_err(),
        Error::General("Secret extraction is disabled".into())
    );
}

// ----------------------------------------------------------- OCSP stapling

/// Pins a certificate and records the OCSP response the server stapled.
#[derive(Debug)]
struct OcspCapturingVerifier {
    inner: Arc<PinnedServerVerifier>,
    seen: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for OcspCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        *self.seen.lock().unwrap() = Some(ocsp_response.to_vec());
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[test]
fn ocsp_response_is_stapled_in_both_versions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let ocsp = b"not really an OCSP response, but opaque to TLS".to_vec();
    for v in browntls::ALL_VERSIONS.iter().copied() {
        let verifier = Arc::new(OcspCapturingVerifier {
            inner: PinnedServerVerifier::new(&chain),
            seen: Mutex::new(None),
        });
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[v])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert_with_ocsp(chain.cert_chain(), chain.private_key(), ocsp.clone())
            .unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            verifier.seen.lock().unwrap().as_deref(),
            Some(&ocsp[..]),
            "{v:?}"
        );
    }
}

// ------------------------------------------------------------ half-RTT data

#[test]
fn server_half_rtt_data_arrives_with_the_handshake() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut server_config = server_config(&chain);
    server_config.send_half_rtt_data = true;
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    // queued before the handshake: sent right after the server's Finished
    server
        .writer()
        .write_all(b"hello before your Finished")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(
        server.is_handshaking(),
        "server still waits for the client Finished"
    );
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(!client.is_handshaking());
    let mut got = Vec::new();
    client.reader().read_to_end(&mut got).ok();
    assert_eq!(got, b"hello before your Finished");

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!server.is_handshaking());
}

// ------------------------------------------------- certificate compression

/// A toy "compressor" (reverses the bytes) standing in for zlib, so the
/// RFC 8879 framing is exercised whatever compression features are enabled
/// (the built-in algorithms have their own cases in `cert_compression.rs`).
#[derive(Debug)]
struct Reverser;

impl CertCompressor for Reverser {
    fn compress(
        &self,
        mut input: Vec<u8>,
        _level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        input.reverse();
        Ok(input)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

impl CertDecompressor for Reverser {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        if input.len() != output.len() {
            return Err(DecompressionFailed);
        }
        for (o, i) in output.iter_mut().zip(input.iter().rev()) {
            *o = *i;
        }
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

static REVERSER: Reverser = Reverser;

#[test]
fn certificates_are_compressed_when_both_sides_agree() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);

    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    client_config.cert_decompressors = vec![&REVERSER];
    client_config.cert_compressors = vec![&REVERSER];
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.cert_compressors = vec![&REVERSER];
    server_config.cert_decompressors = vec![&REVERSER];

    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"compressed"),
        b"compressed"
    );

    // a second handshake reuses the server's cached compression
    let mut client = ClientConnection::new(
        Arc::new({
            let mut c = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                .with_no_client_auth();
            c.cert_decompressors = vec![&REVERSER];
            c.resumption = browntls::client::Resumption::disabled();
            c
        }),
        server_name(),
    )
    .unwrap();
    let mut server_config = common::server_config(&chain);
    server_config.cert_compressors = vec![&REVERSER];
    let server_config = Arc::new(server_config);
    for _ in 0..2 {
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
        client = ClientConnection::new(
            Arc::new({
                let mut c = ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(&[&version::TLS13])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                    .with_no_client_auth();
                c.cert_decompressors = vec![&REVERSER];
                c
            }),
            server_name(),
        )
        .unwrap();
    }
}

#[test]
fn certificates_stay_plain_without_a_common_algorithm() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    client_config.cert_decompressors = vec![&REVERSER];
    // the server has no compressor: it must send a plain Certificate
    let mut server_config = server_config(&chain);
    server_config.cert_compressors.clear();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

// ---------------------------------------------------------- session stores

#[test]
fn custom_server_session_store_sees_puts_and_takes() {
    init_logging();
    #[derive(Debug, Default)]
    struct Counting {
        inner: Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
        puts: Mutex<usize>,
        takes: Mutex<usize>,
    }
    impl browntls::server::StoresServerSessions for Counting {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            *self.puts.lock().unwrap() += 1;
            self.inner.lock().unwrap().insert(key, value);
            true
        }
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.lock().unwrap().get(key).cloned()
        }
        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            *self.takes.lock().unwrap() += 1;
            self.inner.lock().unwrap().remove(key)
        }
        fn can_cache(&self) -> bool {
            true
        }
    }
    let chain = server_chain(KeyType::Ed25519);
    let store = Arc::new(Counting::default());
    let mut server_config = server_config(&chain);
    server_config.session_storage = store.clone();
    server_config.send_tls13_tickets = 3;
    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config(&chain));

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(*store.puts.lock().unwrap(), 3);
    assert_eq!(client.tls13_tickets_received(), 3);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.handshake_kind(),
        Some(browntls::HandshakeKind::Resumed)
    );
    // TLS 1.3 PSKs are single use: the ticket was taken, and fresh ones stored
    assert_eq!(*store.takes.lock().unwrap(), 1);
    assert_eq!(*store.puts.lock().unwrap(), 6);
}

// ---------------------------------------------------------------- blocking I/O

/// A transport that hands out one queued chunk per read, then reports
/// `WouldBlock`, and records what is written to it.
#[derive(Default)]
struct ChunkedIo {
    chunks: std::collections::VecDeque<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for ChunkedIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(chunk) = self.chunks.front_mut() else {
            return Err(std::io::ErrorKind::WouldBlock.into());
        };
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        chunk.drain(..n);
        if chunk.is_empty() {
            self.chunks.pop_front();
        }
        Ok(n)
    }
}

impl Write for ChunkedIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The TLS bytes `conn` has queued.
fn queued_tls<S: browntls::SideData>(conn: &mut browntls::ConnectionCommon<S>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

#[test]
fn stream_read_answers_a_key_update_and_keeps_reading() {
    stream_read_answers_a_key_update(None);
}

#[test]
fn stream_read_writes_answers_past_the_control_backlog_and_keeps_reading() {
    // One KeyUpdate answer is more than this limit lets wait unwritten, so
    // the connection stops wanting to read until the answer is out.
    stream_read_answers_a_key_update(Some(16));
}

fn stream_read_answers_a_key_update(limit: Option<usize>) {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.protocol_version(), Some(version::TLS13.version));
    client.set_buffer_limit(limit.or(Some(64 * 1024)));

    // The peer's KeyUpdate(update_requested) and its next record arrive in
    // separate reads, so answering the KeyUpdate is a pass that reads nothing.
    server.refresh_traffic_keys().unwrap();
    let key_update = queued_tls(&mut server);
    server.writer().write_all(b"hello").unwrap();
    let data = queued_tls(&mut server);
    let mut io = ChunkedIo {
        chunks: [key_update, data].into(),
        written: Vec::new(),
    };

    let mut buf = [0u8; 16];
    let n = Stream::new(&mut client, &mut io).read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello");

    // The client answered with its own KeyUpdate, which the server accepts.
    assert!(!io.written.is_empty());
    server.read_tls(&mut io.written.as_slice()).unwrap();
    server.process_new_packets().unwrap();
}

/// A transport whose writes accept nothing.
struct ZeroWriteIo;

impl Read for ZeroWriteIo {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl Write for ZeroWriteIo {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn complete_io_fails_when_the_transport_accepts_no_bytes() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client: Connection =
        ClientConnection::new(Arc::new(client_config(&chain)), server_name())
            .unwrap()
            .into();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ignored = tx.send(client.complete_io(&mut ZeroWriteIo));
    });
    let err = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("complete_io did not return")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
}

#[test]
fn writes_into_a_full_send_buffer_queue_no_records() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.protocol_version(), Some(version::TLS13.version));
    let _ = queued_tls(&mut client);

    // An empty write sends nothing.
    assert_eq!(client.writer().write(&[]).unwrap(), 0);
    assert!(!client.wants_write());

    // Fill the send buffer, then retry: the retries take nothing and must
    // queue nothing either (not even empty records).
    client.set_buffer_limit(Some(4096));
    let mut taken = 0;
    while let n @ 1.. = client.writer().write(&[0x5a; 1000]).unwrap() {
        taken += n;
    }
    for _ in 0..1000 {
        assert_eq!(client.writer().write(&[0x5a; 1000]).unwrap(), 0);
    }
    let tls = queued_tls(&mut client);
    let mut records = 0;
    let mut rest = tls.as_slice();
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        // More than the AEAD tag and the content type: some plaintext.
        assert!(len > 17, "a record without plaintext was queued");
        rest = &rest[5 + len..];
        records += 1;
    }
    assert!(records <= 5, "{records} records for {taken} bytes");

    // The peer receives exactly the plaintext that was taken.
    server.read_tls(&mut tls.as_slice()).unwrap();
    server.process_new_packets().unwrap();
    let mut received = vec![0; taken + 1];
    assert_eq!(server.reader().read(&mut received).unwrap(), taken);
}
