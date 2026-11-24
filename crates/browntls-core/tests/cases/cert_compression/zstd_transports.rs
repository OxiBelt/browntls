use super::*;
use browntls_core::compress::ZstdDecompressionLimits;

/// Emits a valid single-block frame whose advertised history is larger
/// than any Certificate body. The data itself is copied into a raw block.
#[derive(Debug)]
struct LargeWindow;

impl CertCompressor for LargeWindow {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }

    fn compress(
        &self,
        input: Vec<u8>,
        _level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
        let block = ((input.len() as u32) << 3) | 1;
        frame.extend_from_slice(&block.to_le_bytes()[..3]);
        frame.extend_from_slice(&input);
        Ok(frame)
    }
}

fn configs() -> (
    ClientConfig,
    ServerConfig,
    &'static Counting,
    &'static Counting,
) {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let mut client = tls13_client(&server_chain, Some(&client_chain));
    let mut server = tls13_server(&server_chain, Some(&client_chain));
    client.alpn_protocols = vec![b"cert-compression".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    client.cert_compressors = vec![&LargeWindow];
    server.cert_compressors = vec![&LargeWindow];
    let client_count = Counting::new(&compress::ZSTD);
    let server_count = Counting::new(&compress::ZSTD);
    client.cert_decompressors = vec![client_count];
    server.cert_decompressors = vec![server_count];
    (client, server, client_count, server_count)
}

#[test]
fn buffered_tls_applies_each_endpoint_zstd_policy() {
    let (client, server, client_count, server_count) = configs();
    let (mut client, mut server) = connect(client, server);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!((client_count.calls(), server_count.calls()), (1, 1));

    let restrict = ZstdDecompressionLimits::new(128 * 1024, 128 * 1024).unwrap();
    let bad_certificate = Err(Error::PeerMisbehaved(
        PeerMisbehaved::InvalidCertCompression,
    ));
    let (mut client, server, _, _) = configs();
    client.cert_zstd_decompression_limits = restrict;
    let (mut client, mut server) = connect(client, server);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server).0,
        bad_certificate
    );

    let (client, mut server, _, _) = configs();
    server.cert_zstd_decompression_limits = restrict;
    let (mut client, mut server) = connect(client, server);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server).1,
        bad_certificate
    );
}

fn drive_unbuffered<D: browntls_core::SideData>(
    conn: &mut browntls_core::unbuffered::UnbufferedConnectionCommon<D>,
    input: &mut Vec<u8>,
    output: &mut Vec<u8>,
) -> bool {
    use browntls_core::unbuffered::ConnectionState;

    loop {
        let status = conn.process_tls_records(input);
        let discard = status.discard;
        let done = match status.state.unwrap() {
            ConnectionState::EncodeTlsData(mut encoder) => {
                let mut encoded = vec![0; 1 << 16];
                let len = encoder.encode(&mut encoded).unwrap();
                output.extend_from_slice(&encoded[..len]);
                None
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                None
            }
            ConnectionState::BlockedHandshake => Some(false),
            ConnectionState::WriteTraffic(_) => Some(true),
            other => panic!("unexpected state {other:?}"),
        };
        input.drain(..discard);
        if let Some(done) = done {
            return done;
        }
    }
}

#[test]
fn unbuffered_tls_receives_both_large_window_frames() {
    use browntls_core::client::UnbufferedClientConnection;
    use browntls_core::server::UnbufferedServerConnection;

    let (client, server, client_count, server_count) = configs();
    let mut client = UnbufferedClientConnection::new(Arc::new(client), server_name()).unwrap();
    let mut server = UnbufferedServerConnection::new(Arc::new(server)).unwrap();
    let (mut to_client, mut to_server) = (Vec::new(), Vec::new());
    for _ in 0..20 {
        let c = drive_unbuffered(&mut client, &mut to_client, &mut to_server);
        let s = drive_unbuffered(&mut server, &mut to_server, &mut to_client);
        if c && s && to_client.is_empty() && to_server.is_empty() {
            assert_eq!((client_count.calls(), server_count.calls()), (1, 1));
            return;
        }
    }
    panic!("unbuffered mutual authentication did not complete");
}

#[test]
fn quic_tls_receives_both_large_window_frames() {
    use browntls_core::quic;

    let (client, server, client_count, server_count) = configs();
    let mut client =
        quic::ClientConnection::new(Arc::new(client), quic::Version::V1, server_name(), vec![0])
            .unwrap();
    let mut server =
        quic::ServerConnection::new(Arc::new(server), quic::Version::V1, vec![0]).unwrap();
    let mut wire = Vec::new();
    for _ in 0..20 {
        client.write_hs(&mut wire);
        if !wire.is_empty() {
            server.read_hs(&wire).unwrap();
            wire.clear();
        }
        server.write_hs(&mut wire);
        if !wire.is_empty() {
            client.read_hs(&wire).unwrap();
            wire.clear();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            assert_eq!((client_count.calls(), server_count.calls()), (1, 1));
            return;
        }
    }
    panic!("QUIC mutual authentication did not complete");
}

#[test]
fn dtls_receives_both_large_window_frames() {
    use browntls_core::dtls;
    use std::time::Duration;

    let (client, server, client_count, server_count) = configs();
    let mut client = dtls::ClientConnection::new(Arc::new(client), server_name()).unwrap();
    let mut server =
        dtls::ServerConnection::new_without_cookie_exchange(Arc::new(server), b"peer").unwrap();
    let now = Duration::from_secs(1);
    let mut datagram = Vec::new();
    for _ in 0..20 {
        while client.write_datagram(&mut datagram, now).unwrap() {
            server.read_datagram(&mut datagram, now).unwrap();
            datagram.clear();
        }
        while server.write_datagram(&mut datagram, now).unwrap() {
            client.read_datagram(&mut datagram, now).unwrap();
            datagram.clear();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            assert_eq!((client_count.calls(), server_count.calls()), (1, 1));
            return;
        }
    }
    panic!("DTLS mutual authentication did not complete");
}
