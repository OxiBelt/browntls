// Vectored plaintext writes and the vectored writes of queued TLS bytes.
// Included by `cases/api.rs`.

use std::io::IoSlice;

/// A TLS 1.3 client and server past the handshake, with nothing queued.
fn connected_pair() -> (ClientConnection, ServerConnection) {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.protocol_version(), Some(version::TLS13.version));
    assert!(!client.wants_write() && !server.wants_write());
    (client, server)
}

/// The body lengths of the records in `tls`.
fn record_lengths(tls: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut rest = tls;
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        lengths.push(len);
        rest = &rest[5 + len..];
    }
    lengths
}

/// Everything `conn` decrypts from `tls`.
fn received_plaintext<S: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<S>,
    tls: &[u8],
) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let mut rest = tls;
    while !rest.is_empty() {
        let n = conn.read_tls(&mut rest).unwrap();
        assert!(n > 0, "the connection stopped reading");
        conn.process_new_packets().unwrap();
        match conn.reader().read_to_end(&mut plaintext) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("read failed: {err}"),
        }
    }
    plaintext
}

/// `count` buffers of distinct contents; every seventh is empty.
fn patterned_buffers(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| vec![i as u8; (i % 7) * 3]).collect()
}

#[test]
fn vectored_write_takes_more_buffers_than_one_round_holds() {
    let (mut client, mut server) = connected_pair();
    // 384 buffers with data and 64 empty ones between them.
    let buffers = patterned_buffers(448);
    let slices: Vec<IoSlice<'_>> = buffers.iter().map(|b| IoSlice::new(b)).collect();
    let expected = buffers.concat();

    assert_eq!(
        client.writer().write_vectored(&slices).unwrap(),
        expected.len()
    );
    let tls = queued_tls(&mut client);
    // Buffers share records: each write takes 64 buffers with data, however
    // many empty ones lie between them, and none of these writes fills a
    // record.
    assert_eq!(record_lengths(&tls).len(), 384 / 64);
    assert_eq!(received_plaintext(&mut server, &tls), expected);
}

#[test]
fn vectored_write_skips_empty_buffers() {
    let (mut client, mut server) = connected_pair();
    // 64 buffers with data fit one write, whatever surrounds them.
    let buffers: Vec<Vec<u8>> = (0..200)
        .map(|i| {
            if i % 3 == 1 && i < 192 {
                vec![i as u8; 5]
            } else {
                Vec::new()
            }
        })
        .collect();
    assert_eq!(buffers.iter().filter(|b| !b.is_empty()).count(), 64);
    let slices: Vec<IoSlice<'_>> = buffers.iter().map(|b| IoSlice::new(b)).collect();

    assert_eq!(client.writer().write_vectored(&slices).unwrap(), 64 * 5);
    let tls = queued_tls(&mut client);
    assert_eq!(record_lengths(&tls), [64 * 5 + 17]);
    assert_eq!(received_plaintext(&mut server, &tls), buffers.concat());
}

#[test]
fn vectored_write_fills_records_across_buffers() {
    let (mut client, mut server) = connected_pair();
    let buffers = [
        vec![1u8; 10_000],
        Vec::new(),
        vec![2u8; 10_000],
        vec![3u8; 10_000],
    ];
    let slices: Vec<IoSlice<'_>> = buffers.iter().map(|b| IoSlice::new(b)).collect();

    assert_eq!(client.writer().write_vectored(&slices).unwrap(), 30_000);
    let tls = queued_tls(&mut client);
    // One full record and the rest, whatever the buffer boundaries: the
    // body is the plaintext, the content type and the AEAD tag.
    assert_eq!(record_lengths(&tls), [16_384 + 17, 13_616 + 17]);
    assert_eq!(received_plaintext(&mut server, &tls), buffers.concat());
}

#[test]
fn vectored_write_of_nothing_queues_nothing() {
    let (mut client, _server) = connected_pair();
    assert_eq!(client.writer().write_vectored(&[]).unwrap(), 0);
    let empty = [IoSlice::new(&[]), IoSlice::new(&[])];
    assert_eq!(client.writer().write_vectored(&empty).unwrap(), 0);
    assert!(!client.wants_write());
}

#[test]
fn vectored_write_stops_at_the_send_buffer_limit() {
    let (mut client, mut server) = connected_pair();
    let buffers: Vec<Vec<u8>> = (0..200).map(|i| vec![i as u8; 100]).collect();
    let slices: Vec<IoSlice<'_>> = buffers.iter().map(|b| IoSlice::new(b)).collect();
    let all = buffers.concat();

    // The first 64 buffers fit and are taken whole. Their record counts
    // against the limit, which cuts the next 64 short and ends the write.
    client.set_buffer_limit(Some(10_000));
    let taken = client.writer().write_vectored(&slices).unwrap();
    assert!((6_400..10_000).contains(&taken), "{taken} bytes taken");
    assert_eq!(client.writer().write_vectored(&slices).unwrap(), 0);
    let tls = queued_tls(&mut client);
    let mut received = received_plaintext(&mut server, &tls);
    assert_eq!(received, &all[..taken]);

    // The rest follows from where the write stopped, once the buffer has
    // room again.
    client.set_buffer_limit(None);
    let mut rest = vec![IoSlice::new(&buffers[taken / 100][taken % 100..])];
    rest.extend_from_slice(&slices[taken / 100 + 1..]);
    assert_eq!(
        client.writer().write_vectored(&rest).unwrap(),
        all.len() - taken
    );
    let tls = queued_tls(&mut client);
    received.extend(received_plaintext(&mut server, &tls));
    assert_eq!(received, all);
}

#[test]
fn vectored_write_before_the_handshake_is_buffered_up_to_the_limit() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    client.set_buffer_limit(Some(250));
    let buffers: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 3]).collect();
    let slices: Vec<IoSlice<'_>> = buffers.iter().map(|b| IoSlice::new(b)).collect();

    // 64 buffers (192 bytes) are buffered whole, then 58 bytes of the rest.
    assert_eq!(client.writer().write_vectored(&slices).unwrap(), 250);
    assert_eq!(client.writer().write_vectored(&slices).unwrap(), 0);
    assert_eq!(client.writer().write(b"more").unwrap(), 0);

    // The handshake sends what was buffered.
    do_handshake(&mut client, &mut server).unwrap();
    let tls = queued_tls(&mut client);
    let mut received = received_plaintext(&mut server, &tls);
    match server.reader().read_to_end(&mut received) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) => panic!("read failed: {err}"),
    }
    assert_eq!(received, &buffers.concat()[..250]);
}

/// A transport that records the slice lengths of each vectored write.
#[derive(Default)]
struct VectoredRecorder {
    calls: Vec<Vec<usize>>,
    written: Vec<u8>,
}

impl Write for VectoredRecorder {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("write_tls must write vectored"))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.calls.push(bufs.iter().map(|buf| buf.len()).collect());
        for buf in bufs {
            self.written.extend_from_slice(buf);
        }
        Ok(bufs.iter().map(|buf| buf.len()).sum())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_tls_offers_the_queued_records_in_one_vectored_write() {
    let (mut client, mut server) = connected_pair();
    let mut io = VectoredRecorder::default();
    let mut expected = Vec::new();

    for i in 0..70u8 {
        client.writer().write_all(&[i; 10]).unwrap();
        expected.extend_from_slice(&[i; 10]);
    }
    // Each write is one record of 10 bytes, a content type and a tag behind
    // a 5-byte header. One call offers 64 of them, the next the rest.
    let first = client.write_tls(&mut io).unwrap();
    assert_eq!(io.calls, [vec![5 + 10 + 17; 64]]);
    assert_eq!(first, 64 * 32);
    assert!(client.wants_write());
    assert_eq!(client.write_tls(&mut io).unwrap(), 6 * 32);
    assert_eq!(io.calls[1], [32; 6]);
    assert!(!client.wants_write());
    assert_eq!(client.write_tls(&mut io).unwrap(), 0);
    assert_eq!(io.calls.len(), 2);
    assert_eq!(received_plaintext(&mut server, &io.written), expected);
}
