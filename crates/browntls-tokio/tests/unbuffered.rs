//! The streams over the unbuffered connection API
//! (`browntls_tokio::unbuffered`): handshakes, data transfer and closure
//! between an unbuffered client and server over in-memory and TCP
//! transports, records lent in place, and what `into_parts` returns.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/gate.rs"]
mod gate;

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use browntls_core::unbuffered::ConnectionState;
use browntls_core::{
    Error, HandshakeKind, ReferenceIdentifier, ServiceIdentity, SupportedProtocolVersion,
};
use browntls_tokio::unbuffered::{ClientTlsStream, ServerTlsStream, TlsAcceptor, TlsConnector};
use common::*;
use gate::{Gate, GateState};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

fn connector(pki: &Pki, version: &'static SupportedProtocolVersion) -> TlsConnector {
    TlsConnector::from(Arc::new(pki.client_config(version)))
}

fn acceptor(pki: &Pki, version: &'static SupportedProtocolVersion) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(pki.server_config(version)))
}

fn identity(reference: &str) -> browntls_core::ClientServerIdentity {
    use browntls_core::pki_types::{DnsName, ServerName};

    browntls_core::ClientServerIdentity::new(
        ServerName::try_from("localhost").unwrap(),
        ServiceIdentity::new(vec![ReferenceIdentifier::Dns(
            DnsName::try_from(reference).unwrap().to_owned(),
        )])
        .unwrap(),
    )
}

/// Connects an unbuffered client and server over `client_io` and
/// `server_io`.
async fn pair<C, S>(
    pki: &Pki,
    version: &'static SupportedProtocolVersion,
    client_io: C,
    server_io: S,
) -> (ClientTlsStream<C>, ServerTlsStream<S>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            connector(pki, version).connect(localhost(), client_io),
            acceptor(pki, version).accept(server_io),
        )
    })
    .await
    .expect("handshake timed out");
    // A handshake that only ends when the timer above polls it again lost
    // a wake-up.
    assert!(started.elapsed() < LIMIT / 2, "a wake-up was lost");
    (
        client.expect("client handshake"),
        server.expect("server handshake"),
    )
}

#[tokio::test]
async fn handshake_then_echo_in_both_directions() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (mut client, mut server) = pair(&pki, version, c, s).await;

        assert_eq!(client.get_ref().1.protocol_version(), Some(version.version));
        assert!(!client.get_ref().1.is_handshaking());
        assert!(!server.get_ref().1.is_handshaking());
        assert_eq!(server.get_ref().1.server_name(), Some("localhost"));
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Both sides derive the same exporter value.
        let label = b"EXPORTER-browntls-tokio-test";
        let ours = client
            .get_ref()
            .1
            .export_keying_material([0u8; 32], label, None);
        let theirs = server
            .get_ref()
            .1
            .export_keying_material([0u8; 32], label, None);
        assert_eq!(ours.unwrap(), theirs.unwrap(), "{version:?}");
    }
}

#[tokio::test]
async fn unbuffered_identity_connector_authenticates_reference_identifier() {
    let pki = Pki::new();
    for version in versions() {
        let (client_io, server_io) = duplex(64 * 1024);
        let client_connector = connector(&pki, version);
        let server_acceptor = acceptor(&pki, version);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                client_connector.connect_with_identity_and_callback(
                    identity("localhost"),
                    client_io,
                    |_| {},
                ),
                server_acceptor.accept(server_io),
            )
        })
        .await
        .expect("identity handshake timed out");
        let client = client.expect("client identity handshake");
        let _server = server.expect("server identity handshake");
        assert_eq!(
            client.get_ref().1.matched_service_identity(),
            Some(&ReferenceIdentifier::Dns(
                browntls_core::pki_types::DnsName::try_from("localhost")
                    .unwrap()
                    .to_owned()
            )),
            "{version:?}"
        );
    }
}

#[tokio::test]
async fn bulk_transfer_survives_a_choppy_transport() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(4096);
        let (client, server) = pair(&pki, version, Choppy::new(c, 7), Choppy::new(s, 13)).await;

        let up = pattern(300 * 1024);
        let down: Vec<u8> = pattern(200 * 1024).into_iter().rev().collect();
        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        let (mut server_rd, mut server_wr) = tokio::io::split(server);

        let (up_wr, down_wr) = (up.clone(), down.clone());
        let tasks = async {
            tokio::join!(
                async move {
                    client_wr.write_all(&up_wr).await.unwrap();
                    client_wr.shutdown().await.unwrap();
                },
                async move {
                    server_wr.write_all(&down_wr).await.unwrap();
                    server_wr.shutdown().await.unwrap();
                },
                async move {
                    let mut got = Vec::new();
                    server_rd.read_to_end(&mut got).await.unwrap();
                    got
                },
                async move {
                    let mut got = Vec::new();
                    client_rd.read_to_end(&mut got).await.unwrap();
                    got
                },
            )
        };
        let ((), (), server_got, client_got) = timeout(LIMIT, tasks).await.expect("timed out");
        assert!(
            server_got == up,
            "{version:?}: server received corrupt data"
        );
        assert!(
            client_got == down,
            "{version:?}: client received corrupt data"
        );
    }
}

#[tokio::test]
async fn records_arriving_a_byte_at_a_time_are_reassembled() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(4096);
        let (mut client, mut server) =
            pair(&pki, version, Choppy::new(c, 1), Choppy::new(s, 1)).await;
        let data = pattern(40 * 1024);
        let run = async {
            tokio::join!(
                async {
                    client.write_all(&data).await.unwrap();
                    client.shutdown().await.unwrap();
                },
                async {
                    let mut got = Vec::new();
                    server.read_to_end(&mut got).await.unwrap();
                    got
                },
            )
        };
        let ((), got) = timeout(LIMIT, run).await.expect("timed out");
        assert!(got == data, "{version:?}: corrupt data");
    }
}

#[tokio::test]
async fn close_notify_ends_reads_and_forbids_later_writes() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (mut client, mut server) = pair(&pki, version, c, s).await;

        client.write_all(b"last words").await.unwrap();
        client.shutdown().await.unwrap();
        let err = client.write_all(b"more").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // Shutting down again changes nothing.
        client.shutdown().await.unwrap();

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"last words");
        // End of file is sticky.
        assert_eq!(server.read(&mut [0; 8]).await.unwrap(), 0);
        assert!(server.fill_buf().await.unwrap().is_empty());

        // The server's direction is still open until it closes too.
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"reply");
    }
}

#[tokio::test]
async fn transport_eof_without_close_notify_is_a_truncation() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (mut client, server) = pair(&pki, version, c, s).await;
        let (transport, _) = server.into_inner();
        drop(transport);

        let err = client.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{version:?}");
    }
}

#[tokio::test]
async fn an_untrusted_server_fails_both_handshakes_with_an_alert() {
    let pki = Pki::new();
    let stranger = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                connector(&stranger, version).connect(localhost(), c),
                acceptor(&pki, version).accept(s),
            )
        })
        .await
        .unwrap();

        let err = client.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            matches!(tls_error(&err), Some(Error::InvalidCertificate(_))),
            "{err:?}"
        );
        // The client's alert was written before its future failed.
        let err = server.unwrap_err();
        assert!(
            matches!(tls_error(&err), Some(Error::AlertReceived(_))),
            "{err:?}"
        );
    }
}

#[tokio::test]
async fn fallible_futures_return_the_transport() {
    let pki = Pki::new();
    let stranger = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    let mut connect = connector(&stranger, version).connect(localhost(), c);
    assert!(connect.get_ref().is_some());
    assert!(connect.get_mut().is_some());
    let mut accept = acceptor(&pki, version).accept(s);
    assert!(accept.get_ref().is_some());
    assert!(accept.get_mut().is_some());
    let (client, server) = tokio::join!(connect.into_fallible(), accept.into_fallible());
    let Err((err, mut transport)) = client else {
        panic!("client must fail");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // The transport is still usable: the server's last flight is in it.
    transport.shutdown().await.unwrap();
    let Err((err, _transport)) = server else {
        panic!("server must fail");
    };
    assert!(matches!(tls_error(&err), Some(Error::AlertReceived(_))));
}

#[tokio::test]
async fn a_configuration_the_connection_refuses_fails_the_future_with_the_transport() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut config = pki.server_config(version);
    // Not a size a record may have (RFC 8449 §4 allows 64 and more).
    config.record_size_limit = Some(1);
    let (c, s) = duplex(64);
    let accept = TlsAcceptor::from(Arc::new(config)).accept(s);
    assert!(accept.get_ref().is_some());
    let Err((err, _transport)) = accept.into_fallible().await else {
        panic!("the configuration must be refused");
    };
    assert_eq!(err.kind(), io::ErrorKind::Other);
    drop(c);
}

#[tokio::test]
async fn eof_during_the_handshake_fails_it() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    drop(s);
    let err = connector(&pki, version)
        .connect(localhost(), c)
        .await
        .unwrap_err();
    // The ClientHello cannot be written to a closed duplex, or the reply
    // never comes: either way the handshake fails rather than hangs.
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
        ),
        "{err:?}"
    );

    let (mut c, s) = duplex(64 * 1024);
    c.shutdown().await.unwrap();
    let err = timeout(LIMIT, acceptor(&pki, version).accept(s))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}");
}

#[tokio::test]
async fn close_notify_in_the_middle_of_a_handshake_ends_it() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut hello = Vec::new();
    let mut raw =
        browntls_core::ClientConnection::new(Arc::new(pki.client_config(version)), localhost())
            .unwrap();
    raw.write_tls(&mut hello).unwrap();
    // A plaintext warning-level close_notify alert record.
    hello.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);

    let (mut c, s) = duplex(64 * 1024);
    c.write_all(&hello).await.unwrap();
    // The transport stays open: only the TLS state can end the handshake.
    let result = timeout(LIMIT, acceptor(&pki, version).accept(s))
        .await
        .expect("handshake must end, not spin or hang");
    assert!(result.is_err());
    drop(c);
}

#[tokio::test]
async fn alpn_and_connection_hooks() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut server_config = pki.server_config(version);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    assert_eq!(acceptor.config().alpn_protocols.len(), 2);
    let connector = connector(&pki, version);
    assert!(connector.config().alpn_protocols.is_empty());

    let client_hook = AtomicBool::new(false);
    let server_hook = AtomicBool::new(false);
    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        connector
            .with_alpn(vec![b"http/1.1".to_vec()])
            .connect_with(localhost(), c, |_| client_hook
                .store(true, Ordering::Relaxed)),
        acceptor.accept_with(s, |_| server_hook.store(true, Ordering::Relaxed)),
    );
    let (client, server) = (client.unwrap(), server.unwrap());
    assert!(client_hook.load(Ordering::Relaxed) && server_hook.load(Ordering::Relaxed));
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(server.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        connector
            .with_alpn(vec![b"h2".to_vec()])
            .connect(localhost(), c),
        acceptor.accept(s),
    );
    assert_eq!(
        client.unwrap().get_ref().1.alpn_protocol(),
        Some(&b"h2"[..])
    );
    drop(server);

    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        connector.connect_with(localhost(), c, |_| ()),
        acceptor.accept(s),
    );
    assert_eq!(client.unwrap().get_ref().1.alpn_protocol(), None);
    drop(server);
}

#[tokio::test]
async fn key_updates_keep_the_stream_working() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, mut server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    for round in 0..5u8 {
        // Our own update, with a request for the client's: queued on the
        // connection, sent by the next write.
        let status = server.get_mut().1.process_tls_records(&mut []);
        match status.state.unwrap() {
            ConnectionState::WriteTraffic(writer) => writer.refresh_traffic_keys().unwrap(),
            state => panic!("{state:?}"),
        }
        server.write_all(&[round; 100]).await.unwrap();
        server.flush().await.unwrap();
        let mut buf = [0; 100];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [round; 100]);

        // The client's read answered the request, or its next write does.
        client.write_all(&[round ^ 0xff; 50]).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 50];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [round ^ 0xff; 50]);
    }
}

#[tokio::test]
async fn a_flush_sends_what_was_queued_on_the_connection() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, mut server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    let status = server.get_mut().1.process_tls_records(&mut []);
    match status.state.unwrap() {
        ConnectionState::WriteTraffic(writer) => writer.refresh_traffic_keys().unwrap(),
        state => panic!("{state:?}"),
    }
    // No write: the flush alone sends the KeyUpdate. The client's read
    // processes it and answers, and has no plaintext to return.
    server.flush().await.unwrap();
    let nothing = timeout(Duration::from_millis(100), client.read(&mut [0; 1])).await;
    assert!(nothing.is_err());
    // Both sides moved to new keys in both directions.
    client.write_all(b"after").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0; 5];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after");
}

#[tokio::test]
async fn buffered_reads_and_vectored_writes() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, mut server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    let bufs = [
        io::IoSlice::new(b"first line\n"),
        io::IoSlice::new(b""),
        io::IoSlice::new(b"second "),
        io::IoSlice::new(b"line\n"),
    ];
    assert!(client.is_write_vectored());
    let written = client.write_vectored(&bufs).await.unwrap();
    assert_eq!(written, 23, "a vectored write takes every slice at once");
    client.flush().await.unwrap();
    // The slices were gathered into one record, lent whole.
    assert_eq!(server.fill_buf().await.unwrap().len(), 23);

    assert_eq!(client.write_vectored(&[]).await.unwrap(), 0);
    let one = [io::IoSlice::new(b""), io::IoSlice::new(b"third line\n")];
    assert_eq!(client.write_vectored(&one).await.unwrap(), 11);
    client.shutdown().await.unwrap();
    let err = client.write_vectored(&bufs).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    let mut lines = BufReader::new(server).lines();
    assert_eq!(lines.next_line().await.unwrap().unwrap(), "first line");
    assert_eq!(lines.next_line().await.unwrap().unwrap(), "second line");
    assert_eq!(lines.next_line().await.unwrap().unwrap(), "third line");
    assert_eq!(lines.next_line().await.unwrap(), None);
}

#[tokio::test]
async fn a_vectored_write_gathers_at_most_one_record() {
    let pki = Pki::new();
    let (c, s) = duplex(1 << 20);
    let (mut client, mut server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    let data = pattern(40_000);
    let (a, rest) = data.split_at(10_000);
    let (b, c) = rest.split_at(10_000);
    let bufs = [
        io::IoSlice::new(a),
        io::IoSlice::new(b),
        io::IoSlice::new(c),
    ];
    let written = client.write_vectored(&bufs).await.unwrap();
    assert_eq!(written, 16_384);
    // A first slice of a record or more is written as it is.
    let bufs = [io::IoSlice::new(&data[written..]), io::IoSlice::new(b"x")];
    let more = client.write_vectored(&bufs).await.unwrap();
    assert_eq!(written + more, data.len());
    client.shutdown().await.unwrap();

    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert!(got == data);
}

#[tokio::test]
async fn fill_buf_lends_each_record_where_it_was_decrypted() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(1 << 20);
        let (mut client, mut server) = pair(&pki, version, c, s).await;

        // One write of four full records and a short one.
        let data = pattern(4 * 16_384 + 100);
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let mut got = Vec::new();
        let mut sizes = Vec::new();
        loop {
            let chunk = server.fill_buf().await.unwrap();
            if chunk.is_empty() {
                break;
            }
            // A caller may take less than the record: the rest stays.
            let take = chunk.len().min(10_000);
            got.extend_from_slice(&chunk[..take]);
            sizes.push(chunk.len());
            server.consume(take);
        }
        assert!(got == data, "{version:?}");
        assert_eq!(
            sizes,
            [16_384, 6384, 16_384, 6384, 16_384, 6384, 16_384, 6384, 100],
            "{version:?}"
        );
    }
}

#[tokio::test]
async fn small_records_cross_the_stream() {
    let pki = Pki::new();
    for version in versions() {
        // The client sends small records by its own choice; the server
        // because the client's record size limit asks for them.
        let mut client_config = pki.client_config(version);
        client_config.max_fragment_size = Some(512);
        client_config.record_size_limit = Some(700);
        let (c, s) = duplex(1 << 20);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
                acceptor(&pki, version).accept(s),
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        // One write is many records then, and each is lent whole.
        let data = pattern(100_000);
        let largest = lent_records(&mut client, &mut server, &data).await;
        assert!(largest <= 512, "{version:?}: a record of {largest} bytes");
        let largest = lent_records(&mut server, &mut client, &data).await;
        assert!(largest <= 700, "{version:?}: a record of {largest} bytes");
    }
}

/// Writes `data` to `from` and reads it from `to` record by record; returns
/// the size of the largest record lent.
async fn lent_records<F, T>(from: &mut F, to: &mut T, data: &[u8]) -> usize
where
    F: AsyncWrite + Unpin,
    T: AsyncBufRead + Unpin,
{
    assert_eq!(from.write(data).await.unwrap(), 65_536);
    from.write_all(&data[65_536..]).await.unwrap();
    from.flush().await.unwrap();
    let mut got = Vec::new();
    let mut largest = 0;
    while got.len() < data.len() {
        let chunk = timeout(LIMIT, to.fill_buf()).await.unwrap().unwrap();
        assert!(!chunk.is_empty());
        let len = chunk.len();
        largest = largest.max(len);
        got.extend_from_slice(chunk);
        to.consume(len);
    }
    assert!(got == data);
    largest
}

#[tokio::test]
async fn a_large_write_is_taken_in_parts() {
    let pki = Pki::new();
    let (c, s) = duplex(1 << 20);
    let (mut client, mut server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    let data = pattern(200_000);
    // One call takes four records' worth and no more.
    let n = client.write(&data).await.unwrap();
    assert_eq!(n, 65_536);
    client.write_all(&data[n..]).await.unwrap();
    assert_eq!(client.write(&[]).await.unwrap(), 0);
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert!(got == data);
}

#[tokio::test]
async fn into_parts_keeps_what_the_stream_buffered() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(1 << 20);
        let (mut client, mut server) = pair(&pki, version, c, s).await;

        // Two records reach the server's transport before it reads.
        client.write_all(b"first record").await.unwrap();
        client.flush().await.unwrap();
        client.write_all(b"second record").await.unwrap();
        client.flush().await.unwrap();
        // The server queues a record its transport does not take.
        let (transport, _) = client.into_inner();
        let mut byte = [0; 1];
        server.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"f");
        let debug = format!("{server:?}");
        assert!(debug.contains("plaintext: 11"), "{debug}");
        assert!(!debug.contains("irst"), "{debug}");

        let mut parts = server.into_parts();
        assert_eq!(parts.plaintext, b"irst record");
        assert!(parts.outgoing_tls.is_empty());
        assert!(parts.early_data.is_empty());
        let debug = format!("{parts:?}");
        assert!(debug.contains("plaintext: 11"), "{debug}");
        // The second record is still TLS bytes: the connection takes it
        // from there.
        assert!(!parts.incoming_tls.is_empty());
        let status = parts
            .connection
            .process_tls_records(&mut parts.incoming_tls);
        match status.state.unwrap() {
            ConnectionState::ReadTraffic(record) => {
                assert_eq!(record.payload(), b"second record", "{version:?}");
            }
            state => panic!("{state:?}"),
        }
        drop(transport);
        drop(parts.io);
    }
}

#[tokio::test]
async fn unwritten_records_come_out_of_into_parts() {
    let pki = Pki::new();
    let (c, s) = duplex(1 << 20);
    let gate = Arc::new(GateState::default());
    let c = Gate::new(c, gate.clone());
    let (mut client, server) = pair(&pki, &browntls_core::version::TLS13, c, s).await;

    // The transport takes nothing: the write is accepted, and its record
    // waits in the stream.
    gate.close();
    let n = poll_fn(|cx| Pin::new(&mut client).poll_write(cx, b"left in the outgoing buffer"))
        .await
        .unwrap();
    assert_eq!(n, 27);
    // The next write waits for the transport to take that record.
    let waiting = timeout(Duration::from_millis(100), client.write(b"more")).await;
    assert!(waiting.is_err());

    let parts = client.into_parts();
    assert!(parts.outgoing_tls.len() > 27);
    assert!(parts.plaintext.is_empty());
    assert!(parts.incoming_tls.is_empty());
    drop(server);
}
