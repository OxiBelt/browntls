//! Handshakes, data transfer and closure between a browntls-tokio client and
//! server over in-memory and TCP transports.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use browntls::{Error, ProtocolVersion};
use browntls_tokio::{TlsStream, client, server};
use common::*;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// Connects a client and a server over `client_io` and `server_io`.
async fn pair<C, S>(
    pki: &Pki,
    version: &'static browntls::SupportedProtocolVersion,
    client_io: C,
    server_io: S,
) -> (client::TlsStream<C>, server::TlsStream<S>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connector = pki.connector(version);
    let acceptor = pki.acceptor(version);
    let (client, server) = timeout(
        LIMIT,
        futures_join(
            connector.connect(localhost(), client_io),
            acceptor.accept(server_io),
        ),
    )
    .await
    .expect("handshake timed out");
    (
        client.expect("client handshake"),
        server.expect("server handshake"),
    )
}

async fn futures_join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    tokio::join!(a, b)
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

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
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
async fn close_notify_ends_reads_and_forbids_later_writes() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (mut client, mut server) = pair(&pki, version, c, s).await;

        client.write_all(b"last words").await.unwrap();
        client.shutdown().await.unwrap();
        let err = client.write_all(b"more").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"last words");
        // End of file is sticky.
        assert_eq!(server.read(&mut [0; 8]).await.unwrap(), 0);

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
        let connector = stranger.connector(version);
        let acceptor = pki.acceptor(version);
        let (client, server) = timeout(
            LIMIT,
            futures_join(connector.connect(localhost(), c), acceptor.accept(s)),
        )
        .await
        .unwrap();

        let err = client.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            matches!(tls_error(&err), Some(Error::InvalidCertificate(_))),
            "{err:?}"
        );
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
    let version = &browntls::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    let mut connect = stranger.connector(version).connect(localhost(), c);
    assert!(connect.get_ref().is_some());
    assert!(connect.get_mut().is_some());
    let (client, server) = tokio::join!(
        connect.into_fallible(),
        pki.acceptor(version).accept(s).into_fallible()
    );
    let Err((err, mut transport)) = client else {
        panic!("client must fail");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // The transport is still usable: the server's last flight is in it.
    transport.shutdown().await.unwrap();
    assert!(server.is_err());
}

#[tokio::test]
async fn eof_during_the_handshake_fails_it() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    drop(s);
    let err = pki
        .connector(&browntls::version::TLS13)
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
    let err = timeout(LIMIT, pki.acceptor(&browntls::version::TLS13).accept(s))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}");
}

#[tokio::test]
async fn close_notify_in_the_middle_of_a_handshake_ends_it() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut hello = Vec::new();
    let mut raw =
        browntls::ClientConnection::new(Arc::new(pki.client_config(version)), localhost()).unwrap();
    raw.write_tls(&mut hello).unwrap();
    // A plaintext warning-level close_notify alert record.
    hello.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);

    let (mut c, s) = duplex(64 * 1024);
    c.write_all(&hello).await.unwrap();
    // The transport stays open: only the TLS state can end the handshake.
    let result = timeout(LIMIT, pki.acceptor(version).accept(s))
        .await
        .expect("handshake must end, not spin or hang");
    assert!(result.is_err());
    drop(c);
}

#[tokio::test]
async fn alpn_and_connection_hooks() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut server_config = pki.server_config(version);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = browntls_tokio::TlsAcceptor::from(Arc::new(server_config));
    let connector = pki.connector(version);
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
}

#[tokio::test]
async fn key_updates_keep_the_stream_working() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, mut server) = pair(&pki, &browntls::version::TLS13, c, s).await;

    for round in 0..5u8 {
        server.get_mut().1.refresh_traffic_keys().unwrap();
        server.write_all(&[round; 100]).await.unwrap();
        server.flush().await.unwrap();
        let mut buf = [0; 100];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [round; 100]);

        // The client answers the server's request with its next write.
        client.write_all(&[round ^ 0xff; 50]).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 50];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [round ^ 0xff; 50]);
    }
}

#[tokio::test]
async fn buffered_reads_and_vectored_writes() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, server) = pair(&pki, &browntls::version::TLS13, c, s).await;

    let bufs = [
        io::IoSlice::new(b"first line\n"),
        io::IoSlice::new(b"second "),
        io::IoSlice::new(b"line\n"),
    ];
    assert!(client.is_write_vectored());
    let written = client.write_vectored(&bufs).await.unwrap();
    assert_eq!(written, 23, "a vectored write takes every slice at once");
    client.shutdown().await.unwrap();

    let mut lines = BufReader::new(server).lines();
    assert_eq!(lines.next_line().await.unwrap().unwrap(), "first line");
    assert_eq!(lines.next_line().await.unwrap().unwrap(), "second line");
    assert_eq!(lines.next_line().await.unwrap(), None);
}

#[tokio::test]
async fn the_unified_stream_type_dispatches_to_either_side() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (client, server) = pair(&pki, &browntls::version::TLS13, c, s).await;
    let mut client = TlsStream::from(client);
    let mut server = TlsStream::from(server);
    assert!(matches!(client, TlsStream::Client(_)));
    assert!(!client.get_ref().1.is_handshaking());
    assert_eq!(
        server.get_mut().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );

    client.write_all(b"via enum").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = String::new();
    server.read_to_string(&mut got).await.unwrap();
    assert_eq!(got, "via enum");
    let mut lines = BufReader::new(&mut client).lines();
    server.shutdown().await.unwrap();
    assert_eq!(lines.next_line().await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_loopback_with_concurrent_halves() {
    use tokio::net::{TcpListener, TcpStream};

    let pki = Arc::new(Pki::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_pki = pki.clone();
    let server = tokio::spawn(async move {
        let acceptor = server_pki.acceptor(&browntls::version::TLS13);
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        // Echo until the client closes, then close too.
        let (mut rd, mut wr) = tokio::io::split(tls);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = pki
        .connector(&browntls::version::TLS13)
        .connect(localhost(), tcp)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        assert!(tls.as_raw_fd() >= 0);
    }
    tls.get_ref().0.set_nodelay(true).unwrap();

    let data = pattern(1 << 20);
    let (mut rd, mut wr) = tokio::io::split(tls);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&sent).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut echoed = Vec::new();
    timeout(LIMIT, rd.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    server.await.unwrap();
    assert!(echoed == data, "echo differs");
}

#[tokio::test]
async fn a_corrupt_record_after_the_handshake_fails_the_read_with_an_alert() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let (mut client, server) = pair(&pki, &browntls::version::TLS13, c, s).await;
    let (mut transport, _) = server.into_inner();
    // A garbled application-data record: the client cannot decrypt it.
    transport
        .write_all(&[0x17, 0x03, 0x03, 0x00, 0x20])
        .await
        .unwrap();
    transport.write_all(&[0xAA; 0x20]).await.unwrap();

    let err = client.read(&mut [0; 16]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        matches!(tls_error(&err), Some(Error::DecryptError)),
        "{err:?}"
    );
    // The client told the server why.
    let mut header = [0; 5];
    transport.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 0x17, "an alert record, encrypted under TLS 1.3");
}
