//! `into_split`: the read and write halves of a TLS stream, used from one
//! task and from several, and put back together.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_tokio::{ReuniteError, TlsStream, client, server};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

async fn pair(
    pki: &Pki,
    version: &'static browntls::SupportedProtocolVersion,
    size: usize,
) -> (
    client::TlsStream<DuplexStream>,
    server::TlsStream<DuplexStream>,
) {
    let (c, s) = duplex(size);
    let (client, server) = tokio::join!(
        pki.connector(version).connect(localhost(), c),
        pki.acceptor(version).accept(s),
    );
    (client.unwrap(), server.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_tasks_move_data_both_ways_through_the_halves() {
    use tokio::net::{TcpListener, TcpStream};

    let pki = Arc::new(Pki::new());
    for version in versions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = pki.acceptor(version);
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.unwrap()
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let client = pki
            .connector(version)
            .connect(localhost(), tcp)
            .await
            .unwrap();
        let server = accept.await.unwrap();

        // Each side sends its own megabyte while it receives the other's,
        // in small and large writes, then closes its direction.
        let to_server = pattern(1 << 20);
        let to_client: Vec<u8> = pattern(1 << 20).into_iter().rev().collect();
        let (mut client_rd, mut client_wr) = client.into_split();
        let (mut server_rd, mut server_wr) = server.into_split();

        let data = to_server.clone();
        let client_writer = tokio::spawn(async move {
            for chunk in data.chunks(1021) {
                client_wr.write_all(chunk).await.unwrap();
            }
            client_wr.shutdown().await.unwrap();
            client_wr
        });
        let data = to_client.clone();
        let server_writer = tokio::spawn(async move {
            for chunk in data.chunks(70_001) {
                server_wr.write_all(chunk).await.unwrap();
                server_wr.flush().await.unwrap();
            }
            server_wr.shutdown().await.unwrap();
            server_wr
        });
        let client_reader = tokio::spawn(async move {
            let mut received = Vec::new();
            client_rd.read_to_end(&mut received).await.unwrap();
            (client_rd, received)
        });
        let server_reader = tokio::spawn(async move {
            let mut received = Vec::new();
            server_rd.read_to_end(&mut received).await.unwrap();
            (server_rd, received)
        });

        let (client_wr, server_wr, client_read, server_read) = timeout(LIMIT, async {
            tokio::join!(client_writer, server_writer, client_reader, server_reader)
        })
        .await
        .expect("the halves stopped moving data");
        let (client_rd, at_client) = client_read.unwrap();
        let (server_rd, at_server) = server_read.unwrap();
        assert!(at_client == to_client, "the client read other bytes");
        assert!(at_server == to_server, "the server read other bytes");

        // Together again, the streams show the session both halves closed.
        let client = client_rd.reunite(client_wr.unwrap()).unwrap();
        let server = server_wr.unwrap().reunite(server_rd).unwrap();
        assert!(!client.get_ref().1.is_handshaking());
        assert!(!server.get_ref().1.is_handshaking());
        assert_eq!(server.get_ref().1.server_name(), Some("localhost"));
    }
}

#[tokio::test]
async fn one_task_uses_both_halves() {
    let pki = Pki::new();
    // A transport smaller than the data: neither direction can finish
    // before the other moves.
    let (client, server) = pair(&pki, &browntls::version::TLS13, 4096).await;
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut server_rd, mut server_wr) = server.into_split();
    let data = pattern(200_000);

    let mut echoed = vec![0; data.len()];
    timeout(LIMIT, async {
        tokio::join!(
            async {
                client_wr.write_all(&data).await.unwrap();
                client_wr.flush().await.unwrap();
            },
            async {
                // The server sends back what it reads.
                let mut buf = vec![0; 3000];
                let mut left = data.len();
                while left > 0 {
                    let n = server_rd.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    server_wr.write_all(&buf[..n]).await.unwrap();
                    server_wr.flush().await.unwrap();
                    left -= n;
                }
            },
            async {
                client_rd.read_exact(&mut echoed).await.unwrap();
            },
        )
    })
    .await
    .expect("the halves stopped moving data");
    assert!(echoed == data, "the echo differs");
}

#[tokio::test]
async fn the_write_half_closes_the_session_and_the_read_half_reads_on() {
    let pki = Pki::new();
    for version in versions() {
        let (client, mut server) = pair(&pki, version, 64 * 1024).await;
        let (mut rd, mut wr) = client.into_split();

        wr.write_all(b"last words").await.unwrap();
        wr.shutdown().await.unwrap();
        // `close_notify` is sent: nothing may follow it.
        let err = wr.write_all(b"more").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        let mut heard = Vec::new();
        server.read_to_end(&mut heard).await.unwrap();
        assert_eq!(heard, b"last words");

        // The other direction is still open.
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        rd.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
    }
}

#[tokio::test]
async fn a_dropped_half_leaves_the_other_working() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;

    let (client, mut server) = pair(&pki, version, 64 * 1024).await;
    let (rd, mut wr) = client.into_split();
    drop(rd);
    wr.write_all(b"still writing").await.unwrap();
    wr.flush().await.unwrap();
    let mut buf = [0; 13];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still writing");

    let (client, mut server) = pair(&pki, version, 64 * 1024).await;
    let (mut rd, wr) = client.into_split();
    // Dropping the write half sends no `close_notify`: the server can go
    // on, and the client still reads what it sends.
    drop(wr);
    server.write_all(b"still reading").await.unwrap();
    server.flush().await.unwrap();
    rd.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still reading");
    // With the second half the stream, and its transport, are gone.
    drop(rd);
    let err = server.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn halves_of_different_streams_do_not_reunite() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (client, server) = pair(&pki, version, 64 * 1024).await;
    let (other, _other_server) = pair(&pki, version, 64 * 1024).await;

    let (rd, wr) = client.into_split();
    let (other_rd, other_wr) = other.into_split();
    assert!(rd.is_pair_of(&wr) && wr.is_pair_of(&rd));
    assert!(!rd.is_pair_of(&other_wr) && !other_wr.is_pair_of(&rd));

    let ReuniteError(rd, other_wr) = rd.reunite(other_wr).unwrap_err();
    let ReuniteError(other_rd, wr) = wr.reunite(other_rd).unwrap_err();

    // The halves came back unharmed: each stream still works.
    let mut client = rd.reunite(wr).unwrap();
    let mut server = server;
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut ping = [0; 4];
    server.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
    assert!(other_wr.reunite(other_rd).is_ok());
}

#[tokio::test]
async fn the_unified_stream_splits_too() {
    let pki = Pki::new();
    let (client, server) = pair(&pki, &browntls::version::TLS13, 64 * 1024).await;
    let (mut client_rd, mut client_wr) = TlsStream::from(client).into_split();
    let (mut server_rd, mut server_wr) = TlsStream::from(server).into_split();

    client_wr.write_all(b"ping").await.unwrap();
    client_wr.flush().await.unwrap();
    let mut buf = [0; 4];
    server_rd.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    server_wr.write_all(b"pong").await.unwrap();
    server_wr.flush().await.unwrap();
    client_rd.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    assert!(matches!(
        client_rd.reunite(client_wr).unwrap(),
        TlsStream::Client(_)
    ));
    assert!(matches!(
        server_wr.reunite(server_rd).unwrap(),
        TlsStream::Server(_)
    ));
}
