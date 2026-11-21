//! TLS 1.3 0-RTT data on the server through `TlsAcceptor::early_data`: an
//! accept that returns before the handshake completes, the early data
//! reader, 0.5-RTT answers, and what a handshake failure in that phase does.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read as _, Write as _};
use std::time::Duration;

use browntls_core::server::Acceptor;
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor};
use common::server_early::*;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

#[tokio::test]
async fn early_data_is_read_and_answered_before_the_clients_finished() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    // The ClientHello and the early data; the client then stays silent.
    send(&mut client, &mut c).await;

    let test = async {
        let mut server = setup.acceptor(true).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        assert_eq!(read_early(&mut server, 13).await, b"early request");

        // 0.5-RTT data: written while the client's Finished is still out.
        server.write_all(b"reply").await.unwrap();
        assert!(server.get_ref().1.is_handshaking());

        receive(&mut client, &mut c).await;
        assert!(!client.is_handshaking());
        assert!(client.is_early_data_accepted());
        let mut reply = [0; 5];
        client.reader().read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");

        // The client's EndOfEarlyData and Finished end the early data.
        client.writer().write_all(b"after").unwrap();
        client.send_close_notify();
        send(&mut client, &mut c).await;
        let mut rest = Vec::new();
        server
            .early_data()
            .unwrap()
            .read_to_end(&mut rest)
            .await
            .unwrap();
        assert!(rest.is_empty());
        assert!(!server.get_ref().1.is_handshaking());

        // Ordinary reads see only the 1-RTT data.
        let mut after = Vec::new();
        server.read_to_end(&mut after).await.unwrap();
        assert_eq!(after, b"after");
        // The early data reader stays, at end of file.
        let mut rest = Vec::new();
        server
            .early_data()
            .unwrap()
            .read_to_end(&mut rest)
            .await
            .unwrap();
        assert!(rest.is_empty());
        server.shutdown().await.unwrap();
    };
    timeout(LIMIT, test).await.expect("timed out");
}

#[tokio::test]
async fn without_half_rtt_a_write_waits_for_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;

    let test = async {
        let mut server = setup.acceptor(false).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        assert_eq!(read_early(&mut server, 13).await, b"early request");

        // The write cannot go out yet: it is still waiting when the client
        // has the whole server flight, and no answer with it.
        let mut write = Box::pin(server.write_all(b"reply"));
        let client_side = async {
            receive(&mut client, &mut c).await;
            assert!(!client.is_handshaking());
            assert!(matches!(
                client.reader().read(&mut [0; 8]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock
            ));
        };
        tokio::select! {
            biased;
            result = &mut write => panic!("the write did not wait: {result:?}"),
            () = client_side => {}
        }
        send(&mut client, &mut c).await;
        write.await.unwrap();
        assert!(!server.get_ref().1.is_handshaking());
        server.flush().await.unwrap();

        receive(&mut client, &mut c).await;
        let mut reply = Vec::new();
        // Tickets may come in records of their own, ahead of the answer.
        while reply.len() < 5 {
            let mut chunk = [0; 5];
            match client.reader().read(&mut chunk) {
                Ok(n) => reply.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    receive(&mut client, &mut c).await;
                }
                Err(err) => panic!("{err}"),
            }
        }
        assert_eq!(reply, b"reply");
    };
    timeout(LIMIT, test).await.expect("timed out");
}

#[tokio::test]
async fn a_flush_sends_half_rtt_data_before_it_waits_for_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;

    let test = async {
        // A transport that holds what it is given until it is flushed.
        let s = tokio::io::BufWriter::with_capacity(32 * 1024, s);
        let mut server = setup.acceptor(true).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        assert_eq!(read_early(&mut server, 13).await, b"early request");
        server.write_all(b"reply").await.unwrap();

        let mut flush = Box::pin(server.flush());
        let client_side = async {
            // The server's flight, which `accept` flushed, then the answer.
            let mut reply = [0; 5];
            loop {
                receive(&mut client, &mut c).await;
                match client.reader().read(&mut reply) {
                    Ok(n) => break assert_eq!(&reply[..n], b"reply"),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => panic!("{err}"),
                }
            }
        };
        tokio::select! {
            biased;
            result = &mut flush => panic!("the flush did not wait: {result:?}"),
            () = client_side => {}
        }
        send(&mut client, &mut c).await;
        flush.await.unwrap();
        assert!(!server.get_ref().1.is_handshaking());
    };
    timeout(LIMIT, test).await.expect("timed out");
}

#[tokio::test]
async fn reading_early_data_to_the_end_waits_for_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let data = pattern(ALLOWANCE as usize);
    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(&data).await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert!(client.get_ref().1.is_early_data_accepted());
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(false).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        let mut early = Vec::new();
        server
            .early_data()
            .unwrap()
            .read_to_end(&mut early)
            .await
            .unwrap();
        assert!(early == data, "early data differs");
        assert!(!server.get_ref().1.is_handshaking());
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn an_ordinary_read_completes_the_handshake_and_skips_early_data() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.flush().await.unwrap();
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(true).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after");
        assert!(!server.get_ref().1.is_handshaking());
        // Still there for its reader, which no longer waits for anything.
        let mut early = Vec::new();
        server
            .early_data()
            .unwrap()
            .read_to_end(&mut early)
            .await
            .unwrap();
        assert_eq!(early, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn a_flush_or_a_shutdown_completes_the_handshake() {
    for half_rtt in [false, true] {
        for shutdown in [false, true] {
            let setup = Setup::new();
            setup.first_connection().await;

            let (c, s) = duplex(64 * 1024);
            let client_side = async {
                let mut client = setup.connector.connect(localhost(), c).await.unwrap();
                client.write_all(b"early request").await.unwrap();
                let mut reply = Vec::new();
                if shutdown {
                    client.read_to_end(&mut reply).await.unwrap();
                } else {
                    reply.resize(5, 0);
                    client.read_exact(&mut reply).await.unwrap();
                }
                assert_eq!(reply, b"reply");
                client
            };
            let server_side = async {
                let mut server = setup.acceptor(half_rtt).accept(s).await.unwrap();
                assert!(server.get_ref().1.is_handshaking());
                if half_rtt {
                    server.write_all(b"reply").await.unwrap();
                    assert!(server.get_ref().1.is_handshaking());
                }
                if shutdown {
                    if !half_rtt {
                        server.write_all(b"reply").await.unwrap();
                    }
                    server.shutdown().await.unwrap();
                } else {
                    server.flush().await.unwrap();
                    assert!(!server.get_ref().1.is_handshaking());
                    if !half_rtt {
                        server.write_all(b"reply").await.unwrap();
                        server.flush().await.unwrap();
                    }
                }
                assert!(!server.get_ref().1.is_handshaking());
                assert_eq!(read_early(&mut server, 13).await, b"early request");
                server
            };
            timeout(LIMIT, async { tokio::join!(client_side, server_side) })
                .await
                .expect("timed out");
        }
    }
}

#[tokio::test]
async fn declined_early_data_is_accepted_after_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.flush().await.unwrap();
        assert!(!client.get_ref().1.is_early_data_accepted());
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        // The option is on, but this server takes no early data.
        let acceptor = TlsAcceptor::from(setup.server_config(0, true)).early_data(true);
        let mut server = acceptor.accept(s).await.unwrap();
        assert!(!server.get_ref().1.is_handshaking());
        assert!(server.early_data().is_none());
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn without_the_option_accept_waits_and_the_reader_has_everything() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let acceptor = TlsAcceptor::from(setup.server_config(ALLOWANCE, true));
        let mut server = acceptor.accept(s).await.unwrap();
        assert!(!server.get_ref().1.is_handshaking());
        let mut early = Vec::new();
        server
            .early_data()
            .expect("early data accepted")
            .read_to_end(&mut early)
            .await
            .unwrap();
        assert_eq!(early, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn the_lazy_acceptor_returns_early_too() {
    for half_rtt in [false, true] {
        let setup = Setup::new();
        setup.first_connection().await;

        let (mut c, s) = duplex(64 * 1024);
        let mut client = setup.manual_client(b"early request");
        // The ClientHello and the early data arrive together, so the lazy
        // acceptor reads both; the client then stays silent.
        send(&mut client, &mut c).await;

        let test = async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s)
                .await
                .unwrap();
            let mut server = start
                .early_data(true)
                .into_stream(setup.server_config(ALLOWANCE, half_rtt))
                .await
                .unwrap();
            assert!(server.get_ref().1.is_handshaking());
            assert_eq!(read_early(&mut server, 13).await, b"early request");
            if half_rtt {
                server.write_all(b"reply").await.unwrap();
                assert!(server.get_ref().1.is_handshaking());
            }

            receive(&mut client, &mut c).await;
            assert!(client.is_early_data_accepted());
            send(&mut client, &mut c).await;
            server.flush().await.unwrap();
            assert!(!server.get_ref().1.is_handshaking());
        };
        timeout(LIMIT, test).await.expect("timed out");
    }
}

#[tokio::test]
async fn the_lazy_acceptor_waits_without_the_option() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), s)
            .await
            .unwrap();
        let mut server = start
            .into_stream(setup.server_config(ALLOWANCE, true))
            .await
            .unwrap();
        assert!(!server.get_ref().1.is_handshaking());
        assert_eq!(read_early(&mut server, 13).await, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn what_the_lazy_acceptor_read_past_the_client_hello_is_checked_at_once() {
    for early_data in [false, true] {
        let setup = Setup::new();
        setup.first_connection().await;

        let (mut c, s) = duplex(64 * 1024);
        let mut client = setup.manual_client(b"early request");
        let mut tls = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut tls).unwrap();
        }
        // Not a TLS record, in the same read as the ClientHello.
        tls.extend_from_slice(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        c.write_all(&tls).await.unwrap();

        let test = async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s)
                .await
                .unwrap();
            // The transport stays open and silent: only what was read
            // already can fail the handshake.
            let err = start
                .early_data(early_data)
                .into_stream(setup.server_config(ALLOWANCE, false))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(tls_error(&err).is_some(), "{err:?}");
            // The server's flight, then the alert, reached the client.
            let mut got = vec![0; 32 * 1024];
            let n = c.read(&mut got).await.unwrap();
            let mut got = &got[..n];
            let failed = loop {
                if got.is_empty() {
                    break None;
                }
                client.read_tls(&mut got).unwrap();
                if let Err(err) = client.process_new_packets() {
                    break Some(err);
                }
            };
            assert!(
                matches!(failed, Some(browntls_core::Error::AlertReceived(_))),
                "{failed:?}"
            );
        };
        timeout(LIMIT, test).await.expect("timed out");
    }
}

#[tokio::test]
async fn the_early_phase_survives_a_choppy_transport() {
    for half_rtt in [false, true] {
        let setup = Setup::new();
        setup.first_connection().await;

        let data = pattern(ALLOWANCE as usize);
        let reply = pattern(40_000);
        // Smaller than the early data and than the answer, but room for the
        // server's flight: while that is unwritten the server reads nothing,
        // and a client with early data still to write reads nothing either.
        let (c, s) = duplex(4096);
        let client_side = async {
            let mut client = setup
                .connector
                .connect(localhost(), Choppy::new(c, 97))
                .await
                .unwrap();
            client.write_all(&data).await.unwrap();
            let mut got = vec![0; reply.len()];
            client.read_exact(&mut got).await.unwrap();
            assert!(got == reply, "reply differs");
            assert!(client.get_ref().1.is_early_data_accepted());
            client.write_all(b"after").await.unwrap();
            client.shutdown().await.unwrap();
            client
        };
        let server_side = async {
            let mut server = setup
                .acceptor(half_rtt)
                .accept(Choppy::new(s, 61))
                .await
                .unwrap();
            assert!(server.get_ref().1.is_handshaking());
            // A reader that takes the early data a few bytes at a time.
            let mut early = Vec::new();
            let mut reader = server.early_data().unwrap();
            let mut chunk = [0; 113];
            while early.len() < data.len() {
                let n = reader.read(&mut chunk).await.unwrap();
                assert!(n > 0, "early data ended at {}", early.len());
                early.extend_from_slice(&chunk[..n]);
            }
            assert!(early == data, "early data differs");
            server.write_all(&reply).await.unwrap();
            server.flush().await.unwrap();
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, b"after");
        };
        timeout(LIMIT, async { tokio::join!(client_side, server_side) })
            .await
            .expect("timed out");
    }
}

/// What ended the client's part of a handshake that never completes.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// The transport ends.
    Eof,
    /// Bytes that are no TLS record follow the early data.
    Garbage,
}

#[tokio::test]
async fn a_failed_handshake_ends_the_early_data_and_every_later_operation() {
    // Whether the early data reader or a flush meets the failure first.
    let cases = [Failure::Eof, Failure::Garbage]
        .into_iter()
        .flat_map(|failure| [false, true].map(|half_rtt| (failure, half_rtt)))
        .flat_map(|(failure, half_rtt)| [false, true].map(|flush| (failure, half_rtt, flush)));
    for (failure, half_rtt, flush_first) in cases {
        let setup = Setup::new();
        setup.first_connection().await;

        let (mut c, s) = duplex(64 * 1024);
        let mut client = setup.manual_client(b"early request");
        send(&mut client, &mut c).await;
        let mut server = setup.acceptor(half_rtt).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());

        let _open = match failure {
            Failure::Eof => {
                drop(c);
                None
            }
            Failure::Garbage => {
                c.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await
                    .unwrap();
                // Stays open: only the TLS state ends the operations.
                Some(c)
            }
        };
        let expect = |err: &io::Error| match failure {
            Failure::Eof => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}"),
            Failure::Garbage => assert!(tls_error(err).is_some(), "{err:?}"),
        };

        if flush_first {
            let err = timeout(LIMIT, server.flush()).await.unwrap().unwrap_err();
            expect(&err);
        }
        // The early data that arrived is read; then the failure.
        let mut early = Vec::new();
        let err = timeout(LIMIT, server.early_data().unwrap().read_to_end(&mut early))
            .await
            .unwrap()
            .unwrap_err();
        expect(&err);
        assert_eq!(early, b"early request", "{failure:?}");

        for _ in 0..2 {
            let mut reader = server.early_data().unwrap();
            let err = timeout(LIMIT, reader.read(&mut [0; 4]))
                .await
                .unwrap()
                .unwrap_err();
            expect(&err);
            let err = timeout(LIMIT, server.read(&mut [0; 4]))
                .await
                .unwrap()
                .unwrap_err();
            expect(&err);
            let err = timeout(LIMIT, server.write(b"more"))
                .await
                .unwrap()
                .unwrap_err();
            expect(&err);
            // A write of nothing too, plain or vectored.
            let err = timeout(LIMIT, server.write(&[]))
                .await
                .unwrap()
                .unwrap_err();
            expect(&err);
            let empty = [io::IoSlice::new(b"")];
            let err = timeout(LIMIT, server.write_vectored(&empty))
                .await
                .unwrap()
                .unwrap_err();
            expect(&err);
            let err = timeout(LIMIT, server.flush()).await.unwrap().unwrap_err();
            expect(&err);
        }
        let err = timeout(LIMIT, server.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        expect(&err);
    }
}

#[tokio::test]
async fn a_replayed_first_flight_is_not_accepted_early() {
    let setup = Setup::new();
    setup.first_connection().await;

    let mut client = setup.manual_client(b"early request");
    let mut first_flight = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut first_flight).unwrap();
    }

    // The genuine attempt: the session leaves the storage, and the early
    // data is read before the handshake completes.
    let (mut c, s) = duplex(64 * 1024);
    c.write_all(&first_flight).await.unwrap();
    let mut server = timeout(LIMIT, setup.acceptor(true).accept(s))
        .await
        .unwrap()
        .unwrap();
    assert!(server.get_ref().1.is_handshaking());
    assert_eq!(read_early(&mut server, 13).await, b"early request");

    // The same bytes again, to a server sharing the storage: no session,
    // so no early data, and no stream before a handshake that the replay
    // cannot complete.
    let (mut c, s) = duplex(64 * 1024);
    c.write_all(&first_flight).await.unwrap();
    let mut accept = setup.acceptor(true).accept(s);
    assert!(
        timeout(Duration::from_millis(300), &mut accept)
            .await
            .is_err(),
        "a stream was handed out for a replayed flight"
    );
    // The server answered with a full handshake's flight and waits.
    let mut flight = vec![0; 32 * 1024];
    assert!(c.read(&mut flight).await.unwrap() > 0);
    drop(c);
    let err = timeout(LIMIT, accept).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}");
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn a_tls12_connection_is_accepted_after_its_handshake() {
    let setup = Setup::new();
    let version = &browntls_core::version::TLS12;
    let mut config = setup.pki.server_config(version);
    config.max_early_data_size = ALLOWANCE;
    config.send_half_rtt_data = true;
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config)).early_data(true);

    let (c, s) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            setup.pki.connector(version).connect(localhost(), c),
            acceptor.accept(s)
        )
    })
    .await
    .expect("timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(!server.get_ref().1.is_handshaking());
    assert!(server.early_data().is_none());
    client.write_all(b"plain").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"plain");
}

#[tokio::test]
async fn buffered_reads_and_vectored_writes_work_in_the_early_phase() {
    use tokio::io::AsyncBufReadExt as _;

    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"half reply");
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(true).accept(s).await.unwrap();
        assert!(server.get_ref().1.is_handshaking());
        let bufs = [io::IoSlice::new(b"half "), io::IoSlice::new(b"reply")];
        assert_eq!(server.write_vectored(&bufs).await.unwrap(), 10);
        assert!(server.get_ref().1.is_handshaking());
        // The buffered read completes the handshake and skips early data.
        let chunk = server.fill_buf().await.unwrap().to_vec();
        assert!(!server.get_ref().1.is_handshaking());
        assert!(
            b"after".starts_with(&chunk) && !chunk.is_empty(),
            "{chunk:?}"
        );
        assert_eq!(read_early(&mut server, 13).await, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

const SECRET_TOKEN: &str = "server-early-data-debug-secret";
const SECRET_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nAuthorization: Bearer server-early-data-debug-secret\r\n\r\n";

#[tokio::test]
async fn debug_output_omits_early_data() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(SECRET_REQUEST);
    send(&mut client, &mut c).await;
    let acceptor = setup.acceptor(true);
    assert!(format!("{acceptor:?}").contains("early_data: true"));
    let mut server = acceptor.accept(s).await.unwrap();
    assert!(server.get_ref().1.is_handshaking());

    let numbers: String = SECRET_REQUEST.iter().map(|b| format!("{b}, ")).collect();
    let reveals = |debug: &str| debug.contains(SECRET_TOKEN) || debug.contains(numbers.trim_end());
    for debug in [format!("{server:?}"), format!("{server:#?}")] {
        assert!(!reveals(&debug), "{debug}");
        assert!(debug.contains("half_rtt"), "{debug}");
    }
    let reader = server.early_data().unwrap();
    assert!(!reveals(&format!("{reader:?}")));
    let wrapped = browntls_tokio::TlsStream::Server(server);
    assert!(!reveals(&format!("{wrapped:?}")));
}
