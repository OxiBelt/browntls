//! `browntls-tokio` streams placed by the load-aware routing
//! (`browntls_ktls::routing::AsyncRoutedStream`): in userspace while kernel
//! TLS is not in the order, with the kernel while it is, back in userspace
//! when the kernel cannot take them or the routing keeps them there, timed
//! in both places, and placed in their 0-RTT phase.
//!
//! The routing's state is process-wide, so everything runs in one test
//! function (each integration test file is its own process). The parts
//! that need kernel TLS are skipped without the `tls` module unless
//! `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", feature = "native", feature = "tokio"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls::crypto::native::accel::load::{self, Config, Phase, kernel};
use browntls::server::ServerSessionMemoryCache;
use browntls::{ProtocolVersion, SupportedCipherSuite};
use browntls_ktls::routing::{self, AsyncOffload, AsyncRoutedStream, Place, Records};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// One full record per write, so that every write is long enough to time.
const WRITE: usize = 16384;
const LIMIT: Duration = Duration::from_secs(60);

/// What became of one end of a connection.
#[derive(Debug)]
struct End {
    place: Place,
    /// The kind of the kernel's refusal, for an end that was placed with
    /// the kernel and stayed in userspace.
    refusal: Option<io::ErrorKind>,
}

impl End {
    fn of<T: AsyncOffload>(tls: &AsyncRoutedStream<T>) -> Self {
        Self {
            place: tls.place(),
            refusal: match tls {
                AsyncRoutedStream::Kernel(_) => None,
                AsyncRoutedStream::Userspace(stream) => {
                    stream.kernel_refusal().map(io::Error::kind)
                }
            },
        }
    }
}

/// A connected loopback pair of Tokio sockets: (client, server).
fn tokio_pair() -> (TcpStream, TcpStream) {
    let (client, server) = tcp_pair();
    let tokio = |tcp: std::net::TcpStream| {
        tcp.set_nonblocking(true).unwrap();
        TcpStream::from_std(tcp).unwrap()
    };
    (tokio(client), tokio(server))
}

async fn read_n_async<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    timeout(LIMIT, r.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf
}

async fn read_to_end_async<R: AsyncRead + Unpin>(r: &mut R) -> Vec<u8> {
    let mut buf = Vec::new();
    timeout(LIMIT, r.read_to_end(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf
}

/// Writes `data` one record at a time, and flushes.
async fn write_records<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) {
    timeout(LIMIT, async {
        for chunk in data.chunks(WRITE) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
    })
    .await
    .expect("write timed out");
}

async fn shutdown_async<W: AsyncWrite + Unpin>(w: &mut W) {
    timeout(LIMIT, w.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap();
}

/// Runs one connection with `suite` over loopback, both ends placed after
/// the handshake, the server's on another task: `writes` records of data
/// in each direction and an orderly close. Returns what became of the
/// client's and the server's end.
async fn connection(
    pki: &Pki,
    suite: SupportedCipherSuite,
    writes: usize,
    extraction: bool,
) -> [End; 2] {
    let mut client_config = pki.client_config(suite);
    client_config.enable_secret_extraction = extraction;
    let mut server_config = pki.server_config(suite);
    server_config.enable_secret_extraction = extraction;
    let (client_tcp, server_tcp) = tokio_pair();
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_tcp),
        TlsAcceptor::from(Arc::new(server_config)).accept(server_tcp),
    );
    let (client, server) = (client.unwrap(), server.unwrap());
    let up = Arc::new(pattern(writes * WRITE, 1));
    let down = Arc::new(pattern(writes * WRITE, 2));

    let (sent, expected) = (down.clone(), up.clone());
    let server = tokio::spawn(async move {
        let mut tls = timeout(LIMIT, AsyncRoutedStream::from_server(server))
            .await
            .expect("placement timed out")
            .unwrap();
        let end = End::of(&tls);
        assert_eq!(read_n_async(&mut tls, expected.len()).await, *expected);
        write_records(&mut tls, &sent).await;
        // The client's close_notify.
        assert!(read_to_end_async(&mut tls).await.is_empty());
        shutdown_async(&mut tls).await;
        end
    });
    let mut tls = timeout(LIMIT, AsyncRoutedStream::from_client(client))
        .await
        .expect("placement timed out")
        .unwrap();
    let end = End::of(&tls);
    write_records(&mut tls, &up).await;
    assert_eq!(read_n_async(&mut tls, down.len()).await, *down, "{suite:?}");
    shutdown_async(&mut tls).await;
    assert!(read_to_end_async(&mut tls).await.is_empty(), "{suite:?}");
    [end, server.await.unwrap()]
}

/// Runs one resumed connection with the TLS 1.3 `suite` whose ends are
/// placed in their 0-RTT phase: the client before it has sent anything
/// (it has no cipher suite yet), the server before the client's Finished.
/// The early data reaches the server once and in front, wherever the ends
/// went. Returns what became of the client's and the server's end.
async fn early_connection(pki: &Pki, suite: SupportedCipherSuite) -> [End; 2] {
    const EARLY: &[u8] = b"early request";
    const ALL: &[u8] = b"early request and more";
    let mut client_config = pki.client_config(suite);
    client_config.enable_early_data = true;
    let connector = TlsConnector::from(Arc::new(client_config)).early_data(true);
    let mut server_config = pki.server_config(suite);
    server_config.max_early_data_size = 1024;
    server_config.session_storage = ServerSessionMemoryCache::new(8);
    let acceptor = TlsAcceptor::from(Arc::new(server_config)).early_data(true);

    // A first connection leaves the client a ticket.
    let (client_tcp, server_tcp) = tokio_pair();
    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_tcp),
        acceptor.accept(server_tcp),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    server.write_all(b"t").await.unwrap();
    shutdown_async(&mut server).await;
    assert_eq!(read_to_end_async(&mut client).await, b"t");
    assert!(client.get_ref().1.tls13_tickets_received() > 0);

    let (client_tcp, server_tcp) = tokio_pair();
    let server = tokio::spawn(async move {
        let server = timeout(LIMIT, acceptor.accept(server_tcp))
            .await
            .expect("accept timed out")
            .unwrap();
        assert!(server.get_ref().1.is_handshaking());
        let mut tls = timeout(LIMIT, AsyncRoutedStream::from_server(server))
            .await
            .expect("placement timed out")
            .unwrap();
        let end = End::of(&tls);
        let mut got = Vec::new();
        match &mut tls {
            // The handover completed the handshake and took the early
            // data, which the stream returns first.
            AsyncRoutedStream::Kernel(stream) => {
                assert_eq!(stream.early_data_len(), EARLY.len());
            }
            // Nothing was taken out of the stream: its early data is
            // where it was, and ends with the handshake.
            AsyncRoutedStream::Userspace(stream) => {
                assert_eq!(stream.early_data_len(), 0);
                assert!(stream.received().is_empty());
                let mut early = stream.get_mut().early_data().unwrap();
                timeout(LIMIT, early.read_to_end(&mut got))
                    .await
                    .expect("read timed out")
                    .unwrap();
                assert!(got.starts_with(EARLY));
            }
        }
        got.extend(read_n_async(&mut tls, ALL.len() - got.len()).await);
        assert_eq!(got, ALL);
        write_records(&mut tls, b"reply").await;
        assert!(read_to_end_async(&mut tls).await.is_empty());
        shutdown_async(&mut tls).await;
        end
    });
    let mut client = connector.connect(localhost(), client_tcp).await.unwrap();
    assert!(client.get_ref().1.is_handshaking());
    assert!(client.get_ref().1.negotiated_cipher_suite().is_none());
    client.write_all(EARLY).await.unwrap();
    let mut tls = timeout(LIMIT, AsyncRoutedStream::from_client(client))
        .await
        .expect("placement timed out")
        .unwrap();
    let end = End::of(&tls);
    write_records(&mut tls, &ALL[EARLY.len()..]).await;
    assert_eq!(read_n_async(&mut tls, 5).await, b"reply");
    shutdown_async(&mut tls).await;
    assert!(read_to_end_async(&mut tls).await.is_empty());
    [end, server.await.unwrap()]
}

/// The stream that places connections with `suite`, by the suite's name.
fn records_of(suite: SupportedCipherSuite) -> Option<Records> {
    let name = format!("{:?}", suite.suite());
    if name.contains("AES_128_GCM") {
        Some(Records::Aes128Gcm)
    } else if name.contains("AES_256_GCM") {
        Some(Records::Aes256Gcm)
    } else if name.contains("CHACHA20_POLY1305") {
        Some(Records::ChaCha20Poly1305)
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_go_where_the_routing_places_them() {
    let pki = Pki::new();
    let suites = offloadable_suites();
    let has_kernel_tls = kernel_tls();
    let routed: Vec<(SupportedCipherSuite, Records)> = suites
        .iter()
        .filter_map(|suite| Some((*suite, records_of(*suite)?)))
        .collect();
    assert!(routed.len() >= 3, "{suites:?}");
    assert!(
        routed.len() < suites.len(),
        "AES-CCM has no stream: {suites:?}"
    );
    let tls13 = routed
        .iter()
        .map(|(suite, _)| *suite)
        .find(|suite| suite.version().version == ProtocolVersion::TLSv1_3)
        .unwrap();

    // Kernel TLS is not in the order: every stream stays in userspace and
    // the kernel is not asked, with routing off or on.
    assert!(!routing::is_active());
    for enabled in [false, true] {
        if enabled {
            load::enable(Config::DEFAULT).unwrap();
        }
        for suite in &suites {
            for end in connection(&pki, *suite, 2, true).await {
                assert_eq!(
                    (end.place, end.refusal),
                    (Place::Userspace, None),
                    "{suite:?}"
                );
            }
        }
        for end in early_connection(&pki, tls13).await {
            assert_eq!((end.place, end.refusal), (Place::Userspace, None));
        }
        assert_eq!(kernel::status_all().count(), 0);
    }
    load::disable();

    // Activating asks the running kernel, which may load the `tls` module
    // for it.
    let has_kernel_tls = match routing::activate() {
        Ok(()) => true,
        Err(err) => {
            assert!(!has_kernel_tls && !routing::is_active(), "{err}");
            // Put it in the order all the same: a kernel that refuses.
            kernel::activate();
            false
        }
    };
    assert!(routing::is_active());

    // In the order: every stream goes to the kernel, or stays in userspace
    // with the kernel's refusal when it cannot go.
    for suite in &suites {
        for end in connection(&pki, *suite, 2, true).await {
            if has_kernel_tls {
                assert_eq!((end.place, end.refusal), (Place::Kernel, None), "{suite:?}");
            } else {
                assert_eq!(end.place, Place::Userspace, "{suite:?}");
                assert!(end.refusal.is_some(), "{suite:?}");
            }
        }
        // A stream without a kernel form is refused before the kernel is
        // asked.
        for end in connection(&pki, *suite, 1, false).await {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, Some(io::ErrorKind::Unsupported)),
                "{suite:?}"
            );
        }
    }
    // So do streams in their 0-RTT phase: the handover completes the
    // handshake, and a refusal leaves them in the phase.
    for end in early_connection(&pki, tls13).await {
        if has_kernel_tls {
            assert_eq!((end.place, end.refusal), (Place::Kernel, None));
        } else {
            assert_eq!(end.place, Place::Userspace);
            assert!(end.refusal.is_some());
        }
    }

    // With load-aware routing the writes are timed where they happen.
    load::enable(Config::DEFAULT).unwrap();
    // The streams whose kernel channel has a cost: it is kept when the
    // share changes, and two suites may share a stream.
    let mut kernel_timed = Vec::new();
    for (suite, records) in &routed {
        // Kept in userspace by the routing: the kernel is not asked.
        kernel::set_fixed(*records, 100).unwrap();
        for end in connection(&pki, *suite, 400, true).await {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, None),
                "{suite:?}"
            );
        }
        let s = kernel::status(*records).unwrap();
        println!("{s}");
        assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, 100));
        assert!(s.alternate_cost.is_some_and(|ps| ps > 0), "{s}");
        assert_eq!(
            s.primary_cost.is_some(),
            kernel_timed.contains(records),
            "{s}"
        );

        // All with the kernel.
        kernel::set_fixed(*records, 0).unwrap();
        let ends = connection(&pki, *suite, 400, true).await;
        let s = kernel::status(*records).unwrap();
        println!("{s}");
        for end in ends {
            if has_kernel_tls {
                assert_eq!((end.place, end.refusal), (Place::Kernel, None), "{suite:?}");
                assert!(s.primary_cost.is_some_and(|ps| ps > 0), "{s}");
                kernel_timed.push(*records);
            } else {
                // Refused streams are timed as what they are.
                assert_eq!(end.place, Place::Userspace, "{suite:?}");
                assert!(end.refusal.is_some(), "{suite:?}");
                assert_eq!(s.primary_cost, None, "{s}");
            }
        }

        // Half and half: ends in different places talk to each other.
        kernel::set_fixed(*records, 50).unwrap();
        let mut kept = 0;
        for _ in 0..16 {
            for end in connection(&pki, *suite, 2, true).await {
                if end.refusal.is_none() && end.place == Place::Userspace {
                    kept += 1;
                } else {
                    assert_eq!(end.place == Place::Kernel, has_kernel_tls, "{suite:?}");
                }
            }
        }
        assert!((1..32).contains(&kept), "{suite:?}: {kept} of 32 ends");
        kernel::clear_fixed(*records);
    }
    // A suite without a stream follows the order.
    for suite in suites.iter().filter(|suite| records_of(**suite).is_none()) {
        for end in connection(&pki, *suite, 2, true).await {
            assert_eq!(end.place == Place::Kernel, has_kernel_tls, "{suite:?}");
        }
    }

    // Out of the order again.
    routing::deactivate();
    assert!(!routing::is_active());
    for (suite, _) in &routed {
        for end in connection(&pki, *suite, 2, true).await {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, None),
                "{suite:?}"
            );
        }
    }
    load::disable();
}
