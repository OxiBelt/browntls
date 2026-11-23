//! TLS 1.3 0-RTT data through `TlsConnector::early_data`: accepted,
//! declined (and resent), and a read that completes the handshake.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/gate.rs"]
mod gate;

use std::future::Future as _;
use std::io::Read as _;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake, Waker};
use std::time::Duration;

use browntls_core::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls_core::{HandshakeKind, ServerConfig};
use browntls_tokio::{EarlyDataOutcome, RejectedEarlyDataPolicy, TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

struct Setup {
    pki: Pki,
    cache: Arc<dyn StoresServerSessions>,
    connector: TlsConnector,
}

impl Setup {
    fn new() -> Self {
        Self::with_alpn(&[])
    }

    /// A client offering `alpn`; the server selects the first it supports.
    fn with_alpn(alpn: &[&[u8]]) -> Self {
        let pki = Pki::new();
        let mut client_config = pki.client_config(&browntls_core::version::TLS13);
        client_config.enable_early_data = true;
        client_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Self {
            connector: TlsConnector::from(Arc::new(client_config)).early_data(true),
            cache: ServerSessionMemoryCache::new(8),
            pki,
        }
    }

    fn resend(&self, max_bytes: usize) -> TlsConnector {
        self.connector.clone().rejected_early_data_policy(
            RejectedEarlyDataPolicy::ResendIfSameAlpn {
                max_bytes: NonZeroUsize::new(max_bytes).unwrap(),
            },
        )
    }

    fn acceptor(&self, max_early_data_size: u32) -> TlsAcceptor {
        let mut config: ServerConfig = self.pki.server_config(&browntls_core::version::TLS13);
        config.max_early_data_size = max_early_data_size;
        config.session_storage = self.cache.clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// A full handshake that leaves the client a ticket allowing 1 KiB of
    /// early data.
    async fn first_connection(&self) {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(
            self.connector.connect(localhost(), c),
            self.acceptor(1024).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        // Reading the server's data processes the tickets sent before it.
        server.write_all(b"t").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(client.get_ref().1.tls13_tickets_received() > 0);
    }
}

#[tokio::test]
async fn accepted_early_data_and_a_read_that_completes_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        // Returns before the handshake: nothing has been sent yet.
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        assert!(client.get_ref().1.is_handshaking());
        client.write_all(b"early request").await.unwrap();
        // No flush: the read sends the ClientHello and early data, and
        // completes the handshake.
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert!(client.get_ref().1.is_early_data_accepted());
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Resumed)
        );
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        let mut early = Vec::new();
        server
            .get_mut()
            .1
            .early_data()
            .expect("early data accepted")
            .read_to_end(&mut early)
            .unwrap();
        assert_eq!(early, b"early request");
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        // Ordinary reads see only the 1-RTT data.
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn declined_early_data_is_resent_as_ordinary_data() {
    let setup = Setup::with_alpn(&[b"http/1.1", b"h2"]);
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.resend(512).connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        assert_eq!(
            client.finish_early_data().await.unwrap(),
            EarlyDataOutcome::Rejected {
                early_bytes: 13,
                resent_bytes: 13,
                unresent_bytes: 0,
            },
        );
        assert_eq!(
            client.early_data_outcome(),
            EarlyDataOutcome::Rejected {
                early_bytes: 13,
                resent_bytes: 13,
                unresent_bytes: 0,
            },
        );
        assert!(!client.get_ref().1.is_handshaking());
        assert!(!client.get_ref().1.is_early_data_accepted());
        client.shutdown().await.unwrap();
        // Kept open until the server is done writing its tickets.
        client
    };
    let server_side = async {
        // This server no longer takes early data.
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        assert!(server.get_mut().1.early_data().is_none());
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn early_data_beyond_the_allowance_goes_out_after_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let data = pattern(3000);
    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        // 1 KiB as early data; the write that finds the allowance spent
        // completes the handshake and sends the rest as 1-RTT data.
        client.write_all(&data).await.unwrap();
        assert!(!client.get_ref().1.is_handshaking());
        assert!(client.get_ref().1.is_early_data_accepted());
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        let mut got = Vec::new();
        server
            .get_mut()
            .1
            .early_data()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got.len(), 1024);
        server.read_to_end(&mut got).await.unwrap();
        assert!(got == data, "data differs");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn without_a_ticket_connect_waits_for_the_handshake() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        setup.connector.connect(localhost(), c),
        setup.acceptor(1024).accept(s),
    );
    assert!(!client.unwrap().get_ref().1.is_handshaking());
    server.unwrap();
}

#[tokio::test]
async fn declined_early_data_is_not_resent_when_the_protocol_may_differ() {
    check_rejection(&[b"h2", b"http/1.1"], Some(b"http/1.1")).await;
    check_rejection(&[], None).await;
}

async fn check_rejection(initial: &[&[u8]], next: Option<&[u8]>) {
    let setup = Setup::with_alpn(initial);
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup
            .resend(512)
            .with_alpn(next.into_iter().map(<[u8]>::to_vec).collect())
            .connect(localhost(), c)
            .await
            .unwrap();
        client.write_all(b"early request").await.unwrap();
        let err = client.flush().await.unwrap_err();
        let not_resent = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<browntls_tokio::client::EarlyDataNotResent>())
            .expect("EarlyDataNotResent");
        assert_eq!(not_resent.len, 13);
        assert!(!client.get_ref().1.is_early_data_accepted());
        assert_eq!(
            client.early_data_outcome(),
            EarlyDataOutcome::Rejected {
                early_bytes: 13,
                resent_bytes: 0,
                unresent_bytes: 13
            },
        );
        assert!(client.write_all(b"must wait").await.is_err());
        assert!(client.shutdown().await.is_err());
        assert_eq!(client.acknowledge_rejected_early_data(), Some(13));
        assert_eq!(client.acknowledge_rejected_early_data(), None);
        client.write_all(b"chosen again").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"chosen again");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn reporting_is_the_default_and_survives_finishing_through_a_read_half() {
    let setup = Setup::with_alpn(&[b"h2"]);
    setup.first_connection().await;
    let (c, s) = duplex(4096);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early").await.unwrap();
        let (mut read, mut write) = client.into_split();
        assert_eq!(read.read_u8().await.unwrap(), b'!');
        let outcome = EarlyDataOutcome::Rejected {
            early_bytes: 5,
            resent_bytes: 0,
            unresent_bytes: 5,
        };
        assert_eq!(read.early_data_outcome().await.unwrap(), outcome);
        assert_eq!(write.finish_early_data().await.unwrap(), outcome);
        assert!(write.flush().await.is_err());
        assert_eq!(
            write.acknowledge_rejected_early_data().await.unwrap(),
            Some(5)
        );
        write.write_all(b"one").await.unwrap();
        write.shutdown().await.unwrap();
        (read, write)
    };
    let server_side = async {
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        assert!(server.get_mut().1.early_data().is_none());
        server.write_all(b"!").await.unwrap();
        server.flush().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"one");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn a_cancelled_finisher_leaves_the_parked_reader_registered() {
    struct ReaderWake(AtomicBool);
    impl Wake for ReaderWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let setup = Setup::new();
    setup.first_connection().await;
    let (c, s) = duplex(4096);
    let gate = Arc::new(gate::GateState::default());
    let mut stream = setup
        .connector
        .connect(localhost(), gate::Gate::new(c, gate.clone()))
        .await
        .unwrap();
    stream.write_all(b"early").await.unwrap();
    let (mut reader, mut writer) = stream.into_split();
    gate.close();

    let reader_wake = Arc::new(ReaderWake(AtomicBool::new(false)));
    let waker = Waker::from(reader_wake.clone());
    let mut read = std::pin::pin!(reader.read_u8());
    assert!(
        read.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    {
        let mut finish = std::pin::pin!(writer.finish_early_data());
        assert!(
            finish
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    gate.open();
    assert!(reader_wake.0.load(Ordering::Relaxed));

    let server = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        server.write_all(b"!").await.unwrap();
        server.flush().await.unwrap();
    };
    let (byte, ()) = timeout(LIMIT, async { tokio::join!(read, server) })
        .await
        .unwrap();
    assert_eq!(byte.unwrap(), b'!');
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_reader_waiting_in_the_early_phase_is_woken_by_the_writer() {
    split_reader_waiting_in_the_early_phase_is_woken_by_the_writer(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_native_read_half_waiting_in_the_early_phase_is_woken_by_the_writer() {
    split_reader_waiting_in_the_early_phase_is_woken_by_the_writer(true).await;
}

async fn split_reader_waiting_in_the_early_phase_is_woken_by_the_writer(native: bool) {
    let setup = Arc::new(Setup::new());
    setup.first_connection().await;
    let (c, s) = duplex(64 * 1024);
    let client = setup.connector.connect(localhost(), c).await.unwrap();
    let (mut rd, mut wr) = client.split_either(native);
    // The reader starts the handshake and waits on the transport.
    let reader = tokio::spawn(async move {
        let mut reply = [0; 5];
        rd.read_exact(&mut reply).await.map(|_| reply)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let server_setup = setup.clone();
    let server = tokio::spawn(async move {
        // Let the writer's flush take over the transport first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut server = server_setup.acceptor(1024).accept(s).await.unwrap();
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        server
    });
    wr.write_all(b"early").await.unwrap();
    wr.flush().await.unwrap();
    let reply = timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader was never woken")
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"reply");
    drop(server.await.unwrap());
}

#[tokio::test]
async fn a_failed_early_phase_fails_every_later_operation() {
    let setup = Setup::new();
    setup.first_connection().await;
    let (c, mut s) = duplex(64 * 1024);
    let mut client = setup.connector.connect(localhost(), c).await.unwrap();
    let peer = tokio::spawn(async move {
        let mut hello = [0; 4096];
        let _ = s.read(&mut hello).await;
        s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await
            .unwrap();
        // Stays open: only the TLS state can end the operations below.
        tokio::time::sleep(Duration::from_secs(5)).await;
        s
    });
    let err = timeout(LIMIT, client.read(&mut [0; 4]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    for _ in 0..2 {
        let err = timeout(LIMIT, client.write(b"more"))
            .await
            .unwrap()
            .unwrap_err();
        assert!(tls_error(&err).is_some(), "{err:?}");
        let err = timeout(LIMIT, client.flush()).await.unwrap().unwrap_err();
        assert!(tls_error(&err).is_some(), "{err:?}");
    }
    let err = timeout(LIMIT, client.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert!(tls_error(&err).is_some(), "{err:?}");
    peer.abort();
}

/// Whether `secret` appears in `debug`, either as text or as the run of
/// decimal byte values a derived `Debug` of a byte vector prints (in
/// `{:?}` or `{:#?}` form).
fn debug_reveals(debug: &str, secret: &[u8]) -> bool {
    let text = std::str::from_utf8(secret).unwrap();
    // As written, as `Debug` of a string escapes it, and by its token alone.
    if debug.contains(text) || debug.contains(SECRET_TOKEN) {
        return true;
    }
    let numbers: Vec<u8> = debug
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|n| n.parse::<u8>().ok())
        .collect();
    numbers.windows(secret.len()).any(|w| w == secret)
}

const SECRET_TOKEN: &str = "early-data-debug-secret";
const SECRET_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nAuthorization: Bearer early-data-debug-secret\r\n\r\n";

#[tokio::test]
async fn stream_debug_output_omits_buffered_early_data() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(SECRET_REQUEST).await.unwrap();
        assert!(client.get_ref().1.is_handshaking());
        for debug in [format!("{client:?}"), format!("{client:#?}")] {
            assert!(!debug_reveals(&debug, SECRET_REQUEST), "{debug}");
            assert!(debug.contains("written"), "{debug}");
        }
        let wrapped = browntls_tokio::TlsStream::Client(client);
        assert!(!debug_reveals(&format!("{wrapped:?}"), SECRET_REQUEST));
        let browntls_tokio::TlsStream::Client(mut client) = wrapped else {
            unreachable!()
        };
        client.flush().await.unwrap();
        assert!(client.get_ref().1.is_early_data_accepted());
        assert!(!debug_reveals(&format!("{client:?}"), SECRET_REQUEST));
        client.shutdown().await.unwrap();
        // Kept open until the server is done writing its tickets.
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        let mut early = Vec::new();
        server
            .get_mut()
            .1
            .early_data()
            .expect("early data accepted")
            .read_to_end(&mut early)
            .unwrap();
        assert_eq!(early, SECRET_REQUEST);
        assert!(!debug_reveals(&format!("{server:?}"), SECRET_REQUEST));
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn stream_debug_output_omits_early_data_after_a_failed_early_phase() {
    let setup = Setup::new();
    setup.first_connection().await;
    let (c, mut s) = duplex(64 * 1024);
    let mut client = setup.connector.connect(localhost(), c).await.unwrap();
    client.write_all(SECRET_REQUEST).await.unwrap();
    let peer = tokio::spawn(async move {
        let mut hello = [0; 4096];
        let _ = s.read(&mut hello).await;
        s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        s
    });
    let err = timeout(LIMIT, client.flush()).await.unwrap().unwrap_err();
    assert!(tls_error(&err).is_some(), "{err:?}");
    for debug in [format!("{client:?}"), format!("{client:#?}")] {
        assert!(!debug_reveals(&debug, SECRET_REQUEST), "{debug}");
    }
    // The kept bytes can never be resent now, so they are already dropped.
    assert!(format!("{client:?}").contains("early: None"));
    peer.abort();
}
