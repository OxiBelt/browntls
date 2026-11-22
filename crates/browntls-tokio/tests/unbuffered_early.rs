//! Client early-data I/O through the unbuffered Tokio adapter.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::{Future, poll_fn};
use std::io::IoSlice;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use browntls_core::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls_core::version::TLS13;
use browntls_tokio::unbuffered::{TlsAcceptor, TlsConnector};
use browntls_tokio::{EarlyDataNotResent, EarlyDataOutcome, RejectedEarlyDataPolicy};
use common::{Pki, localhost};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(15);

struct Setup {
    pki: Pki,
    cache: Arc<dyn StoresServerSessions>,
    connector: TlsConnector,
}

impl Setup {
    async fn prime() -> Self {
        let pki = Pki::new();
        let mut config = pki.client_config(&TLS13);
        config.alpn_protocols = vec![b"other".to_vec(), b"h2".to_vec()];
        config.enable_early_data = true;
        let setup = Self {
            pki,
            cache: ServerSessionMemoryCache::new(8),
            connector: TlsConnector::from(Arc::new(config)).early_data(true),
        };
        let (client_io, server_io) = duplex(128);
        let client = async {
            let mut stream = setup
                .connector
                .connect(localhost(), client_io)
                .await
                .unwrap();
            assert!(!stream.get_ref().1.is_handshaking());
            assert_eq!(stream.early_data_outcome(), EarlyDataOutcome::NoEarlyBytes);
            assert_eq!(stream.read_u8().await.unwrap(), b't');
            assert!(stream.get_ref().1.tls13_tickets_received() > 0);
            stream
        };
        let server = async {
            let mut stream = setup.acceptor(1024).accept(server_io).await.unwrap();
            stream.write_all(b"t").await.unwrap();
            stream.flush().await.unwrap();
        };
        timeout(LIMIT, async { tokio::join!(client, server) })
            .await
            .unwrap();
        setup
    }

    fn acceptor(&self, early_data_size: u32) -> TlsAcceptor {
        let mut config = self.pki.server_config(&TLS13);
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.max_early_data_size = early_data_size;
        config.session_storage = self.cache.clone();
        TlsAcceptor::from(Arc::new(config))
    }
}

#[tokio::test]
async fn accepts_early_data_after_the_finish_future_is_cancelled() {
    let setup = Setup::prime().await;
    let (client_io, server_io) = duplex(128);
    let mut client = setup
        .connector
        .connect(localhost(), client_io)
        .await
        .unwrap();
    assert!(client.get_ref().1.is_handshaking());
    assert_eq!(client.early_data_outcome(), EarlyDataOutcome::Pending);
    assert_eq!(
        client
            .write_vectored(&[IoSlice::new(b"ab"), IoSlice::new(b"cd")])
            .await
            .unwrap(),
        4,
    );

    {
        let mut finish = std::pin::pin!(client.finish_early_data());
        assert!(poll_fn(|cx| Poll::Ready(finish.as_mut().poll(cx).is_pending())).await);
    }

    let (mut read, mut write) = client.into_split();
    let client_side = async {
        let outcome = EarlyDataOutcome::Accepted { early_bytes: 4 };
        assert_eq!(write.finish_early_data().await.unwrap(), outcome);
        assert_eq!(read.early_data_outcome().await.unwrap(), outcome);
        write.write_all(b"after").await.unwrap();
        write.shutdown().await.unwrap();
        let mut received = Vec::new();
        read.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
        read.reunite(write).unwrap().into_parts()
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(server_io).await.unwrap();
        assert_eq!(server.take_early_data(), b"abcd");
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"after");
        server.shutdown().await.unwrap();
    };
    let (parts, ()) = timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .unwrap();
    assert_eq!(
        parts.early_data_outcome,
        EarlyDataOutcome::Accepted { early_bytes: 4 },
    );
}

#[tokio::test]
async fn rejection_is_acknowledged_or_resent_once_in_order() {
    for resend in [false, true] {
        let setup = Setup::prime().await;
        let (client_io, server_io) = duplex(128);
        let connector = if resend {
            setup.connector.clone().rejected_early_data_policy(
                RejectedEarlyDataPolicy::ResendIfSameAlpn {
                    max_bytes: NonZeroUsize::new(4).unwrap(),
                },
            )
        } else {
            setup.connector.clone()
        };
        let client_side = async {
            let mut stream = connector.connect(localhost(), client_io).await.unwrap();
            let early = [IoSlice::new(b"ab"), IoSlice::new(b"cdef")];
            let len = stream.write_vectored(&early).await.unwrap();
            assert_eq!(len, if resend { 4 } else { 6 });
            let (mut read, mut write) = stream.into_split();
            assert_eq!(read.read_u8().await.unwrap(), b'!');
            let outcome = EarlyDataOutcome::Rejected {
                early_bytes: len,
                resent_bytes: if resend { len } else { 0 },
                unresent_bytes: if resend { 0 } else { len },
            };
            assert_eq!(write.early_data_outcome().await.unwrap(), outcome);
            if !resend {
                let error = write.write(b"out of order").await.unwrap_err();
                assert_eq!(
                    error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<EarlyDataNotResent>()
                        .unwrap()
                        .len,
                    len
                );
                assert!(write.flush().await.is_err());
                assert_eq!(
                    write.acknowledge_rejected_early_data().await.unwrap(),
                    Some(len)
                );
            }
            write.write_all(b"ordinary").await.unwrap();
            write.shutdown().await.unwrap();
            (read, write)
        };
        let server_side = async {
            let mut server = setup.acceptor(0).accept(server_io).await.unwrap();
            assert!(server.early_data().is_empty());
            server.write_all(b"!").await.unwrap();
            server.flush().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            let expected: &[u8] = if resend { b"abcdordinary" } else { b"ordinary" };
            assert_eq!(received, expected);
        };
        timeout(LIMIT, async { tokio::join!(client_side, server_side) })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn failure_during_the_early_phase_is_sticky() {
    let setup = Setup::prime().await;
    let (client_io, server_io) = duplex(128);
    let mut client = setup
        .connector
        .connect(localhost(), client_io)
        .await
        .unwrap();
    client.write_all(b"early").await.unwrap();
    drop(server_io);
    let error = client.finish_early_data().await.unwrap_err();
    assert_eq!(
        client.early_data_outcome(),
        EarlyDataOutcome::Failed {
            early_bytes: 5,
            queued_resend_bytes: 0,
        },
    );
    assert_eq!(client.read_u8().await.unwrap_err().kind(), error.kind());
    assert_eq!(
        client.write(b"ordinary").await.unwrap_err().kind(),
        error.kind()
    );
    assert_eq!(client.flush().await.unwrap_err().kind(), error.kind());
    assert_eq!(client.shutdown().await.unwrap_err().kind(), error.kind());
}
