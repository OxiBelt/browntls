//! The kernel's zero-copy option for `sendfile` on `AsyncKtlsStream`,
//! against the running kernel over loopback TCP.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(
    target_os = "linux",
    feature = "tokio",
    any(feature = "native", feature = "rustcrypto")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{ProtocolVersion, SupportedCipherSuite};
use browntls_ktls::AsyncKtlsStream;
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const LEN: usize = 200_000;
const LIMIT: Duration = Duration::from_secs(60);

fn tls13(suite: SupportedCipherSuite) -> bool {
    suite.version().version == ProtocolVersion::TLSv1_3
}

fn to_tokio(tcp: std::net::TcpStream) -> TcpStream {
    tcp.set_nonblocking(true).unwrap();
    TcpStream::from_std(tcp).unwrap()
}

/// Both ends in the kernel after a `browntls-tokio` handshake over
/// loopback TCP: (client, server).
async fn kernel_pair(
    pki: &Pki,
    suite: SupportedCipherSuite,
) -> (
    AsyncKtlsStream<ClientConnectionData>,
    AsyncKtlsStream<ServerConnectionData>,
) {
    let (client_tcp, server_tcp) = tcp_pair();
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(pki.client_config(suite)))
            .connect(localhost(), to_tokio(client_tcp)),
        TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(to_tokio(server_tcp)),
    );
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            AsyncKtlsStream::from_client(client.unwrap()),
            AsyncKtlsStream::from_server(server.unwrap()),
        )
    })
    .await
    .expect("handover timed out");
    (client.unwrap(), server.unwrap())
}

/// The option is read back as set, and data, a key refresh and the closure
/// pass with it set.
#[tokio::test]
async fn the_option_is_read_back_and_the_stream_goes_on() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (mut client, mut server) = kernel_pair(&pki, suite).await;
        let (up, down) = (pattern(LEN, 21), pattern(LEN, 22));

        assert!(!client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
        client.set_tx_zerocopy_sendfile(true).unwrap();
        assert!(client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");

        let server_side = async {
            let mut got = vec![0; LEN];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, up, "{suite:?}");
            server.write_all(&down[..LEN / 2]).await.unwrap();
            if tls13(suite) {
                server.refresh_traffic_keys().unwrap();
            }
            server.write_all(&down[LEN / 2..]).await.unwrap();
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            server.shutdown().await.unwrap();
        };
        let client_side = async {
            client.write_all(&up).await.unwrap();
            let mut got = vec![0; LEN];
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got, down, "{suite:?}");
            assert!(client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        };
        timeout(LIMIT, async { tokio::join!(server_side, client_side) })
            .await
            .expect("the exchange timed out");
    }
}
