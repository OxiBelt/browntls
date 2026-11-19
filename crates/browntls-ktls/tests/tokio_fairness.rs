//! A current-thread Tokio read must yield while kernel TLS keeps returning
//! control records without application data.

#![cfg(all(
    target_os = "linux",
    feature = "tokio",
    any(feature = "native", feature = "rustcrypto")
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use browntls::ProtocolVersion;
use browntls_ktls::AsyncKtlsStream;
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(20);

fn to_tokio(tcp: std::net::TcpStream) -> TcpStream {
    tcp.set_nonblocking(true).unwrap();
    TcpStream::from_std(tcp).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn control_only_reads_yield_before_later_application_data() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()
        .into_iter()
        .find(|suite| suite.version().version == ProtocolVersion::TLSv1_3)
        .expect("a TLS 1.3 kTLS suite");
    let (client_tcp, server_tcp) = tcp_pair();
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(pki.client_config(suite)))
            .connect(localhost(), to_tokio(client_tcp)),
        TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(to_tokio(server_tcp)),
    );
    let (client, server) = tokio::join!(
        AsyncKtlsStream::from_client(client.unwrap()),
        AsyncKtlsStream::from_server(server.unwrap()),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    // Only the first refresh asks for an answer. The rest can arrive with
    // no application data and little output to constrain the reader.
    for _ in 0..64 {
        server.refresh_traffic_keys().unwrap();
    }
    server.write_all(b"x").await.unwrap();
    server.flush().await.unwrap();
    timeout(LIMIT, async {
        while server.unsent().unwrap() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the kernel kept records back");
    client.get_ref().readable().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let ran = Arc::new(AtomicBool::new(false));
    let witness = ran.clone();
    tokio::spawn(async move { witness.store(true, Ordering::SeqCst) });
    let mut byte = [0u8; 1];
    let mut read_buf = ReadBuf::new(&mut byte);
    let first = poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut read_buf))).await;
    assert!(
        first.is_pending(),
        "the read consumed the control flood in one poll"
    );
    tokio::task::yield_now().await;
    assert!(ran.load(Ordering::SeqCst), "another task was not scheduled");
    timeout(LIMIT, client.read_exact(&mut byte))
        .await
        .expect("the marker timed out")
        .unwrap();
    assert_eq!(byte, *b"x");
}
