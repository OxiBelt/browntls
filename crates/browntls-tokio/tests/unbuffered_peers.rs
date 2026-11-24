//! Unbuffered streams against other peers and other messages: the buffered
//! streams of this crate and tokio-rustls in both directions, client
//! authentication during and after the handshake, HelloRetryRequest,
//! resumption, 0-RTT data a server accepts, and wake-ups when reads and
//! writes share the transport's write side.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use browntls_core::server::{PostHandshakeAuthStatus, ServerSessionMemoryCache};
use browntls_core::{HandshakeKind, NamedGroup};
use browntls_tokio::EarlyDataOutcome;
use browntls_tokio::unbuffered::{TlsAcceptor, TlsConnector};
use common::*;
use rustls_pki_types as rpki;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// Sends `up` from the client and `down` from the server at the same time,
/// each side closing with `close_notify`, and checks what arrived.
async fn exchange<C, S>(client: C, server: S, up: &[u8], down: &[u8])
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut server_rd, mut server_wr) = tokio::io::split(server);
    let run = async {
        tokio::join!(
            async {
                client_wr.write_all(up).await.unwrap();
                client_wr.shutdown().await.unwrap();
            },
            async {
                server_wr.write_all(down).await.unwrap();
                server_wr.shutdown().await.unwrap();
            },
            async {
                let mut got = Vec::new();
                server_rd.read_to_end(&mut got).await.unwrap();
                got
            },
            async {
                let mut got = Vec::new();
                client_rd.read_to_end(&mut got).await.unwrap();
                got
            },
        )
    };
    let ((), (), server_got, client_got) = timeout(LIMIT, run).await.expect("timed out");
    assert!(server_got == up, "server received corrupt data");
    assert!(client_got == down, "client received corrupt data");
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}

fn rustls_versions(
    version: &'static browntls_core::SupportedProtocolVersion,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    static TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
    static TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    match version.version {
        browntls_core::ProtocolVersion::TLSv1_3 => &TLS13,
        _ => &TLS12,
    }
}

fn rustls_server(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
) -> tokio_rustls::TlsAcceptor {
    let chain = pki
        .server_chain
        .iter()
        .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
        .collect();
    let key = rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(pki.server_key.clone()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls_versions(version))
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn rustls_client(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rpki::CertificateDer::from(pki.ca.as_ref().to_vec()))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls_versions(version))
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn unbuffered_and_buffered_streams_talk_to_each_other() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(4096);
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(version))).connect(localhost(), c),
            pki.acceptor(version).accept(s),
        );
        exchange(
            client.unwrap(),
            server.unwrap(),
            &pattern(256 * 1024),
            &pattern(100 * 1024),
        )
        .await;

        let (c, s) = duplex(4096);
        let (client, server) = tokio::join!(
            pki.connector(version).connect(localhost(), c),
            TlsAcceptor::from(Arc::new(pki.server_config(version))).accept(s),
        );
        exchange(
            client.unwrap(),
            server.unwrap(),
            &pattern(100 * 1024),
            &pattern(256 * 1024),
        )
        .await;
    }
}

#[tokio::test]
async fn an_unbuffered_client_to_a_tokio_rustls_server() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = tcp_pair().await;
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(version))).connect(localhost(), c),
            rustls_server(&pki, version).accept(s),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.get_ref().1.protocol_version(), Some(version.version));
        #[cfg(unix)]
        {
            use std::os::fd::{AsFd, AsRawFd};
            assert_eq!(client.as_raw_fd(), client.as_fd().as_raw_fd());
        }
        exchange(client, server, &pattern(256 * 1024), &pattern(100 * 1024)).await;
    }
}

#[tokio::test]
async fn a_tokio_rustls_client_to_an_unbuffered_server() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = tcp_pair().await;
        let name = rpki::ServerName::try_from("localhost").unwrap();
        let (client, server) = tokio::join!(
            rustls_client(&pki, version).connect(name, c),
            TlsAcceptor::from(Arc::new(pki.server_config(version))).accept(s),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(server.get_ref().1.protocol_version(), Some(version.version));
        exchange(client, server, &pattern(100 * 1024), &pattern(256 * 1024)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_loopback_with_concurrent_halves() {
    let pki = Arc::new(Pki::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_pki = pki.clone();
    let server = tokio::spawn(async move {
        let config = server_pki.server_config(&browntls_core::version::TLS13);
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        // Echo until the client closes, then close too.
        let (mut rd, mut wr) = tokio::io::split(tls);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let config = pki.client_config(&browntls_core::version::TLS13);
    let tls = TlsConnector::from(Arc::new(config))
        .connect(localhost(), tcp)
        .await
        .unwrap();
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

/// A client that sends a request and then only reads, over `client_io`,
/// against a server that asks for a certificate after the handshake and
/// answers only once it has one.
async fn post_handshake_authentication_with_a_reading_client<IO>(client_io: IO, s: DuplexStream)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;

    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_io),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(server.get_ref().1.peer_certificates().is_none());

    let client_side = async {
        client.write_all(b"request\n").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0; 6];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply\n");
        assert_eq!(client.get_ref().1.post_handshake_auth_responses(), 1);
    };
    let server_side = async {
        let mut request = [0; 8];
        server.read_exact(&mut request).await.unwrap();
        // Queued on the connection; the flush encodes and sends it.
        server.get_mut().1.request_client_auth().unwrap();
        server.flush().await.unwrap();
        // Reading processes the answer, which carries no plaintext.
        while server.get_ref().1.post_handshake_auth_status()
            != Some(PostHandshakeAuthStatus::Authenticated)
        {
            let _ = timeout(Duration::from_millis(20), server.read(&mut [0; 1])).await;
        }
        assert!(server.get_ref().1.peer_certificates().is_some());
        server.write_all(b"reply\n").await.unwrap();
        server.flush().await.unwrap();
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("the client never answered the CertificateRequest");
}

#[tokio::test]
async fn a_client_that_only_reads_answers_post_handshake_authentication() {
    let (c, s) = duplex(64 * 1024);
    post_handshake_authentication_with_a_reading_client(c, s).await;
}

#[tokio::test]
async fn a_reading_client_finishes_an_answer_the_transport_took_in_part() {
    // The answer (a certificate chain) leaves seven bytes per write, with a
    // `Pending` between writes: later reads must write the rest.
    let (c, s) = duplex(64 * 1024);
    post_handshake_authentication_with_a_reading_client(Choppy::new(c, 7), s).await;
}

#[tokio::test]
async fn client_authentication_during_the_handshake() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config_with_cert(version)))
                .connect(localhost(), c),
            TlsAcceptor::from(Arc::new(pki.server_config_with_client_auth(version))).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0], "{version:?}");

        client.write_all(b"authenticated").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"authenticated");
    }
}

#[tokio::test]
async fn a_hello_retry_request_over_a_choppy_transport() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut provider = (*provider()).clone();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::secp256r1);
    assert!(!provider.kx_groups.is_empty());
    let server_config = browntls_core::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();

    let (c, s) = duplex(4096);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(version)))
                .connect(localhost(), Choppy::new(c, 5)),
            TlsAcceptor::from(Arc::new(server_config)).accept(Choppy::new(s, 3)),
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert_eq!(
        client.get_ref().1.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::secp256r1
    );
}

/// A server configuration that issues tickets allowing `max_early_data_size`
/// bytes of 0-RTT data.
fn resuming_server(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
    cache: &Arc<ServerSessionMemoryCache>,
    max_early_data_size: u32,
) -> Arc<browntls_core::ServerConfig> {
    let mut config = pki.server_config(version);
    config.max_early_data_size = max_early_data_size;
    config.session_storage = cache.clone();
    Arc::new(config)
}

#[tokio::test]
async fn sessions_are_resumed() {
    let pki = Pki::new();
    for version in versions() {
        let cache = ServerSessionMemoryCache::new(8);
        let server_config = resuming_server(&pki, version, &cache, 1024);
        // The tickets and the client configuration allow 0-RTT data, which
        // an unbuffered client never sends: the resumption carries none.
        let mut client_config = pki.client_config(version);
        client_config.enable_early_data = true;
        let connector = TlsConnector::from(Arc::new(client_config));

        for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let (c, s) = duplex(64 * 1024);
            let (client, server) = tokio::join!(
                connector.connect(localhost(), c),
                TlsAcceptor::from(server_config.clone()).accept(s),
            );
            let (mut client, mut server) = (client.unwrap(), server.unwrap());
            assert_eq!(
                client.get_ref().1.handshake_kind(),
                Some(expected),
                "{version:?}"
            );
            // Reading the server's data processes the tickets before it.
            server.write_all(b"t").await.unwrap();
            server.shutdown().await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"t");
            assert!(server.early_data().is_empty());
            // The resumed TLS 1.3 handshake offered 0-RTT, the server took
            // the offer, and the client closed it with no data in it.
            let offered =
                expected == HandshakeKind::Resumed && *version == browntls_core::version::TLS13;
            assert_eq!(
                client.get_ref().1.is_early_data_accepted(),
                offered,
                "{version:?} {expected:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_unbuffered_server_collects_accepted_early_data() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let cache = ServerSessionMemoryCache::new(8);
    let server_config = resuming_server(&pki, version, &cache, 1024);
    let mut client_config = pki.client_config(version);
    client_config.enable_early_data = true;
    // The buffered connector sends 0-RTT data.
    let connector = browntls_tokio::TlsConnector::from(Arc::new(client_config)).early_data(true);

    // A full handshake leaves the client a ticket.
    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        connector.connect(localhost(), c),
        TlsAcceptor::from(server_config.clone()).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    server.write_all(b"t").await.unwrap();
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert!(client.get_ref().1.tls13_tickets_received() > 0);
    assert!(server.early_data().is_empty());

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = connector.connect(localhost(), c).await.unwrap();
        assert!(client.get_ref().1.is_handshaking());
        client.write_all(b"early request").await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert!(client.get_ref().1.is_early_data_accepted());
        assert_eq!(
            client.early_data_outcome(),
            EarlyDataOutcome::Accepted { early_bytes: 13 },
        );
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
    };
    let server_side = async {
        let mut server = TlsAcceptor::from(server_config.clone())
            .accept(s)
            .await
            .unwrap();
        // Kept apart from ordinary data, and never shown by `Debug`.
        assert_eq!(server.early_data(), b"early request");
        assert!(!format!("{server:?}").contains("early request"));
        assert_eq!(server.take_early_data(), b"early request");
        assert!(server.early_data().is_empty());
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
async fn a_task_polling_both_directions_does_not_spin_while_answering() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;
    // A small transport: the certificate answer only goes out in part.
    let (c, s) = duplex(300);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    server.get_mut().1.request_client_auth().unwrap();
    let mut buf = [0u8; 16];
    let (flushed, _) = tokio::join!(
        server.flush(),
        timeout(Duration::from_millis(100), client.read(&mut buf))
    );
    flushed.unwrap();
    assert!(!format!("{client:?}").contains("unsent: 0"));

    // Poll writes and reads from one task while the server reads nothing:
    // the answer is ahead of the write, and neither can move.
    let big = vec![0u8; 256 * 1024];
    let polls = AtomicUsize::new(0);
    let both = poll_fn(|cx| {
        polls.fetch_add(1, Ordering::Relaxed);
        let _ = Pin::new(&mut client).poll_write(cx, &big);
        let _ = Pin::new(&mut client).poll_read(cx, &mut ReadBuf::new(&mut buf));
        Poll::<()>::Pending
    });
    let _ = timeout(Duration::from_millis(300), both).await;
    let polls = polls.load(Ordering::Relaxed);
    assert!(polls < 100, "the task spun: {polls} polls in 300 ms");
    drop(server);
}

#[tokio::test]
async fn a_parked_writer_is_woken_after_a_read_took_its_registration() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;
    let (c, s) = duplex(300);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    // Leave the client's certificate answer partly written.
    server.get_mut().1.request_client_auth().unwrap();
    let mut buf = [0u8; 16];
    let (flushed, _) = tokio::join!(
        server.flush(),
        timeout(Duration::from_millis(100), client.read(&mut buf))
    );
    flushed.unwrap();
    assert!(!format!("{client:?}").contains("unsent: 0"));

    // A writer task parks on the full transport.
    let (mut rd, mut wr) = tokio::io::split(client);
    let total = 256 * 1024;
    let writer = tokio::spawn(async move {
        wr.write_all(&vec![7u8; total]).await.unwrap();
        wr.flush().await.unwrap();
        wr
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // One read gets data; its answer write meets `Pending` and takes the
    // writer's registration. The reader then stops reading.
    server.write_all(b"data").await.unwrap();
    server.flush().await.unwrap();
    let n = timeout(LIMIT, rd.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"data");

    let server_reads = tokio::spawn(async move {
        let mut got = 0;
        let mut chunk = vec![0u8; 16 * 1024];
        while got < total {
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            got += n;
        }
        got
    });
    timeout(LIMIT, writer)
        .await
        .expect("the writer was never woken")
        .unwrap();
    assert_eq!(timeout(LIMIT, server_reads).await.unwrap().unwrap(), total);
    drop(rd);
}

#[tokio::test]
async fn a_corrupt_record_after_the_handshake_fails_the_read_with_an_alert() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(pki.client_config(version))).connect(localhost(), c),
        pki.acceptor(version).accept(s),
    );
    let (mut client, server) = (client.unwrap(), server.unwrap());
    let (mut transport, _) = server.into_inner();
    // A garbled application-data record: the client cannot decrypt it.
    transport
        .write_all(&[0x17, 0x03, 0x03, 0x00, 0x20])
        .await
        .unwrap();
    transport.write_all(&[0xAA; 0x20]).await.unwrap();

    let err = client.read(&mut [0; 16]).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        matches!(tls_error(&err), Some(browntls_core::Error::DecryptError)),
        "{err:?}"
    );
    // The client told the server why.
    let mut header = [0; 5];
    transport.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 0x17, "an alert record, encrypted under TLS 1.3");

    // The failure is final: reads and writes report it, a flush too once
    // nothing is left to write, and a shutdown still closes the transport.
    let err = client.read(&mut [0; 16]).await.unwrap_err();
    assert!(matches!(
        tls_error(&err),
        Some(browntls_core::Error::DecryptError)
    ));
    let err = client.write(b"x").await.unwrap_err();
    assert!(matches!(
        tls_error(&err),
        Some(browntls_core::Error::DecryptError)
    ));
    let err = client.flush().await.unwrap_err();
    assert!(matches!(
        tls_error(&err),
        Some(browntls_core::Error::DecryptError)
    ));
    client.shutdown().await.unwrap();
    let mut rest = Vec::new();
    transport.read_to_end(&mut rest).await.unwrap();
}
