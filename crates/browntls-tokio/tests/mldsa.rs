//! ML-DSA TLS 1.3 authentication (`draft-ietf-tls-mldsa-06`, the native
//! provider's opt-in) through both Tokio drivers: the streams of the crate
//! root (`TlsConnector`, `TlsAcceptor`) and those of
//! `browntls_tokio::unbuffered`, server and mutual authentication with each
//! parameter set over an in-memory duplex whose small buffer splits the
//! large flights. ML-DSA-87 also runs on the worker threads of a
//! multi-thread runtime: signing needs about 102 KiB of stack, well within
//! Tokio's default of 2 MiB per worker thread.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_core as tls;

#[path = "mldsa/pki.rs"]
mod pki;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::danger::ClientCertVerifier;
use browntls_core::version::TLS13;
use browntls_core::{ClientConfig, HandshakeKind, ServerConfig};
use pki::{Identity, Purpose, Recorder, SETS, Set, localhost, opt_in};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

/// The configurations of one case and the verifiers that record the
/// `CertificateVerify` schemes.
struct Configs {
    set: Set,
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    server_auth: Arc<Recorder<browntls_core::client::WebPkiServerVerifier>>,
    client_auth: Option<Arc<Recorder<dyn ClientCertVerifier>>>,
}

impl Configs {
    fn new(set: Set, mutual: bool) -> Self {
        let server_id = Identity::new(set, Purpose::Server);
        let client_id = mutual.then(|| Identity::new(set, Purpose::Client));
        let server_auth = server_id.server_verifier();
        let client_auth = client_id.as_ref().map(Identity::client_verifier);
        let client = ClientConfig::builder_with_provider(opt_in())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_auth.clone());
        let client = match &client_id {
            Some(id) => client
                .with_client_auth_cert(id.chain(), id.private_key())
                .unwrap(),
            None => client.with_no_client_auth(),
        };
        let server = ServerConfig::builder_with_provider(opt_in())
            .with_protocol_versions(&[&TLS13])
            .unwrap();
        let server = match &client_auth {
            Some(verifier) => server.with_client_cert_verifier(verifier.clone()),
            None => server.with_no_client_auth(),
        };
        let server = server
            .with_single_cert(server_id.chain(), server_id.private_key())
            .unwrap();
        Self {
            set,
            client: Arc::new(client),
            server: Arc::new(server),
            server_auth,
            client_auth,
        }
    }

    /// Each verifier checked one signature, of this set's scheme.
    fn assert_schemes(&self) {
        let scheme = self.set.scheme();
        assert_eq!(self.server_auth.seen(), [scheme], "{:?}", self.set);
        if let Some(client_auth) = &self.client_auth {
            assert_eq!(client_auth.seen(), [scheme], "{:?}", self.set);
        }
    }

    fn mutual(&self) -> bool {
        self.client_auth.is_some()
    }
}

/// Writes `data` on `a`, reads it on `b`, and the other way round.
async fn echo<A, B>(a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let exchange = async {
        let (write, read) = tokio::join!(
            async {
                a.write_all(&data).await?;
                a.flush().await
            },
            async {
                let mut got = vec![0; data.len()];
                b.read_exact(&mut got).await.map(|_| got)
            }
        );
        write.unwrap();
        assert_eq!(read.unwrap(), data);
        b.write_all(b"reply").await.unwrap();
        b.flush().await.unwrap();
        let mut reply = [0; 5];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    };
    timeout(LIMIT, exchange)
        .await
        .expect("data exchange timed out");
}

/// A handshake and data through the streams of the crate root.
async fn buffered(configs: &Configs) {
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    configs.assert_schemes();
    let (_, conn) = client.get_ref();
    assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(conn.peer_certificates().unwrap().len(), 1);
    let (_, conn) = server.get_ref();
    assert_eq!(conn.peer_certificates().is_some(), configs.mutual());
    echo(&mut client, &mut server).await;
}

/// The same through the streams of `browntls_tokio::unbuffered`.
async fn unbuffered(configs: &Configs) {
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::unbuffered::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    configs.assert_schemes();
    let (_, conn) = client.get_ref();
    assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(conn.peer_certificates().unwrap().len(), 1);
    let (_, conn) = server.get_ref();
    assert_eq!(conn.peer_certificates().is_some(), configs.mutual());
    echo(&mut client, &mut server).await;
}

#[tokio::test]
async fn ml_dsa_through_the_buffered_streams() {
    for set in SETS {
        for mutual in [false, true] {
            buffered(&Configs::new(set, mutual)).await;
        }
    }
}

#[tokio::test]
async fn ml_dsa_through_the_unbuffered_streams() {
    for set in SETS {
        for mutual in [false, true] {
            unbuffered(&Configs::new(set, mutual)).await;
        }
    }
}

/// The name of the thread a task runs on.
fn thread_name() -> String {
    std::thread::current().name().unwrap_or("").to_owned()
}

/// ML-DSA-87 mutual authentication with both sides spawned, so that the
/// signing runs on runtime worker threads, whose stack is Tokio's default
/// (`runtime::Builder::thread_stack_size`: 2 MiB) since the runtime sets
/// none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ml_dsa_87_on_multi_thread_runtime_workers() {
    let test_thread = thread_name();
    let mut threads = Vec::new();
    for unbuffered in [false, true] {
        // New configurations: no ticket from the first connection.
        let configs = Configs::new(Set::MlDsa87, true);
        let (c, s) = duplex(4096);
        let (client, server) = if unbuffered {
            let connector = browntls_tokio::unbuffered::TlsConnector::from(configs.client.clone());
            let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(configs.server.clone());
            let client = tokio::spawn(async move {
                let mut tls = connector.connect(localhost(), c).await.unwrap();
                let mut reply = [0; 2];
                tls.read_exact(&mut reply).await.unwrap();
                (reply, thread_name())
            });
            let server = tokio::spawn(async move {
                let mut tls = acceptor.accept(s).await.unwrap();
                tls.write_all(b"ok").await.unwrap();
                tls.flush().await.unwrap();
                thread_name()
            });
            (client, server)
        } else {
            let connector = browntls_tokio::TlsConnector::from(configs.client.clone());
            let acceptor = browntls_tokio::TlsAcceptor::from(configs.server.clone());
            let client = tokio::spawn(async move {
                let mut tls = connector.connect(localhost(), c).await.unwrap();
                let mut reply = [0; 2];
                tls.read_exact(&mut reply).await.unwrap();
                (reply, thread_name())
            });
            let server = tokio::spawn(async move {
                let mut tls = acceptor.accept(s).await.unwrap();
                tls.write_all(b"ok").await.unwrap();
                tls.flush().await.unwrap();
                thread_name()
            });
            (client, server)
        };
        let (reply, client_thread) = timeout(LIMIT, client).await.unwrap().unwrap();
        assert_eq!(&reply, b"ok");
        let server_thread = timeout(LIMIT, server).await.unwrap().unwrap();
        threads.extend([client_thread, server_thread]);
        configs.assert_schemes();
    }
    assert!(
        threads.iter().all(|name| *name != test_thread),
        "{threads:?}"
    );
}
