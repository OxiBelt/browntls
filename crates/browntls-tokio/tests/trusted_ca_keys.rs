//! The `trusted_ca_keys` extension (RFC 6066 §6) through the Tokio streams:
//! the core API reaches it with no API of this crate, on the buffered
//! (`TlsConnector`, `TlsAcceptor`, `LazyConfigAcceptor`) and the unbuffered
//! (`browntls_tokio::unbuffered`) streams. TLS 1.2 only, as the extension.

#![cfg(all(feature = "tls12", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::{Acceptor, ResolvesServerCertUsingTrustedCaKeys, UnbufferedAcceptor};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{ClientConfig, RootCertStore, ServerConfig, TrustedAuthority, version};
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector, unbuffered};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

fn sha1(data: &[u8]) -> [u8; 20] {
    #[cfg(feature = "native")]
    return browntls_core::crypto::native::sha1(data);
    #[cfg(not(feature = "native"))]
    return browntls_core::crypto::rustcrypto::sha1(data);
}

/// Two CAs, each with a `localhost` chain: the server falls back to A's
/// chain and serves B's to a client that lists B's root key.
struct Setup {
    a: Pki,
    b: Pki,
}

impl Setup {
    fn new() -> Self {
        Self {
            a: Pki::new(),
            b: Pki::new(),
        }
    }

    fn certified_key(pki: &Pki) -> Arc<CertifiedKey> {
        Arc::new(
            CertifiedKey::from_der(pki.server_chain.clone(), pki.server_key(), &provider())
                .unwrap(),
        )
    }

    fn server(&self) -> ServerConfig {
        let fallback = Arc::new(SingleCertAndKey::from(Self::certified_key(&self.a)));
        let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(fallback);
        // The test CAs share a subject name, so only the key and
        // certificate hashes tell them apart.
        resolver.add(
            vec![TrustedAuthority::key_sha1_hash(&self.b.ca, sha1).unwrap()],
            Self::certified_key(&self.b),
        );
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver))
    }

    /// A client trusting both CAs that lists B's root key, derived from
    /// its trust anchor.
    fn client(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.a.ca.clone()).unwrap();
        roots.add(self.b.ca.clone()).unwrap();
        let listed = TrustedAuthority::key_sha1_hash_of_anchor(&roots.roots[1], sha1).unwrap();
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.trusted_ca_keys = Some(vec![listed]);
        config
    }

    fn listed(&self) -> Vec<TrustedAuthority> {
        self.client().trusted_ca_keys.unwrap()
    }
}

#[tokio::test]
async fn buffered_streams_negotiate() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let connector = TlsConnector::from(Arc::new(setup.client()));
    let acceptor = TlsAcceptor::from(Arc::new(setup.server()));
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .unwrap();
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let conn = client.get_ref().1;
    assert!(conn.trusted_ca_keys_acknowledged());
    assert_eq!(
        conn.peer_certificates().unwrap()[0],
        setup.b.server_chain[0]
    );

    client.write_all(b"listed").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"listed");
}

#[tokio::test]
async fn lazy_acceptor_reads_the_list() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let connector = TlsConnector::from(Arc::new(setup.client()));
    let config = Arc::new(setup.server());
    let listed = setup.listed();
    let server = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
        assert_eq!(start.client_hello().trusted_ca_keys(), Some(&listed[..]));
        start.into_stream(config).await
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), server)
    })
    .await
    .unwrap();
    let (client, _server) = (client.unwrap(), server.unwrap());
    assert!(client.get_ref().1.trusted_ca_keys_acknowledged());
}

#[tokio::test]
async fn unbuffered_streams_negotiate() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let connector = unbuffered::TlsConnector::from(Arc::new(setup.client()));
    let acceptor = unbuffered::TlsAcceptor::from(Arc::new(setup.server()));
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .unwrap();
    let (client, _server) = (client.unwrap(), server.unwrap());
    let conn = client.get_ref().1;
    assert!(conn.trusted_ca_keys_acknowledged());
    assert_eq!(
        conn.peer_certificates().unwrap()[0],
        setup.b.server_chain[0]
    );
}

#[tokio::test]
async fn unbuffered_lazy_acceptor_reads_the_list() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let connector = unbuffered::TlsConnector::from(Arc::new(setup.client()));
    let config = Arc::new(setup.server());
    let listed = setup.listed();
    let server = async {
        let start = unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s).await?;
        assert_eq!(start.client_hello().trusted_ca_keys(), Some(&listed[..]));
        start.into_stream(config).await
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), server)
    })
    .await
    .unwrap();
    let (client, _server) = (client.unwrap(), server.unwrap());
    assert!(client.get_ref().1.trusted_ca_keys_acknowledged());
}
