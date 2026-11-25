//! A TLS 1.3-only policy through the Tokio streams: an application selects
//! it on the configuration it hands to `TlsConnector`, `TlsAcceptor` or
//! `LazyConfigAcceptor`, reads the negotiated version from the stream, and
//! a peer that only has TLS 1.2 is refused with a `protocol_version` alert
//! (RFC 9852 §4 on applications; RFC 9846 §4.2.1 and Appendix D on the
//! refusal).

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::{ProtocolVersion, ServerConfig, version};
use browntls_tokio::TlsAcceptor;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// An acceptor with the default version list, which is every version the
/// build has: what a server that did not choose a policy runs.
fn default_acceptor(pki: &Pki) -> TlsAcceptor {
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

#[tokio::test]
async fn a_tls13_only_connector_reads_tls13_from_the_stream() {
    let pki = Pki::new();
    for acceptor in [pki.acceptor(&version::TLS13), default_acceptor(&pki)] {
        let (c, s) = duplex(64 * 1024);
        let connector = pki.connector(&version::TLS13);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        // The check an application makes after the handshake.
        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );

        client.write_all(b"policy").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"policy");
    }
}

#[cfg(feature = "tls12")]
mod refusals {
    use std::io;

    use browntls_core::server::Acceptor;
    use browntls_core::{AlertDescription, Error, PeerIncompatible};
    use browntls_tokio::LazyConfigAcceptor;

    use super::*;

    /// What each side of a refused pair reports: the server names the cause
    /// and sends `protocol_version`, the client receives that alert.
    fn assert_refused<C, S>(client: io::Result<C>, server: io::Result<S>) {
        let Err(err) = server else {
            panic!("the server completed a handshake");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            matches!(
                tls_error(&err),
                Some(Error::PeerIncompatible(
                    PeerIncompatible::Tls12NotOfferedOrEnabled
                ))
            ),
            "{err:?}"
        );
        let Err(err) = client else {
            panic!("the client completed a handshake");
        };
        assert!(
            matches!(
                tls_error(&err),
                Some(Error::AlertReceived(AlertDescription::ProtocolVersion))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_tls13_only_acceptor_refuses_a_tls12_client() {
        let pki = Pki::new();
        let (c, s) = duplex(64 * 1024);
        let connector = pki.connector(&version::TLS12);
        let acceptor = pki.acceptor(&version::TLS13);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .unwrap();
        assert_refused(client, server);
    }

    #[tokio::test]
    async fn a_tls13_only_connector_is_refused_by_a_tls12_server() {
        let pki = Pki::new();
        let (c, s) = duplex(64 * 1024);
        let connector = pki.connector(&version::TLS13);
        let acceptor = pki.acceptor(&version::TLS12);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .unwrap();
        assert_refused(client, server);
    }

    /// The policy is the configuration's: a lazy acceptor has none until it
    /// is given one, so the hello of a TLS 1.2 client is read without
    /// complaint and refused by the configuration chosen for it.
    #[tokio::test]
    async fn a_lazy_acceptor_refuses_with_the_configuration_it_is_given() {
        let pki = Pki::new();
        let (c, s) = duplex(64 * 1024);
        let connector = pki.connector(&version::TLS12);
        let config = Arc::new(pki.server_config(&version::TLS13));
        let server = async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
            assert_eq!(start.client_hello().server_name(), Some("localhost"));
            start
                .into_stream(config)
                .into_fallible()
                .await
                .map_err(|(err, _io)| err)
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), server)
        })
        .await
        .unwrap();
        assert_refused(client, server);
    }
}
