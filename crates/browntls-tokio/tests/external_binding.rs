//! External session and identity binding (RFC 8844) through the Tokio
//! streams: per-connection configurations for `TlsConnector` and
//! `TlsAcceptor`, a `LazyConfigAcceptor` (buffered and unbuffered) choosing
//! the server configuration by the client's `tls-id`, and a mismatch
//! surfacing as an I/O error on both ends.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::external_binding::{ExternalBinding, ExternalIdHash, ExternalSessionId};
use browntls_core::server::{Acceptor, ClientHello, UnbufferedAcceptor};
use browntls_core::{AlertDescription, Error, PeerMisbehaved, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

fn tls_id(tag: &str) -> ExternalSessionId {
    ExternalSessionId::new(format!("{tag:-<24}").as_bytes()).unwrap()
}

/// Each end's binding for the signaled session of the client `peer`.
fn bindings(peer: &str) -> (ExternalBinding, ExternalBinding) {
    let assertion = ExternalIdHash::for_assertion(&provider(), peer.as_bytes()).unwrap();
    let client = ExternalBinding {
        id_hash: Some(assertion),
        peer_id_hash: Some(ExternalIdHash::EMPTY),
        session_id: Some(tls_id(peer)),
        peer_session_id: Some(tls_id(&format!("server for {peer}"))),
        require_peer_support: true,
    };
    let server = ExternalBinding {
        id_hash: Some(ExternalIdHash::EMPTY),
        peer_id_hash: Some(assertion),
        session_id: client.peer_session_id.clone(),
        peer_session_id: client.session_id.clone(),
        require_peer_support: true,
    };
    (client, server)
}

fn connector(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
    binding: ExternalBinding,
) -> Arc<browntls_core::ClientConfig> {
    let mut config = pki.client_config(version);
    config.external_binding = Some(binding);
    Arc::new(config)
}

fn server_config(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
    binding: Option<ExternalBinding>,
) -> Arc<ServerConfig> {
    let mut config = pki.server_config(version);
    config.external_binding = binding;
    Arc::new(config)
}

/// The server configuration for the signaled session the ClientHello's
/// `tls-id` names.
fn chosen(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
    hello: &ClientHello<'_>,
) -> Arc<ServerConfig> {
    let id = hello.external_session_id().expect("a tls-id");
    let peer = ["alice", "bob"]
        .into_iter()
        .find(|peer| tls_id(peer) == *id)
        .expect("a signaled session");
    server_config(pki, version, Some(bindings(peer).1))
}

#[tokio::test]
async fn matching_bindings_through_connector_and_acceptor() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = bindings("alice");
        let (client_io, server_io) = duplex(64 * 1024);
        let connector = TlsConnector::from(connector(&pki, version, c));
        let acceptor = TlsAcceptor::from(server_config(&pki, version, Some(s)));
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                connector.connect(localhost(), client_io),
                acceptor.accept(server_io)
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(
            client.get_ref().1.peer_external_session_id(),
            Some(&tls_id("server for alice"))
        );
        assert_eq!(
            client.get_ref().1.peer_external_id_hash(),
            Some(&ExternalIdHash::EMPTY)
        );
        assert_eq!(
            server.get_ref().1.peer_external_session_id(),
            Some(&tls_id("alice"))
        );
        client.write_all(b"bound").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bound");
    }
}

#[tokio::test]
async fn a_mismatch_is_an_io_error_on_both_ends() {
    let pki = Pki::new();
    for version in versions() {
        let (c, _) = bindings("alice");
        // The server serves bob's session.
        let (_, s) = bindings("bob");
        let (client_io, server_io) = duplex(64 * 1024);
        let connector = TlsConnector::from(connector(&pki, version, c));
        let acceptor = TlsAcceptor::from(server_config(&pki, version, Some(s)));
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                connector.connect(localhost(), client_io),
                acceptor.accept(server_io)
            )
        })
        .await
        .unwrap();
        let server_err = server.unwrap_err();
        assert_eq!(server_err.kind(), io::ErrorKind::InvalidData);
        // The hash is compared first.
        assert_eq!(
            tls_error(&server_err),
            Some(&Error::PeerMisbehaved(
                PeerMisbehaved::ExternalIdHashMismatch
            ))
        );
        let client_err = client.unwrap_err();
        assert_eq!(
            tls_error(&client_err),
            Some(&Error::AlertReceived(AlertDescription::IllegalParameter)),
            "{client_err:?}"
        );
    }
}

#[tokio::test]
async fn the_lazy_acceptor_chooses_the_configuration_by_tls_id() {
    let pki = Pki::new();
    for version in versions() {
        for peer in ["alice", "bob"] {
            let (client_io, server_io) = duplex(64 * 1024);
            let connector = TlsConnector::from(connector(&pki, version, bindings(peer).0));
            let server = async {
                let start =
                    browntls_tokio::LazyConfigAcceptor::new(Acceptor::default(), server_io).await?;
                let config = chosen(&pki, version, &start.client_hello());
                start.into_stream(config).await
            };
            let (client, server) = timeout(LIMIT, async {
                tokio::join!(connector.connect(localhost(), client_io), server)
            })
            .await
            .unwrap();
            let (client, server) = (client.unwrap(), server.unwrap());
            assert_eq!(
                server.get_ref().1.peer_external_session_id(),
                Some(&tls_id(peer))
            );
            assert_eq!(
                client.get_ref().1.peer_external_session_id(),
                Some(&tls_id(&format!("server for {peer}")))
            );
        }
    }
}

#[tokio::test]
async fn the_unbuffered_lazy_acceptor_chooses_the_configuration_by_tls_id() {
    use browntls_tokio::unbuffered;
    let pki = Pki::new();
    for version in versions() {
        let (client_io, server_io) = duplex(64 * 1024);
        let connector = unbuffered::TlsConnector::from(connector(&pki, version, bindings("bob").0));
        let server = async {
            let start =
                unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), server_io).await?;
            let config = chosen(&pki, version, &start.client_hello());
            start.into_stream(config).await
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), client_io), server)
        })
        .await
        .unwrap();
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(
            server.get_ref().1.peer_external_session_id(),
            Some(&tls_id("bob"))
        );
        assert_eq!(
            client.get_ref().1.peer_external_id_hash(),
            Some(&ExternalIdHash::EMPTY)
        );
        assert_eq!(
            client.get_ref().1.peer_external_session_id(),
            Some(&tls_id("server for bob"))
        );
    }
}
