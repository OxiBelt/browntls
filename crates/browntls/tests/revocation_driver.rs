//! The transport-independent revocation pause in the ordinary TLS drivers.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used)]

mod common;
#[path = "providers/native.rs"]
mod prov;

use std::io::ErrorKind;
use std::sync::Arc;

use browntls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use browntls::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls::revocation::{PeerEvidence, RevocationCheck, RevocationResponse, RevocationStatus};
use browntls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, ServerConfig,
    ServerConnection, SignatureScheme, SupportedProtocolVersion,
};
use common::{
    Chain, KeyType, PinnedServerVerifier, do_handshake, provider, server_chain, transfer,
};

#[derive(Debug)]
struct Deferred {
    inner: Arc<PinnedServerVerifier>,
}

impl ServerCertVerifier for Deferred {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        staple: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner.verify_server_cert(end, chain, name, staple, now)
    }

    fn verify_server_cert_with_evidence(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.verify_server_cert(
            end,
            chain,
            name,
            evidence.first().and_then(|e| e.ocsp).unwrap_or_default(),
            now,
        )?;
        Ok(RevocationCheck::pending(
            [7; 32],
            vec!["http://ocsp.invalid/".into()],
            vec![0x30, 0],
            |response| match response {
                RevocationResponse::Der(bytes) if bytes == [1] => {
                    Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                }
                RevocationResponse::Unavailable => Err(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus,
                )),
                _ => Err(Error::InvalidCertificate(
                    CertificateError::InvalidOcspResponse,
                )),
            },
        ))
    }

    fn revocation_enabled(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn configs(
    version: &'static SupportedProtocolVersion,
    chain: &Chain,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Deferred {
            inner: PinnedServerVerifier::new(chain),
        }))
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn pause(client: &mut ClientConnection, server: &mut ServerConnection) -> u64 {
    transfer(client, server);
    server.process_new_packets().unwrap();
    transfer(server, client);
    assert!(client.process_new_packets().unwrap().revocation_pending());
    assert!(client.is_handshaking());
    assert!(client.peer_certificates().is_none());
    let mut queued = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut queued).unwrap();
    }
    // TLS 1.3 may already have queued a compatibility ChangeCipherSpec.
    assert!(queued.is_empty() || queued == [20, 3, 3, 0, 1, 1]);
    if !queued.is_empty() {
        server.read_tls(&mut queued.as_slice()).unwrap();
        server.process_new_packets().unwrap();
    }
    assert!(!client.wants_read());
    assert_eq!(
        client.read_tls(&mut &[][..]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    client.pending_revocation().unwrap().id()
}

fn check_roundtrips(version: &'static SupportedProtocolVersion) {
    let (client, server) = configs(version, &server_chain(KeyType::EcdsaP256));

    for _ in 0..2 {
        let mut client = ClientConnection::new(client.clone(), common::server_name()).unwrap();
        let mut server = ServerConnection::new(server.clone()).unwrap();
        let id = pause(&mut client, &mut server);
        assert!(
            client
                .resolve_peer_revocation(id.wrapping_add(1), RevocationResponse::Unavailable)
                .is_err()
        );
        assert_eq!(client.pending_revocation().unwrap().id(), id);
        client
            .resolve_peer_revocation(id, RevocationResponse::Der(vec![1]))
            .unwrap();
        assert!(
            client.wants_write(),
            "client flight requires no new socket input"
        );
        assert!(client.pending_revocation().is_none());
        assert!(
            client
                .resolve_peer_revocation(id, RevocationResponse::Unavailable)
                .is_err()
        );
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.peer_revocation_status(),
            Some(RevocationStatus::Good)
        );
    }
}

#[test]
fn tls13_coalesced_finished_resumes_and_each_connection_is_checked() {
    check_roundtrips(&browntls::version::TLS13);
}

#[test]
fn quic_resumes_with_coalesced_server_finished_and_no_new_crypto_bytes() {
    use browntls::quic::{ClientConnection, KeyChange, ServerConnection, Version};

    let (client, server) = configs(&browntls::version::TLS13, &server_chain(KeyType::EcdsaP256));
    let mut client =
        ClientConnection::new(client, Version::V1, common::server_name(), vec![]).unwrap();
    let mut server = ServerConnection::new(server, Version::V1, vec![]).unwrap();
    let mut flight = Vec::new();
    assert!(client.write_hs(&mut flight).is_none());
    server.read_hs(&flight).unwrap();
    flight.clear();
    assert!(matches!(
        server.write_hs(&mut flight),
        Some(KeyChange::Handshake { .. })
    ));
    client.read_hs(&flight).unwrap();
    flight.clear();
    assert!(matches!(
        client.write_hs(&mut flight),
        Some(KeyChange::Handshake { .. })
    ));
    assert!(flight.is_empty());
    assert!(matches!(
        server.write_hs(&mut flight),
        Some(KeyChange::OneRtt { .. })
    ));
    client.read_hs(&flight).unwrap();
    flight.clear();
    assert!(client.write_hs(&mut flight).is_none());
    assert!(flight.is_empty());
    assert!(client.peer_certificates().is_none());

    let id = client.pending_revocation().unwrap().id();
    client
        .resolve_peer_revocation(id, RevocationResponse::Der(vec![1]))
        .unwrap();
    assert_eq!(
        client.peer_revocation_status(),
        Some(RevocationStatus::Good)
    );
    assert!(matches!(
        client.write_hs(&mut flight),
        Some(KeyChange::OneRtt { .. })
    ));
    server.read_hs(&flight).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

#[test]
#[cfg(feature = "tls12")]
fn tls12_client_flight_resumes_and_each_connection_is_checked() {
    check_roundtrips(&browntls::version::TLS12);
}

#[test]
fn unavailable_status_sends_a_fatal_alert_and_exposes_no_identity() {
    let (client, server) = configs(&browntls::version::TLS13, &server_chain(KeyType::EcdsaP256));
    let mut client = ClientConnection::new(client, common::server_name()).unwrap();
    let mut server = ServerConnection::new(server).unwrap();
    let id = pause(&mut client, &mut server);

    let result = client.resolve_peer_revocation(id, RevocationResponse::Unavailable);
    assert_eq!(
        result,
        Err(Error::InvalidCertificate(
            CertificateError::UnknownRevocationStatus
        ))
    );
    assert!(client.peer_certificates().is_none());
    assert!(client.wants_write());
    transfer(&mut client, &mut server);
    assert!(matches!(
        server.process_new_packets(),
        Err(Error::AlertReceived(_))
    ));
}
