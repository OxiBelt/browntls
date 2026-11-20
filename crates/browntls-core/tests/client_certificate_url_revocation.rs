//! A TLS 1.2 server that fetches the client's chain named by URL (RFC 6066
//! §5) and then looks up the chain's revocation status: the two pauses
//! follow each other, and neither answers the other's query.
//!
//! The verifier is a stand-in that asks for one status lookup and takes the
//! scripted response; nothing here validates OCSP responses.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls_core::certificate_url::{
    CertificateUrl, ClientCertificateUrlPolicy, ClientCertificateUrlResponse, UrlAndHash,
};
use browntls_core::pki_types::{CertificateDer, UnixTime};
use browntls_core::revocation::{
    PeerEvidence, RevocationCheck, RevocationResponse, RevocationStatus,
};
use browntls_core::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName,
    Error, ServerConfig, ServerConnection, SignatureScheme, version,
};
use common::hello_wire::{give, take_flight};
use common::*;

const EE_URL: &str = "http://certs.example/client.der";
const CA_URL: &str = "http://certs.example/ca.der";
const GOOD: &[u8] = b"good";

/// A client certificate verifier that asks for one status lookup: the
/// response `GOOD` is good, any other revoked.
#[derive(Debug)]
struct LookupVerifier(Arc<PinnedClientVerifier>);

impl ClientCertVerifier for LookupVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        panic!("the server must use verify_client_cert_with_evidence");
    }

    fn verify_client_cert_with_evidence(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)?;
        Ok(RevocationCheck::pending(
            [7; 32],
            vec!["http://status.invalid/".into()],
            vec![0x30, 0],
            |response| match response {
                RevocationResponse::Der(body) if body == GOOD => {
                    Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                }
                _ => Err(CertificateError::Revoked.into()),
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
        dss: &DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[test]
fn the_status_lookup_follows_the_url_fetch() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let objects = vec![client_chain.end_entity.to_vec(), client_chain.ca.to_vec()];

    let key = provider()
        .key_provider
        .load_private_key(client_chain.private_key())
        .unwrap();
    let mut key = CertifiedKey::new(Vec::new(), key);
    key.set_certificate_url(Some(
        CertificateUrl::individual_certs(vec![
            UrlAndHash::for_object(EE_URL, &objects[0], prov::sha1).unwrap(),
            UrlAndHash::for_object(CA_URL, &objects[1], prov::sha1).unwrap(),
        ])
        .unwrap(),
    ));
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    client_config.enable_client_certificate_url = true;
    let verifier = Arc::new(LookupVerifier(PinnedClientVerifier::new(
        &client_chain,
        true,
    )));
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    server_config.client_certificate_url = Some(ClientCertificateUrlPolicy::new(prov::sha1));

    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    for _ in 0..2 {
        give(&mut server, &take_flight(&mut client));
        server.process_new_packets().unwrap();
        give(&mut client, &take_flight(&mut server));
        client.process_new_packets().unwrap();
    }

    // The whole client flight has arrived; the server waits for the chain.
    let url_id = server.pending_client_certificate_url().unwrap().id();
    assert!(server.pending_revocation().is_none());
    // No status lookup is pending, so a status answer is refused and the
    // URL query stays.
    assert!(
        server
            .resolve_peer_revocation(0, RevocationResponse::Der(GOOD.to_vec()))
            .is_err()
    );
    assert_eq!(
        server.pending_client_certificate_url().map(|q| q.id()),
        Some(url_id)
    );

    // The chain is verified, ClientKeyExchange and CertificateVerify are
    // processed, and the handshake stops again for the status lookup,
    // still without a reported identity.
    server
        .resolve_client_certificate_url(url_id, ClientCertificateUrlResponse::Fetched(objects))
        .unwrap();
    assert!(server.pending_client_certificate_url().is_none());
    let ocsp_id = server.pending_revocation().expect("a status lookup").id();
    let io = server.process_new_packets().unwrap();
    assert!(io.revocation_pending() && !io.client_certificate_url_pending());
    assert!(server.is_handshaking() && !server.wants_read());
    assert!(server.peer_certificates().is_none());
    assert_eq!(server.peer_revocation_status(), None);

    // The URL query is gone: answering it again is refused, and the lookup
    // stays.
    assert!(
        server
            .resolve_client_certificate_url(url_id, ClientCertificateUrlResponse::Unobtainable)
            .is_err()
    );
    assert_eq!(server.pending_revocation().map(|q| q.id()), Some(ocsp_id));

    server
        .resolve_peer_revocation(ocsp_id, RevocationResponse::Der(GOOD.to_vec()))
        .unwrap();
    give(&mut client, &take_flight(&mut server));
    client.process_new_packets().unwrap();
    assert!(!server.is_handshaking() && !client.is_handshaking());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    assert_eq!(
        server.peer_revocation_status(),
        Some(RevocationStatus::Good)
    );
}
