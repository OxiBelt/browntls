//! Server-side client certificate revocation: where the handshake stops for
//! a status lookup, what the server asks clients for, and which sessions it
//! refuses to store or resume while the verifier evaluates revocation.
//!
//! The verifier here is a stand-in that reports whatever the test scripts;
//! nothing in this target validates OCSP responses or SCTs.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use browntls_core::client::ResolvesClientCert;
use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls_core::psk::ExternalPsk;
use browntls_core::revocation::{
    PeerEvidence, RevocationCheck, RevocationResponse, RevocationStatus,
};
use browntls_core::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls_core::server::{PostHandshakeAuthStatus, StoresServerSessions};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct,
    DistinguishedName, Error, HandshakeKind, ServerConfig, ServerConnection, SignatureScheme,
    SupportedProtocolVersion, version,
};
use common::*;

const OCSP_LEAF: &[u8] = b"leaf status";
/// One SCT, `[0xaa, 0xbb]`.
const SCTS: &[u8] = &[0, 4, 0, 2, 0xaa, 0xbb];
const GOOD: &[u8] = b"good";

/// What the scripted verifier answers once the chain is acceptable.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Script {
    /// The stapled evidence settles it.
    Local,
    /// A lookup is needed: the response `GOOD` is good, any other revoked,
    /// and none at all is indeterminate.
    Lookup,
}

/// A client certificate verifier that evaluates revocation as scripted.
#[derive(Debug)]
struct RevocationVerifier {
    inner: Arc<PinnedClientVerifier>,
    script: Script,
    /// Per verified chain: whether each entry came with (OCSP, SCTs).
    evidence: Mutex<Vec<Vec<(bool, bool)>>>,
}

impl RevocationVerifier {
    fn new(client: &Chain, mandatory: bool, script: Script) -> Arc<Self> {
        Arc::new(Self {
            inner: PinnedClientVerifier::new(client, mandatory),
            script,
            evidence: Mutex::new(Vec::new()),
        })
    }

    fn evidence(&self) -> Vec<Vec<(bool, bool)>> {
        self.evidence.lock().unwrap().clone()
    }
}

impl ClientCertVerifier for RevocationVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
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
        evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        self.evidence.lock().unwrap().push(
            evidence
                .iter()
                .map(|entry| (entry.ocsp.is_some(), entry.scts.is_some()))
                .collect(),
        );
        Ok(match self.script {
            Script::Local => RevocationCheck::Complete(Some(RevocationStatus::Good)),
            Script::Lookup => RevocationCheck::pending(
                [7; 32],
                vec!["http://status.invalid/".into()],
                vec![0x30, 0],
                |response| match response {
                    RevocationResponse::Der(body) if body == GOOD => {
                        Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                    }
                    RevocationResponse::Unavailable => Ok(RevocationCheck::Complete(Some(
                        RevocationStatus::Indeterminate,
                    ))),
                    _ => Err(CertificateError::Revoked.into()),
                },
            ),
        })
    }

    fn revocation_enabled(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A server certificate verifier that evaluates revocation, which makes
/// the client offer `signed_certificate_timestamp`.
#[derive(Debug)]
struct SctOfferingServerVerifier(Arc<PinnedServerVerifier>);

impl ServerCertVerifier for SctOfferingServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn revocation_enabled(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Has certificates, so the client offers post-handshake authentication,
/// but never finds one acceptable for a request.
#[derive(Debug)]
struct DeclinesEveryRequest;

impl ResolvesClientCert for DeclinesEveryRequest {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct Setup {
    server_chain: Chain,
    client_chain: Chain,
}

impl Setup {
    fn new() -> Self {
        init_logging();
        Self {
            server_chain: server_chain(KeyType::EcdsaP256),
            client_chain: client_chain(KeyType::EcdsaP256),
        }
    }

    /// A client of `version`; with `certificate`, it holds the client
    /// chain with an OCSP response for the end entity and an SCT list.
    fn client(
        &self,
        version: &'static SupportedProtocolVersion,
        certificate: bool,
    ) -> ClientConfig {
        let builder = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&self.server_chain));
        let mut config = if certificate {
            let mut key = CertifiedKey::from_der(
                self.client_chain.cert_chain(),
                self.client_chain.private_key(),
                &provider(),
            )
            .unwrap();
            key.set_ocsp_for(0, Some(OCSP_LEAF.to_vec())).unwrap();
            key.set_sct_list(Some(SCTS.to_vec())).unwrap();
            builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)))
        } else {
            builder.with_no_client_auth()
        };
        config.enable_post_handshake_auth = true;
        config
    }

    /// A TLS 1.3 client that declines every certificate request.
    fn declining_client(&self) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&self.server_chain))
            .with_client_cert_resolver(Arc::new(DeclinesEveryRequest));
        config.enable_post_handshake_auth = true;
        config
    }

    fn server(&self, verifier: Arc<dyn ClientCertVerifier>) -> ServerConfig {
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                self.server_chain.cert_chain(),
                self.server_chain.private_key(),
            )
            .unwrap()
    }

    fn revocation_verifier(&self, mandatory: bool, script: Script) -> Arc<RevocationVerifier> {
        RevocationVerifier::new(&self.client_chain, mandatory, script)
    }
}

fn connect(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(client.clone(), server_name()).unwrap(),
        ServerConnection::new(server.clone()).unwrap(),
    )
}

/// Exchanges flights until the handshake ends or the server stops for a
/// status lookup.
fn drive(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..16 {
        let done = !client.is_handshaking() && !server.is_handshaking();
        if done || server.pending_revocation().is_some() {
            return Ok(());
        }
        transfer(client, server);
        server.process_new_packets()?;
        transfer(server, client);
        client.process_new_packets()?;
    }
    panic!("handshake neither completed nor stopped for a lookup");
}

/// Delivers what the server sends after the handshake (tickets).
fn deliver_tickets(client: &mut ClientConnection, server: &mut ServerConnection) {
    transfer(server, client);
    client.process_new_packets().unwrap();
}

/// Runs a whole handshake that needs no lookup and returns its kind.
fn handshake_kind(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> HandshakeKind {
    let (mut client, mut server) = connect(client, server);
    drive(&mut client, &mut server).unwrap();
    assert!(server.pending_revocation().is_none());
    deliver_tickets(&mut client, &mut server);
    server.handshake_kind().unwrap()
}

fn resolve(server: &mut ServerConnection, response: RevocationResponse) -> Result<(), Error> {
    let id = server.pending_revocation().expect("a pending lookup").id();
    server.resolve_peer_revocation(id, response)
}

fn take_tls<A: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<A>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

const VERSIONS: [&SupportedProtocolVersion; 2] = [&version::TLS13, &version::TLS12];

// ------------------------------------------------- initial client authentication

#[test]
fn handshake_waits_for_the_status_lookup_after_the_proof() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(true, Script::Lookup);
        let client_config = Arc::new(setup.client(version, true));
        let server_config = Arc::new(setup.server(verifier.clone()));
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();

        // The whole client flight has arrived, but the server reads nothing
        // past the CertificateVerify and reports no identity yet.
        let query = server.pending_revocation().expect("a pending lookup");
        assert_eq!(query.issuer_key_hash(), &[7; 32]);
        let id = query.id();
        assert!(server.is_handshaking());
        assert!(!server.wants_read());
        assert!(server.peer_certificates().is_none());
        assert_eq!(server.peer_revocation_status(), None);
        assert!(server.process_new_packets().unwrap().revocation_pending());
        assert!(server.is_handshaking(), "{version:?}: input stays unread");

        // A response for another request changes nothing.
        assert!(
            server
                .resolve_peer_revocation(id.wrapping_add(1), RevocationResponse::Unavailable)
                .is_err()
        );
        assert!(server.pending_revocation().is_some());

        resolve(&mut server, RevocationResponse::Der(GOOD.to_vec())).unwrap();
        assert!(server.pending_revocation().is_none());
        drive(&mut client, &mut server).unwrap();
        assert!(!server.is_handshaking() && !client.is_handshaking());
        assert_eq!(
            server.peer_certificates().unwrap(),
            setup.client_chain.cert_chain()
        );
        assert_eq!(
            server.peer_revocation_status(),
            Some(RevocationStatus::Good)
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"after the lookup"),
            b"after the lookup"
        );

        // TLS 1.3 asks for OCSP responses and SCTs in its
        // CertificateRequest; a TLS 1.2 client cannot staple any.
        let stapled = verifier.evidence();
        assert_eq!(stapled.len(), 1, "{version:?}: verified once");
        if version.version == browntls_core::ProtocolVersion::TLSv1_3 {
            assert_eq!(stapled[0].first(), Some(&(true, true)));
            assert!(
                stapled[0]
                    .iter()
                    .skip(1)
                    .all(|entry| *entry == (false, false))
            );
        } else {
            assert!(stapled[0].is_empty());
        }
    }
}

#[test]
fn unavailable_status_is_the_verifiers_call() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(true, Script::Lookup);
        let client_config = Arc::new(setup.client(version, true));
        let server_config = Arc::new(setup.server(verifier));
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();
        resolve(&mut server, RevocationResponse::Unavailable).unwrap();
        drive(&mut client, &mut server).unwrap();
        assert_eq!(
            server.peer_revocation_status(),
            Some(RevocationStatus::Indeterminate)
        );
    }
}

#[test]
fn revoked_client_certificate_fails_the_handshake() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(true, Script::Lookup);
        let client_config = Arc::new(setup.client(version, true));
        let server_config = Arc::new(setup.server(verifier));
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();

        let err = resolve(&mut server, RevocationResponse::Der(b"revoked".to_vec())).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidCertificate(CertificateError::Revoked),
            "{version:?}"
        );
        assert!(server.pending_revocation().is_none());
        assert!(server.peer_certificates().is_none());
        assert_eq!(server.peer_revocation_status(), None);
        assert!(
            server.process_new_packets().is_err(),
            "the connection is over"
        );

        transfer(&mut server, &mut client);
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::AlertReceived(AlertDescription::CertificateRevoked),
            "{version:?}"
        );
    }
}

#[test]
fn locally_settled_status_does_not_stop_the_handshake() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(true, Script::Local);
        let client_config = Arc::new(setup.client(version, true));
        let server_config = Arc::new(setup.server(verifier));
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();
        assert!(server.pending_revocation().is_none());
        assert!(!server.is_handshaking());
        assert_eq!(
            server.peer_revocation_status(),
            Some(RevocationStatus::Good)
        );
    }
}

#[test]
fn client_auth_stays_optional() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(false, Script::Lookup);
        let client_config = Arc::new(setup.client(version, false));
        let server_config = Arc::new(setup.server(verifier.clone()));
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();
        assert!(server.pending_revocation().is_none());
        assert!(!server.is_handshaking());
        assert!(server.peer_certificates().is_none());
        assert_eq!(server.peer_revocation_status(), None);
        assert!(verifier.evidence().is_empty(), "nothing to verify");
    }
}

#[test]
fn mandatory_client_auth_still_needs_a_certificate() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(true, Script::Lookup);
        let client_config = Arc::new(setup.client(version, false));
        let server_config = Arc::new(setup.server(verifier));
        let (mut client, mut server) = connect(&client_config, &server_config);
        let (_, server_result) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_result.unwrap_err(),
            Error::NoCertificatesPresented,
            "{version:?}"
        );
        assert!(server.pending_revocation().is_none());
    }
}

#[test]
fn evidence_is_not_requested_without_revocation() {
    // The client holds an OCSP response and SCTs and staples them when
    // asked. A server whose verifier does not evaluate revocation does not
    // ask, and would refuse them as unsolicited.
    let setup = Setup::new();
    let client_config = Arc::new(setup.client(&version::TLS13, true));
    let server_config =
        Arc::new(setup.server(PinnedClientVerifier::new(&setup.client_chain, true)));
    let (mut client, mut server) = connect(&client_config, &server_config);
    drive(&mut client, &mut server).unwrap();
    assert_eq!(
        server.peer_certificates().unwrap(),
        setup.client_chain.cert_chain()
    );
    assert_eq!(server.peer_revocation_status(), None);
}

#[test]
fn no_half_rtt_data_ahead_of_a_client_certificate_under_evaluation() {
    let setup = Setup::new();
    // Without revocation, half-RTT data precedes client authentication.
    for (evaluated, expected) in [(false, &b"half-RTT"[..]), (true, &b""[..])] {
        let verifier: Arc<dyn ClientCertVerifier> = if evaluated {
            setup.revocation_verifier(true, Script::Lookup)
        } else {
            PinnedClientVerifier::new(&setup.client_chain, true)
        };
        let mut server_config = setup.server(verifier);
        server_config.send_half_rtt_data = true;
        let client_config = Arc::new(setup.client(&version::TLS13, true));
        let (mut client, mut server) = connect(&client_config, &Arc::new(server_config));
        server.writer().write_all(b"half-RTT").unwrap();

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        let mut got = Vec::new();
        client.reader().read_to_end(&mut got).ok();
        assert_eq!(got, expected, "revocation evaluated: {evaluated}");

        // The data follows once the client is authenticated.
        drive(&mut client, &mut server).unwrap();
        if evaluated {
            resolve(&mut server, RevocationResponse::Der(GOOD.to_vec())).unwrap();
            drive(&mut client, &mut server).unwrap();
        }
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        client.reader().read_to_end(&mut got).ok();
        assert_eq!(got, b"half-RTT");
    }
}

// ------------------------------------------------------- sessions and tickets

#[test]
fn sessions_with_a_client_certificate_are_neither_stored_nor_resumed() {
    let setup = Setup::new();
    for version in VERSIONS {
        for mandatory in [true, false] {
            let verifier = setup.revocation_verifier(mandatory, Script::Local);
            let client_config = Arc::new(setup.client(version, true));
            let server_config = Arc::new(setup.server(verifier.clone()));
            for attempt in 0..3 {
                assert_eq!(
                    handshake_kind(&client_config, &server_config),
                    HandshakeKind::Full,
                    "{version:?}, mandatory {mandatory}, attempt {attempt}"
                );
            }
            assert_eq!(verifier.evidence().len(), 3, "verified afresh each time");
        }
    }
}

#[test]
fn tls12_revocation_policy_disables_ticket_resumption() {
    let setup = Setup::new();
    let verifier = setup.revocation_verifier(false, Script::Local);
    let client_config = Arc::new(setup.client(&version::TLS12, true));
    let mut server_config = setup.server(verifier);
    server_config.ticketer = prov::Ticketer::new().unwrap();
    let server_config = Arc::new(server_config);
    for _ in 0..2 {
        assert_eq!(
            handshake_kind(&client_config, &server_config),
            HandshakeKind::Full
        );
    }

    // The full handshake still works when the optional certificate is absent.
    let anonymous = Arc::new(setup.client(&version::TLS12, false));
    assert_eq!(
        handshake_kind(&anonymous, &server_config),
        HandshakeKind::Full
    );
    assert_eq!(
        handshake_kind(&anonymous, &server_config),
        HandshakeKind::Full
    );
}

#[test]
fn certificate_sessions_without_optional_client_certificates_do_not_resume() {
    let setup = Setup::new();
    for version in VERSIONS {
        let verifier = setup.revocation_verifier(false, Script::Lookup);
        let client_config = Arc::new(setup.client(version, false));
        let server_config = Arc::new(setup.server(verifier));
        assert_eq!(
            handshake_kind(&client_config, &server_config),
            HandshakeKind::Full,
            "{version:?}"
        );
        assert_eq!(
            handshake_kind(&client_config, &server_config),
            HandshakeKind::Full,
            "{version:?}"
        );
    }
}

#[test]
fn old_anonymous_sessions_cannot_satisfy_required_client_authentication() {
    let setup = Setup::new();
    for version in VERSIONS {
        let client_config = Arc::new(setup.client(version, false));
        let before = Arc::new(setup.server(Arc::new(browntls_core::server::NoClientAuth)));
        assert_eq!(handshake_kind(&client_config, &before), HandshakeKind::Full);
        assert_eq!(
            handshake_kind(&client_config, &before),
            HandshakeKind::Resumed
        );
        let mut after = setup.server(setup.revocation_verifier(true, Script::Local));
        after.session_storage = before.session_storage.clone();
        let (mut client, mut server) = connect(&client_config, &Arc::new(after));
        assert!(drive(&mut client, &mut server).is_err(), "{version:?}");
        assert_ne!(
            server.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "{version:?}"
        );
    }
}

#[test]
fn sessions_stored_before_revocation_was_evaluated_are_not_resumed() {
    let setup = Setup::new();
    for version in VERSIONS {
        let client_config = Arc::new(setup.client(version, true));
        let before = setup.server(PinnedClientVerifier::new(&setup.client_chain, true));
        let storage: Arc<dyn StoresServerSessions> = before.session_storage.clone();
        let before = Arc::new(before);
        assert_eq!(handshake_kind(&client_config, &before), HandshakeKind::Full);
        assert_eq!(
            handshake_kind(&client_config, &before),
            HandshakeKind::Resumed,
            "{version:?}: the control resumes"
        );

        // The same session store, now behind a verifier that evaluates
        // revocation: the stored session carries the client's chain.
        let verifier = setup.revocation_verifier(true, Script::Local);
        let mut after = setup.server(verifier.clone());
        after.session_storage = storage;
        let after = Arc::new(after);
        let (mut client, mut server) = connect(&client_config, &after);
        drive(&mut client, &mut server).unwrap();
        assert_eq!(
            server.handshake_kind(),
            Some(HandshakeKind::Full),
            "{version:?}"
        );
        assert_eq!(verifier.evidence().len(), 1, "{version:?}: verified afresh");
        assert_eq!(
            server.peer_revocation_status(),
            Some(RevocationStatus::Good)
        );
    }
}

#[test]
fn external_psk_only_sessions_are_unaffected() {
    let setup = Setup::new();
    let verifier = setup.revocation_verifier(true, Script::Lookup);
    // First handshake's kind and tickets, then the next handshake's kind.
    let run = |verifier: Arc<dyn ClientCertVerifier>| {
        let psk = Arc::new(
            ExternalPsk::new(b"device 7".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256).unwrap(),
        );
        let mut client_config = setup.client(&version::TLS13, false);
        client_config.external_psks = vec![psk.clone()];
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_external_psks_only(Arc::new(vec![psk])),
        );
        let (mut client, mut server) = connect(&client_config, &server_config);
        drive(&mut client, &mut server).unwrap();
        assert!(!server.is_handshaking());
        assert!(server.external_psk_identity().is_some());
        deliver_tickets(&mut client, &mut server);
        (
            server.handshake_kind(),
            client.tls13_tickets_received(),
            handshake_kind(&client_config, &server_config),
        )
    };

    let evaluated = run(verifier.clone());
    let control = run(PinnedClientVerifier::new(&setup.client_chain, true));
    assert_eq!(evaluated, control);
    assert!(evaluated.1 > 0, "tickets are still issued");
    assert!(
        verifier.evidence().is_empty(),
        "no certificate was involved"
    );
}

#[test]
fn raw_public_key_sessions_are_unaffected() {
    // A verifier that takes only raw public keys has no certificate whose
    // status it could evaluate, whatever it reports.
    let setup = Setup::new();
    for version in VERSIONS {
        let evaluating = Arc::new(RevocationVerifier {
            inner: PinnedClientVerifier::raw_public_key(&setup.client_chain),
            script: Script::Local,
            evidence: Mutex::new(Vec::new()),
        });
        // The kinds of two handshakes in a row.
        let run = |verifier: Arc<dyn ClientCertVerifier>| {
            let client_config = Arc::new(
                ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::raw_public_key(
                        &setup.server_chain,
                    ))
                    .with_client_cert_resolver(RawKeyResolver::new(&setup.client_chain)),
            );
            let server_config = Arc::new(
                ServerConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(RawKeyResolver::new(&setup.server_chain)),
            );
            [
                handshake_kind(&client_config, &server_config),
                handshake_kind(&client_config, &server_config),
            ]
        };

        let evaluated = run(evaluating.clone());
        let control = run(PinnedClientVerifier::raw_public_key(&setup.client_chain));
        assert_eq!(evaluated, control, "{version:?}");
        assert_eq!(
            evaluated,
            [HandshakeKind::Full, HandshakeKind::Resumed],
            "{version:?}"
        );
        // Verified once, with no evidence requested for the raw key.
        let stapled = evaluating.evidence();
        assert_eq!(stapled.len(), 1, "{version:?}");
        assert!(stapled[0].iter().all(|entry| *entry == (false, false)));
    }
}

// -------------------------------------------- post-handshake client authentication

/// A handshake without client authentication, then a post-handshake
/// request carried up to the server having read the client's answer.
fn post_handshake_exchange(
    setup: &Setup,
    verifier: Arc<RevocationVerifier>,
    client_config: ClientConfig,
) -> (ClientConnection, ServerConnection) {
    let client_config = Arc::new(client_config);
    let mut server_config = setup.server(verifier);
    server_config.request_client_auth_after_handshake = true;
    let (mut client, mut server) = connect(&client_config, &Arc::new(server_config));
    drive(&mut client, &mut server).unwrap();
    deliver_tickets(&mut client, &mut server);
    assert!(server.peer_certificates().is_none(), "deferred");

    server.request_client_auth().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    (client, server)
}

#[test]
fn post_handshake_auth_waits_for_the_status_lookup() {
    let setup = Setup::new();
    let verifier = setup.revocation_verifier(true, Script::Lookup);
    let (mut client, mut server) = post_handshake_exchange(
        &setup,
        verifier.clone(),
        setup.client(&version::TLS13, true),
    );
    assert!(server.process_new_packets().unwrap().revocation_pending());

    // The connection stays established; the answer's Finished is unread
    // and neither the identity nor the outcome is reported.
    assert!(!server.is_handshaking());
    assert!(server.pending_revocation().is_some());
    assert!(server.peer_certificates().is_none());
    assert_eq!(server.peer_revocation_status(), None);
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Requested)
    );
    assert_eq!(verifier.evidence().len(), 1);
    assert_eq!(verifier.evidence()[0].first(), Some(&(true, true)));

    resolve(&mut server, RevocationResponse::Der(GOOD.to_vec())).unwrap();
    assert!(server.pending_revocation().is_none());
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(
        server.peer_certificates().unwrap(),
        setup.client_chain.cert_chain()
    );
    assert_eq!(
        server.peer_revocation_status(),
        Some(RevocationStatus::Good)
    );
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"authenticated"),
        b"authenticated"
    );
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"and back"),
        b"and back"
    );

    // A second request runs the evaluation again.
    server.request_client_auth().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    assert!(server.process_new_packets().unwrap().revocation_pending());
    resolve(&mut server, RevocationResponse::Unavailable).unwrap();
    assert_eq!(
        server.peer_revocation_status(),
        Some(RevocationStatus::Indeterminate)
    );
    assert_eq!(verifier.evidence().len(), 2);
}

#[test]
fn post_handshake_auth_with_a_revoked_certificate_ends_the_connection() {
    let setup = Setup::new();
    let verifier = setup.revocation_verifier(true, Script::Lookup);
    let (mut client, mut server) =
        post_handshake_exchange(&setup, verifier, setup.client(&version::TLS13, true));
    server.process_new_packets().unwrap();

    let err = resolve(&mut server, RevocationResponse::Der(b"revoked".to_vec())).unwrap_err();
    assert_eq!(err, Error::InvalidCertificate(CertificateError::Revoked));
    assert!(server.peer_certificates().is_none());
    assert_eq!(server.peer_revocation_status(), None);
    assert_ne!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::CertificateRevoked)
    );
}

#[test]
fn post_handshake_auth_settled_locally_or_declined_does_not_stop() {
    let setup = Setup::new();
    let verifier = setup.revocation_verifier(false, Script::Local);
    let (_client, mut server) =
        post_handshake_exchange(&setup, verifier, setup.client(&version::TLS13, true));
    assert!(!server.process_new_packets().unwrap().revocation_pending());
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(
        server.peer_revocation_status(),
        Some(RevocationStatus::Good)
    );

    let verifier = setup.revocation_verifier(false, Script::Lookup);
    let (_client, mut server) =
        post_handshake_exchange(&setup, verifier.clone(), setup.declining_client());
    assert!(!server.process_new_packets().unwrap().revocation_pending());
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Declined)
    );
    assert!(server.peer_certificates().is_none());
    assert_eq!(server.peer_revocation_status(), None);
    assert!(verifier.evidence().is_empty());
}

// ------------------------------------------------------------ TLS 1.2 SCT list

#[test]
fn tls12_server_hello_carries_the_sct_list_only_when_offered() {
    let setup = Setup::new();
    let mut key = CertifiedKey::from_der(
        setup.server_chain.cert_chain(),
        setup.server_chain.private_key(),
        &provider(),
    )
    .unwrap();
    key.set_sct_list(Some(SCTS.to_vec())).unwrap();
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key))),
    );
    // signed_certificate_timestamp (18) carrying the configured list.
    let mut extension = vec![0, 18, 0, u8::try_from(SCTS.len()).unwrap()];
    extension.extend_from_slice(SCTS);

    for offered in [false, true] {
        let mut client_config = setup.client(&version::TLS12, false);
        if offered {
            client_config.dangerous().set_certificate_verifier(Arc::new(
                SctOfferingServerVerifier(PinnedServerVerifier::new(&setup.server_chain)),
            ));
        }
        let (mut client, mut server) = connect(&Arc::new(client_config), &server_config);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        let flight = take_tls(&mut server);
        assert_eq!(contains(&flight, &extension), offered, "offered: {offered}");
    }
}
