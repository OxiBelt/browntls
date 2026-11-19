// Shared cases, included by `tests/resumption_binding.rs` (RustCrypto
// provider) and `tests/resumption_binding_native.rs` (native provider).
// Provider items are reached through the including target's `prov` module.
//
// A client session store can be shared between configurations (it is an
// `Arc` inside `Resumption`). A session must only be resumed by a
// configuration whose server certificate verifier and client credential
// resolver are the very objects that established it: resuming skips server
// certificate verification and, in TLS 1.2, keeps the client identity.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_core::client::Resumption;
use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls_core::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error, HandshakeKind,
    ServerConfig, ServerConnection, SignatureScheme, SupportedProtocolVersion, version,
};
use common::*;

/// Delegates to a pinned verifier and counts certificate verifications.
#[derive(Debug)]
struct CountingVerifier {
    inner: Arc<PinnedServerVerifier>,
    cert_calls: AtomicUsize,
}

impl CountingVerifier {
    /// Accepts only `chain`'s end-entity certificate.
    fn pinned_to(chain: &Chain) -> Arc<Self> {
        Arc::new(Self {
            inner: PinnedServerVerifier::new(chain),
            cert_calls: AtomicUsize::new(0),
        })
    }

    fn cert_calls(&self) -> usize {
        self.cert_calls.load(Ordering::SeqCst)
    }
}

impl ServerCertVerifier for CountingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.cert_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
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

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

fn client(
    version: &'static SupportedProtocolVersion,
    verifier: Arc<dyn ServerCertVerifier>,
    resumption: Resumption,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = resumption;
    config
}

fn server(version: &'static SupportedProtocolVersion, chain: &Chain) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap(),
    )
}

const VERSIONS: [&SupportedProtocolVersion; 2] = [&version::TLS12, &version::TLS13];

/// Completes a full handshake with `config` and collects its tickets, so
/// the shared store holds a resumable session for `server_name()`.
fn establish(config: &Arc<ClientConfig>, server_config: &Arc<ServerConfig>) {
    let mut client = ClientConnection::new(config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    // TLS 1.3 tickets arrive after the handshake.
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
}

#[test]
fn shared_store_does_not_resume_under_a_stricter_verifier() {
    init_logging();
    for version in VERSIONS {
        let served = server_chain(KeyType::EcdsaP256);
        let other = server_chain(KeyType::EcdsaP256);
        let shared = Resumption::in_memory_sessions(8);
        let server_config = server(version, &served);

        let lenient = Arc::new(client(
            version,
            PinnedServerVerifier::new(&served),
            shared.clone(),
        ));
        establish(&lenient, &server_config);

        // A configuration whose verifier rejects the served certificate,
        // sharing the store, must verify (and so reject) the server.
        let strict_verifier = CountingVerifier::pinned_to(&other);
        let strict = Arc::new(client(version, strict_verifier.clone(), shared));
        let mut client = ClientConnection::new(strict, server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
        assert!(
            matches!(client_res, Err(Error::InvalidCertificate(_))),
            "{version:?}: {client_res:?}"
        );
        assert_eq!(strict_verifier.cert_calls(), 1, "{version:?}");
        assert_ne!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    }
}

#[test]
fn shared_store_runs_a_replaced_verifier_in_a_full_handshake() {
    init_logging();
    for version in VERSIONS {
        let chain = server_chain(KeyType::EcdsaP256);
        let server_config = server(version, &chain);
        let first = Arc::new(client(
            version,
            PinnedServerVerifier::new(&chain),
            Resumption::in_memory_sessions(8),
        ));
        establish(&first, &server_config);

        // A clone keeps the store but gets another (also accepting)
        // verifier: it must not inherit the session, and its verifier runs.
        let replacement = CountingVerifier::pinned_to(&chain);
        let mut second = (*first).clone();
        second
            .dangerous()
            .set_certificate_verifier(replacement.clone());
        let second = Arc::new(second);
        establish(&second, &server_config);
        assert_eq!(replacement.cert_calls(), 1, "{version:?}");

        // The session it saved is bound to the replacement and resumes.
        let mut client = ClientConnection::new(second, server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "{version:?}"
        );
        assert_eq!(replacement.cert_calls(), 1, "{version:?}");
    }
}

#[test]
fn cloned_config_with_the_same_verifier_still_resumes() {
    init_logging();
    for version in VERSIONS {
        let chain = server_chain(KeyType::EcdsaP256);
        let server_config = server(version, &chain);
        let verifier = CountingVerifier::pinned_to(&chain);
        let first = Arc::new(client(
            version,
            verifier.clone(),
            Resumption::in_memory_sessions(8),
        ));
        establish(&first, &server_config);
        assert_eq!(verifier.cert_calls(), 1);

        // Same verifier and resolver objects through a cloned configuration.
        let mut second = (*first).clone();
        second.alpn_protocols = vec![b"h2".to_vec()];
        let mut client = ClientConnection::new(Arc::new(second), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "{version:?}"
        );
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(verifier.cert_calls(), 1, "{version:?}");
    }
}

#[test]
fn shared_store_does_not_carry_client_credentials_to_another_config() {
    init_logging();
    for version in VERSIONS {
        let served = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::Ed25519);
        let shared = Resumption::in_memory_sessions(8);
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_protocol_versions(&[version])
                .unwrap()
                .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
                .with_single_cert(served.cert_chain(), served.private_key())
                .unwrap(),
        );
        let verifier: Arc<dyn ServerCertVerifier> = PinnedServerVerifier::new(&served);

        let mut with_cert = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap();
        with_cert.resumption = shared.clone();
        let with_cert = Arc::new(with_cert);
        establish(&with_cert, &server_config);

        // Same verifier object, no client certificate: the session that
        // authenticated the client must not be offered.
        let anonymous = Arc::new(client(version, verifier, shared));
        let mut client = ClientConnection::new(anonymous, server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            server.handshake_kind(),
            Some(HandshakeKind::Full),
            "{version:?}"
        );
        assert!(server.peer_certificates().is_none(), "{version:?}");
    }
}
