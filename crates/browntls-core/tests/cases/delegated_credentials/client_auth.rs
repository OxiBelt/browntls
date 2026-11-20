// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers: TLS 1.3 client authentication with a delegated
// credential (RFC 9345 §4.1.2).

use browntls_core::delegated_credential::{Presented, validate};
use browntls_core::server::PostHandshakeAuthStatus;
use browntls_core::server::danger::ClientCertVerifier;

/// A client configuration that trusts `server` and authenticates with
/// `certified_key`.
fn client_with(server: &Chain, certified_key: CertifiedKey) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
}

/// A server configuration that serves `server`, requires the client
/// certificate `verifier` accepts, and accepts delegated credentials for it.
fn dc_server(server: &Chain, verifier: Arc<dyn ClientCertVerifier>) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    config.enable_delegated_credentials = true;
    config
}

#[test]
fn client_authenticates_with_a_delegated_credential() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for &cert_type in KeyType::SIGNING {
        let chain = delegation_client_chain(cert_type);
        for dc_scheme in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ] {
            let (dc, key) = issue_for(Side::Client, &chain, dc_scheme, shifted(24 * 3600));
            let ck = certified_key(&chain)
                .with_client_delegated_credential(dc.clone(), key)
                .unwrap();
            let verifier = SchemeRecordingClientVerifier::new(
                PinnedClientVerifier::new(&chain, true),
                &prov::SUPPORTED_SIG_ALGS.supported_schemes(),
            );
            let (mut client, mut server) = connect(
                client_with(&server_chain, ck),
                dc_server(&server_chain, verifier.clone()),
            );
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            assert_eq!(
                server.client_delegated_credential(),
                Some(&dc),
                "{cert_type:?} {dc_scheme:?}"
            );
            // The credential's signature (certificate key), then
            // CertificateVerify (credential key).
            assert_eq!(verifier.seen(), [dc.algorithm, dc_scheme]);
            assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
            // The server authenticated with its certificate key.
            assert!(client.delegated_credential().is_none());
            assert_eq!(
                send_and_receive(&mut client, &mut server, b"hello"),
                b"hello"
            );
            assert_eq!(
                send_and_receive(&mut server, &mut client, b"world"),
                b"world"
            );
        }
    }
}

/// A client certificate resolver whose answer the test changes between
/// connections or requests; one object, so sessions it established stay
/// resumable (client sessions are bound to their resolver). `None`
/// declines a request.
#[derive(Debug)]
struct SwitchingResolver(std::sync::Mutex<Option<Arc<CertifiedKey>>>);

impl SwitchingResolver {
    fn new(key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(Some(Arc::new(key)))))
    }

    fn set(&self, key: Option<CertifiedKey>) {
        *self.0.lock().unwrap() = key.map(Arc::new);
    }
}

impl browntls_core::client::ResolvesClientCert for SwitchingResolver {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.0.lock().unwrap().clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A client configuration that trusts `server` and authenticates with what
/// `resolver` currently holds.
fn client_switching(server: &Chain, resolver: Arc<SwitchingResolver>) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_client_cert_resolver(resolver)
}

/// Accepts exactly `chain`'s client certificate, recording the scheme of
/// every signature checked, with the CertificateRequest offering all the
/// provider's schemes.
fn recording_verifier(chain: &Chain) -> Arc<SchemeRecordingClientVerifier> {
    SchemeRecordingClientVerifier::new(
        PinnedClientVerifier::new(chain, true),
        &prov::SUPPORTED_SIG_ALGS.supported_schemes(),
    )
}

/// `chain`'s certified key with the client credentials `dcs`, most
/// preferred first.
fn with_client_credentials(
    chain: &Chain,
    dcs: Vec<(DelegatedCredential, Arc<dyn SigningKey>)>,
) -> CertifiedKey {
    dcs.into_iter().fold(certified_key(chain), |ck, (dc, key)| {
        ck.with_client_delegated_credential(dc, key).unwrap()
    })
}

#[test]
fn client_credential_not_used_unless_both_sides_opt_in() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let ck = with_client_credentials(&chain, vec![(dc, key)]);
    let cert_key_signs = [SignatureScheme::ECDSA_NISTP256_SHA256];

    // The server did not enable them: its CertificateRequest carries no
    // `delegated_credential` extension, so the certificate key signs.
    let verifier = recording_verifier(&chain);
    let mut server_config = dc_server(&server_chain, verifier.clone());
    server_config.enable_delegated_credentials = false;
    let (mut client, mut server) = connect(client_with(&server_chain, ck.clone()), server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), cert_key_signs);
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);

    // The client has no credential.
    let verifier = recording_verifier(&chain);
    let (mut client, mut server) = connect(
        client_with(&server_chain, certified_key(&chain)),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), cert_key_signs);

    // The client has only a server's credential, attached as one: a side
    // only presents credentials attached for itself.
    let (server_dc, server_key) = issue_for(
        Side::Server,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let server_only = certified_key(&chain)
        .with_delegated_credential(server_dc, server_key)
        .unwrap();
    assert_eq!(server_only.delegated_credentials()[0].side(), Side::Server);
    let verifier = recording_verifier(&chain);
    let (mut client, mut server) = connect(
        client_with(&server_chain, server_only),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), cert_key_signs);

    // TLS 1.2: delegated credentials are TLS 1.3 only.
    #[cfg(feature = "tls12")]
    {
        let verifier = recording_verifier(&chain);
        let mut server_config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&browntls_core::version::TLS12])
            .unwrap()
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        server_config.enable_delegated_credentials = true;
        let (mut client, mut server) =
            connect(client_with(&server_chain, ck.clone()), server_config);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_2));
        assert!(server.client_delegated_credential().is_none());
        assert_eq!(verifier.seen(), cert_key_signs);
    }

    // The server accepts no scheme the credential uses: the client falls
    // back to its certificate key.
    let verifier = SchemeRecordingClientVerifier::new(
        PinnedClientVerifier::new(&chain, true),
        &cert_key_signs,
    );
    let (mut client, mut server) = connect(
        client_with(&server_chain, ck),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), cert_key_signs);
}

/// The credential's own signature uses a scheme the CertificateRequest's
/// `signature_algorithms` lacks, although its key's scheme is accepted:
/// the client does not send it (RFC 9345 §4.1.2).
#[test]
fn client_credential_signed_with_an_unoffered_scheme_is_not_sent() {
    if !prov::SIGNS_RSA {
        return;
    }
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::Rsa2048);
    let (dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    // The certificate key signs the credential with its strongest scheme.
    assert_eq!(dc.algorithm, SignatureScheme::RSA_PSS_SHA512);
    let offer = [SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ED25519];
    let verifier =
        SchemeRecordingClientVerifier::new(PinnedClientVerifier::new(&chain, true), &offer);
    let (mut client, mut server) = connect(
        client_with(
            &server_chain,
            with_client_credentials(&chain, vec![(dc, key)]),
        ),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), [SignatureScheme::RSA_PSS_SHA256]);
}

#[test]
fn client_skips_unusable_credentials() {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    // A server's credential, expired, valid for too long, then a good one.
    let server_side = issue_for(
        Side::Server,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let expired = issue_for(Side::Client, &chain, SignatureScheme::ED25519, shifted(-60));
    let too_long = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(MAX_VALIDITY.as_secs() as i64 + 3600),
    );
    let good = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        shifted(3600),
    );
    let good_dc = good.0.clone();
    let ck = certified_key(&chain)
        .with_delegated_credential(server_side.0, server_side.1)
        .unwrap();
    let ck = [expired, too_long, good]
        .into_iter()
        .fold(ck, |ck, (dc, key)| {
            ck.with_client_delegated_credential(dc, key).unwrap()
        });
    let verifier = recording_verifier(&chain);
    let (mut client, mut server) = connect(
        client_with(&server_chain, ck),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.client_delegated_credential(), Some(&good_dc));
    assert_eq!(
        verifier.seen(),
        [good_dc.algorithm, SignatureScheme::ECDSA_NISTP384_SHA384]
    );
}

/// The client, whose clock is `client_skew` seconds off, presents `ck`
/// (for `chain`) to a server that accepts client credentials; returns the
/// `(client, server)` results.
fn presented_to_server(
    chain: &Chain,
    ck: CertifiedKey,
    client_skew: i64,
) -> (Result<(), Error>, Result<(), Error>) {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&server_chain, ck);
    client_config.time_provider = Arc::new(FixedTime(shifted(client_skew)));
    let (mut client, mut server) = connect(
        client_config,
        dc_server(&server_chain, PinnedClientVerifier::new(chain, true)),
    );
    do_handshake_until_error(&mut client, &mut server)
}

/// Asserts the server refused the client's credential with `expected`,
/// answered with `illegal_parameter` (RFC 9345 §4.1.3).
fn assert_illegal_parameter(
    (client, server): (Result<(), Error>, Result<(), Error>),
    expected: PeerMisbehaved,
) {
    assert_eq!(server, Err(Error::PeerMisbehaved(expected)));
    assert_eq!(
        client,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn server_rejects_expired_client_credential() {
    // The client's clock is two hours behind: it still sees an hour left.
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let dc = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(-3600),
    );
    let ck = with_client_credentials(&chain, vec![dc]);
    assert_illegal_parameter(
        presented_to_server(&chain, ck, -2 * 3600),
        PeerMisbehaved::DelegatedCredentialExpired,
    );
}

#[test]
fn server_rejects_client_credential_valid_too_long() {
    // The client's clock is two hours ahead: it sees less than a week left.
    let week = MAX_VALIDITY.as_secs() as i64;
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let dc = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(week + 3600),
    );
    let ck = with_client_credentials(&chain, vec![dc]);
    assert_illegal_parameter(
        presented_to_server(&chain, ck, 2 * 3600),
        PeerMisbehaved::DelegatedCredentialValidityTooLong,
    );
}

/// A credential issued for a server, attached as a client's: its signature
/// covers the side (RFC 9345 §4), so it does not verify as a client's.
#[test]
fn server_rejects_a_server_credential_presented_by_a_client() {
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let dc = issue_for(
        Side::Server,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let ck = with_client_credentials(&chain, vec![dc]);
    assert_eq!(ck.delegated_credentials()[0].side(), Side::Client);
    assert_illegal_parameter(
        presented_to_server(&chain, ck, 0),
        PeerMisbehaved::DelegatedCredentialBadSignature,
    );
}

#[test]
fn server_rejects_tampered_client_credential() {
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    // Moving the expiry by a second invalidates the signature.
    let (mut dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    dc.credential.valid_time -= 1;
    let ck = with_client_credentials(&chain, vec![(dc, key)]);
    assert_illegal_parameter(
        presented_to_server(&chain, ck, 0),
        PeerMisbehaved::DelegatedCredentialBadSignature,
    );

    // So does a flipped bit in the signature itself.
    let (mut dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    *dc.signature.last_mut().unwrap() ^= 1;
    let ck = with_client_credentials(&chain, vec![(dc, key)]);
    assert_illegal_parameter(
        presented_to_server(&chain, ck, 0),
        PeerMisbehaved::DelegatedCredentialBadSignature,
    );
}

#[test]
fn client_certificate_must_permit_delegation() {
    // Without the DelegationUsage extension, no client credential can be
    // issued for the certificate or attached to it (RFC 9345 §4.2).
    let plain = client_chain(KeyType::EcdsaP256);
    let delegation = delegation_client_chain(KeyType::EcdsaP256);
    let (_, spki) = dc_key(&rcgen::PKCS_ED25519);
    let cert_key = provider()
        .key_provider
        .load_private_key(plain.private_key())
        .unwrap();
    assert!(
        DelegatedCredential::issue(
            Side::Client,
            &plain.end_entity,
            &*cert_key,
            plain.key_type.schemes(),
            Credential {
                valid_time: valid_time_until(&plain.end_entity, shifted(3600)).unwrap(),
                dc_cert_verify_algorithm: SignatureScheme::ED25519,
                public_key: spki,
            },
        )
        .is_err()
    );
    let (dc, key) = issue_for(
        Side::Client,
        &delegation,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    assert!(
        certified_key(&plain)
            .with_client_delegated_credential(dc, key)
            .is_err()
    );
}

/// With client credentials enabled, one on an entry other than the end
/// entity's is `illegal_parameter` (RFC 9345 §4.1.2).
#[test]
fn server_rejects_a_client_credential_not_on_the_end_entity() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (dc, _) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let (error, alert) = hand_made_client_certificate(
        &server_chain,
        dc_server(&server_chain, PinnedClientVerifier::new(&chain, true)),
        &[
            (chain.end_entity.as_ref(), None),
            (chain.ca.as_ref(), Some(&dc)),
        ],
    );
    assert_eq!(
        error,
        Error::PeerMisbehaved(PeerMisbehaved::DelegatedCredentialNotOnEndEntity)
    );
    assert_eq!(alert, [2, u8::from(AlertDescription::IllegalParameter)]);
}

/// Forwards everything to `PinnedClientVerifier` except
/// `verify_tls13_signature_with_delegated_key`, which keeps the trait's
/// refusing default.
#[derive(Debug)]
struct NoDelegatedKeys(Arc<PinnedClientVerifier>);

impl ClientCertVerifier for NoDelegatedKeys {
    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[browntls_core::DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &browntls_core::pki_types::CertificateDer<'_>,
        intermediates: &[browntls_core::pki_types::CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<browntls_core::server::danger::ClientCertVerified, Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &browntls_core::pki_types::CertificateDer<'_>,
        dss: &browntls_core::DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &browntls_core::pki_types::CertificateDer<'_>,
        dss: &browntls_core::DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.0.requires_raw_public_keys()
    }
}

/// A server whose client certificate verifier cannot verify signatures made
/// with a credential's key fails the handshake in which the client uses
/// one, with `handshake_failure`.
#[test]
fn server_verifier_without_delegated_key_support_fails_the_handshake() {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let dc = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let (mut client, mut server) = connect(
        client_with(&server_chain, with_client_credentials(&chain, vec![dc])),
        dc_server(
            &server_chain,
            Arc::new(NoDelegatedKeys(PinnedClientVerifier::new(&chain, true))),
        ),
    );
    let (client, server) = do_handshake_until_error(&mut client, &mut server);
    assert!(matches!(server, Err(Error::General(_))), "{server:?}");
    assert_eq!(
        client,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
    // The wrapper's certificate-key path still works.
    let (mut client, mut server) = connect(
        client_with(&server_chain, certified_key(&chain)),
        dc_server(
            &server_chain,
            Arc::new(NoDelegatedKeys(PinnedClientVerifier::new(&chain, true))),
        ),
    );
    do_handshake(&mut client, &mut server).unwrap();
}

/// Each side authenticates with its own credential in one handshake.
#[test]
fn both_sides_authenticate_with_delegated_credentials() {
    init_logging();
    let server_chain = delegation_server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::Ed25519);
    let (server_dc, server_key) = issue(&server_chain, SignatureScheme::ED25519, shifted(3600));
    let (client_dc, client_key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let server_ck = certified_key(&server_chain)
        .with_delegated_credential(server_dc.clone(), server_key)
        .unwrap();
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(recording_verifier(&chain))
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(server_ck)));
    server_config.enable_delegated_credentials = true;
    let mut client_config = client_with(
        &server_chain,
        with_client_credentials(&chain, vec![(client_dc.clone(), client_key)]),
    );
    client_config.enable_delegated_credentials = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&server_dc));
    assert_eq!(server.client_delegated_credential(), Some(&client_dc));
    assert_eq!(
        client.peer_certificates().unwrap()[0],
        server_chain.end_entity
    );
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"mutual"),
        b"mutual"
    );
}

/// `validate`, public for callers that handle credentials themselves,
/// checks a client's credential (RFC 9345 §4.1.3).
#[test]
fn validate_a_client_credential_directly() {
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let verifier = PinnedClientVerifier::new(&chain, true);
    let (dc, _) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let presented = Presented {
        side: Side::Client,
        end_entity: &chain.end_entity,
        offered_dc_schemes: &[SignatureScheme::ED25519],
        offered_sig_schemes: &[SignatureScheme::ECDSA_NISTP256_SHA256],
        cert_verify_scheme: SignatureScheme::ED25519,
        now: now(),
    };
    let check = |presented: &Presented<'_>| {
        validate(&dc, presented, |message, dss| {
            verifier.verify_tls13_signature(message, &chain.end_entity, dss)
        })
    };
    assert_eq!(check(&presented), Ok(dc.expiry(&chain.end_entity).unwrap()));

    // The signature covers the side: as a server's, it does not verify.
    assert_eq!(
        check(&Presented {
            side: Side::Server,
            ..presented
        }),
        Err(PeerMisbehaved::DelegatedCredentialBadSignature.into())
    );
    // CertificateVerify must use the credential's scheme.
    assert_eq!(
        check(&Presented {
            cert_verify_scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            ..presented
        }),
        Err(PeerMisbehaved::DelegatedCredentialSchemeMismatch.into())
    );
    // Both schemes must have been offered.
    assert_eq!(
        check(&Presented {
            offered_dc_schemes: &[SignatureScheme::ECDSA_NISTP256_SHA256],
            ..presented
        }),
        Err(PeerMisbehaved::DelegatedCredentialWithUnofferedScheme.into())
    );
    assert_eq!(
        check(&Presented {
            offered_sig_schemes: &[SignatureScheme::ED25519],
            ..presented
        }),
        Err(PeerMisbehaved::DelegatedCredentialWithUnofferedScheme.into())
    );
    // At the expiry it is expired.
    assert_eq!(
        check(&Presented {
            now: dc.expiry(&chain.end_entity).unwrap(),
            ..presented
        }),
        Err(PeerMisbehaved::DelegatedCredentialExpired.into())
    );
}
