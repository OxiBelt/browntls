// Shared cases, included by `tests/delegated_credentials.rs` (RustCrypto
// provider) and `tests/delegated_credentials_native.rs` (native provider):
// TLS 1.3 server authentication with delegated credentials (RFC 9345),
// browntls client against browntls server (no other implementation the
// project tests against supports RFC 9345).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use browntls::crypto::hash::HashAlgorithm;
use browntls::delegated_credential::{
    Credential, DelegatedCredential, MAX_VALIDITY, valid_time_until,
};
use browntls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime};
use browntls::psk::ExternalPsk;
use browntls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use browntls::time_provider::TimeProvider;
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, PeerMisbehaved,
    ProtocolVersion, ServerConfig, ServerConnection, Side, SignatureScheme,
};
use common::*;

/// A fixed clock.
#[derive(Debug)]
struct FixedTime(UnixTime);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

/// A clock shared by configurations whose time can advance between flights.
#[derive(Debug)]
struct AdjustableTime(AtomicU64);

impl AdjustableTime {
    fn new(time: UnixTime) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(time.as_secs())))
    }

    fn set(&self, time: UnixTime) {
        self.0.store(time.as_secs(), Ordering::SeqCst);
    }
}

impl TimeProvider for AdjustableTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.0.load(Ordering::SeqCst),
        )))
    }
}

fn now() -> UnixTime {
    UnixTime::now()
}

fn shifted(by: i64) -> UnixTime {
    let secs = now().as_secs().checked_add_signed(by).unwrap();
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

fn seconds_after(time: UnixTime, seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(time.as_secs().saturating_add(seconds)))
}

/// A delegated-credential key of `kind`, as an rcgen key pair and loaded by
/// the provider under test.
fn dc_key(
    alg: &'static rcgen::SignatureAlgorithm,
) -> (Arc<dyn SigningKey>, SubjectPublicKeyInfoDer<'static>) {
    let pair = rcgen::KeyPair::generate_for(alg).unwrap();
    let key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pair.serialize_der(),
        )))
        .unwrap();
    let spki = SubjectPublicKeyInfoDer::from(rcgen::PublicKeyData::subject_public_key_info(&pair));
    (key, spki)
}

/// A delegated credential for `chain`'s end entity, expiring at `expiry`,
/// with an ECDSA P-256 or Ed25519 key.
fn issue(
    chain: &Chain,
    dc_scheme: SignatureScheme,
    expiry: UnixTime,
) -> (DelegatedCredential, Arc<dyn SigningKey>) {
    let alg = match dc_scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        SignatureScheme::ED25519 => &rcgen::PKCS_ED25519,
        other => panic!("no rcgen key for {other:?}"),
    };
    let (key, spki) = dc_key(alg);
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let dc = DelegatedCredential::issue(
        Side::Server,
        &chain.end_entity,
        &*cert_key,
        chain.key_type.schemes(),
        Credential {
            valid_time: valid_time_until(&chain.end_entity, expiry).unwrap(),
            dc_cert_verify_algorithm: dc_scheme,
            public_key: spki,
        },
    )
    .unwrap();
    (dc, key)
}

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

fn server_with(certified_key: CertifiedKey) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
}

fn dc_client(chain: &Chain) -> ClientConfig {
    let mut config = client_config(chain);
    config.enable_delegated_credentials = true;
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn take_tickets(client: &mut ClientConnection, server: &mut ServerConnection) {
    transfer(server, client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);
}

#[test]
fn handshake_with_delegated_credential() {
    init_logging();
    for &cert_type in KeyType::SIGNING {
        let chain = delegation_server_chain(cert_type);
        for dc_scheme in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ] {
            let (dc, key) = issue(&chain, dc_scheme, shifted(24 * 3600));
            let ck = certified_key(&chain)
                .with_delegated_credential(dc.clone(), key)
                .unwrap();
            let verifier = SchemeRecordingServerVerifier::new(
                PinnedServerVerifier::new(&chain),
                &prov::SUPPORTED_SIG_ALGS.supported_schemes(),
            );
            let mut client_config = client_config(&chain);
            client_config.enable_delegated_credentials = true;
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());
            let (mut client, mut server) = connect(client_config, server_with(ck));
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            assert_eq!(
                client.delegated_credential(),
                Some(&dc),
                "{cert_type:?} {dc_scheme:?}"
            );
            // The credential's signature (certificate key), then
            // CertificateVerify (credential key).
            assert_eq!(verifier.seen(), [dc.algorithm, dc_scheme]);
            assert_eq!(client.peer_certificates().unwrap()[0], chain.end_entity);
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

#[test]
fn not_used_unless_both_sides_opt_in() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, shifted(3600));
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();

    // The client did not offer the extension: the certificate key signs.
    let (mut client, mut server) = connect(client_config(&chain), server_with(ck.clone()));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());

    // The server has no credential.
    let (mut client, mut server) = connect(dc_client(&chain), server_with(certified_key(&chain)));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());

    // TLS 1.2: delegated credentials are TLS 1.3 only.
    #[cfg(feature = "tls12")]
    {
        let server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&browntls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(ck.clone())));
        let (mut client, mut server) = connect(dc_client(&chain), server);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
        assert!(client.delegated_credential().is_none());
    }

    // The client accepts no scheme the credential uses: the server falls
    // back to its certificate key.
    let mut client_config = client_config(&chain);
    client_config.enable_delegated_credentials = true;
    client_config
        .dangerous()
        .set_certificate_verifier(SchemeRecordingServerVerifier::new(
            PinnedServerVerifier::new(&chain),
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
        ));
    let (mut client, mut server) = connect(client_config, server_with(ck));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());
}

#[test]
fn server_skips_unusable_credentials() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    // Expired, then valid for too long, then a good one.
    let (expired, k1) = issue(&chain, SignatureScheme::ED25519, shifted(-60));
    let (too_long, k2) = issue(
        &chain,
        SignatureScheme::ED25519,
        shifted(MAX_VALIDITY.as_secs() as i64 + 3600),
    );
    let (good, k3) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let ck = certified_key(&chain)
        .with_delegated_credential(expired, k1)
        .unwrap()
        .with_delegated_credential(too_long, k2)
        .unwrap()
        .with_delegated_credential(good.clone(), k3)
        .unwrap();
    let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&good));
}

/// A server whose clock is `skew` seconds off sends a credential the client
/// rejects.
fn rejected_by_client(
    expiry: UnixTime,
    server_skew: i64,
) -> (Result<(), Error>, Result<(), Error>) {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();
    let mut server = server_with(ck);
    server.time_provider = Arc::new(FixedTime(shifted(server_skew)));
    let (mut client, mut server) = connect(dc_client(&chain), server);
    do_handshake_until_error(&mut client, &mut server)
}

#[test]
fn expired_credential_is_illegal_parameter() {
    let (client, server) = rejected_by_client(shifted(-3600), -2 * 3600);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialExpired
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn credential_valid_too_long_is_illegal_parameter() {
    let week = MAX_VALIDITY.as_secs() as i64;
    let (client, server) = rejected_by_client(shifted(week + 3600), 2 * 3600);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialValidityTooLong
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn tampered_credential_is_illegal_parameter() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (mut dc, key) = issue(&chain, SignatureScheme::ED25519, shifted(3600));
    // Moving the expiry by a second invalidates the signature.
    dc.credential.valid_time -= 1;
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();
    let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
    let (client, server) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialBadSignature
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn credential_key_must_match() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, _) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let (other_key, _) = dc_key(&rcgen::PKCS_ECDSA_P256_SHA256);
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc.clone(), other_key)
            .is_err()
    );
    // A key that cannot sign with the credential's scheme.
    let (ed_key, _) = dc_key(&rcgen::PKCS_ED25519);
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc, ed_key)
            .is_err()
    );
}

#[test]
fn certificate_must_permit_delegation() {
    // Without the DelegationUsage extension, no credential can be issued or
    // attached.
    let chain = server_chain(KeyType::EcdsaP256);
    let (_, spki) = dc_key(&rcgen::PKCS_ED25519);
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let credential = Credential {
        valid_time: valid_time_until(&chain.end_entity, shifted(3600)).unwrap(),
        dc_cert_verify_algorithm: SignatureScheme::ED25519,
        public_key: spki,
    };
    assert!(
        DelegatedCredential::issue(
            Side::Server,
            &chain.end_entity,
            &*cert_key,
            chain.key_type.schemes(),
            credential.clone(),
        )
        .is_err()
    );
    // Nor attached to its certificate.
    let delegation = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&delegation, SignatureScheme::ED25519, shifted(3600));
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .is_err()
    );
}

#[test]
fn wire_round_trip() {
    let chain = delegation_server_chain(KeyType::Ed25519);
    let (dc, _) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let bytes = dc.to_bytes();
    assert_eq!(DelegatedCredential::from_bytes(&bytes).unwrap(), dc);
    let expiry = dc.expiry(&chain.end_entity).unwrap().as_secs();
    assert!(expiry.abs_diff(shifted(3600).as_secs()) <= 1);
}

#[test]
fn resumption_and_descendants_keep_the_original_expiry() {
    init_logging();
    for stateless in [false, true] {
        let chain = delegation_server_chain(KeyType::EcdsaP256);
        let base = now();
        let expiry = seconds_after(base, 60);
        let client_clock = AdjustableTime::new(base);
        let server_clock = AdjustableTime::new(base);
        let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
        let dc_key = certified_key(&chain)
            .with_delegated_credential(dc.clone(), key)
            .unwrap();

        let mut client_config = dc_client(&chain);
        client_config.time_provider = client_clock.clone();
        let client_config = Arc::new(client_config);

        let mut delegated_server = server_with(dc_key);
        delegated_server.time_provider = server_clock.clone();
        let mut certificate_server = server_with(certified_key(&chain));
        certificate_server.time_provider = server_clock.clone();
        if stateless {
            let ticketer = prov::Ticketer::new().unwrap();
            delegated_server.ticketer = ticketer.clone();
            delegated_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
            certificate_server.ticketer = ticketer;
            certificate_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
        } else {
            let cache: Arc<dyn browntls::server::StoresServerSessions> =
                browntls::server::ServerSessionMemoryCache::new(16);
            delegated_server.session_storage = cache.clone();
            certificate_server.session_storage = cache;
        }
        let delegated_server = Arc::new(delegated_server);
        let certificate_server = Arc::new(certificate_server);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.delegated_credential(), Some(&dc));
        take_tickets(&mut client, &mut server);

        client_clock.set(seconds_after(base, 30));
        server_clock.set(seconds_after(base, 30));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(client.delegated_credential().is_none());
        take_tickets(&mut client, &mut server);

        // The newest ticket is a descendant of the resumed session. The
        // client rejects it at the original exact deadline, while a server
        // clock still before that deadline would otherwise accept it.
        client_clock.set(expiry);
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(client.delegated_credential().is_none());
    }
}

#[test]
fn server_rejects_expired_ticket_and_early_data() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock;
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    let mut delegated_server = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    delegated_server.time_provider = server_clock.clone();
    delegated_server.session_storage = cache.clone();
    delegated_server.max_early_data_size = 1024;
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(delegated_server)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    server_clock.set(expiry);
    let mut certificate_server = server_with(certified_key(&chain));
    certificate_server.time_provider = server_clock;
    certificate_server.session_storage = cache;
    certificate_server.max_early_data_size = 1024;
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    client
        .early_data()
        .expect("ticket permits early data before the client deadline")
        .write_all(b"replayable")
        .unwrap();
    let mut server = ServerConnection::new(Arc::new(certificate_server)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
}

#[test]
fn resumption_expiring_before_server_finished_is_aborted() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    server_config.time_provider = server_clock;
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    client_clock.set(expiry);
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::DelegatedCredentialExpired)
    );
    transfer(&mut client, &mut server);
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::IllegalParameter)
    );
}

#[test]
fn expired_ticket_cannot_extend_an_attacker_only_delegated_key() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    // The certificate key is deliberately absent: only the delegated key can
    // authenticate. A full fallback after expiry must therefore fail.
    let attacker_key = CertifiedKey::new(chain.cert_chain(), key.clone())
        .with_delegated_credential(dc, key)
        .unwrap();

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(attacker_key);
    server_config.time_provider = server_clock;
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    client_clock.set(expiry);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let (client_result, server_result) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_result,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialExpired
        ))
    );
    assert_eq!(
        server_result,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn external_psk_session_keeps_delegated_credential_expiry() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let psk =
        || ExternalPsk::new(b"combined".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256).unwrap();
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let certified = certified_key(&chain)
        .with_delegated_credential(dc.clone(), key)
        .unwrap();

    let mut first_client = dc_client(&chain);
    first_client.time_provider = client_clock.clone();
    first_client.external_psks = vec![Arc::new(psk())];
    first_client.cert_with_extern_psk = true;
    first_client.require_cert_with_extern_psk = true;
    let mut resumed_client = first_client.clone();
    resumed_client.cert_with_extern_psk = false;
    resumed_client.require_cert_with_extern_psk = false;
    let first_client = Arc::new(first_client);
    let resumed_client = Arc::new(resumed_client);

    let mut first_server = server_with(certified.clone());
    first_server.time_provider = server_clock.clone();
    first_server.session_storage = cache.clone();
    first_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    first_server.cert_with_extern_psk = true;
    let mut resumed_server = server_with(certified);
    resumed_server.time_provider = server_clock;
    resumed_server.session_storage = cache;
    resumed_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    let first_server = Arc::new(first_server);
    let resumed_server = Arc::new(resumed_server);

    let mut client = ClientConnection::new(first_client, server_name()).unwrap();
    let mut server = ServerConnection::new(first_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    take_tickets(&mut client, &mut server);

    let mut client = ClientConnection::new(resumed_client.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    take_tickets(&mut client, &mut server);

    client_clock.set(expiry);
    let mut client = ClientConnection::new(resumed_client, server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    assert!(client.delegated_credential().is_none());
}

#[test]
fn server_rejects_descendant_ticket_at_deadline() {
    for stateless in [false, true] {
        let chain = delegation_server_chain(KeyType::EcdsaP256);
        let base = now();
        let expiry = seconds_after(base, 60);
        let client_clock = AdjustableTime::new(base);
        let server_clock = AdjustableTime::new(base);
        let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
        let dc_key = certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap();

        let mut client_config = dc_client(&chain);
        client_config.time_provider = client_clock;
        let client_config = Arc::new(client_config);

        let mut delegated_server = server_with(dc_key);
        delegated_server.time_provider = server_clock.clone();
        let mut certificate_server = server_with(certified_key(&chain));
        certificate_server.time_provider = server_clock.clone();
        if stateless {
            let ticketer = prov::Ticketer::new().unwrap();
            delegated_server.ticketer = ticketer.clone();
            delegated_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
            certificate_server.ticketer = ticketer;
            certificate_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
        } else {
            let cache: Arc<dyn browntls::server::StoresServerSessions> =
                browntls::server::ServerSessionMemoryCache::new(16);
            delegated_server.session_storage = cache.clone();
            certificate_server.session_storage = cache;
        }
        let delegated_server = Arc::new(delegated_server);
        let certificate_server = Arc::new(certificate_server);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        take_tickets(&mut client, &mut server);

        // The first-generation ticket resumes and produces descendant tickets.
        server_clock.set(seconds_after(base, 30));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        take_tickets(&mut client, &mut server);

        // A descendant remains valid immediately before the deadline.
        server_clock.set(seconds_after(base, 59));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        take_tickets(&mut client, &mut server);

        // Only the server clock reaches the deadline, proving that it rejects
        // the newest descendant rather than relying on the client-side check.
        server_clock.set(expiry);
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn server_sends_no_ticket_after_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let mut client_config = dc_client(&chain);
    client_config.time_provider = AdjustableTime::new(base);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc.clone(), key)
            .unwrap(),
    );
    server_config.time_provider = server_clock.clone();

    let (mut client, mut server) = connect(client_config, server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));

    server_clock.set(expiry);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!server.is_handshaking());
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 0);
}

#[test]
fn client_discards_ticket_received_at_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    server_config.time_provider = AdjustableTime::new(base);
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());

    client_clock.set(expiry);
    assert!(transfer(&mut server, &mut client) > 0);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 0);

    // Rewinding the clock proves no ticket was retained for a later offer.
    client_clock.set(base);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn server_rejects_external_psk_ticket_at_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let psk =
        || ExternalPsk::new(b"combined".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256).unwrap();
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let certified = certified_key(&chain)
        .with_delegated_credential(dc.clone(), key)
        .unwrap();

    let mut first_client = dc_client(&chain);
    first_client.time_provider = client_clock;
    first_client.external_psks = vec![Arc::new(psk())];
    first_client.cert_with_extern_psk = true;
    first_client.require_cert_with_extern_psk = true;
    let mut resumed_client = first_client.clone();
    resumed_client.cert_with_extern_psk = false;
    resumed_client.require_cert_with_extern_psk = false;

    let mut first_server = server_with(certified.clone());
    first_server.time_provider = server_clock.clone();
    first_server.session_storage = cache.clone();
    first_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    first_server.cert_with_extern_psk = true;
    let mut resumed_server = server_with(certified);
    resumed_server.time_provider = server_clock.clone();
    resumed_server.session_storage = cache;
    resumed_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    let resumed_client = Arc::new(resumed_client);
    let resumed_server = Arc::new(resumed_server);

    let (mut client, mut server) = connect(first_client, first_server);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));
    take_tickets(&mut client, &mut server);

    server_clock.set(seconds_after(base, 59));
    let mut client = ClientConnection::new(resumed_client.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    take_tickets(&mut client, &mut server);

    // The client still offers the ticket, while the server rejects it and
    // falls through to the external PSK at the exact deadline.
    server_clock.set(expiry);
    let mut client = ClientConnection::new(resumed_client, server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
}

/// Records the secrets a connection derives.
#[derive(Debug, Default)]
struct SecretLog(std::sync::Mutex<Vec<(String, Vec<u8>)>>);

impl browntls::KeyLog for SecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), secret.to_vec()));
    }
}

/// HKDF-Expand-Label with an empty context (RFC 9846 §7.1).
fn expand_label<T: From<[u8; N]>, const N: usize>(
    expander: &dyn browntls::crypto::tls13::HkdfExpander,
    label: &[u8],
    len: u16,
) -> T {
    let label_len = [u8::try_from(6 + label.len()).unwrap()];
    browntls::crypto::tls13::expand(
        expander,
        &[&len.to_be_bytes(), &label_len, b"tls13 ", label, &[0]],
    )
}

/// The record key and IV of a TLS 1.3 traffic secret (RFC 9846 §7.3).
fn traffic_key_iv(
    suite: &browntls::Tls13CipherSuite,
    secret: &[u8],
) -> (
    browntls::crypto::cipher::AeadKey,
    browntls::crypto::cipher::Iv,
) {
    let expander = suite
        .hkdf_provider
        .expander_for_okm(&browntls::crypto::tls13::OkmBlock::new(secret));
    let key_len = suite.aead_alg.key_len();
    let key: browntls::crypto::cipher::AeadKey =
        expand_label(&*expander, b"key", u16::try_from(key_len).unwrap());
    (
        key.with_length(key_len),
        expand_label(&*expander, b"iv", 12),
    )
}

/// browntls clients never present delegated credentials and servers never
/// ask for them, so a client Certificate entry carrying one is an
/// unsolicited extension (`unsupported_extension`). The client's flight is
/// replaced with a hand-made Certificate encrypted under the client
/// handshake traffic key.
#[test]
fn server_rejects_a_client_credential() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = delegation_server_chain(KeyType::EcdsaP256);
    let log = Arc::new(SecretLog::default());
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&browntls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    server_config.key_log = log.clone();
    let (mut client, mut server) = connect(client_config(&server_chain), server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    // The server's flight is dropped: the client never answers it.
    while server.wants_write() {
        server.write_tls(&mut std::io::sink()).unwrap();
    }

    let (_, spki) = dc_key(&rcgen::PKCS_ED25519);
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time: 3600,
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: spki,
        },
        algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
        signature: vec![1; 64],
    }
    .to_bytes();
    let u24 = |len: usize| u32::try_from(len).unwrap().to_be_bytes()[1..].to_vec();
    let u16 = |len: usize| u16::try_from(len).unwrap().to_be_bytes().to_vec();
    let cert = client_chain.end_entity.as_ref();
    let mut extension = vec![0x00, 0x22];
    extension.extend(u16(dc.len()));
    extension.extend(&dc);
    let mut entry = u24(cert.len());
    entry.extend(cert);
    entry.extend(u16(extension.len()));
    entry.extend(&extension);
    let mut body = vec![0]; // empty certificate_request_context
    body.extend(u24(entry.len()));
    body.extend(&entry);
    let mut message = vec![11]; // Certificate
    message.extend(u24(body.len()));
    message.extend(&body);

    let suite = server.negotiated_cipher_suite().unwrap().tls13().unwrap();
    let secret = |name: &str| {
        log.0
            .lock()
            .unwrap()
            .iter()
            .find(|(label, _)| label == name)
            .unwrap()
            .1
            .clone()
    };
    let (key, iv) = traffic_key_iv(suite, &secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
    let record = suite
        .aead_alg
        .encrypter(key, iv)
        .encrypt(
            browntls::crypto::cipher::OutboundPlainMessage {
                typ: browntls::ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: browntls::crypto::cipher::OutboundChunks::Single(&message),
            },
            0,
        )
        .unwrap()
        .encode();

    server.read_tls(&mut &record[..]).unwrap();
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::UnsolicitedCertExtension
        ))
    );

    // After its Finished the server writes with its first application
    // traffic key, from sequence number 0.
    let mut alert = Vec::new();
    server.write_tls(&mut alert).unwrap();
    let (key, iv) = traffic_key_iv(suite, &secret("SERVER_TRAFFIC_SECRET_0"));
    assert_eq!(alert[0], 0x17);
    let plain = suite
        .aead_alg
        .decrypter(key, iv)
        .decrypt(
            browntls::crypto::cipher::InboundOpaqueMessage::new(
                browntls::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut alert[5..],
            ),
            0,
        )
        .unwrap();
    assert_eq!(plain.typ, browntls::ContentType::Alert);
    assert_eq!(
        plain.payload,
        [2, u8::from(AlertDescription::UnsupportedExtension)]
    );
}
