// Shared cases, included by `tests/delegated_credentials.rs` (RustCrypto
// provider) and `tests/delegated_credentials_native.rs` (native provider):
// TLS 1.3 server and client authentication with delegated credentials (RFC
// 9345), browntls client against browntls server (no other implementation
// the project tests against supports RFC 9345).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::delegated_credential::{
    Credential, DelegatedCredential, MAX_VALIDITY, valid_time_until,
};
use browntls_core::pki_types::{
    PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use browntls_core::psk::ExternalPsk;
use browntls_core::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use browntls_core::time_provider::TimeProvider;
use browntls_core::{
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

/// A server's delegated credential for `chain`'s end entity, expiring at
/// `expiry`, with an ECDSA P-256, P-384 or Ed25519 key.
fn issue(
    chain: &Chain,
    dc_scheme: SignatureScheme,
    expiry: UnixTime,
) -> (DelegatedCredential, Arc<dyn SigningKey>) {
    issue_for(Side::Server, chain, dc_scheme, expiry)
}

/// A delegated credential with which `side` authenticates as `chain`'s end
/// entity, expiring at `expiry`, with an ECDSA P-256, P-384 or Ed25519 key.
fn issue_for(
    side: Side,
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
        side,
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
        .with_single_certified_key(certified_key)
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

include!("delegated_credentials/handshake.rs");
include!("delegated_credentials/resumption.rs");
include!("delegated_credentials/client_auth.rs");
include!("delegated_credentials/client_auth_selection.rs");
include!("delegated_credentials/client_auth_post_handshake.rs");
include!("delegated_credentials/client_auth_resumption.rs");
