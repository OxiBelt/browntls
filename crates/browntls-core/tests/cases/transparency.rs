// Shared cases, included by `tests/transparency.rs` (RustCrypto provider)
// and `tests/transparency_native.rs` (native provider). Provider items are
// reached through the including target's `prov` module, and SHA-256
// through its `digests` function.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::transparency::{
    CtV2LogConfig, CtV2Requirements, CtV2TrustedTreeHead, TransparencyStatus, TreeHead,
};
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, Error, HandshakeKind,
    ServerConfig, ServerConnection, SupportedProtocolVersion, version,
};
use common::*;
use ct_v2::*;

const VERSIONS: [&SupportedProtocolVersion; 2] = [&version::TLS12, &version::TLS13];

/// A CA, its server chain, and two logs (ECDSA and Ed25519).
struct Fixture {
    pki: CtPki,
    chain: Chain,
    log_a: Log,
    log_b: Log,
}

impl Fixture {
    fn new() -> Self {
        let pki = CtPki::new(digests().sha256);
        let chain = pki.chain();
        Self {
            pki,
            chain,
            log_a: Log::ecdsa(1),
            log_b: Log::ed25519(2),
        }
    }

    /// An `x509_sct_v2` of `log` for the plain chain.
    fn sct(&self, log: &Log) -> Vec<u8> {
        self.pki.x509_sct(log, &self.chain.end_entity)
    }

    fn requirements(&self, logs: &[&Log]) -> CtV2Requirements {
        CtV2Requirements::new(digests(), logs.iter().map(|log| log.config()).collect())
    }

    fn client(
        &self,
        requirements: Option<CtV2Requirements>,
        v: &'static SupportedProtocolVersion,
    ) -> Arc<ClientConfig> {
        Arc::new(client_with(&self.pki, requirements, v))
    }
}

fn verifier(pki: &CtPki, requirements: Option<CtV2Requirements>) -> Arc<WebPkiServerVerifier> {
    let mut builder = WebPkiServerVerifier::builder_with_provider(pki.roots(), provider());
    if let Some(requirements) = requirements {
        builder = builder.with_certificate_transparency(requirements);
    }
    builder.build().unwrap()
}

fn client_with(
    pki: &CtPki,
    requirements: Option<CtV2Requirements>,
    v: &'static SupportedProtocolVersion,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[v])
        .unwrap()
        .with_webpki_verifier(verifier(pki, requirements))
        .with_no_client_auth()
}

/// A server for `chain` sending `list` in `transparency_info` and stapling
/// `ocsp`.
fn server(
    chain: &Chain,
    list: Option<Vec<u8>>,
    ocsp: Option<Vec<u8>>,
    v: &'static SupportedProtocolVersion,
) -> Arc<ServerConfig> {
    let mut key =
        CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap();
    key.set_transparency_info(list).unwrap();
    key.ocsp = ocsp;
    Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[v])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key))),
    )
}

/// Runs a handshake; returns both connections and their results.
fn connect(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (
    ClientConnection,
    ServerConnection,
    Result<(), Error>,
    Result<(), Error>,
) {
    let mut c = ClientConnection::new(client.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(server.clone()).unwrap();
    let (cr, sr) = do_handshake_until_error(&mut c, &mut s);
    if cr.is_ok() && sr.is_ok() {
        // TLS 1.3 tickets follow the handshake.
        transfer(&mut s, &mut c);
        c.process_new_packets().unwrap();
    }
    (c, s, cr, sr)
}

fn status(verified_scts: usize, distinct_logs: usize, inclusion_proven: usize) -> TransparencyStatus {
    TransparencyStatus::new(verified_scts, distinct_logs, inclusion_proven)
}

/// Asserts the client refused the certificate with `expected`.
fn assert_refused(client: Result<(), Error>, server: Result<(), Error>, expected: CertificateError) {
    assert_eq!(client, Err(Error::InvalidCertificate(expected)));
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::CertificateUnknown))
    );
}

fn insufficient(counted_scts: usize, distinct_logs: usize) -> CertificateError {
    CertificateError::InsufficientTransparency {
        counted_scts,
        distinct_logs,
    }
}

#[test]
fn stapled_list_meets_the_policy() {
    init_logging();
    let fx = Fixture::new();
    let list = list(&[fx.sct(&fx.log_a)]);
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let server = server(&fx.chain, Some(list.clone()), None, v);
        let (c, _s, cr, sr) = connect(&client, &server);
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(c.peer_transparency_info(), Some(&list[..]));
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
    }
}

#[test]
fn nothing_is_sent_unless_offered() {
    let fx = Fixture::new();
    let list = list(&[fx.sct(&fx.log_a)]);
    for v in VERSIONS {
        // A client that does not offer the extension would refuse an
        // answer, so the handshake succeeding shows none was sent.
        let server = server(&fx.chain, Some(list.clone()), None, v);
        let (c, _s, cr, sr) = connect(&fx.client(None, v), &server);
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_info(), None);
        assert_eq!(c.peer_transparency_status(), None);
    }
}

#[test]
fn raw_items_on_request_without_a_policy() {
    let fx = Fixture::new();
    let list = list(&[fx.sct(&fx.log_a)]);
    for v in VERSIONS {
        let mut config = client_with(&fx.pki, None, v);
        config.request_transparency_info = true;
        let server = server(&fx.chain, Some(list.clone()), None, v);
        let (c, _s, cr, sr) = connect(&Arc::new(config), &server);
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_info(), Some(&list[..]));
        assert_eq!(c.peer_transparency_status(), None);
    }
}

#[test]
fn no_list_fails_when_only_tls_could_deliver() {
    let fx = Fixture::new();
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, None, None, v));
        assert_refused(cr, sr, insufficient(0, 0));
    }
}

#[test]
fn sct_embedded_in_the_certificate_suffices() {
    let fx = Fixture::new();
    let chain = fx.pki.embedded(&[fx.pki.precert_sct(&fx.log_a)]);
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let (c, _s, cr, sr) = connect(&client, &server(&chain, None, None, v));
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_info(), None);
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
    }
}

#[test]
fn sct_in_the_stapled_ocsp_response_suffices() {
    let fx = Fixture::new();
    let info = list(&[fx.sct(&fx.log_a)]);
    let ocsp = fx.pki.ocsp(&fx.chain.end_entity, Some(&info));
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let server = server(&fx.chain, None, Some(ocsp.clone()), v);
        let (c, _s, cr, sr) = connect(&client, &server);
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
    }

    // A response that does not authenticate (signed for another
    // certificate's issuer) is no source.
    let other = CtPki::new(digests().sha256);
    let forged = other.ocsp(&fx.chain.end_entity, Some(&info));
    let v = &version::TLS13;
    let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
    let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, None, Some(forged), v));
    assert_refused(cr, sr, insufficient(0, 0));
}

#[test]
fn distinct_logs_are_counted() {
    let fx = Fixture::new();
    let one = list(&[fx.sct(&fx.log_a)]);
    let both = list(&[fx.sct(&fx.log_a), fx.sct(&fx.log_b)]);
    for v in VERSIONS {
        let mut requirements = fx.requirements(&[&fx.log_a, &fx.log_b]);
        requirements.min_distinct_logs = 2;
        let client = fx.client(Some(requirements), v);
        let (c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(both.clone()), None, v));
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_status(), Some(status(2, 2, 0)));

        let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(one.clone()), None, v));
        assert_refused(cr, sr, insufficient(1, 1));
    }
}

/// A tree of two entries, the end entity's first: its SCT's timestamp,
/// the SCT, the inclusion proof and the root.
fn tree(fx: &Fixture) -> (u64, Vec<u8>, Vec<u8>, [u8; 32]) {
    let sha256 = digests().sha256;
    let ts = sct_time_ms();
    let entry = fx.pki.x509_entry(&fx.chain.end_entity, ts);
    let sct = fx.log_a.sct(false, ts, &entry);
    let sibling = leaf_hash(sha256, b"another entry");
    let root = node_hash(sha256, &leaf_hash(sha256, &entry), &sibling);
    (ts, sct, fx.log_a.inclusion(2, 0, &[sibling]), root)
}

#[test]
fn inclusion_with_a_delivered_tree_head() {
    let fx = Fixture::new();
    let (ts, sct, proof, root) = tree(&fx);
    let sth = fx.log_a.sth(ts + 1000, 2, &root);
    for v in VERSIONS {
        let mut requirements = fx.requirements(&[&fx.log_a]);
        requirements.require_inclusion = true;
        let client = fx.client(Some(requirements), v);
        let full = list(&[sct.clone(), proof.clone(), sth.clone()]);
        let (c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(full), None, v));
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 1)));

        // Without the tree head the SCT does not count.
        let partial = list(&[sct.clone(), proof.clone()]);
        let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(partial), None, v));
        assert_refused(cr, sr, insufficient(0, 0));
    }
}

#[test]
fn inclusion_with_a_trusted_tree_head() {
    let fx = Fixture::new();
    let (ts, sct, proof, root) = tree(&fx);
    for v in VERSIONS {
        let mut requirements = fx.requirements(&[&fx.log_a]);
        requirements.require_inclusion = true;
        requirements.trusted_tree_heads = vec![CtV2TrustedTreeHead {
            log_id: fx.log_a.id.clone(),
            tree_head: TreeHead {
                timestamp_ms: ts + 1000,
                tree_size: 2,
                root_hash: root,
            },
        }];
        let client = fx.client(Some(requirements), v);
        let items = list(&[sct.clone(), proof.clone()]);
        let (c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(items), None, v));
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 1)));
    }
}

#[test]
fn sct_of_a_wrong_key_or_certificate_does_not_count() {
    let fx = Fixture::new();
    let other = CtPki::new(digests().sha256);
    let foreign = other.x509_sct(&fx.log_a, &other.chain().end_entity);
    for v in VERSIONS {
        // The log's ID with another log's key.
        let mut requirements = fx.requirements(&[]);
        requirements.logs = vec![CtV2LogConfig::new(fx.log_a.id.clone(), fx.log_b.spki.clone())];
        let client = fx.client(Some(requirements), v);
        let items = list(&[fx.sct(&fx.log_a)]);
        let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(items), None, v));
        assert_refused(cr, sr, insufficient(0, 0));

        // An SCT the right log signed for another certificate.
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let items = list(std::slice::from_ref(&foreign));
        let (_c, _s, cr, sr) = connect(&client, &server(&fx.chain, Some(items), None, v));
        assert_refused(cr, sr, insufficient(0, 0));
    }
}

#[test]
fn verifier_build_checks_the_logs() {
    let fx = Fixture::new();
    let mut requirements = fx.requirements(&[&fx.log_a]);
    requirements
        .logs
        .push(CtV2LogConfig::new(fx.log_b.id.clone(), b"not a key".to_vec()));
    let built = WebPkiServerVerifier::builder_with_provider(fx.pki.roots(), provider())
        .with_certificate_transparency(requirements)
        .build();
    assert!(matches!(
        built,
        Err(browntls_core::client::VerifierBuilderError::InvalidTransparencyLog(_))
    ));
    let mut requirements = fx.requirements(&[&fx.log_a]);
    requirements.trusted_tree_heads = vec![CtV2TrustedTreeHead {
        log_id: vec![0x80],
        tree_head: TreeHead {
            timestamp_ms: 0,
            tree_size: 0,
            root_hash: [0; 32],
        },
    }];
    let built = WebPkiServerVerifier::builder_with_provider(fx.pki.roots(), provider())
        .with_certificate_transparency(requirements)
        .build();
    assert!(built.is_err());

    // Two logs sharing a key, or an ID: an SCT's signature does not cover
    // its log ID, so one SCT could count for both.
    // The same key also as the `SubjectPublicKeyInfo`'s contents, and as a
    // compressed point (ECDSA P-256: 30 59, 30 13 <algorithm>, 03 42 00 04
    // X Y).
    let spki = &fx.log_a.spki;
    assert_eq!(spki[..2], [0x30, 0x59]);
    let mut compressed = vec![0x30, 0x39];
    compressed.extend_from_slice(&spki[2..23]);
    compressed.extend([0x03, 0x22, 0x00, 2 | (spki[90] & 1)]);
    compressed.extend_from_slice(&spki[27..59]);
    let new_id = |n| vec![0x2b, 0x65, 0x50, n];
    let twins = [
        CtV2LogConfig::new(new_id(9), spki.clone()),
        CtV2LogConfig::new(new_id(10), spki[2..].to_vec()),
        CtV2LogConfig::new(new_id(11), compressed),
        CtV2LogConfig::new(fx.log_a.id.clone(), fx.log_b.spki.clone()),
    ];
    for twin in twins {
        let mut requirements = fx.requirements(&[&fx.log_a]);
        requirements.logs.push(twin);
        let built = WebPkiServerVerifier::builder_with_provider(fx.pki.roots(), provider())
            .with_certificate_transparency(requirements)
            .build();
        assert!(matches!(
            built,
            Err(browntls_core::client::VerifierBuilderError::DuplicateTransparencyLog)
        ));
    }
}

#[test]
fn verifier_api_enforces_without_the_handshake() {
    use browntls_core::client::danger::ServerCertVerifier;
    use browntls_core::pki_types::UnixTime;

    let fx = Fixture::new();
    let verifier = verifier(&fx.pki, Some(fx.requirements(&[&fx.log_a])));
    assert!(verifier.requests_transparency_info());
    let now = UnixTime::now();
    // The legacy entry point has only the OCSP response.
    let refused = verifier.verify_server_cert(
        &fx.chain.end_entity,
        &[],
        &server_name(),
        &[],
        now,
    );
    assert_eq!(
        refused.unwrap_err(),
        Error::InvalidCertificate(insufficient(0, 0))
    );
    let ocsp = fx
        .pki
        .ocsp(&fx.chain.end_entity, Some(&list(&[fx.sct(&fx.log_a)])));
    verifier
        .verify_server_cert(&fx.chain.end_entity, &[], &server_name(), &ocsp, now)
        .unwrap();
    // The evidence entry point enforces too, so a wrapper that forwards
    // only it keeps the policy.
    let evidence = [browntls_core::revocation::CertificateEvidence {
        transparency_info: Some(&[0, 0]),
        ..Default::default()
    }];
    assert!(
        verifier
            .verify_server_cert_with_evidence(
                &fx.chain.end_entity,
                &[],
                &server_name(),
                &evidence,
                now
            )
            .is_err()
    );
    assert!(!WebPkiServerVerifier::builder_with_provider(fx.pki.roots(), provider())
        .build()
        .unwrap()
        .requests_transparency_info());
}

include!("transparency/resumption.rs");
include!("transparency/wire.rs");
include!("transparency/unbuffered.rs");
include!("transparency/intermediate.rs");
include!("transparency/forged.rs");
include!("transparency/revocation.rs");
