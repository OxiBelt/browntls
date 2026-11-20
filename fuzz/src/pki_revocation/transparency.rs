//! RFC 9162 Certificate Transparency 2.0: `TransItemList`s, `TransItem`s,
//! Merkle proofs and the certificate-bound verifier, over signed fixtures
//! and arbitrary input.
//!
//! Properties: parsing then encoding gives the input back; verification
//! never panics; a list whose SCT, inclusion proof and tree head all verify
//! no longer does so with any one bit flipped.

use std::sync::OnceLock;

use browntls_core::crypto::native;
use browntls_core::revocation::RevocationDigests;
use browntls_pki::Cert;
use browntls_pki::transparency::{
    ArtifactExtensions, ConsistencyProofDataV2, CtV2Log, CtV2Options, CtV2Policy, CtV2Report,
    CtV2Verifier, InclusionProofDataV2, LogId, LogSignatureAlgorithm, MerklePath, SctEntryType,
    SctSource, SignedCertificateTimestampDataV2, SignedTreeHeadDataV2,
    TimestampedCertificateEntryDataV2, TransItem, TransItemList, TreeHead, TreeHeadDataV2,
    TreeHeadSource, merkle,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData as _, SigningKey as _,
};

use super::fixtures::{NOW, time};

const LOG_ID: &[u8] = &[0x2b, 0x65, 0x50, 0x01];
const ED_LOG_ID: &[u8] = &[0x2b, 0x65, 0x50, 0x02];
const SCT_TIME: u64 = (NOW - 7200) * 1000;
const TREE_SIZE: usize = 5;
const OLD_SIZE: usize = 2;
const LEAF_INDEX: usize = 3;

fn sha256(data: &[u8]) -> [u8; 32] {
    (RevocationDigests::native().sha256)(data)
}

struct Fixture {
    leaf: Vec<u8>,
    issuer_spki: Vec<u8>,
    log_spki: Vec<u8>,
    ed_spki: Vec<u8>,
    /// The `x509_entry_v2` the TLS SCT signs.
    entry: Vec<u8>,
    /// An `x509_sct_v2`, its inclusion proof and a tree head of size 5.
    tls: Vec<u8>,
    /// An Ed25519 `x509_sct_v2`, a consistency proof from size 2 to 5, an
    /// item of an unknown type.
    ocsp: Vec<u8>,
    /// Signed tree heads of sizes 2 and 5.
    old_sth: Vec<u8>,
    new_sth: Vec<u8>,
}

impl Fixture {
    fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::new)
    }

    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "transparency fixture CA");
        let issuer_spki = ca_key.subject_public_key_info();
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let log_key = KeyPair::generate().unwrap();
        let ed_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer_key_hash = sha256(&issuer_spki);

        // The precertificate, then the certificate embedding its SCT.
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.serial_number = Some(77u64.into());
        let plain = params.signed_by(&key, &issuer).unwrap().der().to_vec();
        let precert_tbs = tbs(&plain);
        let precert_entry = entry_item(true, &issuer_key_hash, &precert_tbs);
        let embedded = sct_item(true, LOG_ID, &log_key.sign(&precert_entry).unwrap());
        let embedded = TransItemList::encode(&[&embedded]).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 101, 75],
                der_octet_string(&embedded),
            ));
        let leaf = params.signed_by(&key, &issuer).unwrap().der().to_vec();

        let entry = entry_item(false, &issuer_key_hash, &tbs(&leaf));
        let sct = sct_item(false, LOG_ID, &log_key.sign(&entry).unwrap());
        let ed_sct = sct_item(false, ED_LOG_ID, &ed_key.sign(&entry).unwrap());
        let mut entries: Vec<Vec<u8>> = (0..TREE_SIZE).map(|i| vec![i as u8; 9]).collect();
        entries[LEAF_INDEX] = entry.clone();
        let root = merkle::merkle_tree_hash(sha256, &entries);
        let old_root = merkle::merkle_tree_hash(sha256, &entries[..OLD_SIZE]);
        let inclusion_path = path(LEAF_INDEX, &entries);
        let inclusion = TransItem::InclusionProofV2(InclusionProofDataV2 {
            log_id: LogId::new(LOG_ID).unwrap(),
            tree_size: TREE_SIZE as u64,
            leaf_index: LEAF_INDEX as u64,
            inclusion_path: MerklePath::from_nodes(&inclusion_path),
        });
        let sth = |size: usize, root: &[u8; 32]| {
            let tree_head = TreeHeadDataV2 {
                timestamp_ms: SCT_TIME + 1,
                tree_size: size as u64,
                root_hash: root,
                sth_extensions: ArtifactExtensions::EMPTY,
            };
            let signature = log_key.sign(&tree_head.encode().unwrap()).unwrap();
            TransItem::SignedTreeHeadV2(SignedTreeHeadDataV2 {
                log_id: LogId::new(LOG_ID).unwrap(),
                tree_head,
                signature: &signature,
            })
            .encode()
            .unwrap()
        };
        let (old_sth, new_sth) = (sth(OLD_SIZE, &old_root), sth(TREE_SIZE, &root));
        let consistency_path = proof(OLD_SIZE, &entries);
        let consistency = TransItem::ConsistencyProofV2(ConsistencyProofDataV2 {
            log_id: LogId::new(LOG_ID).unwrap(),
            tree_size_1: OLD_SIZE as u64,
            tree_size_2: TREE_SIZE as u64,
            consistency_path: MerklePath::from_nodes(&consistency_path),
        });
        let tls = TransItemList::encode(&[&sct, &inclusion.encode().unwrap(), &new_sth]).unwrap();
        let ed_item = TransItem::parse(&ed_sct).unwrap();
        let unknown = TransItem::parse(&[0xf0, 0x00, 1]).unwrap();
        let ocsp = TransItemList::encode_items(&[ed_item, consistency, unknown]).unwrap();

        Self {
            leaf,
            issuer_spki,
            log_spki: log_key.subject_public_key_info(),
            ed_spki: ed_key.subject_public_key_info(),
            entry,
            tls,
            ocsp,
            old_sth,
            new_sth,
        }
    }

    fn logs(&self) -> [CtV2Log<'_>; 2] {
        [
            CtV2Log::new(LOG_ID, &self.log_spki)
                .unwrap()
                .with_timestamp_window(0, u64::MAX),
            CtV2Log::new(ED_LOG_ID, &self.ed_spki).unwrap(),
        ]
    }
}

fn tbs(cert: &[u8]) -> Vec<u8> {
    let der = browntls_pki::CertificateDer::from(cert);
    Cert::try_from(&der)
        .unwrap()
        .signed_data()
        .message()
        .to_vec()
}

fn der_octet_string(value: &[u8]) -> Vec<u8> {
    let len = match value.len() {
        n @ 0..0x80 => vec![n as u8],
        n @ 0x80..0x100 => vec![0x81, n as u8],
        n => [&[0x82][..], &u16::try_from(n).unwrap().to_be_bytes()].concat(),
    };
    [&[0x04][..], &len, value].concat()
}

fn entry_item(precert: bool, issuer_key_hash: &[u8; 32], tbs: &[u8]) -> Vec<u8> {
    let entry = TimestampedCertificateEntryDataV2 {
        timestamp_ms: SCT_TIME,
        issuer_key_hash,
        tbs_certificate: tbs,
        sct_extensions: ArtifactExtensions::EMPTY,
    };
    let item = if precert {
        TransItem::PrecertEntryV2(entry)
    } else {
        TransItem::X509EntryV2(entry)
    };
    item.encode().unwrap()
}

fn sct_item(precert: bool, log_id: &[u8], signature: &[u8]) -> Vec<u8> {
    let sct = SignedCertificateTimestampDataV2 {
        log_id: LogId::new(log_id).unwrap(),
        timestamp_ms: SCT_TIME,
        sct_extensions: ArtifactExtensions::EMPTY,
        signature,
    };
    let item = if precert {
        TransItem::PrecertSctV2(sct)
    } else {
        TransItem::X509SctV2(sct)
    };
    item.encode().unwrap()
}

/// The largest power of two smaller than `n` (`n > 1`).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// `PATH(m, D_n)` (RFC 9162 §2.1.3.1).
fn path(m: usize, d: &[Vec<u8>]) -> Vec<[u8; 32]> {
    if d.len() <= 1 {
        return Vec::new();
    }
    let k = split(d.len());
    let (mut out, other) = if m < k {
        (path(m, &d[..k]), &d[k..])
    } else {
        (path(m - k, &d[k..]), &d[..k])
    };
    out.push(merkle::merkle_tree_hash(sha256, other));
    out
}

/// `SUBPROOF(m, D_n, b)` (RFC 9162 §2.1.4.1).
fn subproof(m: usize, d: &[Vec<u8>], b: bool) -> Vec<[u8; 32]> {
    if m == d.len() {
        return if b {
            Vec::new()
        } else {
            vec![merkle::merkle_tree_hash(sha256, d)]
        };
    }
    let k = split(d.len());
    let (mut out, other) = if m <= k {
        (subproof(m, &d[..k], b), &d[k..])
    } else {
        (subproof(m - k, &d[k..], false), &d[..k])
    };
    out.push(merkle::merkle_tree_hash(sha256, other));
    out
}

fn proof(m: usize, d: &[Vec<u8>]) -> Vec<[u8; 32]> {
    subproof(m, d, true)
}

fn with_policy<R>(fixture: &Fixture, f: impl FnOnce(&CtV2Policy<'_>, &Cert<'_>) -> R) -> R {
    let logs = fixture.logs();
    let provider = native::default_provider();
    let policy = CtV2Policy {
        logs: &logs,
        trusted_tree_heads: &[],
        supported_sig_algs: provider.signature_verification_algorithms.all,
        sha256,
        options: CtV2Options::default(),
    };
    let der = browntls_pki::CertificateDer::from(fixture.leaf.as_slice());
    let cert = Cert::try_from(&der).unwrap();
    f(&policy, &cert)
}

pub(super) fn run(bytes: &[u8]) {
    let fixture = Fixture::get();
    let Some((&mode, rest)) = bytes.split_first() else {
        return canned(fixture);
    };
    match mode % 4 {
        0 => list(fixture, rest),
        1 => item(fixture, rest),
        2 => proofs(rest),
        _ => tamper(fixture, rest),
    }
}

/// The fixtures verify, through every public function.
fn canned(fixture: &Fixture) {
    with_policy(fixture, |policy, cert| {
        let mut verifier =
            CtV2Verifier::new(policy, cert, &fixture.issuer_spki, time(NOW)).unwrap();
        assert_eq!(verifier.verify_embedded().unwrap().verified, 1);
        let report = verifier.verify_tls_extension(&fixture.tls).unwrap();
        assert_eq!((report.verified, report.inclusion_proven), (1, 1));
        let report = verifier.verify_ocsp_response(&fixture.ocsp).unwrap();
        assert_eq!(
            (report.verified, report.ignored, report.unknown_type),
            (1, 1, 1)
        );
        assert_eq!(
            verifier.verify_tls_extension(&[]),
            Ok(CtV2Report::default())
        );
        let verified = verifier.verified();
        assert_eq!(verified.len(), 3);
        let tls = verified[1];
        assert_eq!(tls.log_id(), LOG_ID);
        assert_eq!(tls.log_index(), 0);
        assert_eq!(tls.timestamp_ms(), SCT_TIME);
        assert_eq!(tls.entry_type(), SctEntryType::X509);
        assert_eq!(tls.source(), SctSource::TlsExtension);
        let evidence = tls.inclusion().unwrap();
        assert_eq!(evidence.leaf_index, LEAF_INDEX as u64);
        assert_eq!(
            evidence.tree_head_source,
            TreeHeadSource::Delivered(SctSource::TlsExtension)
        );
        assert_eq!(verified[0].entry_type(), SctEntryType::Precert);
        assert_eq!(verifier.into_verified()[2].log_index(), 1);
    });

    // An auditor's view of the same artifacts.
    let logs = fixture.logs();
    let algs = native::default_provider()
        .signature_verification_algorithms
        .all;
    let log = &logs[0];
    assert_eq!(log.id().as_bytes(), LOG_ID);
    assert_eq!(
        log.signature_algorithm(),
        LogSignatureAlgorithm::EcdsaSecp256r1Sha256
    );
    assert_eq!(logs[1].signature_algorithm().signature_scheme(), 0x0807);
    let head = |item: &[u8]| -> TreeHead {
        let TransItem::SignedTreeHeadV2(sth) = TransItem::parse(item).unwrap() else {
            panic!("not a tree head")
        };
        log.verify_tree_head(&sth, algs).unwrap()
    };
    let (older, newer) = (head(&fixture.old_sth), head(&fixture.new_sth));
    let list = TransItemList::parse(&fixture.tls).unwrap();
    assert_eq!(list.len(), 3);
    assert!(!list.is_empty() && list.has_sct());
    let items: Vec<_> = list.iter().collect();
    let TransItem::X509SctV2(sct) = items[0] else {
        panic!("not an SCT")
    };
    assert!(items[0].is_sct());
    log.verify_sct(&sct, &fixture.entry, algs).unwrap();
    let TransItem::InclusionProofV2(inclusion) = items[1] else {
        panic!("not a proof")
    };
    let leaf_hash = merkle::leaf_hash(sha256, &fixture.entry);
    log.verify_inclusion_proof(sha256, &inclusion, &leaf_hash, &newer)
        .unwrap();
    merkle::verify_inclusion(
        sha256,
        &leaf_hash,
        inclusion.leaf_index,
        inclusion.tree_size,
        inclusion.inclusion_path,
        &newer.root_hash,
    )
    .unwrap();
    let path = inclusion.inclusion_path;
    assert_eq!(path.iter().count(), path.len());
    assert!(!path.is_empty());
    let ocsp = TransItemList::parse(&fixture.ocsp).unwrap();
    let Some(TransItem::ConsistencyProofV2(consistency)) = ocsp.iter().nth(1) else {
        panic!("not a consistency proof")
    };
    log.verify_consistency_proof(sha256, &consistency, &older, &newer)
        .unwrap();
    merkle::verify_consistency(
        sha256,
        older.tree_size,
        newer.tree_size,
        &older.root_hash,
        &newer.root_hash,
        consistency.consistency_path,
    )
    .unwrap();
    let serialized: Vec<_> = list.serialized_items().collect();
    assert_eq!(TransItemList::encode(&serialized).unwrap(), fixture.tls);
    assert_eq!(TransItemList::encode_items(&items).unwrap(), fixture.tls);
    assert_eq!(
        items[2].versioned_type(),
        browntls_pki::transparency::versioned_type::SIGNED_TREE_HEAD_V2
    );
    let extensions = ArtifactExtensions::from_encoded(b"\x00\x01\x00\x01x").unwrap();
    assert!(extensions.is_ordered());
    assert_eq!(extensions.as_bytes().len(), 5);
    assert_eq!(extensions.iter().count(), 1);
    let (a, b) = (
        merkle::leaf_hash(sha256, b"a"),
        merkle::leaf_hash(sha256, b"b"),
    );
    assert_eq!(
        merkle::root_from_leaf_hashes(sha256, [a, b]),
        merkle::node_hash(sha256, &a, &b)
    );
}

/// Any list: exact round trip, and verification from every source.
fn list(fixture: &Fixture, bytes: &[u8]) {
    if let Ok(list) = TransItemList::parse(bytes) {
        let items: Vec<_> = list.iter().collect();
        assert_eq!(items.len(), list.len());
        assert!(!list.is_empty());
        assert_eq!(TransItemList::encode_items(&items).unwrap(), bytes);
        let serialized: Vec<_> = list.serialized_items().collect();
        assert_eq!(TransItemList::encode(&serialized).unwrap(), bytes);
        assert_eq!(list.has_sct(), items.iter().any(TransItem::is_sct));
    }
    with_policy(fixture, |policy, cert| {
        let mut verifier =
            CtV2Verifier::new(policy, cert, &fixture.issuer_spki, time(NOW)).unwrap();
        let _ = verifier.verify_tls_extension(bytes);
        let _ = verifier.verify_ocsp_response(bytes);
        let _ = verifier.verify_embedded();
        assert!(verifier.verified().len() <= policy.options.max_items);
    });
}

/// Any item: exact round trip, and the auditor's verifications.
fn item(fixture: &Fixture, bytes: &[u8]) {
    let Ok(item) = TransItem::parse(bytes) else {
        return;
    };
    assert_eq!(item.encode().unwrap(), bytes);
    let logs = fixture.logs();
    let algs = native::default_provider()
        .signature_verification_algorithms
        .all;
    let head = TreeHead {
        timestamp_ms: SCT_TIME,
        tree_size: TREE_SIZE as u64,
        root_hash: [0; 32],
    };
    for log in &logs {
        let _ = match item {
            TransItem::X509SctV2(sct) | TransItem::PrecertSctV2(sct) => {
                log.verify_sct(&sct, &fixture.entry, algs)
            }
            TransItem::SignedTreeHeadV2(sth) => log.verify_tree_head(&sth, algs).map(|_| ()),
            TransItem::InclusionProofV2(proof) => {
                log.verify_inclusion_proof(sha256, &proof, &[0; 32], &head)
            }
            TransItem::ConsistencyProofV2(proof) => {
                log.verify_consistency_proof(sha256, &proof, &head, &head)
            }
            _ => Ok(()),
        };
    }
}

/// Merkle verification of arbitrary sizes and paths never panics.
fn proofs(bytes: &[u8]) {
    let Some((sizes, nodes)) = bytes.split_first_chunk::<16>() else {
        return;
    };
    let first = u64::from_be_bytes(sizes[..8].try_into().unwrap());
    let second = u64::from_be_bytes(sizes[8..].try_into().unwrap());
    let nodes: Vec<[u8; 32]> = nodes.as_chunks::<32>().0.to_vec();
    let path = MerklePath::from_nodes(&nodes);
    let root = nodes.first().copied().unwrap_or_default();
    let _ = merkle::verify_inclusion(sha256, &root, first, second, path, &root);
    let _ = merkle::verify_consistency(sha256, first, second, &root, &root, path);
    let _ = merkle::merkle_tree_hash(sha256, bytes.chunks(7));
}

/// One bit flipped anywhere in the TLS list: never an SCT with proven
/// inclusion.
fn tamper(fixture: &Fixture, bytes: &[u8]) {
    let index = bytes.iter().fold(0usize, |acc, &b| {
        acc.wrapping_mul(31).wrapping_add(usize::from(b))
    });
    let mut tampered = fixture.tls.clone();
    let bit = index % (tampered.len() * 8);
    tampered[bit / 8] ^= 1 << (bit % 8);
    with_policy(fixture, |policy, cert| {
        let mut verifier =
            CtV2Verifier::new(policy, cert, &fixture.issuer_spki, time(NOW)).unwrap();
        if let Ok(report) = verifier.verify_tls_extension(&tampered) {
            assert!(report.verified + report.inclusion_proven < 2, "{report:?}");
        }
    });
}

pub(super) fn seeds() -> Vec<Vec<u8>> {
    let fixture = Fixture::get();
    let mut nodes = vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3];
    nodes.extend([7u8; 64]);
    vec![
        vec![],
        [&[0][..], &fixture.tls].concat(),
        [&[0][..], &fixture.ocsp].concat(),
        [&[1][..], &fixture.old_sth].concat(),
        [&[1][..], &fixture.entry].concat(),
        [&[2][..], &nodes].concat(),
        vec![3, 0],
        vec![3, 200],
    ]
}
