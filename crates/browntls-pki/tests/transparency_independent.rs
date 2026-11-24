//! Public PKI API conformance against RFC 9162 artifacts produced by
//! Python and OpenSSL. See `data/ct_v2_independent/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::transparency::merkle::{
    MAX_CONSISTENCY_PATH_LEN, MAX_INCLUSION_PATH_LEN, MerkleError, leaf_hash,
};
use browntls_pki::transparency::{
    CtV2Log, CtV2Options, CtV2Policy, CtV2Report, CtV2Verifier, LogSignatureAlgorithm, MerklePath,
    SctEntryType, SctSource, TransItem, TransItemList, TransparencyError, TreeHead, TreeHeadSource,
};
use browntls_pki::{Cert, CertificateDer, KeyUsage};
use sha2::{Digest as _, Sha256};

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("data/ct_v2_independent/", $name))
    };
}

const P256_ID: &[u8] = b"\x2b\x06\x01\x04\x01\x81\xfd\x59\x01";
const ED25519_ID: &[u8] = b"\x2b\x06\x01\x04\x01\x81\xfd\x59\x02";
const ISSUER_SPKI: &[u8] = fixture!("issuer-spki.der");
const TLS_LIST: &[u8] = fixture!("tls-list.bin");
const OCSP_LIST: &[u8] = fixture!("ocsp-list.bin");
const X509_ENTRY: &[u8] = fixture!("x509-entry.bin");
const PRECERT_ENTRY: &[u8] = fixture!("precert-entry.bin");
const PRECERT_MS: u64 = 1_717_200_000_000;
const X509_MS: u64 = PRECERT_MS + 2_000;
const OLD_HEAD_MS: u64 = PRECERT_MS + 3_000;
const NEW_HEAD_MS: u64 = PRECERT_MS + 4_000;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn logs() -> [CtV2Log<'static>; 2] {
    [
        CtV2Log::new(P256_ID, fixture!("p256-spki.der")).unwrap(),
        CtV2Log::new(ED25519_ID, fixture!("ed25519-spki.der")).unwrap(),
    ]
}

fn policy<'a>(logs: &'a [CtV2Log<'a>], options: CtV2Options) -> CtV2Policy<'a> {
    CtV2Policy {
        logs,
        trusted_tree_heads: &[],
        supported_sig_algs: common::ALGS,
        sha256,
        options,
    }
}

fn verifier<'a>(policy: &'a CtV2Policy<'a>, cert: &'a Cert<'a>) -> CtV2Verifier<'a> {
    CtV2Verifier::new(policy, cert, ISSUER_SPKI, common::secs(NEW_HEAD_MS / 1000)).unwrap()
}

fn report(set: impl FnOnce(&mut CtV2Report)) -> CtV2Report {
    let mut report = CtV2Report::default();
    set(&mut report);
    report
}

#[test]
fn certificate_tls_and_ocsp_lists_bind_the_expected_entries() {
    let der = CertificateDer::from_slice(fixture!("leaf.der"));
    let roots = [CertificateDer::from_slice(fixture!("issuer.der"))];
    let issuer = Cert::try_from(&roots[0]).unwrap();
    assert_eq!(issuer.subject_public_key_info().as_ref(), ISSUER_SPKI);
    assert_eq!(
        common::verify(
            &der,
            &[],
            &common::anchors(&roots),
            common::ALGS,
            common::secs(NEW_HEAD_MS / 1000),
            KeyUsage::server_auth(),
            None,
            None,
        ),
        Ok(())
    );

    let cert = Cert::try_from(&der).unwrap();
    let logs = logs();
    let policy = policy(&logs, CtV2Options::default());
    let mut verifier = verifier(&policy, &cert);

    assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(verifier.verified()[0].inclusion(), None);
    assert_eq!(
        verifier.verify_tls_extension(TLS_LIST),
        Ok(report(|r| {
            r.verified = 1;
            r.inclusion_proofs = 1;
            r.tree_heads = 1;
            r.tree_heads_verified = 1;
            r.inclusion_proven = 1;
        }))
    );
    // This PKI API takes the already-extracted OCSP extension value.
    assert_eq!(
        verifier.verify_ocsp_response(OCSP_LIST),
        Ok(report(|r| {
            r.verified = 1;
            r.duplicate = 1;
            r.inclusion_proofs = 1;
            r.tree_heads = 1;
            r.tree_heads_verified = 1;
            r.inclusion_proven = 1;
        }))
    );

    let results: Vec<_> = verifier
        .verified()
        .iter()
        .map(|sct| {
            (
                sct.log_id(),
                sct.timestamp_ms(),
                sct.entry_type(),
                sct.source(),
            )
        })
        .collect();
    assert_eq!(
        results,
        [
            (
                ED25519_ID,
                PRECERT_MS,
                SctEntryType::Precert,
                SctSource::Embedded
            ),
            (
                P256_ID,
                X509_MS,
                SctEntryType::X509,
                SctSource::TlsExtension
            ),
            (
                ED25519_ID,
                X509_MS,
                SctEntryType::X509,
                SctSource::OcspResponse
            ),
        ]
    );
    for (sct, index, source) in [
        (&verifier.verified()[0], 4, SctSource::OcspResponse),
        (&verifier.verified()[1], 2, SctSource::TlsExtension),
    ] {
        let inclusion = sct.inclusion().unwrap();
        assert_eq!(inclusion.tree_size, 5);
        assert_eq!(inclusion.leaf_index, index);
        assert_eq!(inclusion.tree_head_timestamp_ms, NEW_HEAD_MS);
        assert_eq!(
            inclusion.tree_head_source,
            TreeHeadSource::Delivered(source)
        );
        assert_eq!(inclusion.proof_source, source);
    }
    assert_eq!(verifier.verified()[2].inclusion(), None);
}

#[test]
fn auditor_checks_both_log_algorithms_against_independent_roots() {
    let [p256, ed25519] = logs();
    let tls: Vec<_> = TransItemList::parse(TLS_LIST).unwrap().iter().collect();
    let ocsp: Vec<_> = TransItemList::parse(OCSP_LIST).unwrap().iter().collect();
    let [p256_proof, p256_sct, p256_head] = tls.as_slice() else {
        panic!("unexpected TLS fixture layout");
    };
    let [precert_sct, _, ed25519_proof, ed25519_head] = ocsp.as_slice() else {
        panic!("unexpected OCSP fixture layout");
    };
    for (log, algorithm, (sct, entry, expected_leaf), (proof, old, new, consistency)) in [
        (
            p256,
            LogSignatureAlgorithm::EcdsaSecp256r1Sha256,
            (p256_sct, X509_ENTRY, fixture!("x509-leaf-hash.bin")),
            (
                p256_proof,
                fixture!("p256-old-head.bin").as_slice(),
                p256_head,
                fixture!("p256-consistency.bin"),
            ),
        ),
        (
            ed25519,
            LogSignatureAlgorithm::Ed25519,
            (
                precert_sct,
                PRECERT_ENTRY,
                fixture!("precert-leaf-hash.bin"),
            ),
            (
                ed25519_proof,
                fixture!("ed25519-old-head.bin").as_slice(),
                ed25519_head,
                fixture!("ed25519-consistency.bin"),
            ),
        ),
    ] {
        assert_eq!(log.signature_algorithm(), algorithm);
        let (TransItem::X509SctV2(sct) | TransItem::PrecertSctV2(sct)) = sct else {
            panic!("expected an SCT");
        };
        let TransItem::InclusionProofV2(proof) = proof else {
            panic!("expected an inclusion proof");
        };
        let TransItem::SignedTreeHeadV2(old) = TransItem::parse(old).unwrap() else {
            panic!("expected the old tree head");
        };
        let TransItem::SignedTreeHeadV2(new) = new else {
            panic!("expected the new tree head");
        };
        let TransItem::ConsistencyProofV2(consistency) = TransItem::parse(consistency).unwrap()
        else {
            panic!("expected a consistency proof");
        };

        assert_eq!(log.verify_sct(sct, entry, common::ALGS), Ok(()));
        let head3 = log.verify_tree_head(&old, common::ALGS).unwrap();
        let head5 = log.verify_tree_head(new, common::ALGS).unwrap();
        assert_eq!(
            head3,
            TreeHead {
                timestamp_ms: OLD_HEAD_MS,
                tree_size: 3,
                root_hash: *fixture!("root-3.bin"),
            }
        );
        assert_eq!(
            head5,
            TreeHead {
                timestamp_ms: NEW_HEAD_MS,
                tree_size: 5,
                root_hash: *fixture!("root-5.bin"),
            }
        );
        let leaf = leaf_hash(sha256, entry);
        assert_eq!(&leaf, expected_leaf);
        assert_eq!(
            log.verify_inclusion_proof(sha256, proof, &leaf, &head5),
            Ok(())
        );
        assert_eq!(
            log.verify_consistency_proof(sha256, &consistency, &head3, &head5),
            Ok(())
        );

        let mut changed_sct = *sct;
        let mut signature = sct.signature.to_vec();
        *signature.last_mut().unwrap() ^= 1;
        changed_sct.signature = &signature;
        assert_eq!(
            log.verify_sct(&changed_sct, entry, common::ALGS),
            Err(TransparencyError::InvalidSignature)
        );
        let mut changed_head = *new;
        changed_head.tree_head.timestamp_ms += 1;
        assert_eq!(
            log.verify_tree_head(&changed_head, common::ALGS),
            Err(TransparencyError::InvalidSignature)
        );

        let mut changed_leaf = leaf;
        changed_leaf[0] ^= 1;
        assert_eq!(
            log.verify_inclusion_proof(sha256, proof, &changed_leaf, &head5),
            Err(TransparencyError::InvalidProof(MerkleError::RootMismatch))
        );
        let mut changed_root = head3;
        changed_root.root_hash[0] ^= 1;
        assert_eq!(
            log.verify_consistency_proof(sha256, &consistency, &changed_root, &head5),
            Err(TransparencyError::InvalidProof(MerkleError::RootMismatch))
        );

        let nodes = [[0; 32]; MAX_CONSISTENCY_PATH_LEN + 1];
        let should_not_hash = |_: &[u8]| panic!("oversized proof must be rejected before hashing");
        let mut long_inclusion = *proof;
        long_inclusion.inclusion_path =
            MerklePath::from_nodes(&nodes[..MAX_INCLUSION_PATH_LEN + 1]);
        assert_eq!(
            log.verify_inclusion_proof(should_not_hash, &long_inclusion, &leaf, &head5),
            Err(TransparencyError::InvalidProof(MerkleError::PathTooLong))
        );
        let mut long_consistency = consistency;
        long_consistency.consistency_path = MerklePath::from_nodes(&nodes);
        assert_eq!(
            log.verify_consistency_proof(should_not_hash, &long_consistency, &head3, &head5),
            Err(TransparencyError::InvalidProof(MerkleError::PathTooLong))
        );
    }
}

#[test]
fn malformed_lists_are_atomic_and_work_budgets_span_sources() {
    let der = CertificateDer::from_slice(fixture!("leaf.der"));
    let cert = Cert::try_from(&der).unwrap();
    let logs = logs();
    let test_policy = policy(&logs, CtV2Options::default());
    let mut session = verifier(&test_policy, &cert);
    assert_eq!(session.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(
        session.verify_tls_extension(&TLS_LIST[..TLS_LIST.len() - 1]),
        Err(TransparencyError::MalformedList)
    );
    let list = TransItemList::parse(TLS_LIST).unwrap();
    let mut items = list.serialized_items();
    let sct = items.nth(1).unwrap();
    let head = items.next().unwrap();
    let truncated_head = &head[..head.len() - 1];
    assert!(matches!(
        TransItem::parse(truncated_head),
        Err(TransparencyError::MalformedItem)
    ));
    let malformed_item = TransItemList::encode(&[sct, truncated_head]).unwrap();
    assert_eq!(
        session.verify_tls_extension(&malformed_item),
        Err(TransparencyError::MalformedList)
    );
    assert_eq!(session.verified().len(), 1);
    assert_eq!(
        session
            .verify_tls_extension(TLS_LIST)
            .unwrap()
            .inclusion_proven,
        1
    );

    let mut options = CtV2Options::default();
    options.max_items = 7; // One embedded item, three TLS items, then four OCSP items.
    let test_policy = policy(&logs, options);
    let mut session = verifier(&test_policy, &cert);
    session.verify_embedded().unwrap();
    session.verify_tls_extension(TLS_LIST).unwrap();
    assert_eq!(
        session.verify_ocsp_response(OCSP_LIST),
        Err(TransparencyError::TooManyItems)
    );
    assert_eq!(session.verified().len(), 2);
    assert_eq!(session.verified()[0].inclusion(), None);
    assert!(session.verified()[1].inclusion().is_some());

    let mut options = CtV2Options::default();
    options.max_signature_verifications = 4; // Three SCTs and two signed tree heads.
    let test_policy = policy(&logs, options);
    let mut session = verifier(&test_policy, &cert);
    session.verify_embedded().unwrap();
    session.verify_tls_extension(TLS_LIST).unwrap();
    assert_eq!(
        session.verify_ocsp_response(OCSP_LIST),
        Err(TransparencyError::SignatureBudgetExceeded)
    );
    assert_eq!(session.verified().len(), 3);
    assert_eq!(session.verified()[0].inclusion(), None);
    assert!(session.verified()[1].inclusion().is_some());

    // P-256 costs four hashes, Ed25519 needs two more across the same verifier.
    for budget in [5, 6] {
        let mut options = CtV2Options::default();
        options.max_hash_operations = budget;
        let test_policy = policy(&logs, options);
        let mut session = verifier(&test_policy, &cert);
        session.verify_embedded().unwrap();
        assert_eq!(
            session
                .verify_tls_extension(TLS_LIST)
                .unwrap()
                .inclusion_proven,
            1
        );
        let result = session.verify_ocsp_response(OCSP_LIST);
        if budget == 5 {
            assert_eq!(result, Err(TransparencyError::HashBudgetExceeded));
        } else {
            assert_eq!(result.unwrap().inclusion_proven, 1);
        }
        assert_eq!(session.verified()[0].inclusion().is_some(), budget == 6);
        assert!(session.verified()[1].inclusion().is_some());
    }
}

#[test]
fn log_validity_and_tree_head_order_apply_to_independent_signatures() {
    let der = CertificateDer::from_slice(fixture!("leaf.der"));
    let cert = Cert::try_from(&der).unwrap();
    let [p256, ed25519] = logs();
    let windowed_logs = [
        p256.with_timestamp_window(X509_MS, X509_MS + 1),
        ed25519.with_timestamp_window(0, PRECERT_MS),
    ];
    let test_policy = policy(&windowed_logs, CtV2Options::default());
    let mut session = verifier(&test_policy, &cert);
    assert_eq!(
        session.verify_embedded(),
        Ok(report(|r| r.outside_log_validity = 1))
    );
    assert_eq!(session.verify_tls_extension(TLS_LIST).unwrap().verified, 1);

    let logs = logs();
    let test_policy = policy(&logs, CtV2Options::default());
    let mut session = CtV2Verifier::new(
        &test_policy,
        &cert,
        ISSUER_SPKI,
        common::secs(PRECERT_MS / 1000),
    )
    .unwrap();
    assert_eq!(session.verify_embedded().unwrap().verified, 1);
    assert_eq!(
        session
            .verify_tls_extension(TLS_LIST)
            .unwrap()
            .future_timestamp,
        1
    );

    // Swap only the tree head. Both heads have valid signatures over the
    // same root and size, but the stale one predates the embedded SCT.
    let supplied = TransItemList::parse(OCSP_LIST).unwrap();
    let proof = supplied.serialized_items().nth(2).unwrap();
    let stale_list = TransItemList::encode(&[proof, fixture!("ed25519-stale-head.bin")]).unwrap();
    let mut session = verifier(&test_policy, &cert);
    session.verify_embedded().unwrap();
    let stale = session.verify_ocsp_response(&stale_list).unwrap();
    assert_eq!(stale.tree_heads_verified, 1);
    assert_eq!(stale.inclusion_proven, 0);
    assert_eq!(session.verified()[0].inclusion(), None);

    assert_eq!(
        session
            .verify_ocsp_response(OCSP_LIST)
            .unwrap()
            .inclusion_proven,
        1
    );
    assert_eq!(
        session.verified()[0]
            .inclusion()
            .unwrap()
            .tree_head_timestamp_ms,
        NEW_HEAD_MS
    );
}
