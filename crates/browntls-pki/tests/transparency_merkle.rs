//! RFC 9162 Merkle trees and the auditor functions: the proof verification
//! of §2.1.3.2 and §2.1.4.2 against a reference tree built from the §2.1.1
//! definition and the proof generators of §2.1.3.1 and §2.1.4.1, for every
//! leaf, tree size and pair of tree sizes up to 64 leaves, and the
//! standalone verification of signed tree heads and proofs of a log.
//!
//! RFC 9162 publishes no hash test vector: this is self-consistency against
//! the RFC text (its §2.1.5 example included), not interoperability.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ct_v2.rs"]
mod support;

use support::*;

const MAX_LEAVES: usize = 64;

fn inclusion(
    m: usize,
    n: usize,
    p: &[[u8; 32]],
    leaf_hash: &[u8; 32],
    root: &[u8; 32],
) -> Result<(), MerkleError> {
    merkle::verify_inclusion(
        digest,
        leaf_hash,
        m as u64,
        n as u64,
        MerklePath::from_nodes(p),
        root,
    )
}

fn consistency(
    m: usize,
    n: usize,
    first: &[u8; 32],
    second: &[u8; 32],
    p: &[[u8; 32]],
) -> Result<(), MerkleError> {
    merkle::verify_consistency(
        digest,
        m as u64,
        n as u64,
        first,
        second,
        MerklePath::from_nodes(p),
    )
}

#[test]
fn tree_hash_matches_the_definition() {
    let d = entries(MAX_LEAVES + 3);
    for n in 0..=d.len() {
        assert_eq!(
            merkle::merkle_tree_hash(digest, &d[..n]),
            mth(&d[..n]),
            "{n}"
        );
        let leaves: Vec<_> = d[..n]
            .iter()
            .map(|e| merkle::leaf_hash(digest, e))
            .collect();
        assert_eq!(merkle::root_from_leaf_hashes(digest, leaves), mth(&d[..n]));
    }
    assert_eq!(mth(&[]), digest(b""));
    assert_eq!(
        merkle::node_hash(digest, &[1; 32], &[2; 32]),
        node(&[1; 32], &[2; 32])
    );
}

/// The §2.1.5 example: a tree of seven leaves.
#[test]
fn rfc_example_proofs() {
    let d = entries(7);
    let [a, b, c, dd, e, f, d6] = std::array::from_fn(|i| leaf(&d[i]));
    let (g, h, i, j) = (node(&a, &b), node(&c, &dd), node(&e, &f), d6);
    let (k, l) = (node(&g, &h), node(&i, &j));
    let root = node(&k, &l);
    assert_eq!(mth(&d), root);
    assert_eq!(path(0, &d), [b, h, l]);
    assert_eq!(path(3, &d), [c, g, l]);
    assert_eq!(path(4, &d), [f, j, k]);
    assert_eq!(path(6, &d), [i, k]);
    assert_eq!(proof(3, &d), [c, dd, g, l]);
    assert_eq!(proof(4, &d), [l]);
    assert_eq!(proof(6, &d), [i, j, k]);
    for (m, p) in [
        (0, path(0, &d)),
        (3, path(3, &d)),
        (4, path(4, &d)),
        (6, path(6, &d)),
    ] {
        assert_eq!(inclusion(m, 7, &p, &leaf(&d[m]), &root), Ok(()));
    }
    let hash0 = mth(&d[..3]);
    assert_eq!(hash0, node(&g, &c));
    assert_eq!(consistency(3, 7, &hash0, &root, &proof(3, &d)), Ok(()));
    assert_eq!(consistency(4, 7, &k, &root, &[l]), Ok(()));
    assert_eq!(
        consistency(6, 7, &mth(&d[..6]), &root, &proof(6, &d)),
        Ok(())
    );
}

#[test]
fn every_inclusion_proof_verifies_and_no_tampered_one_does() {
    let d = entries(MAX_LEAVES);
    for n in 1..=MAX_LEAVES {
        let tree = &d[..n];
        let root = mth(tree);
        for m in 0..n {
            let leaf_hash = leaf(&tree[m]);
            let p = path(m, tree);
            assert_eq!(inclusion(m, n, &p, &leaf_hash, &root), Ok(()), "({m}, {n})");
            // Every path element, the leaf and the root, tampered.
            for at in 0..p.len() {
                let mut bad = p.clone();
                bad[at][at % 32] ^= 1;
                assert!(inclusion(m, n, &bad, &leaf_hash, &root).is_err());
            }
            let mut other_leaf = leaf_hash;
            other_leaf[0] ^= 0x80;
            assert!(inclusion(m, n, &p, &other_leaf, &root).is_err());
            let mut other_root = root;
            other_root[31] ^= 1;
            assert_eq!(
                inclusion(m, n, &p, &leaf_hash, &other_root),
                Err(MerkleError::RootMismatch)
            );
            // Other indexes and sizes.
            for other in [m ^ 1, (m + 1) % n, n - 1 - m] {
                if other != m && other < n {
                    assert!(
                        inclusion(other, n, &p, &leaf_hash, &root).is_err(),
                        "{other} for ({m}, {n})"
                    );
                }
            }
            assert_eq!(
                inclusion(n, n, &p, &leaf_hash, &root),
                Err(MerkleError::LeafIndexOutOfRange)
            );
            // Another size whose tree gives the leaf a path of another
            // length. (A path of the same shape may verify for another
            // size: only the signed tree head binds the size.)
            for size in [n + 1, 2 * n, n.saturating_sub(1).max(m + 1)] {
                let longer = entries(size);
                if size != n && path(m, &longer).len() != p.len() {
                    assert!(
                        inclusion(m, size, &p, &leaf_hash, &root).is_err(),
                        "size {size} for ({m}, {n})"
                    );
                }
            }
            // Extra and missing nodes.
            let mut extra = p.clone();
            extra.push(root);
            assert!(inclusion(m, n, &extra, &leaf_hash, &root).is_err());
            extra = [&[leaf_hash][..], &p].concat();
            assert!(inclusion(m, n, &extra, &leaf_hash, &root).is_err());
            if !p.is_empty() {
                assert!(inclusion(m, n, &p[..p.len() - 1], &leaf_hash, &root).is_err());
                assert!(inclusion(m, n, &p[1..], &leaf_hash, &root).is_err());
            }
        }
    }
}

#[test]
fn every_consistency_proof_verifies_and_no_tampered_one_does() {
    let d = entries(MAX_LEAVES);
    let roots: Vec<_> = (0..=MAX_LEAVES).map(|n| mth(&d[..n])).collect();
    for n in 1..=MAX_LEAVES {
        let second = roots[n];
        // Equal sizes: the empty proof of §5.3.
        assert_eq!(consistency(n, n, &second, &second, &[]), Ok(()));
        assert_eq!(
            consistency(n, n, &roots[n - 1], &second, &[]),
            Err(MerkleError::RootMismatch)
        );
        assert_eq!(
            consistency(n, n, &second, &second, &[second]),
            Err(MerkleError::WrongPathLength)
        );
        assert_eq!(
            consistency(0, n, &roots[0], &second, &[]),
            Err(MerkleError::InvalidTreeSizes)
        );
        for m in 1..n {
            let first = roots[m];
            let p = proof(m, &d[..n]);
            assert!(p.len() <= n.next_power_of_two().trailing_zeros() as usize + 1);
            assert_eq!(consistency(m, n, &first, &second, &p), Ok(()), "({m}, {n})");
            assert_eq!(
                consistency(n, m, &second, &first, &p),
                Err(MerkleError::InvalidTreeSizes)
            );
            assert_eq!(
                consistency(m, n, &first, &second, &[]),
                Err(MerkleError::WrongPathLength)
            );
            for at in 0..p.len() {
                let mut bad = p.clone();
                bad[at][7] ^= 4;
                assert!(
                    consistency(m, n, &first, &second, &bad).is_err(),
                    "node {at} of ({m}, {n})"
                );
            }
            let mut other = first;
            other[3] ^= 1;
            assert!(consistency(m, n, &other, &second, &p).is_err());
            other = second;
            other[3] ^= 1;
            assert!(consistency(m, n, &first, &other, &p).is_err());
            // Other sizes, with the roots of those sizes.
            if m + 1 < n {
                assert!(consistency(m + 1, n, &roots[m + 1], &second, &p).is_err());
            }
            if m > 1 {
                assert!(consistency(m - 1, n, &roots[m - 1], &second, &p).is_err());
            }
            if n < MAX_LEAVES {
                assert!(consistency(m, n + 1, &first, &roots[n + 1], &p).is_err());
            }
            let mut extra = p.clone();
            extra.push(second);
            assert!(consistency(m, n, &first, &second, &extra).is_err());
            if p.len() > 1 {
                assert!(consistency(m, n, &first, &second, &p[..p.len() - 1]).is_err());
                assert!(consistency(m, n, &first, &second, &p[1..]).is_err());
            }
        }
    }
}

#[test]
fn paths_beyond_a_64_bit_tree_are_refused() {
    let nodes = vec![[0u8; 32]; 70];
    let root = [0u8; 32];
    assert_eq!(
        inclusion(0, usize::MAX, &nodes[..65], &root, &root),
        Err(MerkleError::PathTooLong)
    );
    assert_eq!(
        inclusion(0, usize::MAX, &nodes[..64], &root, &root),
        Err(MerkleError::RootMismatch)
    );
    assert_eq!(
        consistency(3, usize::MAX, &root, &root, &nodes[..66]),
        Err(MerkleError::PathTooLong)
    );
    // The largest tree: every leaf index has a 64-node path, which the
    // verification walks without overflow.
    let max = u64::MAX;
    for index in [0, 1, max / 2, max - 2] {
        let result = merkle::verify_inclusion(
            digest,
            &root,
            index,
            max,
            MerklePath::from_nodes(&nodes[..64]),
            &root,
        );
        assert!(matches!(
            result,
            Err(MerkleError::RootMismatch | MerkleError::PathLengthMismatch)
        ));
    }
}

#[test]
fn auditor_verifies_tree_heads_and_proofs_of_a_log() {
    for log in [Log::ecdsa(1), Log::ed25519(2)] {
        let trusted = log.trusted();
        let d = entries(13);
        let (old, new) = (mth(&d[..5]), mth(&d));
        let sth = |ts, size, root: &[u8; 32], ext: &[u8]| log.sth(ts, size, root, ext);
        let old_item = sth(TIMESTAMP_MS, 5, &old, b"");
        let new_item = sth(TIMESTAMP_MS + 9, 13, &new, b"\x00\x01\x00\x00");
        let verify = |item: &[u8]| match TransItem::parse(item).unwrap() {
            TransItem::SignedTreeHeadV2(sth) => trusted.verify_tree_head(&sth, ALGS),
            other => panic!("{other:?}"),
        };
        let older = verify(&old_item).unwrap();
        let newer = verify(&new_item).unwrap();
        assert_eq!(
            older,
            TreeHead {
                timestamp_ms: TIMESTAMP_MS,
                tree_size: 5,
                root_hash: old
            }
        );
        assert_eq!(newer.tree_size, 13);

        // Tampered heads, misordered extensions, another log.
        let mut tampered = old_item.clone();
        let at = 2 + 1 + log.id.len() + 3;
        tampered[at] ^= 1;
        assert_eq!(verify(&tampered), Err(TransparencyError::InvalidSignature));
        let misordered = sth(TIMESTAMP_MS, 5, &old, b"\x00\x01\x00\x00\x00\x01\x00\x00");
        assert_eq!(
            verify(&misordered),
            Err(TransparencyError::InvalidExtensions)
        );
        let other = Log::ecdsa(log.id[3]);
        let foreign_item = other.sth(1, 5, &old, b"");
        let TransItem::SignedTreeHeadV2(foreign) = TransItem::parse(&foreign_item).unwrap() else {
            panic!()
        };
        assert_eq!(
            trusted.verify_tree_head(&foreign, ALGS),
            Err(TransparencyError::InvalidSignature)
        );
        let renamed_item = Log::ecdsa(3).sth(1, 5, &old, b"");
        let TransItem::SignedTreeHeadV2(renamed) = TransItem::parse(&renamed_item).unwrap() else {
            panic!()
        };
        assert_eq!(
            trusted.verify_tree_head(&renamed, ALGS),
            Err(TransparencyError::LogIdMismatch)
        );
        let TransItem::SignedTreeHeadV2(sth_data) = TransItem::parse(&old_item).unwrap() else {
            panic!()
        };
        assert_eq!(
            trusted.verify_tree_head(&sth_data, P256_ONLY),
            if log.id[3] == 1 {
                Ok(older)
            } else {
                Err(TransparencyError::UnsupportedSignatureAlgorithm)
            }
        );

        // Consistency between the two heads.
        let item = consistency_item(&log.id, 5, 13, &proof(5, &d));
        let TransItem::ConsistencyProofV2(cp) = TransItem::parse(&item).unwrap() else {
            panic!()
        };
        assert_eq!(
            trusted.verify_consistency_proof(digest, &cp, &older, &newer),
            Ok(())
        );
        assert_eq!(
            trusted.verify_consistency_proof(digest, &cp, &newer, &older),
            Err(TransparencyError::TreeSizeMismatch)
        );
        let forged = TreeHead {
            root_hash: [9; 32],
            ..newer
        };
        assert!(matches!(
            trusted.verify_consistency_proof(digest, &cp, &older, &forged),
            Err(TransparencyError::InvalidProof(_))
        ));
        let foreign_cp = consistency_item(&[0x2b, 0x65, 0x50, 0x7f], 5, 13, &proof(5, &d));
        let TransItem::ConsistencyProofV2(foreign_cp) = TransItem::parse(&foreign_cp).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            trusted.verify_consistency_proof(digest, &foreign_cp, &older, &newer),
            Err(TransparencyError::LogIdMismatch)
        );

        // Inclusion of entry 7 in the newer tree.
        let item = log.inclusion(13, 7, &path(7, &d));
        let TransItem::InclusionProofV2(ip) = TransItem::parse(&item).unwrap() else {
            panic!()
        };
        let leaf_hash = merkle::leaf_hash(digest, &d[7]);
        assert_eq!(
            trusted.verify_inclusion_proof(digest, &ip, &leaf_hash, &newer),
            Ok(())
        );
        assert_eq!(
            trusted.verify_inclusion_proof(digest, &ip, &leaf_hash, &older),
            Err(TransparencyError::TreeSizeMismatch)
        );
        let other_leaf = merkle::leaf_hash(digest, &d[6]);
        assert_eq!(
            trusted.verify_inclusion_proof(digest, &ip, &other_leaf, &newer),
            Err(TransparencyError::InvalidProof(MerkleError::RootMismatch))
        );
    }
}

#[test]
fn logs_take_only_registered_algorithms() {
    let ecdsa = Log::ecdsa(1);
    let ed25519 = Log::ed25519(2);
    assert_eq!(
        ecdsa.trusted().signature_algorithm(),
        LogSignatureAlgorithm::EcdsaSecp256r1Sha256
    );
    assert_eq!(
        ed25519.trusted().signature_algorithm(),
        LogSignatureAlgorithm::Ed25519
    );
    assert_eq!(
        LogSignatureAlgorithm::EcdsaSecp256r1Sha256.signature_scheme(),
        0x0403
    );
    assert_eq!(LogSignatureAlgorithm::Ed25519.signature_scheme(), 0x0807);
    // The key's contents also identify it.
    let contents = &ecdsa.spki[2..];
    assert_eq!(
        CtV2Log::new(&ecdsa.id, contents).unwrap().id(),
        ecdsa.trusted().id()
    );
    assert_eq!(ecdsa.trusted().id().as_bytes(), &ecdsa.id[..]);
    for alg in [&rcgen::PKCS_ECDSA_P384_SHA384, &rcgen::PKCS_RSA_SHA256] {
        let key = key_for(alg).subject_public_key_info();
        assert_eq!(
            CtV2Log::new(&ecdsa.id, &key).err(),
            Some(TransparencyError::UnsupportedLogKey)
        );
    }
    assert_eq!(
        CtV2Log::new(&ecdsa.id, &[0x30, 0]).err(),
        Some(TransparencyError::MalformedLogKey)
    );
    assert_eq!(
        CtV2Log::new(&[0x2b], &ecdsa.spki).err(),
        Some(TransparencyError::MalformedLogId)
    );
    assert_eq!(
        CtV2Log::new(&[0x2b, 0x80], &ecdsa.spki).err(),
        Some(TransparencyError::MalformedLogId)
    );
}

#[test]
fn items_round_trip_through_lists() {
    let log = Log::ecdsa(4);
    let d = entries(9);
    let items = vec![
        log.sct(false, TIMESTAMP_MS, b"issuer", b"\x30\x00", b""),
        log.sct(
            true,
            TIMESTAMP_MS,
            b"issuer",
            b"\x30\x00",
            b"\x00\x09\x00\x01x",
        ),
        log.sth(TIMESTAMP_MS, 9, &mth(&d), b""),
        log.inclusion(9, 2, &path(2, &d)),
        consistency_item(&log.id, 3, 9, &proof(3, &d)),
        entry(false, 1, b"issuer", b"\x30\x00", b""),
        entry(true, 1, b"issuer", b"\x30\x00", b""),
        vec![0xe0, 0x00, 1, 2, 3],
    ];
    let encoded = list(&items);
    let parsed = TransItemList::parse(&encoded).unwrap();
    assert_eq!(parsed.len(), items.len());
    assert!(!parsed.is_empty());
    assert!(parsed.has_sct());
    let mut types = Vec::new();
    for (item, expected) in parsed.iter().zip(&items) {
        assert_eq!(&item.encode().unwrap(), expected);
        types.push(item.versioned_type());
    }
    assert_eq!(
        types,
        [
            versioned_type::X509_SCT_V2,
            versioned_type::PRECERT_SCT_V2,
            versioned_type::SIGNED_TREE_HEAD_V2,
            versioned_type::INCLUSION_PROOF_V2,
            versioned_type::CONSISTENCY_PROOF_V2,
            versioned_type::X509_ENTRY_V2,
            versioned_type::PRECERT_ENTRY_V2,
            0xe000,
        ]
    );
    let all: Vec<_> = (&parsed).into_iter().collect();
    assert_eq!(TransItemList::encode_items(&all).unwrap(), encoded);
    let serialized: Vec<_> = parsed.serialized_items().collect();
    assert_eq!(TransItemList::encode(&serialized).unwrap(), encoded);
    assert!(!TransItemList::parse(&list(&items[2..])).unwrap().has_sct());

    // A tree head's signed structure is its own encoding.
    let TransItem::SignedTreeHeadV2(sth) = TransItem::parse(&items[2]).unwrap() else {
        panic!()
    };
    assert_eq!(
        sth.tree_head.encode().unwrap(),
        tree_head(TIMESTAMP_MS, 9, &mth(&d), b"")
    );
    let TransItem::PrecertSctV2(sct) = TransItem::parse(&items[1]).unwrap() else {
        panic!()
    };
    let extensions: Vec<_> = sct.sct_extensions.iter().collect();
    assert_eq!(
        extensions,
        [ArtifactExtension {
            extension_type: 9,
            data: b"x"
        }]
    );
    assert_eq!(sct.sct_extensions.as_bytes(), b"\x00\x09\x00\x01x");
    let TransItem::InclusionProofV2(ip) = TransItem::parse(&items[3]).unwrap() else {
        panic!()
    };
    assert_eq!(ip.inclusion_path.len(), path(2, &d).len());
    assert!(!ip.inclusion_path.is_empty());
    assert!(ip.inclusion_path.iter().eq(path(2, &d).iter()));
}
