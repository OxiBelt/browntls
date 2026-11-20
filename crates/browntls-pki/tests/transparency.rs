//! RFC 9162 verification of the SCTs, signed tree heads and inclusion
//! proofs delivered with a certificate, with certificates and ECDSA P-256
//! and Ed25519 logs generated at run time: the three delivery mechanisms,
//! the precertificate reconstruction, inclusion evidence across sources,
//! and the ways each can fail.
//!
//! No public CT 2.0 log or second implementation was available: logs here
//! are built from the RFC text, so this is self-consistency evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ct_v2.rs"]
mod support;

use support::*;

/// A verifier for `cert`, issued by `ca`, at `NOW`.
fn verifier<'a>(policy: &'a CtV2Policy<'a>, cert: &'a Cert<'a>, ca: &Ca) -> CtV2Verifier<'a> {
    CtV2Verifier::new(policy, cert, &ca.issuer_spki, NOW).unwrap()
}

/// Verifies one TLS extension list for `cert` with `logs` and `options`.
fn verify_tls(
    logs: &[CtV2Log<'_>],
    options: CtV2Options,
    ca: &Ca,
    cert: &CertificateDer<'_>,
    data: &[u8],
) -> Result<CtV2Report, TransparencyError> {
    let policy = policy(logs, options);
    let cert = Cert::try_from(cert).unwrap();
    verifier(&policy, &cert, ca).verify_tls_extension(data)
}

/// An `x509_sct_v2` of `log` for `cert`.
fn x509_sct(
    log: &Log,
    ca: &Ca,
    cert: &CertificateDer<'_>,
    timestamp_ms: u64,
    ext: &[u8],
) -> Vec<u8> {
    log.sct(false, timestamp_ms, &ca.issuer_spki, &Ca::tbs(cert), ext)
}

#[test]
fn scts_from_the_three_sources() {
    let ca = Ca::new();
    let (ecdsa, ed25519) = (Log::ecdsa(1), Log::ed25519(2));
    let der = ca.with_embedded(&[
        ca.precert_sct(&ecdsa, TIMESTAMP_MS),
        ca.precert_sct(&ed25519, TIMESTAMP_MS),
    ]);
    let cert = Cert::try_from(&der).unwrap();
    let logs = [ecdsa.trusted(), ed25519.trusted()];
    let policy = policy(&logs, CtV2Options::default());

    // The issuer key as a complete SubjectPublicKeyInfo and as contents.
    for issuer_spki in [&ca.issuer_spki[..], &ca.issuer_spki[2..]] {
        let mut verifier = CtV2Verifier::new(&policy, &cert, issuer_spki, NOW).unwrap();
        assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 2)));
        let tls = list(&[
            x509_sct(&ecdsa, &ca, &der, TIMESTAMP_MS, b""),
            ca.precert_sct(&ed25519, TIMESTAMP_MS + 1),
        ]);
        assert_eq!(
            verifier.verify_tls_extension(&tls),
            Ok(report(|r| r.verified = 2))
        );
        let ocsp = list(&[
            x509_sct(&ed25519, &ca, &der, TIMESTAMP_MS + 2, b""),
            // Already verified from the certificate.
            ca.precert_sct(&ecdsa, TIMESTAMP_MS),
        ]);
        assert_eq!(
            verifier.verify_ocsp_response(&ocsp),
            Ok(report(|r| {
                r.verified = 1;
                r.duplicate = 1;
            }))
        );
        let verified = verifier.verified();
        let summary: Vec<_> = verified
            .iter()
            .map(|v| {
                (
                    v.log_index(),
                    v.timestamp_ms(),
                    v.entry_type(),
                    v.source(),
                    v.inclusion(),
                )
            })
            .collect();
        use SctEntryType::{Precert, X509};
        use SctSource::{Embedded, OcspResponse, TlsExtension};
        assert_eq!(
            summary,
            [
                (0, TIMESTAMP_MS, Precert, Embedded, None),
                (1, TIMESTAMP_MS, Precert, Embedded, None),
                (0, TIMESTAMP_MS, X509, TlsExtension, None),
                (1, TIMESTAMP_MS + 1, Precert, TlsExtension, None),
                (1, TIMESTAMP_MS + 2, X509, OcspResponse, None),
            ]
        );
        assert_eq!(verified[0].log_id(), &ecdsa.id[..]);
        assert_eq!(verified[1].log_id(), &ed25519.id[..]);
        assert_eq!(verifier.into_verified().len(), 5);
    }
    assert_eq!(
        CtV2Verifier::new(&policy, &cert, &[0x30, 0x00], NOW).err(),
        Some(TransparencyError::MalformedIssuerKey)
    );

    // A certificate without the extension has no embedded SCT.
    let plain = ca.plain();
    let cert = Cert::try_from(&plain).unwrap();
    assert_eq!(
        verifier(&policy, &cert, &ca).verify_embedded(),
        Ok(CtV2Report::default())
    );
}

#[test]
fn scts_bind_the_issuer_key_the_certificate_and_the_type() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let policy = policy(&logs, CtV2Options::default());
    let invalid = Ok(report(|r| r.invalid_signature = 1));
    let sct = ca.precert_sct(&log, TIMESTAMP_MS);
    let der = ca.with_embedded(std::slice::from_ref(&sct));
    let cert = Cert::try_from(&der).unwrap();

    // Another issuer key: the end entity's own.
    let other = cert.subject_public_key_info();
    let mut verifier = CtV2Verifier::new(&policy, &cert, &other, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), invalid);
    assert!(verifier.verified().is_empty());

    // The same list in a certificate for another name.
    let mut params = ca.params.clone();
    params.subject_alt_names = ee_params(&["other.example.com"]).subject_alt_names;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            TRANSPARENCY_ARCS,
            octet_string(&list(std::slice::from_ref(&sct))),
        ));
    let renamed = ca.issue(&params);
    let renamed = Cert::try_from(&renamed).unwrap();
    assert_eq!(
        verifier_for(&policy, &renamed, &ca).verify_embedded(),
        invalid
    );

    // The precertificate SCT presented as an x509_sct_v2, and an
    // x509_sct_v2 over the certificate presented as a precert_sct_v2.
    let mut as_x509 = sct.clone();
    as_x509[1] = 2;
    assert_eq!(
        verify_tls(&logs, CtV2Options::default(), &ca, &der, &list(&[as_x509])),
        invalid
    );
    let mut as_precert = x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"");
    as_precert[1] = 3;
    assert_eq!(
        verify_tls(
            &logs,
            CtV2Options::default(),
            &ca,
            &der,
            &list(&[as_precert])
        ),
        invalid
    );
    // An SCT over the certificate without the extension is not one for
    // the certificate with it.
    let plain = ca.plain();
    let sct = x509_sct(&log, &ca, &plain, TIMESTAMP_MS, b"");
    assert_eq!(
        verify_tls(&logs, CtV2Options::default(), &ca, &der, &list(&[sct])),
        invalid
    );

    // Every signed field: timestamp, extensions, signature.
    let tbs = Ca::tbs(&plain);
    let signature = log.sign(&entry(false, TIMESTAMP_MS, &ca.issuer_spki, &tbs, b""));
    for (timestamp, ext, sig) in [
        (TIMESTAMP_MS - 1, &b""[..], signature.clone()),
        (TIMESTAMP_MS, b"\x00\x01\x00\x00", signature.clone()),
        (
            TIMESTAMP_MS,
            b"",
            [
                &signature[..signature.len() - 1],
                &[signature[signature.len() - 1] ^ 1],
            ]
            .concat(),
        ),
    ] {
        let sct = sct_item(false, &log.id, timestamp, ext, &sig);
        assert_eq!(
            verify_tls(&logs, CtV2Options::default(), &ca, &plain, &list(&[sct])),
            invalid
        );
    }
}

fn verifier_for<'a>(policy: &'a CtV2Policy<'a>, cert: &'a Cert<'a>, ca: &Ca) -> CtV2Verifier<'a> {
    verifier(policy, cert, ca)
}

#[test]
fn precertificate_without_both_transparency_extensions() {
    let ca = Ca::new();
    let log = Log::ed25519(5);
    let logs = [log.trusted()];
    let policy = policy(&logs, CtV2Options::default());
    let v2 = octet_string(&list(&[ca.precert_sct(&log, TIMESTAMP_MS)]));
    // A version 1 list: removed whatever it holds.
    let v1 = octet_string(b"\x00\x04\x00\x02\x07\x07");
    let tls = list(&[ca.precert_sct(&log, TIMESTAMP_MS + 1)]);
    for extensions in [
        vec![(TRANSPARENCY_ARCS, v2.clone()), (SCT_LIST_ARCS, v1.clone())],
        vec![(SCT_LIST_ARCS, v1.clone()), (TRANSPARENCY_ARCS, v2.clone())],
    ] {
        let der = ca.with_extensions(&extensions);
        let cert = Cert::try_from(&der).unwrap();
        let mut verifier = verifier(&policy, &cert, &ca);
        assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 1)));
        assert_eq!(
            verifier.verify_tls_extension(&tls),
            Ok(report(|r| r.verified = 1))
        );
    }

    // Precertificate SCTs from TLS for a certificate with only the version
    // 1 list.
    let der = ca.with_extensions(&[(SCT_LIST_ARCS, v1.clone())]);
    assert_eq!(
        verify_tls(&logs, CtV2Options::default(), &ca, &der, &tls),
        Ok(report(|r| r.verified = 1))
    );

    // A repeated Transparency Information extension.
    let der = ca.with_extensions(&[
        (TRANSPARENCY_ARCS, v2.clone()),
        (TRANSPARENCY_ARCS, v2.clone()),
    ]);
    let cert = Cert::try_from(&der).unwrap();
    let mut verifier = verifier(&policy, &cert, &ca);
    assert_eq!(
        verifier.verify_embedded(),
        Err(TransparencyError::DuplicateExtension)
    );
    assert_eq!(
        verifier.verify_tls_extension(&tls),
        Err(TransparencyError::DuplicateExtension)
    );
    // An x509_sct_v2 does not need the reconstruction.
    let x509 = list(&[x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"")]);
    assert_eq!(
        verifier.verify_tls_extension(&x509),
        Ok(report(|r| r.verified = 1))
    );
}

#[test]
fn embedded_items_are_for_the_precertificate() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let none = policy(&logs, options(|o| o.max_signature_verifications = 0));
    let plain = ca.plain();
    let der = ca.with_embedded(&[
        x509_sct(&log, &ca, &plain, TIMESTAMP_MS, b""),
        vec![0xf0, 0x01, 9],
        entry(true, 1, b"issuer", b"\x30\x00", b""),
    ]);
    let cert = Cert::try_from(&der).unwrap();
    assert_eq!(
        verifier(&none, &cert, &ca).verify_embedded(),
        Ok(report(|r| {
            r.misplaced = 1;
            r.unknown_type = 1;
            r.ignored = 1;
        }))
    );

    // The extension value must be an OCTET STRING of exactly one list.
    let items = list(&[ca.precert_sct(&log, TIMESTAMP_MS)]);
    let mut trailing = octet_string(&items);
    trailing.push(0);
    for value in [
        items.clone(),
        trailing,
        octet_string(&items[..items.len() - 1]),
        octet_string(&[0, 0]),
    ] {
        let der = ca.with_extensions(&[(TRANSPARENCY_ARCS, value)]);
        let cert = Cert::try_from(&der).unwrap();
        let policy = policy(&logs, CtV2Options::default());
        assert_eq!(
            verifier(&policy, &cert, &ca).verify_embedded(),
            Err(TransparencyError::MalformedList)
        );
    }
}

#[test]
fn extensions_must_be_ordered_without_repetition() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let der = ca.plain();
    let ordered = b"\x00\x01\x00\x01a\xe0\x00\x00\x00";
    assert_eq!(
        verify_tls(
            &logs,
            CtV2Options::default(),
            &ca,
            &der,
            &list(&[x509_sct(&log, &ca, &der, TIMESTAMP_MS, ordered)])
        ),
        Ok(report(|r| r.verified = 1))
    );
    // Correctly signed, but invalid: and costs no signature verification.
    let no_signature = options(|o| o.max_signature_verifications = 0);
    for ext in [
        &b"\x00\x02\x00\x00\x00\x01\x00\x00"[..],
        b"\x00\x01\x00\x00\x00\x01\x00\x00",
    ] {
        let sct = x509_sct(&log, &ca, &der, TIMESTAMP_MS, ext);
        assert_eq!(
            verify_tls(&logs, no_signature.clone(), &ca, &der, &list(&[sct])),
            Ok(report(|r| r.invalid_extensions = 1))
        );
    }
}

#[test]
fn log_trust_and_time() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let der = ca.plain();
    let items = list(&[x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"")]);
    let verified = Ok(report(|r| r.verified = 1));

    // Unknown logs cost no signature verification; the ID must match too.
    let none = options(|o| o.max_signature_verifications = 0);
    let unknown = Ok(report(|r| r.unknown_log = 1));
    assert_eq!(
        verify_tls(&[Log::ecdsa(2).trusted()], none.clone(), &ca, &der, &items),
        unknown
    );
    assert_eq!(verify_tls(&[], none, &ca, &der, &items), unknown);
    let impostor = Log::ecdsa(1);
    assert_eq!(
        verify_tls(
            &[impostor.trusted()],
            CtV2Options::default(),
            &ca,
            &der,
            &items
        ),
        Ok(report(|r| r.invalid_signature = 1))
    );
    // The first log with the ID is used.
    let logs = [log.trusted(), impostor.trusted()];
    assert_eq!(
        verify_tls(&logs, CtV2Options::default(), &ca, &der, &items),
        verified
    );

    // The window is half open.
    let outside = Ok(report(|r| r.outside_log_validity = 1));
    for (from_ms, until_ms, expected) in [
        (TIMESTAMP_MS, TIMESTAMP_MS + 1, &verified),
        (TIMESTAMP_MS + 1, u64::MAX, &outside),
        (0, TIMESTAMP_MS, &outside),
    ] {
        let logs = [log.trusted().with_timestamp_window(from_ms, until_ms)];
        assert_eq!(
            &verify_tls(&logs, CtV2Options::default(), &ca, &der, &items),
            expected
        );
    }

    // Timestamps after the verification time, unless tolerated.
    let logs = [log.trusted()];
    let at = |ms: u64| UnixTime::since_unix_epoch(core::time::Duration::from_millis(ms));
    let future = Ok(report(|r| r.future_timestamp = 1));
    let cert = Cert::try_from(&der).unwrap();
    for (tolerance, now_ms, expected) in [
        (0, TIMESTAMP_MS, &verified),
        (0, TIMESTAMP_MS - 1_000, &future),
        (60_000, TIMESTAMP_MS - 60_000, &verified),
        (60_000, TIMESTAMP_MS - 61_000, &future),
    ] {
        let policy = policy(&logs, options(|o| o.future_tolerance_ms = tolerance));
        let mut verifier = CtV2Verifier::new(&policy, &cert, &ca.issuer_spki, at(now_ms)).unwrap();
        assert_eq!(&verifier.verify_tls_extension(&items), expected);
    }
}

#[test]
fn the_signature_algorithm_is_the_logs() {
    let ca = Ca::new();
    let der = ca.plain();
    let tbs = Ca::tbs(&der);
    let ed25519 = Log::ed25519(2);
    let ecdsa_key = key_for(&rcgen::PKCS_ECDSA_P256_SHA256);
    // An ECDSA signature for an Ed25519 log.
    let signature = ecdsa_key
        .sign(&entry(false, TIMESTAMP_MS, &ca.issuer_spki, &tbs, b""))
        .unwrap();
    let sct = sct_item(false, &ed25519.id, TIMESTAMP_MS, b"", &signature);
    let logs = [ed25519.trusted()];
    assert_eq!(
        verify_tls(&logs, CtV2Options::default(), &ca, &der, &list(&[sct])),
        Ok(report(|r| r.invalid_signature = 1))
    );

    // The application's algorithms decide what can be verified.
    let ecdsa = Log::ecdsa(1);
    let items = list(&[
        x509_sct(&ed25519, &ca, &der, TIMESTAMP_MS, b""),
        x509_sct(&ecdsa, &ca, &der, TIMESTAMP_MS, b""),
    ]);
    let logs = [ed25519.trusted(), ecdsa.trusted()];
    let cert = Cert::try_from(&der).unwrap();
    for (algs, expected) in [
        (
            P256_ONLY,
            report(|r| {
                r.verified = 1;
                r.unsupported_algorithm = 1;
            }),
        ),
        (&[][..], report(|r| r.unsupported_algorithm = 2)),
        (ALGS, report(|r| r.verified = 2)),
    ] {
        let algs: &[&dyn SignatureVerificationAlgorithm] = algs;
        let policy = CtV2Policy {
            supported_sig_algs: algs,
            ..policy(&logs, CtV2Options::default())
        };
        assert_eq!(
            verifier(&policy, &cert, &ca).verify_tls_extension(&items),
            Ok(expected)
        );
    }
}

#[test]
fn malformed_lists_verify_nothing() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let der = ca.plain();
    let cert = Cert::try_from(&der).unwrap();
    let sct = x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"");
    let good = list(std::slice::from_ref(&sct));
    let policy = policy(&logs, CtV2Options::default());
    let mut verifier = verifier(&policy, &cert, &ca);
    for len in 2..good.len() {
        assert_eq!(
            verifier.verify_tls_extension(&good[..len]),
            Err(TransparencyError::MalformedList),
            "{len}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        verifier.verify_tls_extension(&trailing),
        Err(TransparencyError::MalformedList)
    );
    // A valid SCT beside a malformed item of a defined type: nothing.
    let mut long = sct.clone();
    long.push(0);
    for second in [
        long,
        vec![],
        vec![1],
        vec![1, 4, 0],
        sct[..sct.len() - 1].to_vec(),
    ] {
        assert_eq!(
            verifier.verify_tls_extension(&list(&[sct.clone(), second])),
            Err(TransparencyError::MalformedList)
        );
    }
    assert!(verifier.verified().is_empty());
    // What a server may send instead of nothing (RFC 9162 §6.5), and an
    // empty list from OCSP.
    assert_eq!(
        verifier.verify_tls_extension(&[]),
        Ok(CtV2Report::default())
    );
    assert_eq!(
        verifier.verify_tls_extension(&[0, 0]),
        Ok(CtV2Report::default())
    );
    assert_eq!(
        verifier.verify_ocsp_response(&[0, 0]),
        Err(TransparencyError::MalformedList)
    );
    assert_eq!(
        verifier.verify_ocsp_response(&octet_string(&good)),
        Err(TransparencyError::MalformedList)
    );
    // Items of unknown types are skipped.
    assert_eq!(
        verifier.verify_tls_extension(&list(&[vec![0, 0], sct, vec![0xff, 0xff, 1, 2]])),
        Ok(report(|r| {
            r.verified = 1;
            r.unknown_type = 2;
        }))
    );
}

#[test]
fn limits_bound_lists_items_and_work_across_sources() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let der = ca.with_embedded(&[ca.precert_sct(&log, TIMESTAMP_MS)]);
    let cert = Cert::try_from(&der).unwrap();
    let sct = |offset: u64, ext: &[u8]| x509_sct(&log, &ca, &der, TIMESTAMP_MS + offset, ext);

    // Items: one embedded, then the TLS and OCSP lists against three.
    let three = policy(&logs, options(|o| o.max_items = 3));
    let mut verifier3 = verifier(&three, &cert, &ca);
    assert_eq!(verifier3.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(
        verifier3.verify_tls_extension(&list(&[sct(1, b""), sct(2, b""), sct(3, b"")])),
        Err(TransparencyError::TooManyItems)
    );
    assert_eq!(verifier3.verified().len(), 1);
    assert_eq!(
        verifier3.verify_ocsp_response(&list(&[vec![0xf0, 0], sct(1, b"")])),
        Ok(report(|r| {
            r.unknown_type = 1;
            r.verified = 1;
        }))
    );
    assert_eq!(
        verifier3.verify_tls_extension(&list(&[sct(2, b"")])),
        Err(TransparencyError::TooManyItems)
    );

    // Signatures: shared, and what was verified before the limit is kept.
    let two = policy(&logs, options(|o| o.max_signature_verifications = 2));
    let mut verifier2 = verifier(&two, &cert, &ca);
    assert_eq!(verifier2.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(verifier2.verify_embedded(), Ok(report(|r| r.duplicate = 1)));
    assert_eq!(
        verifier2.verify_tls_extension(&list(&[sct(1, b""), sct(2, b"")])),
        Err(TransparencyError::SignatureBudgetExceeded)
    );
    assert_eq!(verifier2.verified().len(), 2);

    // Sizes of the list, of extensions and of signatures.
    let one = list(&[sct(1, b"\x00\x01\x00\x00")]);
    let sth = log.sth(TIMESTAMP_MS, 1, &[0; 32], b"\x00\x01\x00\x00");
    for (edited, data, expected) in [
        (
            options(|o| o.max_list_len = one.len()),
            &one,
            Ok(report(|r| r.verified = 1)),
        ),
        (
            options(|o| o.max_list_len = one.len() - 1),
            &one,
            Err(TransparencyError::ListTooLarge),
        ),
        (
            options(|o| o.max_extensions_len = 3),
            &one,
            Err(TransparencyError::ItemTooLarge),
        ),
        (
            options(|o| o.max_signature_len = 60),
            &one,
            Err(TransparencyError::ItemTooLarge),
        ),
        (
            options(|o| o.max_extensions_len = 3),
            &list(std::slice::from_ref(&sth)),
            Err(TransparencyError::ItemTooLarge),
        ),
        (
            options(|o| o.max_signature_len = 60),
            &list(std::slice::from_ref(&sth)),
            Err(TransparencyError::ItemTooLarge),
        ),
    ] {
        assert_eq!(verify_tls(&logs, edited, &ca, &der, data), expected);
    }
    // The embedded list is subject to the same limits.
    let tiny = policy(&logs, options(|o| o.max_list_len = 16));
    assert_eq!(
        verifier(&tiny, &cert, &ca).verify_embedded(),
        Err(TransparencyError::ListTooLarge)
    );
}

/// A tree of `size` entries with `leaf` at `index`, its root and the
/// inclusion path of `leaf`.
fn tree(leaf: Vec<u8>, size: usize, index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut d = entries(size);
    d[index] = leaf;
    (mth(&d), path(index, &d))
}

#[test]
fn inclusion_proven_with_a_delivered_tree_head() {
    let ca = Ca::new();
    for log in [Log::ecdsa(1), Log::ed25519(2)] {
        let logs = [log.trusted()];
        let policy = policy(&logs, CtV2Options::default());
        let der = ca.plain();
        let cert = Cert::try_from(&der).unwrap();
        let leaf = entry(false, TIMESTAMP_MS, &ca.issuer_spki, &Ca::tbs(&der), b"");
        let (root, p) = tree(leaf, 11, 6);
        let items = list(&[
            log.inclusion(11, 6, &p),
            x509_sct(&log, &ca, &der, TIMESTAMP_MS, b""),
            log.sth(TIMESTAMP_MS + 5, 11, &root, b""),
        ]);
        let mut verifier = verifier(&policy, &cert, &ca);
        assert_eq!(
            verifier.verify_tls_extension(&items),
            Ok(report(|r| {
                r.verified = 1;
                r.tree_heads = 1;
                r.inclusion_proofs = 1;
                r.inclusion_proven = 1;
                r.tree_heads_verified = 1;
            }))
        );
        let evidence = verifier.verified()[0].inclusion().unwrap();
        assert_eq!(
            (
                evidence.tree_size,
                evidence.leaf_index,
                evidence.tree_head_timestamp_ms
            ),
            (11, 6, TIMESTAMP_MS + 5)
        );
        assert_eq!(
            evidence.tree_head_source,
            TreeHeadSource::Delivered(SctSource::TlsExtension)
        );
        assert_eq!(evidence.proof_source, SctSource::TlsExtension);
        // Delivering it again proves nothing new.
        assert_eq!(
            verifier.verify_ocsp_response(&items),
            Ok(report(|r| {
                r.verified = 1;
                r.tree_heads = 1;
                r.inclusion_proofs = 1;
            }))
            .map(|mut r| {
                // The x509 SCT from OCSP is a duplicate of the TLS one.
                r.verified = 0;
                r.duplicate = 1;
                r
            })
        );
    }
}

#[test]
fn inclusion_needs_a_matching_valid_tree_head() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let logs = [log.trusted()];
    let der = ca.plain();
    let cert = Cert::try_from(&der).unwrap();
    let leaf = entry(false, TIMESTAMP_MS, &ca.issuer_spki, &Ca::tbs(&der), b"");
    let (root, p) = tree(leaf.clone(), 9, 2);
    let sct = x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"");
    let proof = log.inclusion(9, 2, &p);
    let proven = |items: &[Vec<u8>], trusted: &[TrustedTreeHead<'_>]| {
        let policy = CtV2Policy {
            trusted_tree_heads: trusted,
            ..policy(&logs, CtV2Options::default())
        };
        let mut verifier = verifier(&policy, &cert, &ca);
        let report = verifier.verify_tls_extension(&list(items)).unwrap();
        (verifier.verified()[0].inclusion(), report)
    };

    // Trusted by the application, without a signed tree head in the list.
    let head = TreeHead {
        timestamp_ms: TIMESTAMP_MS,
        tree_size: 9,
        root_hash: root,
    };
    let trusted = [TrustedTreeHead {
        log_id: log.trusted().id(),
        tree_head: head,
    }];
    let (evidence, _) = proven(&[sct.clone(), proof.clone()], &trusted);
    assert_eq!(evidence.unwrap().tree_head_source, TreeHeadSource::Trusted);
    // Older than the SCT, of another size or of another log: not evidence.
    for (timestamp_ms, tree_size, log_id) in [
        (TIMESTAMP_MS - 1, 9, log.trusted().id()),
        (TIMESTAMP_MS, 10, log.trusted().id()),
        (
            TIMESTAMP_MS,
            9,
            LogId::new(&[0x2b, 0x65, 0x50, 0x09]).unwrap(),
        ),
    ] {
        let trusted = [TrustedTreeHead {
            log_id,
            tree_head: TreeHead {
                timestamp_ms,
                tree_size,
                ..head
            },
        }];
        assert_eq!(proven(&[sct.clone(), proof.clone()], &trusted).0, None);
    }

    // A tree head of another size is not even verified.
    let (evidence, report) = proven(
        &[
            sct.clone(),
            proof.clone(),
            log.sth(TIMESTAMP_MS, 10, &root, b""),
        ],
        &[],
    );
    assert_eq!(
        (evidence, report.tree_heads_verified, report.tree_heads),
        (None, 0, 1)
    );
    // One older than the SCT is verified but not used.
    let (evidence, report) = proven(
        &[
            sct.clone(),
            proof.clone(),
            log.sth(TIMESTAMP_MS - 1, 9, &root, b""),
        ],
        &[],
    );
    assert_eq!((evidence, report.tree_heads_verified), (None, 1));
    // A forged one, and one with misordered extensions.
    let mut forged = log.sth(TIMESTAMP_MS, 9, &root, b"");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let misordered = log.sth(TIMESTAMP_MS, 9, &root, b"\x00\x02\x00\x00\x00\x01\x00\x00");
    for sth in [forged, misordered] {
        let (evidence, report) = proven(&[sct.clone(), proof.clone(), sth], &[]);
        assert_eq!((evidence, report.tree_heads_invalid), (None, 1));
    }
    // A signed tree head of another log with the same ID.
    let (evidence, _) = proven(
        &[
            sct.clone(),
            proof.clone(),
            Log::ecdsa(1).sth(TIMESTAMP_MS, 9, &root, b""),
        ],
        &[],
    );
    assert_eq!(evidence, None);
    // A proof for another leaf, or for another index.
    let sth = log.sth(TIMESTAMP_MS, 9, &root, b"");
    let other = log.inclusion(9, 3, &tree(leaf.clone(), 9, 3).1);
    let shifted = log.inclusion(9, 3, &p);
    for proof in [other, shifted] {
        let (evidence, report) = proven(&[sct.clone(), proof, sth.clone()], &[]);
        assert_eq!((evidence, report.inclusion_proven), (None, 0));
    }
    // A proof or tree head of an unknown log is ignored.
    let stranger = Log::ecdsa(9);
    let (evidence, report) = proven(
        &[
            sct.clone(),
            stranger.inclusion(9, 2, &p),
            stranger.sth(TIMESTAMP_MS, 9, &root, b""),
        ],
        &[],
    );
    assert_eq!((evidence, report.ignored), (None, 2));
}

#[test]
fn inclusion_evidence_across_sources() {
    let ca = Ca::new();
    let log = Log::ed25519(3);
    let logs = [log.trusted()];
    let policy = policy(&logs, CtV2Options::default());
    let der = ca.with_embedded(&[ca.precert_sct(&log, TIMESTAMP_MS)]);
    let cert = Cert::try_from(&der).unwrap();
    let leaf = entry(true, TIMESTAMP_MS, &ca.issuer_spki, &ca.precert_tbs(), b"");
    let (root, p) = tree(leaf, 70, 64);

    // The proof in the OCSP response, the tree head in the TLS extension.
    let mut verifier = verifier(&policy, &cert, &ca);
    assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(
        verifier.verify_ocsp_response(&list(&[log.inclusion(70, 64, &p)])),
        Ok(report(|r| r.inclusion_proofs = 1))
    );
    assert_eq!(verifier.verified()[0].inclusion(), None);
    assert_eq!(
        verifier.verify_tls_extension(&list(&[log.sth(TIMESTAMP_MS + 1, 70, &root, b"")])),
        Ok(report(|r| {
            r.tree_heads = 1;
            r.inclusion_proven = 1;
            r.tree_heads_verified = 1;
        }))
    );
    let evidence = verifier.verified()[0].inclusion().unwrap();
    assert_eq!(evidence.proof_source, SctSource::OcspResponse);
    assert_eq!(
        evidence.tree_head_source,
        TreeHeadSource::Delivered(SctSource::TlsExtension)
    );
    assert_eq!(evidence.leaf_index, 64);

    // Proof and tree head first, SCT last.
    let mut verifier = verifier_for(&policy, &cert, &ca);
    let evidence_items = list(&[
        log.inclusion(70, 64, &p),
        log.sth(TIMESTAMP_MS, 70, &root, b""),
    ]);
    assert_eq!(
        verifier.verify_tls_extension(&evidence_items),
        Ok(report(|r| {
            r.tree_heads = 1;
            r.inclusion_proofs = 1;
        }))
    );
    assert_eq!(
        verifier.verify_embedded(),
        Ok(report(|r| {
            r.verified = 1;
            r.inclusion_proven = 1;
            r.tree_heads_verified = 1;
        }))
    );

    // Hash budget: the path and one leaf hash.
    let needed = p.len() + 1;
    for (budget, expected) in [
        (needed, Ok(1)),
        (needed - 1, Err(TransparencyError::HashBudgetExceeded)),
    ] {
        let policy = crate::policy(&logs, options(|o| o.max_hash_operations = budget));
        let mut verifier = verifier_for(&policy, &cert, &ca);
        verifier.verify_embedded().unwrap();
        let items = list(&[
            log.inclusion(70, 64, &p),
            log.sth(TIMESTAMP_MS, 70, &root, b""),
        ]);
        assert_eq!(
            verifier
                .verify_tls_extension(&items)
                .map(|r| r.inclusion_proven),
            expected
        );
        assert_eq!(verifier.verified().len(), 1);
    }
    // The tree head's signature counts against the signature budget.
    let one = crate::policy(&logs, options(|o| o.max_signature_verifications = 1));
    let mut verifier = verifier_for(&one, &cert, &ca);
    verifier.verify_embedded().unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&evidence_items),
        Err(TransparencyError::SignatureBudgetExceeded)
    );
}

#[test]
fn servers_check_lists_before_stapling() {
    let ca = Ca::new();
    let log = Log::ecdsa(1);
    let der = ca.plain();
    let sct = x509_sct(&log, &ca, &der, TIMESTAMP_MS, b"");
    let sth = log.sth(TIMESTAMP_MS, 1, &[0; 32], b"");
    let with = list(&[sct.clone(), sth.clone()]);
    assert!(TransItemList::parse(&with).unwrap().has_sct());
    let without = list(&[sth]);
    assert!(!TransItemList::parse(&without).unwrap().has_sct());
    // A submitter checks the SCT a log returned.
    let TransItem::X509SctV2(data) = TransItem::parse(&sct).unwrap() else {
        panic!()
    };
    let signed = entry(false, TIMESTAMP_MS, &ca.issuer_spki, &Ca::tbs(&der), b"");
    let trusted = log.trusted();
    assert_eq!(trusted.verify_sct(&data, &signed, ALGS), Ok(()));
    assert_eq!(
        trusted.verify_sct(&data, &signed[1..], ALGS),
        Err(TransparencyError::InvalidSignature)
    );
    assert_eq!(
        Log::ecdsa(2).trusted().verify_sct(&data, &signed, ALGS),
        Err(TransparencyError::LogIdMismatch)
    );
    let misordered = SignedCertificateTimestampDataV2 {
        sct_extensions: ArtifactExtensions::from_encoded(b"\x00\x01\x00\x00\x00\x01\x00\x00")
            .unwrap(),
        ..data
    };
    assert_eq!(
        trusted.verify_sct(&misordered, &signed, ALGS),
        Err(TransparencyError::InvalidExtensions)
    );
    assert_eq!(TRANSPARENCY_INFO_EXTENSION_TYPE, 52);
    assert_eq!(
        TRANSPARENCY_INFO_OID,
        browntls_pki::ocsp::oid::TRANSPARENCY_INFO
    );
    let cert = ca.with_embedded(&[ca.precert_sct(&log, TIMESTAMP_MS)]);
    assert!(
        Cert::try_from(&cert)
            .unwrap()
            .extension(TRANSPARENCY_INFO_OID)
            .is_some()
    );
}
