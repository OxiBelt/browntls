//! Public test vectors from the rustls/webpki corpus (see `data/README.md`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::{
    BorrowedCertRevocationList, CertRevocationList, CertificateDer, EndEntityCert, Error, KeyUsage,
    OwnedCertRevocationList, RawPublicKeyEntity, RevocationCheckDepth, RevocationOptionsBuilder,
    ServerName, SubjectPublicKeyInfoDer, anchor_from_trusted_cert,
};
use common::*;

macro_rules! data {
    ($path:expr) => {
        &include_bytes!(concat!("data/webpki/", $path))[..]
    };
}

type Bytes = &'static [u8];
/// `(end entity, intermediates, root, CRL)`.
type ChainCase = (Bytes, [Bytes; 2], Bytes, Bytes);
/// `(end entity, SPKI, algorithm, good signature, bad signature)`.
type SignatureCase = (
    Bytes,
    Bytes,
    &'static dyn browntls_pki::SignatureVerificationAlgorithm,
    Bytes,
    Bytes,
);

fn cert(bytes: &'static [u8]) -> CertificateDer<'static> {
    CertificateDer::from(bytes)
}

fn check_chain(
    ee: &'static [u8],
    intermediates: &[&'static [u8]],
    root: &'static [u8],
    time: u64,
    usage: KeyUsage,
) -> Result<(), Error> {
    let roots = [cert(root)];
    let intermediates: Vec<CertificateDer<'static>> =
        intermediates.iter().map(|i| cert(i)).collect();
    verify(
        &cert(ee),
        &intermediates,
        &anchors(&roots),
        ALGS,
        secs(time),
        usage,
        None,
        None,
    )
}

fn names(ee: &'static [u8], valid: &[&str], invalid: &[&str]) {
    let der = cert(ee);
    let ee = EndEntityCert::try_from(&der).unwrap();
    for name in valid {
        let name = ServerName::try_from(*name).unwrap();
        assert_eq!(ee.verify_is_valid_for_subject_name(&name), Ok(()), "{name}");
    }
    for name in invalid {
        let name = ServerName::try_from(*name).unwrap();
        assert_eq!(
            ee.verify_is_valid_for_subject_name(&name),
            Err(Error::CertNotValidForName),
            "{name}"
        );
    }
}

#[test]
fn netflix_rsa_chain_with_v1_root() {
    let ee = data!("netflix/ee.der");
    let inter = data!("netflix/inter.der");
    let ca = data!("netflix/ca.der");
    assert_eq!(
        check_chain(ee, &[inter], ca, 1_492_441_716, KeyUsage::server_auth()),
        Ok(())
    );
    // The v1 root parses as an anchor but not as an end entity.
    assert!(anchor_from_trusted_cert(&cert(ca)).is_ok());
    assert_eq!(
        EndEntityCert::try_from(&cert(ca)).err(),
        Some(Error::UnsupportedCertVersion)
    );
    names(
        ee,
        &["www.netflix.com", "netflix.com", "WWW.NETFLIX.CA"],
        &["netflix.net", "foo.netflix.com"],
    );
    // Validity boundaries.
    let not_before = 1_478_563_200;
    let not_after = 1_541_203_199;
    assert_eq!(
        check_chain(ee, &[inter], ca, not_before - 1, KeyUsage::server_auth()),
        Err(Error::CertNotValidYet {
            time: secs(not_before - 1),
            not_before: secs(not_before),
        })
    );
    assert_eq!(
        check_chain(ee, &[inter], ca, not_after + 1, KeyUsage::server_auth()),
        Err(Error::CertExpired {
            time: secs(not_after + 1),
            not_after: secs(not_after),
        })
    );
}

#[test]
fn sanofi_rsa_signature_with_absent_parameters() {
    let ee = data!("sanofi/ee.der");
    let inter = data!("sanofi/inter.der");
    let ca = data!("sanofi/ca.der");
    assert_eq!(
        check_chain(ee, &[inter], ca, 1_746_549_566, KeyUsage::server_auth()),
        Ok(())
    );
    // Without the absent-parameters variant the signature algorithm is
    // unknown to the provider.
    let roots = [cert(ca)];
    let result = verify(
        &cert(ee),
        &[cert(inter)],
        &anchors(&roots),
        &[&RSA_PKCS1_SHA256, &RSA_PKCS1_SHA384, &RSA_PKCS1_SHA512],
        secs(1_746_549_566),
        KeyUsage::server_auth(),
        None,
        None,
    );
    assert_eq!(result, Err(Error::UnsupportedSignatureAlgorithm));
}

#[test]
fn cloudflare_dns_ip_addresses() {
    let ee = data!("cloudflare_dns/ee.der");
    let inter = data!("cloudflare_dns/inter.der");
    let ca = data!("cloudflare_dns/ca.der");
    assert_eq!(
        check_chain(ee, &[inter], ca, 1_663_495_771, KeyUsage::server_auth()),
        Ok(())
    );
    names(
        ee,
        &[
            "cloudflare-dns.com",
            "wildcard.cloudflare-dns.com",
            "one.one.one.one",
            "1.1.1.1",
            "1.0.0.1",
            "162.159.36.1",
            "162.159.46.1",
            "2606:4700:4700::1111",
            "2606:4700:4700:0000:0000:0000:0000:1001",
            "2606:4700:4700::64",
            "2606:4700:4700::6400",
        ],
        &["1.1.1.2", "2606:4700:4700::1112", "cloudflare.com"],
    );
}

#[test]
fn wpt_and_ed25519_chains() {
    assert_eq!(
        check_chain(
            data!("wpt/ee.der"),
            &[],
            data!("wpt/ca.der"),
            1_619_256_684,
            KeyUsage::server_auth()
        ),
        Ok(())
    );
    assert_eq!(
        check_chain(
            data!("ed25519/ee.der"),
            &[],
            data!("ed25519/ca.der"),
            1_547_363_522,
            KeyUsage::server_auth()
        ),
        Ok(())
    );
    // The Ed25519 raw public key is a complete SubjectPublicKeyInfo.
    let spki = SubjectPublicKeyInfoDer::from(data!("ed25519/ee-pubkey.der"));
    assert!(RawPublicKeyEntity::try_from(&spki).is_ok());
    let ee = SubjectPublicKeyInfoDer::from(data!("ed25519/ee.der"));
    assert!(RawPublicKeyEntity::try_from(&ee).is_err());
}

#[test]
fn critical_extensions() {
    let root = data!("critical_extensions/root-cert.der");
    let ca = data!("critical_extensions/ca-cert.der");
    assert_eq!(
        check_chain(
            data!("critical_extensions/ee-cert-noncrit-unknown-ext.der"),
            &[ca],
            root,
            1_670_779_098,
            KeyUsage::server_auth()
        ),
        Ok(())
    );
    assert_eq!(
        EndEntityCert::try_from(&cert(data!(
            "critical_extensions/ee-cert-crit-unknown-ext.der"
        )))
        .err(),
        Some(Error::UnsupportedCriticalExtension)
    );
}

#[test]
fn serial_numbers_and_unique_ids() {
    assert!(anchor_from_trusted_cert(&cert(data!("misc/serial_zero.der"))).is_ok());
    assert!(anchor_from_trusted_cert(&cert(data!("misc/serial_neg.der"))).is_ok());
    assert_eq!(
        check_chain(
            data!("misc/serial_neg_ee.der"),
            &[],
            data!("misc/serial_neg_ca.der"),
            1_667_401_500,
            KeyUsage::server_auth()
        ),
        Ok(())
    );
    let large = cert(data!("misc/serial_large_positive.der"));
    let ee = EndEntityCert::try_from(&large).unwrap();
    assert_eq!(
        ee.serial().len(),
        21,
        "20-octet value with a sign-protecting zero"
    );
    assert!(EndEntityCert::try_from(&cert(data!("misc/issuer_and_subject_unique_id.der"))).is_ok());
}

#[test]
fn certificate_versions_and_extension_lists() {
    assert_eq!(
        EndEntityCert::try_from(&cert(data!("cert_v1.der"))).err(),
        Some(Error::UnsupportedCertVersion)
    );
    assert!(anchor_from_trusted_cert(&cert(data!("cert_v1.der"))).is_ok());
    assert!(EndEntityCert::try_from(&cert(data!("cert_without_extensions.der"))).is_ok());
    assert!(EndEntityCert::try_from(&cert(data!("cert_with_empty_extensions.der"))).is_ok());
}

#[test]
fn subject_alternative_name_vectors() {
    names(
        data!("misc/dns_names_and_wildcards.der"),
        &["www.netflix.com", "anything.netflix.com", "netflix.com"],
        &["netflix.net", "a.b.netflix.com"],
    );
    // One entry is the invalid name "www.netflix:com"; the others still work.
    names(
        data!("misc/invalid_subject_alternative_name.der"),
        &["account.netflix.com", "release-stage.netflix.com"],
        &["www.netflix.com"],
    );
    names(
        data!("misc/no_subject_alternative_name.der"),
        &[],
        &["example.com"],
    );
    names(
        data!("misc/uri_san_ee.der"),
        &["example.com"],
        &["www.example.com"],
    );
    assert!(EndEntityCert::try_from(&cert(data!("misc/empty_sequence_common_name.der"))).is_ok());
}

#[test]
fn custom_extended_key_usages() {
    let mdoc = KeyUsage::required(&[40, 129, 140, 93, 5, 1, 2]);
    let ee = data!("misc/mdoc_eku.ee.der");
    let ca = data!("misc/mdoc_eku.ca.der");
    assert_eq!(check_chain(ee, &[], ca, 1_609_459_200, mdoc), Ok(()));
    assert_eq!(
        check_chain(ee, &[], ca, 1_609_459_200, KeyUsage::server_auth()),
        Err(Error::RequiredEkuNotFound)
    );
    let time = 0x1fed_f00d;
    assert_eq!(
        check_chain(
            data!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der"),
            &[],
            data!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der"),
            time,
            KeyUsage::client_auth()
        ),
        Ok(())
    );
    let ee = data!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = data!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    assert_eq!(
        check_chain(ee, &[], ca, time, KeyUsage::client_auth()),
        Ok(())
    );
    assert_eq!(
        check_chain(ee, &[], ca, time, KeyUsage::server_auth()),
        Ok(())
    );
}

const REVOKED_SERIAL: &[u8] = &[0x03, 0xae, 0x51, 0xdb, 0x51, 0x15, 0x5a, 0x3c];

fn parse_crl(bytes: &'static [u8]) -> Result<CertRevocationList<'static>, Error> {
    BorrowedCertRevocationList::from_der(bytes).map(CertRevocationList::from)
}

#[test]
fn crl_parsing_vectors() {
    let crl = parse_crl(data!("crls/crl.valid.der")).unwrap();
    assert!(crl.find_serial(REVOKED_SERIAL).unwrap().is_some());
    assert!(crl.find_serial(&[1, 2, 3]).unwrap().is_none());
    let owned = OwnedCertRevocationList::from_der(data!("crls/crl.valid.der")).unwrap();
    assert!(
        CertRevocationList::from(owned)
            .find_serial(REVOKED_SERIAL)
            .unwrap()
            .is_some()
    );

    let empty = BorrowedCertRevocationList::from_der(data!("crls/crl.empty.der")).unwrap();
    assert_eq!(empty.into_iter().count(), 0);
    assert!(empty.to_owned().is_ok());

    for (file, expected) in [
        (
            "crls/crl.mismatched.sigalg.der",
            Error::SignatureAlgorithmMismatch,
        ),
        ("crls/crl.invalid.this.update.time.der", Error::BadDerTime),
        ("crls/crl.missing.next.update.der", Error::BadDerTime),
        ("crls/crl.wrong.version.der", Error::UnsupportedCrlVersion),
        ("crls/crl.missing.exts.der", Error::MalformedExtensions),
        ("crls/crl.delta.der", Error::UnsupportedDeltaCrl),
        (
            "crls/crl.unknown.crit.ext.der",
            Error::UnsupportedCriticalExtension,
        ),
        ("crls/crl.negative.crl.number.der", Error::InvalidCrlNumber),
        ("crls/crl.too.long.crl.number.der", Error::InvalidCrlNumber),
        (
            "crls/crl.idp.indirect_crl.der",
            Error::UnsupportedIndirectCrl,
        ),
        (
            "crls/crl.idp.only_attribute_certs.der",
            Error::MalformedExtensions,
        ),
        (
            "crls/crl.idp.only_some_reasons.der",
            Error::UnsupportedRevocationReasonsPartitioning,
        ),
        ("crls/crl.idp.invalid.bool.der", Error::BadDer),
        ("crls/crl.idp.unknown.tag.der", Error::BadDer),
        ("crls/crl.idp.invalid.name.der", Error::MalformedExtensions),
        (
            "crls/crl.idp.name_relative_to_issuer.der",
            Error::UnsupportedCrlIssuingDistributionPoint,
        ),
        (
            "crls/crl.idp.no_distribution_point_name.der",
            Error::UnsupportedCrlIssuingDistributionPoint,
        ),
    ] {
        let bytes: &'static [u8] = match file {
            "crls/crl.mismatched.sigalg.der" => data!("crls/crl.mismatched.sigalg.der"),
            "crls/crl.invalid.this.update.time.der" => {
                data!("crls/crl.invalid.this.update.time.der")
            }
            "crls/crl.missing.next.update.der" => data!("crls/crl.missing.next.update.der"),
            "crls/crl.wrong.version.der" => data!("crls/crl.wrong.version.der"),
            "crls/crl.missing.exts.der" => data!("crls/crl.missing.exts.der"),
            "crls/crl.delta.der" => data!("crls/crl.delta.der"),
            "crls/crl.unknown.crit.ext.der" => data!("crls/crl.unknown.crit.ext.der"),
            "crls/crl.negative.crl.number.der" => data!("crls/crl.negative.crl.number.der"),
            "crls/crl.too.long.crl.number.der" => data!("crls/crl.too.long.crl.number.der"),
            "crls/crl.idp.indirect_crl.der" => data!("crls/crl.idp.indirect_crl.der"),
            "crls/crl.idp.only_attribute_certs.der" => {
                data!("crls/crl.idp.only_attribute_certs.der")
            }
            "crls/crl.idp.only_some_reasons.der" => data!("crls/crl.idp.only_some_reasons.der"),
            "crls/crl.idp.invalid.bool.der" => data!("crls/crl.idp.invalid.bool.der"),
            "crls/crl.idp.unknown.tag.der" => data!("crls/crl.idp.unknown.tag.der"),
            "crls/crl.idp.invalid.name.der" => data!("crls/crl.idp.invalid.name.der"),
            "crls/crl.idp.name_relative_to_issuer.der" => {
                data!("crls/crl.idp.name_relative_to_issuer.der")
            }
            _ => data!("crls/crl.idp.no_distribution_point_name.der"),
        };
        assert_eq!(parse_crl(bytes).err(), Some(expected), "{file}");
    }

    for file in [
        data!("crls/crl.idp.valid.der"),
        data!("crls/crl.idp.only_user_certs.der"),
        data!("crls/crl.idp.only_ca_certs.der"),
        data!("crls/crl.idp.explicit.false.bool.der"),
    ] {
        let crl = parse_crl(file).unwrap();
        assert!(crl.issuing_distribution_point().is_some());
    }
}

#[test]
fn crl_entry_vectors() {
    let negative = parse_crl(data!("crls/crl.negative.serial.der")).unwrap();
    assert!(negative.find_serial(REVOKED_SERIAL).unwrap().is_none());
    assert!(
        negative
            .find_serial(&[0xfd, 0x78, 0xa8, 0x4e])
            .unwrap()
            .is_some()
    );
    let topbit = parse_crl(data!("crls/crl.topbit.serial.der")).unwrap();
    assert!(
        topbit
            .find_serial(&[0x00, 0x80, 0xfe, 0xed, 0xf0, 0x0d])
            .unwrap()
            .is_some()
    );
    let no_exts = parse_crl(data!("crls/crl.no.entry.exts.der")).unwrap();
    assert!(no_exts.find_serial(REVOKED_SERIAL).unwrap().is_some());
    let empty_exts =
        BorrowedCertRevocationList::from_der(data!("crls/crl.entry.empty.ext.seq.der")).unwrap();
    assert!(empty_exts.to_owned().is_ok());
    let dated = parse_crl(data!("crls/crl.entry.invalidity.date.der")).unwrap();
    assert!(
        dated
            .find_serial(REVOKED_SERIAL)
            .unwrap()
            .unwrap()
            .invalidity_date
            .is_some()
    );

    // Entry-level problems surface when the entries are read.
    for (bytes, expected) in [
        (
            data!("crls/crl.entry.unknown.crit.ext.der"),
            Error::UnsupportedCriticalExtension,
        ),
        (
            data!("crls/crl.entry.invalid.reason.der"),
            Error::UnsupportedRevocationReason,
        ),
        (
            data!("crls/crl.entry.issuer.ext.der"),
            Error::UnsupportedIndirectCrl,
        ),
    ] {
        let borrowed = BorrowedCertRevocationList::from_der(bytes).unwrap();
        assert_eq!(borrowed.to_owned().err(), Some(expected.clone()));
        let crl = CertRevocationList::from(borrowed);
        assert_eq!(crl.find_serial(REVOKED_SERIAL).err(), Some(expected));
    }
}

#[test]
fn distribution_point_vectors_parse() {
    for bytes in [
        data!("crl_distrib_point/with_reasons.der"),
        data!("crl_distrib_point/with_crl_issuer.der"),
        data!("crl_distrib_point/unknown_tag.der"),
        data!("crl_distrib_point/only_reasons.der"),
        data!("crl_distrib_point/dp_name_relative_to_issuer.der"),
        data!("crl_distrib_point/unknown_dp_name_tag.der"),
        data!("crl_distrib_point/multiple_distribution_points.der"),
    ] {
        assert!(EndEntityCert::try_from(&cert(bytes)).is_ok());
    }
}

#[test]
fn distribution_point_chains_against_scoped_crls() {
    // Each chain's end entity has a distribution point this crate cannot
    // match against the CRL's issuing distribution point, so the CRL is not
    // authoritative and the status is unknown. Without CRLs they verify.
    let time = 0x1fed_f00d;
    let cases: [ChainCase; 4] = [
        (
            data!("client_auth_revocation/indirect_dp_chain.ee.der"),
            [
                data!("client_auth_revocation/indirect_dp_chain.int.a.ca.der"),
                data!("client_auth_revocation/indirect_dp_chain.int.b.ca.der"),
            ],
            data!("client_auth_revocation/indirect_dp_chain.root.ca.der"),
            data!("client_auth_revocation/ee_indirect_dp_unknown_status.crl.der"),
        ),
        (
            data!("client_auth_revocation/reasons_dp_chain.ee.der"),
            [
                data!("client_auth_revocation/reasons_dp_chain.int.a.ca.der"),
                data!("client_auth_revocation/reasons_dp_chain.int.b.ca.der"),
            ],
            data!("client_auth_revocation/reasons_dp_chain.root.ca.der"),
            data!("client_auth_revocation/ee_reasons_dp_unknown_status.crl.der"),
        ),
        (
            data!("client_auth_revocation/nofullname_dp_chain.ee.der"),
            [
                data!("client_auth_revocation/nofullname_dp_chain.int.a.ca.der"),
                data!("client_auth_revocation/nofullname_dp_chain.int.b.ca.der"),
            ],
            data!("client_auth_revocation/nofullname_dp_chain.root.ca.der"),
            data!("client_auth_revocation/ee_nofullname_dp_unknown_status.crl.der"),
        ),
        (
            data!("client_auth_revocation/invalid_dp_chain.ee.der"),
            [
                data!("client_auth_revocation/invalid_dp_chain.int.a.ca.der"),
                data!("client_auth_revocation/invalid_dp_chain.int.b.ca.der"),
            ],
            data!("client_auth_revocation/invalid_dp_chain.root.ca.der"),
            data!("client_auth_revocation/ee_dp_invalid.crl.der"),
        ),
    ];
    for (ee, intermediates, root, crl) in cases {
        assert_eq!(
            check_chain(ee, &intermediates, root, time, KeyUsage::client_auth()),
            Ok(())
        );
        let crl = parse_crl(crl).unwrap();
        let crls = [&crl];
        let revocation = RevocationOptionsBuilder::new(&crls)
            .unwrap()
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        let roots = [cert(root)];
        let intermediates: Vec<CertificateDer<'static>> =
            intermediates.iter().map(|i| cert(i)).collect();
        assert_eq!(
            verify(
                &cert(ee),
                &intermediates,
                &anchors(&roots),
                ALGS,
                secs(time),
                KeyUsage::client_auth(),
                Some(revocation),
                None,
            ),
            Err(Error::UnknownRevocationStatus)
        );
    }
}

#[test]
fn signature_vectors() {
    let message = data!("signatures/message.bin");
    let cases: [SignatureCase; 2] = [
        (
            data!("signatures/ecdsa_p256.ee.der"),
            data!("signatures/ecdsa_p256.spki.der"),
            &ECDSA_P256_SHA384,
            data!("signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature.sig.bin"),
            data!("signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature.sig.bin"),
        ),
        (
            data!("signatures/ecdsa_p384.ee.der"),
            data!("signatures/ecdsa_p384.spki.der"),
            &ECDSA_P384_SHA256,
            data!("signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature.sig.bin"),
            data!("signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature.sig.bin"),
        ),
    ];
    for (ee, spki, alg, good, bad) in cases {
        let ee_der = cert(ee);
        let ee = EndEntityCert::try_from(&ee_der).unwrap();
        assert_eq!(ee.verify_signature(alg, message, good), Ok(()));
        assert_eq!(
            ee.verify_signature(alg, message, bad),
            Err(Error::InvalidSignatureForPublicKey)
        );
        let spki = SubjectPublicKeyInfoDer::from(spki);
        let rpk = RawPublicKeyEntity::try_from(&spki).unwrap();
        assert_eq!(rpk.verify_signature(alg, message, good), Ok(()));
        assert_eq!(
            rpk.verify_signature(alg, message, bad),
            Err(Error::InvalidSignatureForPublicKey)
        );
        assert_eq!(
            ee.subject_public_key_info().as_ref(),
            spki.as_ref(),
            "certificate SPKI equals the standalone SPKI vector"
        );
    }
    // An RSA key is rejected by every ECDSA and Ed25519 algorithm and
    // accepted only with a matching PKCS#1 algorithm identifier.
    let rsa = cert(data!("signatures/rsa_2048.ee.der"));
    let rsa = EndEntityCert::try_from(&rsa).unwrap();
    for alg in [&ECDSA_P256_SHA256, &ECDSA_P384_SHA384, &ED25519] {
        assert_eq!(
            rsa.verify_signature(alg, message, &[]),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
    }
    assert_eq!(
        rsa.verify_signature(&RSA_PKCS1_SHA256, message, &[]),
        Err(Error::InvalidSignatureForPublicKey)
    );
}
