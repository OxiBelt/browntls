//! RFC 6962 SCT verification with certificates and logs generated at run
//! time: SCTs embedded in the certificate, from the TLS extension and from
//! an OCSP response, signed by ECDSA and RSA logs, and the ways each can
//! fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::sct::{
    CtLog, CtPolicy, EMBEDDED_SCT_LIST_OID, OCSP_SCT_LIST_OID, SctEntryType, SctError, SctOptions,
    SctReport, SctSource, SctVerifier,
};
use browntls_pki::{Cert, CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use common::*;
use rcgen::{
    CertificateParams, CertifiedIssuer, CustomExtension, KeyPair, PublicKeyData as _, SerialNumber,
    SigningKey as _,
};
use sha2::Digest as _;

/// Arcs of the embedded SCT list extension, 1.3.6.1.4.1.11129.2.4.2.
const SCT_LIST_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

/// 2024-05-01T00:00:00Z in milliseconds: before `NOW`.
const TIMESTAMP_MS: u64 = 1_714_521_600_000;

fn digest(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// A DER `OCTET STRING` (contents shorter than 64 KiB).
fn octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// A CT log with its signing key.
struct Log {
    key: KeyPair,
    spki: Vec<u8>,
    /// `SignatureAlgorithm` of the `digitally-signed` struct.
    signature_algorithm: u8,
}

impl Log {
    fn ecdsa() -> Self {
        Self::new(&rcgen::PKCS_ECDSA_P256_SHA256, 3)
    }

    fn rsa() -> Self {
        Self::new(&rcgen::PKCS_RSA_SHA256, 1)
    }

    fn new(alg: &'static rcgen::SignatureAlgorithm, signature_algorithm: u8) -> Self {
        let key = key_for(alg);
        let spki = key.subject_public_key_info();
        Self {
            key,
            spki,
            signature_algorithm,
        }
    }

    fn id(&self) -> [u8; 32] {
        digest(&self.spki)
    }

    fn trusted(&self) -> CtLog<'_> {
        CtLog::new(&self.spki, digest).unwrap()
    }

    /// A serialized version 1 SCT over `entry`.
    fn sct(&self, timestamp_ms: u64, entry: &Entry<'_>, extensions: &[u8]) -> Vec<u8> {
        let signature = self
            .key
            .sign(&signed_input(timestamp_ms, entry, extensions))
            .unwrap();
        self.serialize(
            timestamp_ms,
            extensions,
            [4, self.signature_algorithm],
            &signature,
        )
    }

    fn serialize(
        &self,
        timestamp_ms: u64,
        extensions: &[u8],
        algorithms: [u8; 2],
        signature: &[u8],
    ) -> Vec<u8> {
        let mut sct = vec![0];
        sct.extend(self.id());
        sct.extend(timestamp_ms.to_be_bytes());
        sct.extend((extensions.len() as u16).to_be_bytes());
        sct.extend(extensions);
        sct.extend(algorithms);
        sct.extend((signature.len() as u16).to_be_bytes());
        sct.extend(signature);
        sct
    }
}

/// The entry a log signs (RFC 6962 §3.2).
enum Entry<'a> {
    X509(&'a [u8]),
    Precert {
        issuer_spki: &'a [u8],
        tbs: &'a [u8],
    },
}

/// The `digitally-signed` input of an SCT, built independently of the
/// implementation.
fn signed_input(timestamp_ms: u64, entry: &Entry<'_>, extensions: &[u8]) -> Vec<u8> {
    let mut input = vec![0, 0];
    input.extend(timestamp_ms.to_be_bytes());
    let body = match entry {
        Entry::X509(cert) => {
            input.extend([0, 0]);
            cert
        }
        Entry::Precert { issuer_spki, tbs } => {
            input.extend([0, 1]);
            input.extend(digest(issuer_spki));
            tbs
        }
    };
    input.extend(&(body.len() as u32).to_be_bytes()[1..]);
    input.extend(*body);
    input.extend((extensions.len() as u16).to_be_bytes());
    input.extend(extensions);
    input
}

/// A `SignedCertificateTimestampList`.
fn sct_list(scts: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for sct in scts {
        entries.extend((sct.len() as u16).to_be_bytes());
        entries.extend(sct);
    }
    let mut list = (entries.len() as u16).to_be_bytes().to_vec();
    list.extend(entries);
    list
}

/// An issuer and an end-entity key, to issue the same certificate with and
/// without embedded SCTs.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    issuer_spki: Vec<u8>,
    ee_key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let issuer = CertifiedIssuer::self_signed(ca_params("ct issuer"), key_for(alg)).unwrap();
        let issuer_spki = issuer.key().subject_public_key_info();
        let mut params = ee_params(&["ct.example.com"]);
        params.serial_number = Some(SerialNumber::from_slice(&[0x5c, 0x01, 0x02]));
        Self {
            issuer,
            issuer_spki,
            ee_key: key_for(alg),
            params,
        }
    }

    fn issue(&self, params: &CertificateParams) -> CertificateDer<'static> {
        let cert = params.signed_by(&self.ee_key, &self.issuer).unwrap();
        cert.der().to_vec().into()
    }

    /// The certificate without SCTs: what a precertificate commits to.
    fn plain(&self) -> CertificateDer<'static> {
        self.issue(&self.params)
    }

    /// The `TBSCertificate` a log signs for the precertificate.
    fn precert_tbs(&self) -> Vec<u8> {
        let plain = self.plain();
        Cert::try_from(&plain)
            .unwrap()
            .signed_data()
            .message()
            .to_vec()
    }

    /// The certificate with `extn_value` as its SCT list extension.
    fn with_extension(&self, extn_value: Vec<u8>) -> CertificateDer<'static> {
        let mut params = self.params.clone();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(SCT_LIST_ARCS, extn_value));
        self.issue(&params)
    }

    /// The certificate with SCTs of `logs` over its precertificate embedded.
    fn with_embedded(&self, logs: &[&Log]) -> CertificateDer<'static> {
        let scts: Vec<_> = logs.iter().map(|log| self.precert_sct(log)).collect();
        self.with_extension(octet_string(&sct_list(&scts)))
    }

    fn precert_sct(&self, log: &Log) -> Vec<u8> {
        let entry = Entry::Precert {
            issuer_spki: &self.issuer_spki,
            tbs: &self.precert_tbs(),
        };
        log.sct(TIMESTAMP_MS, &entry, b"")
    }
}

fn policy<'a>(logs: &'a [CtLog<'a>], options: SctOptions) -> CtPolicy<'a> {
    CtPolicy {
        logs,
        supported_sig_algs: ALGS,
        sha256: digest,
        options,
    }
}

/// The default options, edited: `SctOptions` is non-exhaustive.
fn options(edit: impl FnOnce(&mut SctOptions)) -> SctOptions {
    let mut options = SctOptions::default();
    edit(&mut options);
    options
}

fn report(edit: impl FnOnce(&mut SctReport)) -> SctReport {
    let mut report = SctReport::default();
    edit(&mut report);
    report
}

/// Verifies one TLS extension list for `cert` with default options.
fn verify_tls(
    logs: &[CtLog<'_>],
    cert: &CertificateDer<'_>,
    list: &[u8],
) -> Result<SctReport, SctError> {
    let policy = policy(logs, SctOptions::default());
    let cert = Cert::try_from(cert).unwrap();
    SctVerifier::new(&policy, &cert, None, NOW)
        .unwrap()
        .verify_tls_extension(list)
}

#[test]
fn oids_are_the_rfc_6962_arcs() {
    let ca = Ca::new();
    let der = ca.with_embedded(&[&Log::ecdsa()]);
    let cert = Cert::try_from(&der).unwrap();
    assert!(cert.extension(EMBEDDED_SCT_LIST_OID).is_some());
    assert_eq!(EMBEDDED_SCT_LIST_OID[..9], OCSP_SCT_LIST_OID[..9]);
    assert_eq!(OCSP_SCT_LIST_OID[9], 5);
}

#[test]
fn embedded_scts_verify_as_precert_entries() {
    let ca = Ca::new();
    let (ecdsa, rsa) = (Log::ecdsa(), Log::rsa());
    let der = ca.with_embedded(&[&ecdsa, &rsa]);
    let cert = Cert::try_from(&der).unwrap();
    let logs = [ecdsa.trusted(), rsa.trusted()];
    let policy = policy(&logs, SctOptions::default());

    // The issuer key as a complete SubjectPublicKeyInfo and as its contents.
    let issuer_der = ca.issuer.der().to_vec().into();
    let anchor = browntls_pki::anchor_from_trusted_cert(&issuer_der).unwrap();
    for issuer_spki in [&ca.issuer_spki[..], &anchor.subject_public_key_info[..]] {
        let mut verifier = SctVerifier::new(&policy, &cert, Some(issuer_spki), NOW).unwrap();
        assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 2)));
        let verified = verifier.verified();
        assert_eq!(verified.len(), 2);
        for (sct, log) in verified.iter().zip([&ecdsa, &rsa]) {
            assert_eq!(sct.log_id(), &log.id());
            assert_eq!(sct.log_id(), log.trusted().id());
            assert_eq!(sct.timestamp_ms(), TIMESTAMP_MS);
            assert_eq!(sct.source(), SctSource::Embedded);
            assert_eq!(sct.entry_type(), SctEntryType::Precert);
        }
        // Verifying the same source again verifies nothing new.
        assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.duplicate = 2)));
        assert_eq!(verifier.into_verified().len(), 2);
    }
}

#[test]
fn embedded_scts_need_the_issuer_key_and_this_certificate() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let der = ca.with_embedded(&[&log]);
    let cert = Cert::try_from(&der).unwrap();
    let logs = [log.trusted()];
    let policy = policy(&logs, SctOptions::default());
    let invalid = Ok(report(|r| r.invalid_signature = 1));

    let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), Err(SctError::IssuerKeyRequired));
    assert_eq!(
        SctVerifier::new(&policy, &cert, Some(&[0x30, 0x00]), NOW).err(),
        Some(SctError::MalformedIssuerKey)
    );

    // Another issuer key: the end entity's own.
    let other_spki = cert.subject_public_key_info();
    let mut verifier = SctVerifier::new(&policy, &cert, Some(&other_spki), NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), invalid);
    assert!(verifier.verified().is_empty());

    // The same list in a certificate for another name.
    let mut params = ca.params.clone();
    params.subject_alt_names = ee_params(&["other.example.com"]).subject_alt_names;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            SCT_LIST_ARCS,
            octet_string(&sct_list(&[ca.precert_sct(&log)])),
        ));
    let renamed = ca.issue(&params);
    let renamed = Cert::try_from(&renamed).unwrap();
    let mut verifier = SctVerifier::new(&policy, &renamed, Some(&ca.issuer_spki), NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), invalid);

    // An SCT over the complete certificate is not an embedded SCT.
    let plain = ca.plain();
    let x509_sct = log.sct(TIMESTAMP_MS, &Entry::X509(&plain), b"");
    let der = ca.with_extension(octet_string(&sct_list(&[x509_sct])));
    let cert = Cert::try_from(&der).unwrap();
    let mut verifier = SctVerifier::new(&policy, &cert, Some(&ca.issuer_spki), NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), invalid);

    // A certificate without the extension has no embedded SCT.
    let cert = Cert::try_from(&plain).unwrap();
    let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), Ok(SctReport::default()));
}

#[test]
fn embedded_extension_value_must_hold_exactly_one_list() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let logs = [log.trusted()];
    let policy = policy(&logs, SctOptions::default());
    let list = sct_list(&[ca.precert_sct(&log)]);
    let mut trailing = octet_string(&list);
    trailing.push(0);
    let mut long_list = list.clone();
    long_list.push(0);
    for extn_value in [
        list.clone(),
        trailing,
        octet_string(&long_list),
        octet_string(&list[..list.len() - 1]),
        octet_string(&[]),
        vec![0x04, 0x81, 0x02, 0x00, 0x00],
    ] {
        let der = ca.with_extension(extn_value);
        let cert = Cert::try_from(&der).unwrap();
        let mut verifier = SctVerifier::new(&policy, &cert, Some(&ca.issuer_spki), NOW).unwrap();
        assert_eq!(verifier.verify_embedded(), Err(SctError::MalformedList));
        assert!(verifier.verified().is_empty());
    }

    let mut params = ca.params.clone();
    for _ in 0..2 {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                SCT_LIST_ARCS,
                octet_string(&list),
            ));
    }
    let der = ca.issue(&params);
    let cert = Cert::try_from(&der).unwrap();
    let mut verifier = SctVerifier::new(&policy, &cert, Some(&ca.issuer_spki), NOW).unwrap();
    assert_eq!(
        verifier.verify_embedded(),
        Err(SctError::DuplicateSctExtension)
    );
}

#[test]
fn tls_and_ocsp_scts_verify_as_x509_entries() {
    let ca = Ca::new();
    let (ecdsa, rsa) = (Log::ecdsa(), Log::rsa());
    let der = ca.plain();
    let cert = Cert::try_from(&der).unwrap();
    let logs = [ecdsa.trusted(), rsa.trusted()];
    let policy = policy(&logs, SctOptions::default());

    // A log's CtExtensions are signed and need not be empty.
    let tls = sct_list(&[ecdsa.sct(
        TIMESTAMP_MS,
        &Entry::X509(&der),
        b"\x00\x00\x05\x00\x00\x00\x00\x07",
    )]);
    let ocsp = sct_list(&[
        rsa.sct(TIMESTAMP_MS + 1, &Entry::X509(&der), b""),
        ecdsa.sct(TIMESTAMP_MS, &Entry::X509(&der), b""),
    ]);

    let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&tls),
        Ok(report(|r| r.verified = 1))
    );
    // The ECDSA log's SCT with the same timestamp is already verified.
    assert_eq!(
        verifier.verify_ocsp_extension(&octet_string(&ocsp)),
        Ok(report(|r| {
            r.verified = 1;
            r.duplicate = 1;
        }))
    );
    let verified = verifier.verified();
    assert_eq!(verified.len(), 2);
    assert_eq!(
        (
            verified[0].log_id(),
            verified[0].timestamp_ms(),
            verified[0].source()
        ),
        (&ecdsa.id(), TIMESTAMP_MS, SctSource::TlsExtension)
    );
    assert_eq!(
        (
            verified[1].log_id(),
            verified[1].timestamp_ms(),
            verified[1].source()
        ),
        (&rsa.id(), TIMESTAMP_MS + 1, SctSource::OcspResponse)
    );
    assert!(
        verified
            .iter()
            .all(|sct| sct.entry_type() == SctEntryType::X509)
    );

    // The OCSP value is the OCTET STRING, not the bare list.
    let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
    assert_eq!(
        verifier.verify_ocsp_extension(&ocsp),
        Err(SctError::MalformedList)
    );
    let mut trailing = octet_string(&ocsp);
    trailing.push(0);
    assert_eq!(
        verifier.verify_ocsp_extension(&trailing),
        Err(SctError::MalformedList)
    );
    assert_eq!(
        verifier.verify_tls_extension(&octet_string(&tls)),
        Err(SctError::MalformedList)
    );
}

#[test]
fn every_signed_field_is_covered() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let der = ca.plain();
    let logs = [log.trusted()];
    let extensions = b"\x00\x01";
    let input = signed_input(TIMESTAMP_MS, &Entry::X509(&der), extensions);
    let signature = log.key.sign(&input).unwrap();
    let invalid = Ok(report(|r| r.invalid_signature = 1));

    let good = log.serialize(TIMESTAMP_MS, extensions, [4, 3], &signature);
    assert_eq!(
        verify_tls(&logs, &der, &sct_list(&[good])),
        Ok(report(|r| r.verified = 1))
    );
    // Another timestamp, other extensions, a damaged signature.
    let sct = log.serialize(TIMESTAMP_MS - 1, extensions, [4, 3], &signature);
    assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), invalid);
    for other in [&b""[..], b"\x00\x02", b"\x00\x01\x00"] {
        let sct = log.serialize(TIMESTAMP_MS, other, [4, 3], &signature);
        assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), invalid);
    }
    let mut damaged = signature.clone();
    *damaged.last_mut().unwrap() ^= 1;
    let sct = log.serialize(TIMESTAMP_MS, extensions, [4, 3], &damaged);
    assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), invalid);
    let sct = log.serialize(TIMESTAMP_MS, extensions, [4, 3], &[]);
    assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), invalid);

    // Another certificate from the same issuer, for the same key.
    let mut params = ca.params.clone();
    params.serial_number = Some(SerialNumber::from_slice(&[0x5c, 0x01, 0x03]));
    let other = ca.issue(&params);
    let good = log.serialize(TIMESTAMP_MS, extensions, [4, 3], &signature);
    assert_eq!(
        verify_tls(&logs, &other, &sct_list(std::slice::from_ref(&good))),
        invalid
    );

    // A log with another key that claims the signing log's ID cannot be
    // configured; the same key under its own ID does not match the SCT.
    let impostor = Log::ecdsa();
    assert_eq!(
        impostor.trusted().with_expected_id(&log.id()).err(),
        Some(SctError::LogIdMismatch)
    );
    assert_eq!(
        verify_tls(&[impostor.trusted()], &der, &sct_list(&[good])),
        Ok(report(|r| r.unknown_log = 1))
    );
}

#[test]
fn precert_scts_out_of_band_are_opt_in() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let logs = [log.trusted()];
    let list = sct_list(&[ca.precert_sct(&log)]);
    let allow = options(|o| o.allow_out_of_band_precert_entry = true);
    let strict = policy(&logs, SctOptions::default());
    let lenient = policy(&logs, allow);
    let invalid = Ok(report(|r| r.invalid_signature = 1));

    // For the certificate without SCTs and for the one that embeds them.
    for der in [ca.plain(), ca.with_embedded(&[&Log::ecdsa()])] {
        let cert = Cert::try_from(&der).unwrap();
        let issuer = Some(&ca.issuer_spki[..]);

        let mut verifier = SctVerifier::new(&strict, &cert, issuer, NOW).unwrap();
        assert_eq!(verifier.verify_tls_extension(&list), invalid);
        assert_eq!(
            verifier.verify_ocsp_extension(&octet_string(&list)),
            invalid
        );

        // Without the issuer key there is no precertificate entry to try.
        let mut verifier = SctVerifier::new(&lenient, &cert, None, NOW).unwrap();
        assert_eq!(verifier.verify_tls_extension(&list), invalid);

        let mut verifier = SctVerifier::new(&lenient, &cert, issuer, NOW).unwrap();
        assert_eq!(
            verifier.verify_ocsp_extension(&octet_string(&list)),
            Ok(report(|r| r.verified = 1))
        );
        let verified = verifier.verified()[0];
        assert_eq!(verified.entry_type(), SctEntryType::Precert);
        assert_eq!(verified.source(), SctSource::OcspResponse);
        assert_eq!(verified.timestamp_ms(), TIMESTAMP_MS);

        // An x509_entry SCT is still verified first, with one signature.
        let x509 = sct_list(&[log.sct(TIMESTAMP_MS + 5, &Entry::X509(&der), b"")]);
        let one = policy(
            &logs,
            options(|o| {
                o.allow_out_of_band_precert_entry = true;
                o.max_signature_verifications = 1;
            }),
        );
        let mut verifier = SctVerifier::new(&one, &cert, issuer, NOW).unwrap();
        assert_eq!(
            verifier.verify_tls_extension(&x509),
            Ok(report(|r| r.verified = 1))
        );
        assert_eq!(verifier.verified()[0].entry_type(), SctEntryType::X509);
        // The fallback costs a second verification.
        let mut verifier = SctVerifier::new(&one, &cert, issuer, NOW).unwrap();
        assert_eq!(
            verifier.verify_tls_extension(&list),
            Err(SctError::SignatureBudgetExceeded)
        );
    }
}

#[test]
fn log_trust_and_time() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let der = ca.plain();
    let cert = Cert::try_from(&der).unwrap();
    let list = sct_list(&[log.sct(TIMESTAMP_MS, &Entry::X509(&der), b"")]);
    let verified = Ok(report(|r| r.verified = 1));

    // Unknown logs cost no signature verification.
    let unknown = Log::ecdsa();
    let logs = [unknown.trusted()];
    let none = policy(&logs, options(|o| o.max_signature_verifications = 0));
    let mut verifier = SctVerifier::new(&none, &cert, None, NOW).unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&list),
        Ok(report(|r| r.unknown_log = 1))
    );
    assert_eq!(
        verify_tls(&[], &der, &list),
        Ok(report(|r| r.unknown_log = 1))
    );

    // The log's timestamp window is half open.
    let outside = Ok(report(|r| r.outside_log_validity = 1));
    for (from_ms, until_ms, expected) in [
        (0, u64::MAX, &verified),
        (TIMESTAMP_MS, TIMESTAMP_MS + 1, &verified),
        (TIMESTAMP_MS + 1, u64::MAX, &outside),
        (0, TIMESTAMP_MS, &outside),
        (TIMESTAMP_MS, TIMESTAMP_MS, &outside),
    ] {
        let logs = [log.trusted().with_timestamp_window(from_ms, until_ms)];
        assert_eq!(&verify_tls(&logs, &der, &list), expected);
    }

    // Timestamps after the verification time are refused unless tolerated.
    let logs = [log.trusted()];
    let at = |ms: u64| UnixTime::since_unix_epoch(core::time::Duration::from_millis(ms));
    let future = Ok(report(|r| r.future_timestamp = 1));
    let strict = policy(&logs, SctOptions::default());
    let tolerant = policy(&logs, options(|o| o.future_tolerance_ms = 60_000));
    for (policy, now_ms, expected) in [
        (&strict, TIMESTAMP_MS, &verified),
        (&strict, TIMESTAMP_MS - 1_000, &future),
        (&tolerant, TIMESTAMP_MS - 60_000, &verified),
        (&tolerant, TIMESTAMP_MS - 61_000, &future),
    ] {
        let mut verifier = SctVerifier::new(policy, &cert, None, at(now_ms)).unwrap();
        assert_eq!(&verifier.verify_tls_extension(&list), expected);
    }

    // Log keys must be SubjectPublicKeyInfo, complete or contents.
    assert_eq!(
        CtLog::new(&log.spki[..log.spki.len() - 1], digest).err(),
        Some(SctError::MalformedLogKey)
    );
    assert_eq!(
        CtLog::new(&[], digest).err(),
        Some(SctError::MalformedLogKey)
    );
    let contents = &log.spki[2..];
    let from_contents = CtLog::new(contents, digest).unwrap();
    assert_eq!(from_contents.id(), &log.id());
    assert_eq!(verify_tls(&[from_contents], &der, &list), verified);
    assert!(log.trusted().with_expected_id(&log.id()).is_ok());
}

#[test]
fn signature_algorithms_are_those_of_rfc_6962() {
    let ca = Ca::new();
    let (ecdsa, rsa, ed25519) = (Log::ecdsa(), Log::rsa(), Log::new(&rcgen::PKCS_ED25519, 7));
    let der = ca.plain();
    let cert = Cert::try_from(&der).unwrap();
    let logs = [ecdsa.trusted(), rsa.trusted(), ed25519.trusted()];
    let unsupported = Ok(report(|r| r.unsupported_algorithm = 1));
    let input = signed_input(TIMESTAMP_MS, &Entry::X509(&der), b"");

    // Declared algorithms that are not SHA-256 with ECDSA or RSA, or that
    // do not match the log's key.
    let signature = ecdsa.key.sign(&input).unwrap();
    for algorithms in [[4, 1], [5, 3], [2, 3], [4, 0], [4, 2], [8, 7], [0, 3]] {
        let sct = ecdsa.serialize(TIMESTAMP_MS, b"", algorithms, &signature);
        assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), unsupported);
    }
    let signature = rsa.key.sign(&input).unwrap();
    let sct = rsa.serialize(TIMESTAMP_MS, b"", [4, 3], &signature);
    assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), unsupported);
    // Ed25519 is not an RFC 6962 log algorithm, whatever the SCT declares.
    for algorithms in [[8, 7], [4, 3], [4, 1]] {
        let sct = ed25519.sct(TIMESTAMP_MS, &Entry::X509(&der), b"");
        let mut sct = sct;
        sct[43..45].copy_from_slice(&algorithms);
        assert_eq!(verify_tls(&logs, &der, &sct_list(&[sct])), unsupported);
    }

    // The application's algorithms decide what can be verified.
    let list = sct_list(&[
        rsa.sct(TIMESTAMP_MS, &Entry::X509(&der), b""),
        ecdsa.sct(TIMESTAMP_MS, &Entry::X509(&der), b""),
    ]);
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
        let policy = CtPolicy {
            supported_sig_algs: algs,
            ..policy(&logs, SctOptions::default())
        };
        let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
        assert_eq!(verifier.verify_tls_extension(&list), Ok(expected));
    }
}

#[test]
fn limits_bound_entries_sizes_and_signatures_across_sources() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let der = ca.with_embedded(&[&log]);
    let cert = Cert::try_from(&der).unwrap();
    let logs = [log.trusted()];
    let issuer = Some(&ca.issuer_spki[..]);
    let sct = |offset: u64| log.sct(TIMESTAMP_MS + offset, &Entry::X509(&der), b"");

    // Entries: one embedded, then two of three allowed from TLS and OCSP.
    let three = policy(&logs, options(|o| o.max_scts = 3));
    let mut verifier = SctVerifier::new(&three, &cert, issuer, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(
        verifier.verify_tls_extension(&sct_list(&[sct(1), sct(2), sct(3)])),
        Err(SctError::TooManyScts)
    );
    assert_eq!(verifier.verified().len(), 1);
    // Skipped SCTs count: another version, an unknown log.
    let unknown = Log::ecdsa().sct(TIMESTAMP_MS, &Entry::X509(&der), b"");
    assert_eq!(
        verifier.verify_tls_extension(&sct_list(&[vec![1, 2, 3], unknown])),
        Ok(report(|r| {
            r.unsupported_version = 1;
            r.unknown_log = 1;
        }))
    );
    assert_eq!(
        verifier.verify_ocsp_extension(&octet_string(&sct_list(&[sct(1)]))),
        Err(SctError::TooManyScts)
    );

    // Signatures: the budget is shared, duplicates and skipped SCTs are
    // free, and what was verified before the limit is kept.
    let two = policy(&logs, options(|o| o.max_signature_verifications = 2));
    let mut verifier = SctVerifier::new(&two, &cert, issuer, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.verified = 1)));
    assert_eq!(verifier.verify_embedded(), Ok(report(|r| r.duplicate = 1)));
    let mut bad = sct(4);
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        verifier.verify_tls_extension(&sct_list(&[vec![9], bad])),
        Ok(report(|r| {
            r.unsupported_version = 1;
            r.invalid_signature = 1;
        }))
    );
    assert_eq!(
        verifier.verify_ocsp_extension(&octet_string(&sct_list(&[sct(5)]))),
        Err(SctError::SignatureBudgetExceeded)
    );
    assert_eq!(verifier.verified().len(), 1);

    // Sizes.
    let list = sct_list(&[sct(1)]);
    let exact = list.len();
    for (edited, expected) in [
        (options(|_| ()), Ok(report(|r| r.verified = 1))),
        (
            options(|o| o.max_signature_len = 16),
            Err(SctError::SctTooLarge),
        ),
        (
            options(|o| o.max_list_len = 16),
            Err(SctError::ListTooLarge),
        ),
    ] {
        let policy = policy(&logs, edited);
        let mut verifier = SctVerifier::new(&policy, &cert, issuer, NOW).unwrap();
        assert_eq!(verifier.verify_tls_extension(&list), expected);
    }
    let policy_fits = policy(&logs, options(|o| o.max_list_len = exact));
    let mut verifier = SctVerifier::new(&policy_fits, &cert, issuer, NOW).unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&list),
        Ok(report(|r| r.verified = 1))
    );
    let policy_small = policy(&logs, options(|o| o.max_list_len = exact - 1));
    let mut verifier = SctVerifier::new(&policy_small, &cert, issuer, NOW).unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&list),
        Err(SctError::ListTooLarge)
    );
    // The embedded list is subject to the same limits.
    let policy_tiny = policy(&logs, options(|o| o.max_list_len = 16));
    let mut verifier = SctVerifier::new(&policy_tiny, &cert, issuer, NOW).unwrap();
    assert_eq!(verifier.verify_embedded(), Err(SctError::ListTooLarge));
    let with_extensions = log.sct(TIMESTAMP_MS, &Entry::X509(&der), b"x");
    let policy_no_ext = policy(&logs, options(|o| o.max_sct_extensions_len = 0));
    let mut verifier = SctVerifier::new(&policy_no_ext, &cert, issuer, NOW).unwrap();
    assert_eq!(
        verifier.verify_tls_extension(&sct_list(&[with_extensions])),
        Err(SctError::SctTooLarge)
    );
}

#[test]
fn malformed_lists_verify_nothing() {
    let ca = Ca::new();
    let log = Log::ecdsa();
    let der = ca.plain();
    let logs = [log.trusted()];
    let sct = log.sct(TIMESTAMP_MS, &Entry::X509(&der), b"");
    let good = sct_list(std::slice::from_ref(&sct));
    assert_eq!(
        verify_tls(&logs, &der, &good),
        Ok(report(|r| r.verified = 1))
    );
    for len in 0..good.len() {
        assert_eq!(
            verify_tls(&logs, &der, &good[..len]),
            Err(SctError::MalformedList),
            "truncated to {len}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        verify_tls(&logs, &der, &trailing),
        Err(SctError::MalformedList)
    );

    // A valid SCT followed by a malformed one: neither is verified.
    let mut long = sct.clone();
    long.push(0);
    let policy = policy(&logs, SctOptions::default());
    let cert = Cert::try_from(&der).unwrap();
    let mut verifier = SctVerifier::new(&policy, &cert, None, NOW).unwrap();
    for second in [long, vec![], vec![0], sct[..sct.len() - 1].to_vec()] {
        assert_eq!(
            verifier.verify_tls_extension(&sct_list(&[sct.clone(), second])),
            Err(SctError::MalformedList)
        );
    }
    assert!(verifier.verified().is_empty());
    assert_eq!(
        verifier.verify_tls_extension(&good),
        Ok(report(|r| r.verified = 1))
    );
}
