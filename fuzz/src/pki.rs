//! `browntls-pki`: PEM, DER and X.509 parsing, path validation, CRLs.

use core::time::Duration;

use browntls_pki::pem::{self, PemObject};
use browntls_pki::{
    AlgorithmIdentifier, BorrowedCertRevocationList, CertRevocationList, CertificateDer,
    CertificateRevocationListDer, CertificateSigningRequestDer, DnsName, EndEntityCert,
    ExpirationPolicy, InvalidSignature, KeyUsage, OwnedCertRevocationList, PrivateKeyDer,
    RawPublicKeyEntity, RevocationCheckDepth, RevocationOptionsBuilder, ServerName,
    SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime, UnknownStatusPolicy, alg_id,
    anchor_from_trusted_cert,
};

use crate::{take_byte, take_field};

/// How the stand-in signature algorithms answer.
#[derive(Debug, Clone, Copy)]
enum Verdict {
    /// Every signature verifies, so path building explores every candidate.
    Accept,
    /// No signature verifies.
    Reject,
    /// The last signature byte decides.
    FromSignature,
}

/// `browntls-pki` has no cryptography of its own; this stands in for a
/// provider's algorithm so that the fuzzer, which cannot forge signatures,
/// still gets past signature checks.
#[derive(Debug)]
struct FakeAlgorithm {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    verdict: Verdict,
}

impl SignatureVerificationAlgorithm for FakeAlgorithm {
    fn verify_signature(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let ok = match self.verdict {
            Verdict::Accept => true,
            Verdict::Reject => false,
            Verdict::FromSignature => signature.last().is_some_and(|b| b & 1 == 0),
        };
        if ok { Ok(()) } else { Err(InvalidSignature) }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

fn algorithms(verdict: Verdict) -> [FakeAlgorithm; 6] {
    let alg = |public_key, signature| FakeAlgorithm {
        public_key,
        signature,
        verdict,
    };
    [
        alg(alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
        alg(alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
        alg(alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA256),
        alg(alg_id::RSA_ENCRYPTION, alg_id::RSA_PSS_SHA256),
        alg(alg_id::RSASSA_PSS, alg_id::RSA_PSS_SHA256),
        alg(alg_id::ED25519, alg_id::ED25519),
    ]
}

/// 2026-11-15 00:00:00 UTC; fixed so that findings reproduce.
const NOW: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_794_700_800));

/// X.509 parsing and path validation (`fuzz_targets/pki_cert.rs`).
///
/// Input: one flag byte, then length-prefixed fields (16-bit big-endian
/// length each): end-entity certificate, two intermediates, a trust anchor
/// certificate, a CRL and a subject name; what remains is a signature.
pub fn pki_cert(mut data: &[u8]) {
    let flags = take_byte(&mut data);
    let end_entity = CertificateDer::from(take_field(&mut data));
    let intermediates = [
        CertificateDer::from(take_field(&mut data)),
        CertificateDer::from(take_field(&mut data)),
    ];
    let anchor_cert = CertificateDer::from(take_field(&mut data));
    let crl_der = take_field(&mut data);
    let name = take_field(&mut data);
    let signature = data;

    let verdict = match flags & 3 {
        0 | 1 => Verdict::Accept,
        2 => Verdict::FromSignature,
        _ => Verdict::Reject,
    };
    let algorithms = algorithms(verdict);
    let algorithms: Vec<&dyn SignatureVerificationAlgorithm> = algorithms
        .iter()
        .map(|a| a as &dyn SignatureVerificationAlgorithm)
        .collect();

    // Names are parsed whatever the certificate turns out to be.
    let server_name = ServerName::try_from(name).ok();
    if let Ok(text) = core::str::from_utf8(name)
        && let Ok(dns) = DnsName::try_from(text)
    {
        let _ = dns.to_lowercase_owned();
    }
    if let Some(server_name) = &server_name {
        let _ = server_name.to_str();
        let _ = server_name.to_owned();
    }

    // A raw public key (RFC 7250) from the same bytes.
    let spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
    if let Ok(raw) = RawPublicKeyEntity::try_from(&spki) {
        for alg in &algorithms {
            let _ = raw.verify_signature(*alg, b"message", signature);
        }
    }

    // Trust anchors: the fuzzed certificate, and the end entity itself (a
    // self-issued path), when they parse as anchors.
    let mut anchors = Vec::new();
    if let Ok(anchor) = anchor_from_trusted_cert(&anchor_cert) {
        let _ = anchor.to_owned();
        anchors.push(anchor);
    }
    if flags & 4 != 0
        && let Ok(anchor) = anchor_from_trusted_cert(&end_entity)
    {
        anchors.push(anchor);
    }

    let Ok(cert) = EndEntityCert::try_from(&end_entity) else {
        return;
    };
    let _ = cert.subject_public_key_info();
    let _ = (cert.der(), cert.serial(), cert.issuer(), cert.subject());
    if let Some(server_name) = &server_name {
        let _ = cert.verify_is_valid_for_subject_name(server_name);
    }
    for alg in &algorithms {
        let _ = cert.verify_signature(*alg, b"message", signature);
    }

    let usage = if flags & 8 != 0 {
        KeyUsage::client_auth()
    } else {
        KeyUsage::server_auth()
    };
    let crl = BorrowedCertRevocationList::from_der(crl_der)
        .ok()
        .map(CertRevocationList::Borrowed);
    let crls: Vec<&CertRevocationList<'_>> = crl.iter().collect();
    let revocation = (flags & 16 != 0)
        .then(|| RevocationOptionsBuilder::new(&crls).ok())
        .flatten()
        .map(|builder| {
            builder
                .with_depth(if flags & 32 != 0 {
                    RevocationCheckDepth::Chain
                } else {
                    RevocationCheckDepth::EndEntity
                })
                .with_status_policy(if flags & 64 != 0 {
                    UnknownStatusPolicy::Allow
                } else {
                    UnknownStatusPolicy::Deny
                })
                .with_expiration_policy(if flags & 128 != 0 {
                    ExpirationPolicy::Enforce
                } else {
                    ExpirationPolicy::Ignore
                })
                .build()
        });
    let reject_first_path = |_: &browntls_pki::VerifiedPath<'_>| Err(browntls_pki::Error::BadDer);
    let path_verifier: Option<browntls_pki::PathVerifier<'_>> =
        (flags & 3 == 1).then_some(&reject_first_path);

    if let Ok(path) = cert.verify_for_usage(
        &algorithms,
        &anchors,
        &intermediates,
        NOW,
        usage,
        revocation,
        path_verifier,
    ) {
        // A path can only end at one of the anchors we supplied, and with
        // no signature accepted there is no path at all.
        assert!(!anchors.is_empty());
        assert!(!matches!(verdict, Verdict::Reject));
        let _ = path.end_entity().subject();
        let _ = path.anchor().subject.as_ref();
        assert!(path.intermediate_certificates().count() <= intermediates.len());
    }
}

/// PEM decoding (`fuzz_targets/pki_pem.rs`): section iteration, Base64, and
/// every `PemObject` type.
pub fn pki_pem(data: &[u8]) {
    for (_kind, der) in pem::sections(data).flatten() {
        // PEM is only an armour: the contents go to the DER parsers.
        let der = CertificateDer::from(der);
        let _ = EndEntityCert::try_from(&der);
    }
    let _ = pem::base64_decode(data);
    let _ = CertificateDer::from_pem_slice(data);
    let _ = SubjectPublicKeyInfoDer::from_pem_slice(data);
    let _ = CertificateSigningRequestDer::from_pem_slice(data);
    let _ = PrivateKeyDer::from_pem_slice(data);
    let certs = CertificateDer::pem_slice_iter(data).count();
    let crls = CertificateRevocationListDer::pem_slice_iter(data).count();
    // Every section yields at most one item per type, and a section holds at
    // least its two boundary lines.
    assert!(certs <= data.len() / 20 + 1 && crls <= data.len() / 20 + 1);
}

/// CRL parsing (`fuzz_targets/pki_crl.rs`).
///
/// Input: one flag byte, a length-prefixed serial number and a
/// length-prefixed issuer key; what remains is the CRL.
pub fn pki_crl(mut data: &[u8]) {
    let flags = take_byte(&mut data);
    let serial = take_field(&mut data);
    let issuer_spki = take_field(&mut data);

    let borrowed = BorrowedCertRevocationList::from_der(data);
    let owned = OwnedCertRevocationList::from_der(data);
    let Ok(borrowed) = borrowed else {
        // The owned form parses the same structure and the entries as well.
        assert!(owned.is_err());
        return;
    };

    let mut entries = 0usize;
    let mut entries_ok = true;
    for entry in &borrowed {
        match entry {
            Ok(entry) => {
                let _ = entry.to_owned();
                entries += 1;
            }
            Err(_) => {
                entries_ok = false;
                break;
            }
        }
    }
    let converted = borrowed.to_owned();
    // The owned form exists exactly when every entry is well formed.
    assert_eq!(owned.is_ok(), entries_ok);
    assert_eq!(converted.is_ok(), entries_ok);
    if let Ok(owned) = &owned {
        // Serial numbers are unique keys in the owned form.
        assert!(owned.revoked_certs().count() <= entries);
    }

    let algorithms = algorithms(if flags & 1 != 0 {
        Verdict::Accept
    } else {
        Verdict::FromSignature
    });
    let algorithms: Vec<&dyn SignatureVerificationAlgorithm> = algorithms
        .iter()
        .map(|a| a as &dyn SignatureVerificationAlgorithm)
        .collect();

    let borrowed = CertRevocationList::Borrowed(borrowed);
    let found = borrowed.find_serial(serial);
    let _ = (
        borrowed.issuer(),
        borrowed.issuing_distribution_point(),
        borrowed.this_update(),
        borrowed.next_update(),
    );
    let _ = borrowed.verify_signature(&algorithms, issuer_spki);

    if let Ok(owned) = owned {
        let owned = CertRevocationList::Owned(owned);
        // Both forms agree on whether a serial number is revoked.
        if let (Ok(a), Ok(b)) = (&found, owned.find_serial(serial)) {
            assert_eq!(a.is_some(), b.is_some());
        }
        assert_eq!(owned.issuer(), borrowed.issuer());
        assert_eq!(owned.this_update(), borrowed.this_update());
        assert_eq!(owned.next_update(), borrowed.next_update());
        let _ = owned.verify_signature(&algorithms, issuer_spki);
    }
}
