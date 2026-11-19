//! Exercises the public PKI APIs with signed fixtures and arbitrary evidence.

use browntls_core::crypto::native;
use browntls_core::revocation::RevocationDigests;
use browntls_pki::ocsp::{
    CertId, CertIdHash, CertStatus, OcspIssuer, OcspPolicy, OcspResponse, ResponderId,
    ResponseStatus, ca_issuer_uris, encode_request, has_ocsp_nocheck, must_staple,
    ocsp_responder_uris,
};
use browntls_pki::sct::{CtLog, CtPolicy, SctEntryType, SctOptions, SctSource, SctVerifier};
use browntls_pki::{Cert, anchor_from_trusted_cert};

use super::fixtures::{
    CA_URI, Fixture, NEXT_UPDATE, NOW, RESPONDER, SCT_TIME, THIS_UPDATE, hashers, time,
};

pub(super) fn ocsp(fixture: &Fixture, bytes: &[u8]) {
    let ca = Cert::try_from(&fixture.ca).unwrap();
    let leaf = Cert::try_from(&fixture.leaf).unwrap();
    let digests = RevocationDigests::native();
    let provider = native::default_provider();
    let algorithms = provider.signature_verification_algorithms.all;
    let hashers = hashers(digests);

    let canned = bytes.is_empty();
    let der = if canned {
        fixture.response.as_slice()
    } else {
        bytes
    };
    let Ok(response) = OcspResponse::from_der(der) else {
        assert!(!canned);
        return;
    };
    let verify = |issuer: &OcspIssuer<'_>, now| {
        response.verify(
            &leaf,
            issuer,
            &OcspPolicy::fetched(algorithms, hashers, time(now)),
        )
    };
    let result = verify(&OcspIssuer::from_cert(&ca), NOW);
    for entry in response
        .basic()
        .into_iter()
        .flat_map(|basic| basic.responses())
    {
        let id = entry.cert_id();
        if let Some(algorithm) = id.hash_algorithm() {
            assert_eq!(id.hash_algorithm_oid(), algorithm.oid());
            assert_eq!(id.issuer_name_hash().len(), algorithm.output_len());
            assert_eq!(id.issuer_key_hash().len(), algorithm.output_len());
        }
    }
    if !canned {
        return;
    }

    assert_eq!(response.status(), ResponseStatus::Successful);
    let basic = response.basic().unwrap();
    let mut entries = basic.responses();
    let single = entries.next().unwrap();
    assert!(entries.next().is_none());
    assert_eq!(single.status(), CertStatus::Good);
    assert_eq!(single.this_update(), time(THIS_UPDATE));
    assert_eq!(single.next_update(), Some(time(NEXT_UPDATE)));
    assert_eq!(single.sct_list(), Some(fixture.scts.as_slice()));
    assert_eq!(basic.produced_at(), time(THIS_UPDATE));
    assert!(matches!(basic.responder_id(), ResponderId::ByKey(key) if key.len() == 20));
    assert_eq!(basic.certificates().count(), 0);
    assert_eq!(basic.nonce(), None);
    basic
        .signed_data()
        .verify_signature(algorithms, &ca.subject_public_key_info())
        .unwrap();

    let actual = single.cert_id();
    let algorithm = actual.hash_algorithm().unwrap();
    let id = CertId::from_parts(
        algorithm,
        actual.issuer_name_hash(),
        actual.issuer_key_hash(),
        actual.serial(),
    )
    .unwrap();
    assert!(id.matches(&actual));
    assert_eq!(id.hash_algorithm(), CertIdHash::Sha1);
    assert_eq!(id.issuer_name_hash(), actual.issuer_name_hash());
    assert_eq!(id.issuer_key_hash(), actual.issuer_key_hash());
    assert_eq!(id.serial(), leaf.serial());
    let derived = CertId::new(algorithm, &hashers, &leaf, &ca.subject_public_key_info()).unwrap();
    assert_eq!(derived.to_der(), id.to_der());
    assert_eq!(encode_request(&id, None), encode_request(&derived, None));
    let verified = result.unwrap();
    assert_eq!(verified.status, CertStatus::Good);
    let anchor = anchor_from_trusted_cert(&fixture.ca).unwrap();
    let issuer = OcspIssuer::from_trust_anchor(&anchor);
    let explicit = OcspIssuer::new(issuer.subject(), issuer.subject_public_key_info());
    assert_eq!(verify(&issuer, NOW), Ok(verified));
    assert_eq!(verify(&explicit, NOW), Ok(verified));
    assert!(verify(&explicit, NEXT_UPDATE + 600).unwrap_err().is_stale());

    assert!(!must_staple(&leaf).unwrap());
    assert!(!has_ocsp_nocheck(&leaf).unwrap());
    assert!(ocsp_responder_uris(&leaf).unwrap().eq([RESPONDER]));
    assert!(ca_issuer_uris(&leaf).unwrap().eq([CA_URI]));
}

pub(super) fn sct(fixture: &Fixture, bytes: &[u8]) {
    let leaf = Cert::try_from(&fixture.leaf).unwrap();
    let digests = RevocationDigests::native();
    let provider = native::default_provider();
    let log_id = (digests.sha256)(&fixture.log_spki);
    let logs = [CtLog::new(&fixture.log_spki, digests.sha256)
        .unwrap()
        .with_expected_id(&log_id)
        .unwrap()
        .with_timestamp_window(SCT_TIME, SCT_TIME + 1)];
    let policy = CtPolicy {
        logs: &logs,
        supported_sig_algs: provider.signature_verification_algorithms.all,
        sha256: digests.sha256,
        options: SctOptions::default(),
    };
    let ca = Cert::try_from(&fixture.ca).unwrap();
    let issuer = ca.subject_public_key_info();
    let mut verifier = SctVerifier::new(&policy, &leaf, Some(issuer.as_ref()), time(NOW)).unwrap();
    verifier.verify_embedded().unwrap();
    if !bytes.is_empty() {
        let _ = verifier.verify_tls_extension(bytes);
        let _ = verifier.verify_ocsp_extension(bytes);
        return;
    }

    verifier.verify_tls_extension(&fixture.scts).unwrap();
    let [sct] = verifier.verified() else {
        panic!("the fixture has one verified SCT");
    };
    assert_eq!(sct.log_id(), logs[0].id());
    assert_eq!(sct.timestamp_ms(), SCT_TIME);
    assert_eq!(sct.source(), SctSource::TlsExtension);
    assert_eq!(sct.entry_type(), SctEntryType::X509);
    assert_eq!(verifier.into_verified().len(), 1);
}
