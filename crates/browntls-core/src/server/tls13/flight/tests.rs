//! The server Certificate message's stapled OCSP responses and SCT list.

use alloc::boxed::Box;
use alloc::vec;

use browntls_pki::CertificateDer;

use super::*;
use crate::enums::{CipherSuite, SignatureAlgorithm};
use crate::msgs::handshake::{CertificateStatusRequest, ClientExtensions, Random};
use crate::sign::{Signer, SigningKey};
use crate::sync::Arc;

const SCTS: &[u8] = &[0, 3, 0, 1, 0xaa];

/// One optional value per Certificate entry, in chain order.
type PerEntry = Vec<Option<Vec<u8>>>;

#[derive(Debug)]
struct NoKey;

impl SigningKey for NoKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

/// A three-certificate chain with OCSP responses for the end entity and
/// the last certificate, and an SCT list.
fn certified_key() -> CertifiedKey {
    let chain = vec![
        CertificateDer::from(vec![1]),
        CertificateDer::from(vec![2]),
        CertificateDer::from(vec![3]),
    ];
    let mut key = CertifiedKey::new(chain, Arc::new(NoKey));
    key.set_ocsp_for(0, Some(vec![0x10])).unwrap();
    key.set_ocsp_for(2, Some(vec![0x12])).unwrap();
    key.set_sct_list(Some(SCTS.to_vec())).unwrap();
    key
}

fn client_hello(status_request: bool, sct_request: bool) -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        compression_methods: vec![Compression::Null],
        extensions: ClientExtensions {
            certificate_status_request: status_request.then(CertificateStatusRequest::build_ocsp),
            sct_request: sct_request.then_some(()),
            ..Default::default()
        },
    }
}

/// The OCSP responses and SCT lists of the message built for a client
/// that sent the given requests, after a trip over the wire.
fn sent_evidence(
    key: &CertifiedKey,
    status_request: bool,
    sct_request: bool,
) -> (PerEntry, PerEntry) {
    let body = certificate_body(key, &client_hello(status_request, sct_request), None, None);
    let encoded = body.get_encoding();
    let parsed = CertificatePayloadTls13::read_bytes(&encoded).unwrap();
    assert_eq!(parsed, body);
    assert_eq!(parsed.entries.len(), key.cert.len());
    assert!(
        parsed
            .entries
            .iter()
            .all(|e| e.delegated_credential.is_none())
    );
    (parsed.ocsp_responses(), parsed.sct_lists())
}

#[test]
fn nothing_is_sent_unasked() {
    let key = certified_key();
    let (ocsp, scts) = sent_evidence(&key, false, false);
    assert_eq!(ocsp, [None, None, None]);
    assert_eq!(scts, [None, None, None]);
    // Exactly the bare chain.
    assert_eq!(
        certificate_body(&key, &client_hello(false, false), None, None).get_encoding(),
        CertificatePayloadTls13::new(key.cert.iter(), None).get_encoding()
    );
}

#[test]
fn status_request_gets_every_configured_response() {
    let (ocsp, scts) = sent_evidence(&certified_key(), true, false);
    assert_eq!(ocsp, [Some(vec![0x10]), None, Some(vec![0x12])]);
    assert_eq!(scts, [None, None, None]);
}

#[test]
fn sct_request_gets_the_end_entity_list() {
    let (ocsp, scts) = sent_evidence(&certified_key(), false, true);
    assert_eq!(ocsp, [None, None, None]);
    assert_eq!(scts, [Some(SCTS.to_vec()), None, None]);
}

#[test]
fn both_requests_get_both() {
    let (ocsp, scts) = sent_evidence(&certified_key(), true, true);
    assert_eq!(ocsp, [Some(vec![0x10]), None, Some(vec![0x12])]);
    assert_eq!(scts, [Some(SCTS.to_vec()), None, None]);
}

#[test]
fn requests_without_configured_evidence_get_the_bare_chain() {
    let mut key = certified_key();
    key.set_ocsp_for(0, None).unwrap();
    key.set_ocsp_for(2, None).unwrap();
    key.set_sct_list(None).unwrap();
    let (ocsp, scts) = sent_evidence(&key, true, true);
    assert_eq!(ocsp, [None, None, None]);
    assert_eq!(scts, [None, None, None]);
}

#[test]
fn end_entity_response_set_through_the_field_is_stapled() {
    let mut key = certified_key();
    key.ocsp = Some(vec![0x20, 0x21]);
    let (ocsp, _) = sent_evidence(&key, true, false);
    assert_eq!(ocsp[0], Some(vec![0x20, 0x21]));
}

#[test]
fn transparency_info_only_when_offered_and_for_x509() {
    // One `x509_sct_v2` of log 1.3.101.80.1 (RFC 9162 §4.8).
    let mut sct = vec![1, 2, 4, 0x2b, 0x65, 0x50, 1];
    sct.extend(7u64.to_be_bytes());
    sct.extend([0, 0, 0, 1, 0x55]);
    let len = u16::try_from(sct.len()).unwrap();
    let list = [&(len + 2).to_be_bytes()[..], &len.to_be_bytes(), &sct].concat();
    let mut key = certified_key();
    key.set_transparency_info(Some(list.clone())).unwrap();

    let mut offered = client_hello(false, false);
    offered.extensions.transparency_info = Some(());
    let body = certificate_body(&key, &offered, None, None);
    let encoded = body.get_encoding();
    let parsed = CertificatePayloadTls13::read_bytes(&encoded).unwrap();
    assert_eq!(parsed.end_entity_transparency_info(), Some(&list[..]));
    assert!(
        parsed.entries[1..]
            .iter()
            .all(|e| e.transparency_info.is_none())
    );

    // Not offered, or a raw public key negotiated: nothing.
    let body = certificate_body(&key, &client_hello(false, false), None, None);
    assert!(!body.has_transparency_info());
    let rpk = Some(CertificateType::RawPublicKey);
    assert!(!certificate_body(&key, &offered, None, rpk).has_transparency_info());
}
