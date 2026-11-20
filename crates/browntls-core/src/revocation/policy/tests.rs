//! Policy tests.

#![cfg(all(feature = "native", feature = "std"))]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use browntls_pki::crlite::{CrliteLayer, CrliteLimits, CrliteSnapshot, CrliteSnapshotSource};
use browntls_pki::{
    Cert, CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer,
    ServerName, UnixTime,
};

use super::{CtLogKey, RevocationData, RevocationDigests, RevocationPolicy, SharedRevocationData};
use crate::crypto::native;
use crate::error::{CertificateError, Error};
use crate::revocation::{CertificateEvidence, RevocationCheck, RevocationStatus};
use crate::sync::Arc;
use crate::verify::ServerCertVerifier;
use crate::{RootCertStore, SignatureScheme};

fn time(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

fn filter(log: &[u8; 32], issuer: &[u8; 32], revoked: bool) -> Vec<u8> {
    // V4, one coverage interval, one issuer, and two empty matrices.
    // Inverting the empty block changes all covered serials to revoked.
    let mut card = vec![4, 0, 0, 1];
    card.extend_from_slice(log);
    card.extend_from_slice(&0u64.to_be_bytes());
    card.extend_from_slice(&u64::MAX.to_be_bytes());
    card.extend_from_slice(&1u32.to_be_bytes());
    card.extend_from_slice(issuer);
    card.extend_from_slice(&[0; 17]);
    card.push(u8::from(revoked));
    card.extend_from_slice(&[0; 7]);
    card
}

fn sct_input(cert: &[u8], timestamp: u64) -> Vec<u8> {
    let mut input = vec![0, 0];
    input.extend_from_slice(&timestamp.to_be_bytes());
    input.extend_from_slice(&[0, 0]);
    input.extend_from_slice(&(u32::try_from(cert.len()).unwrap()).to_be_bytes()[1..]);
    input.extend_from_slice(cert);
    input.extend_from_slice(&[0, 0]);
    input
}

#[test]
fn a_verified_sct_enables_crlite_and_rotation_applies_to_the_next_check() {
    let now = UnixTime::now();
    let digests = RevocationDigests::native();
    let provider = Arc::new(native::default_provider());
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
        .unwrap();
    let ca = CertificateDer::from(ca.der().to_vec());
    let leaf = CertificateDer::from(leaf.der().to_vec());
    let ca_cert = Cert::try_from(&ca).unwrap();
    let issuer_id = (digests.sha256)(ca_cert.subject_public_key_info().as_ref());
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();

    let log = rcgen::KeyPair::generate().unwrap();
    let log_key = rcgen::PublicKeyData::subject_public_key_info(&log);
    let log_id = (digests.sha256)(&log_key);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(log.serialize_der()));
    let signing = provider.key_provider.load_private_key(key).unwrap();
    let signer = signing
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .unwrap();
    let timestamp = now.as_secs() * 1000;
    let signature = signer.sign(&sct_input(leaf.as_ref(), timestamp)).unwrap();
    let mut entry = vec![0];
    entry.extend_from_slice(&log_id);
    entry.extend_from_slice(&timestamp.to_be_bytes());
    entry.extend_from_slice(&[0, 0, 4, 3]);
    entry.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
    entry.extend_from_slice(&signature);
    let mut list = u16::try_from(entry.len() + 2)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(&u16::try_from(entry.len()).unwrap().to_be_bytes());
    list.extend_from_slice(&entry);

    let data = |generation, revoked| {
        let bytes = filter(&log_id, &issuer_id, revoked);
        let source = CrliteSnapshotSource {
            generation,
            expiry: time(now.as_secs() + 60),
            full: CrliteLayer {
                effective: now,
                clubcard: &bytes,
            },
            deltas: &[],
            delta_tip: 0,
        };
        RevocationData::new(
            CrliteSnapshot::new(&source, &CrliteLimits::DEFAULT).unwrap(),
            vec![CtLogKey::new(log_key.clone())],
            &digests,
        )
        .unwrap()
    };
    let shared = Arc::new(SharedRevocationData::new());
    shared.replace(data(1, false)).unwrap();
    let verifier =
        crate::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .with_revocation_policy(
                RevocationPolicy::new(digests).with_revocation_data(shared.clone()),
            )
            .build()
            .unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let verify = |sct: &[u8]| {
        verifier.verify_server_cert_with_evidence(
            &leaf,
            &[],
            &name,
            &[CertificateEvidence {
                ocsp: None,
                scts: Some(sct),
                transparency_info: None,
            }],
            now,
        )
    };
    assert!(matches!(
        &verify(&list),
        Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
    ));
    let mut bad = list.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(
        verify(&bad),
        Err(Error::InvalidCertificate(
            CertificateError::UnknownRevocationStatus
        ))
    ));
    shared.replace(data(2, true)).unwrap();
    assert!(shared.replace(data(1, false)).is_err());
    assert!(matches!(
        verify(&list),
        Err(Error::InvalidCertificate(CertificateError::Revoked))
    ));
}

fn ca_parameters(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

fn test_issuer(
    name: &str,
) -> (
    CertificateDer<'static>,
    rcgen::Issuer<'static, rcgen::KeyPair>,
) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = ca_parameters(name);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    (der.into(), rcgen::Issuer::new(params, key))
}

fn crl(issuer: &rcgen::Issuer<'_, rcgen::KeyPair>) -> CertificateRevocationListDer<'static> {
    let list = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 1, 1),
        next_update: rcgen::date_time_ymd(2028, 1, 1),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    list.signed_by(issuer).unwrap().der().to_vec().into()
}

#[test]
fn full_chain_revocation_tries_another_valid_cross_signed_path() {
    let (root_a, issuer_a) = test_issuer("Root A");
    let (root_b, issuer_b) = test_issuer("Root B");
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let params = ca_parameters("Cross signed issuer");
    let first = CertificateDer::from(
        params
            .signed_by(&intermediate_key, &issuer_a)
            .unwrap()
            .der()
            .to_vec(),
    );
    let second = CertificateDer::from(
        params
            .signed_by(&intermediate_key, &issuer_b)
            .unwrap()
            .der()
            .to_vec(),
    );
    let intermediate = rcgen::Issuer::new(params, intermediate_key);
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&rcgen::KeyPair::generate().unwrap(), &intermediate)
        .unwrap();
    let leaf = CertificateDer::from(leaf.der().to_vec());
    let mut roots = RootCertStore::empty();
    roots.add(root_a).unwrap();
    roots.add(root_b).unwrap();
    let verifier = crate::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(native::default_provider()),
    )
    .with_crls([crl(&intermediate), crl(&issuer_b)])
    .allow_unknown_revocation_status()
    .enforce_revocation_expiration()
    .with_revocation_policy(RevocationPolicy::new(RevocationDigests::native()).check_full_chain())
    .build()
    .unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let now = time(1_800_000_000);
    assert!(matches!(
        verifier.verify_server_cert_with_evidence(
            &leaf,
            core::slice::from_ref(&first),
            &name,
            &[],
            now
        ),
        Err(Error::InvalidCertificate(
            CertificateError::UnknownRevocationStatus
        ))
    ));
    assert!(matches!(
        verifier.verify_server_cert_with_evidence(&leaf, &[first, second], &name, &[], now),
        Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
    ));
}
