//! OCSP responses whose signatures involve ML-DSA, through the consumers
//! of the provider's algorithm list: a `WebPkiServerVerifier` with a
//! `RevocationPolicy` (stapled responses) and `ServerStapleResolver`.
//!
//! Three shapes: a response signed by an ML-DSA CA; a response signed by a
//! delegated responder with an ML-DSA key under a classical CA (the path is
//! classical, so only the response signature needs ML-DSA); and a delegated
//! responder with a classical key whose certificate an ML-DSA CA signed.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier as _;
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use browntls_core::revocation::{RevocationDigests, RevocationPolicy, ServerStapleResolver};
use browntls_core::sign::CertifiedKey;
use browntls_core::time_provider::TimeProvider;
use browntls_core::{CertificateError, Error};
use browntls_pki::Cert;
use browntls_pki::ocsp::{CertId, CertIdHash, CertIdHashers};

use crate::ml_dsa::{Key, SETS, Set};
use crate::ocsp_wire as wire;
use crate::x509::{CertSpec, ext_key_usage, extension, key_usage, ku, name};
use crate::{
    Chain, Impl, Issuer, MlKey, NOW, Purpose, UNSUPPORTED, build_chain, default_provider, now,
    opt_in_provider,
};

/// `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck` (encoded arcs).
const OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const OCSP_NOCHECK: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05];

const INVALID_STAPLE: Error = Error::InvalidCertificate(CertificateError::InvalidOcspResponse);

/// A "good" response for the chain's end entity (issued by the root),
/// naming `responder` and carrying `certs`; not yet signed.
fn response(chain: &Chain, responder: &str, certs: Vec<Vec<u8>>) -> wire::Response {
    let hashers = CertIdHashers {
        sha1: None,
        sha256: Some(RevocationDigests::native().sha256),
    };
    let ee = CertificateDer::from(&chain.ee[..]);
    let root = CertificateDer::from(&chain.root[..]);
    let leaf = Cert::try_from(&ee).unwrap();
    let root = Cert::try_from(&root).unwrap();
    let cert_id = CertId::new(
        CertIdHash::Sha256,
        &hashers,
        &leaf,
        root.subject_public_key_info().as_ref(),
    )
    .unwrap();
    wire::Response {
        version: None,
        responder_id: wire::tlv(0xa1, &name(responder)),
        produced_at: NOW - 3600,
        singles: vec![wire::Single::for_cert(&cert_id, NOW - 3600, NOW + 86_400)],
        extensions: Vec::new(),
        certs,
    }
}

/// `response` signed with ML-DSA by `key` (`ocsp_wire` signs only with
/// ECDSA P-256).
fn signed_ml_dsa(response: &wire::Response, key: &MlKey, by: Impl) -> Vec<u8> {
    let tbs = response.tbs();
    let signature = [&[0u8][..], &key.sign(by, &tbs)].concat();
    let mut basic = [
        &tbs[..],
        &wire::tlv(0x30, key.set.alg_id().as_bytes()),
        &wire::tlv(0x03, &signature),
    ]
    .concat();
    if !response.certs.is_empty() {
        basic.extend_from_slice(&wire::tlv(0xa0, &wire::tlv(0x30, &response.certs.concat())));
    }
    wire::successful(&wire::tlv(0x30, &basic))
}

/// A delegated OCSP responder certificate for `subject_key`, issued by the
/// root: digitalSignature, `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck`.
fn responder_cert(root: Issuer<'_>, subject_key: &Key) -> Vec<u8> {
    let spec = CertSpec::bare("responder", "root", subject_key).with(vec![
        key_usage(&[ku::DIGITAL_SIGNATURE]),
        ext_key_usage(&[OCSP_SIGNING]),
        extension(OCSP_NOCHECK, false, &[0x05, 0x00]),
    ]);
    root.sign_cert(&spec)
}

/// Verifies the chain's end entity with a strict revocation policy (stapled
/// OCSP required) and `staple`.
fn verify(chain: &Chain, provider: Arc<CryptoProvider>, staple: &[u8]) -> Result<(), Error> {
    let verifier = WebPkiServerVerifier::builder_with_provider(chain.roots(), provider)
        .with_revocation_policy(RevocationPolicy::new(RevocationDigests::native()))
        .build()
        .unwrap();
    verifier
        .verify_server_cert(
            &CertificateDer::from(&chain.ee[..]),
            &chain.intermediates(),
            &ServerName::try_from("example.com").unwrap(),
            staple,
            now(),
        )
        .map(|_| ())
}

#[test]
fn staple_signed_by_an_ml_dsa_ca() {
    let ee = Key::p256();
    for set in SETS {
        let root_key = MlKey::new(set, "root");
        for by in [Impl::Native, Impl::Oracle] {
            let chain = build_chain(Issuer::MlDsa(&root_key, by), &[], &ee, Purpose::Server);
            let staple = signed_ml_dsa(&response(&chain, "root", vec![]), &root_key, by);
            let what = format!("{set:?} by {by:?}");
            assert_eq!(verify(&chain, opt_in_provider(), &staple), Ok(()), "{what}");
            // The response ends with its signature.
            let mut tampered = staple.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert_eq!(
                verify(&chain, opt_in_provider(), &tampered),
                Err(INVALID_STAPLE),
                "{what}"
            );
            // Without the staple the strict policy has no evidence.
            assert!(verify(&chain, opt_in_provider(), &[]).is_err(), "{what}");
            // The default table fails on the path before the staple.
            assert_eq!(
                verify(&chain, default_provider(), &staple),
                Err(UNSUPPORTED),
                "{what}"
            );
        }
    }
}

#[test]
fn staple_signed_by_an_ml_dsa_delegated_responder_under_a_classical_ca() {
    let ee = Key::p256();
    let root_key = Key::p256();
    let root = Issuer::Classical(&root_key);
    let chain = build_chain(root, &[], &ee, Purpose::Server);
    for set in SETS {
        let responder = MlKey::new(set, "responder");
        let certs = vec![responder_cert(root, &responder.oracle)];
        for by in [Impl::Native, Impl::Oracle] {
            let staple = signed_ml_dsa(
                &response(&chain, "responder", certs.clone()),
                &responder,
                by,
            );
            let what = format!("{set:?} by {by:?}");
            assert_eq!(verify(&chain, opt_in_provider(), &staple), Ok(()), "{what}");
            // The path is classical: with the default table only the
            // response signature is unsupported, and the staple is invalid.
            assert_eq!(
                verify(&chain, default_provider(), &staple),
                Err(INVALID_STAPLE),
                "{what}"
            );
        }
        // A response by another responder key is refused.
        let stranger = MlKey::new(set, "stranger");
        let forged = signed_ml_dsa(
            &response(&chain, "responder", certs.clone()),
            &stranger,
            Impl::Native,
        );
        assert_eq!(
            verify(&chain, opt_in_provider(), &forged),
            Err(INVALID_STAPLE),
            "{set:?}"
        );
    }
}

#[test]
fn classical_delegated_responder_certified_by_an_ml_dsa_ca() {
    let ee = Key::p256();
    let root_key = MlKey::new(Set::MlDsa87, "root");
    let root = Issuer::MlDsa(&root_key, Impl::Native);
    let chain = build_chain(root, &[], &ee, Purpose::Server);
    let responder_key = Key::p256();
    let Key::P256(pair) = &responder_key else {
        unreachable!()
    };
    let certs = vec![responder_cert(root, &responder_key)];
    let staple = response(&chain, "responder", certs).signed_by(pair);
    assert_eq!(verify(&chain, opt_in_provider(), &staple), Ok(()));
    assert_eq!(
        verify(&chain, default_provider(), &staple),
        Err(UNSUPPORTED)
    );
}

#[derive(Debug)]
struct FixedClock;

impl TimeProvider for FixedClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(now())
    }
}

fn resolver(
    chain: &Chain,
    ee: &Key,
    staple: Vec<u8>,
    provider: Arc<CryptoProvider>,
) -> Result<ServerStapleResolver, Error> {
    let Key::P256(pair) = ee else { unreachable!() };
    let mut key = CertifiedKey::from_der(
        vec![CertificateDer::from(chain.ee.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der())),
        &provider,
    )?;
    key.ocsp = Some(staple);
    ServerStapleResolver::new(
        key,
        chain.roots(),
        provider,
        RevocationDigests::native(),
        Arc::new(FixedClock),
    )
}

#[test]
fn server_staple_resolver() {
    let ee = Key::p256();
    // The resolver validates the server's own ML-DSA-signed chain and an
    // ML-DSA-signed staple with the provider's list.
    let root_key = MlKey::new(Set::MlDsa44, "root");
    let chain = build_chain(
        Issuer::MlDsa(&root_key, Impl::Native),
        &[],
        &ee,
        Purpose::Server,
    );
    let staple = signed_ml_dsa(&response(&chain, "root", vec![]), &root_key, Impl::Oracle);
    let installed = resolver(&chain, &ee, staple.clone(), opt_in_provider()).unwrap();
    assert_eq!(
        installed.staple_expiry(),
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            NOW + 86_400
        )))
    );
    assert_eq!(
        resolver(&chain, &ee, staple, default_provider()).err(),
        Some(UNSUPPORTED)
    );

    // A classical chain with an ML-DSA delegated responder: only the
    // staple needs ML-DSA.
    let classical_root = Key::p256();
    let root = Issuer::Classical(&classical_root);
    let chain = build_chain(root, &[], &ee, Purpose::Server);
    let responder = MlKey::new(Set::MlDsa65, "responder");
    let certs = vec![responder_cert(root, &responder.oracle)];
    let staple = signed_ml_dsa(
        &response(&chain, "responder", certs),
        &responder,
        Impl::Native,
    );
    assert!(
        resolver(&chain, &ee, staple.clone(), opt_in_provider())
            .unwrap()
            .staple_expiry()
            .is_some()
    );
    assert_eq!(
        resolver(&chain, &ee, staple, default_provider()).err(),
        Some(INVALID_STAPLE)
    );
}
