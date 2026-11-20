//! Process-local credentials and signed evidence for the revocation harness.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use browntls_core::RootCertStore;
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use browntls_core::revocation::RevocationDigests;
use browntls_core::sign::CertifiedKey;
use browntls_core::time_provider::TimeProvider;
use browntls_pki::ocsp::{CertId, CertIdHash, CertIdHashers, oid};
use browntls_pki::{Cert, UnixTime};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData as _, SigningKey as _,
};

#[path = "../../../crates/browntls-pki/tests/common/ocsp_wire.rs"]
mod wire;

use wire::{Response, Single, seq, tlv};

pub(super) const NOW: u64 = 1_717_200_000;
pub(super) const THIS_UPDATE: u64 = NOW - 3600;
pub(super) const NEXT_UPDATE: u64 = NOW + 3600;
pub(super) const SCT_TIME: u64 = THIS_UPDATE * 1000;
pub(super) const RESPONDER: &str = "http://ocsp.invalid/";
pub(super) const CA_URI: &str = "http://issuer.invalid/ca.der";

pub(super) fn time(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

#[derive(Debug)]
pub(super) struct Clock;

impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(time(NOW))
    }
}

pub(super) fn hashers(digests: RevocationDigests) -> CertIdHashers {
    CertIdHashers {
        sha1: digests.sha1,
        sha256: Some(digests.sha256),
    }
}

pub(super) struct Fixture {
    pub(super) ca: CertificateDer<'static>,
    pub(super) leaf: CertificateDer<'static>,
    pub(super) response: Vec<u8>,
    pub(super) log_spki: Vec<u8>,
    pub(super) scts: Vec<u8>,
    key: Vec<u8>,
}

impl Fixture {
    pub(super) fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::new)
    }

    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "revocation fixture CA");
        let ca: CertificateDer<'static> = ca_params
            .self_signed(&ca_key)
            .unwrap()
            .der()
            .to_vec()
            .into();
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_params.serial_number = Some(42u64.into());
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let describe =
            |method: &[u8], url: &str| seq(&[&tlv(0x06, method), &tlv(0x86, url.as_bytes())]);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                seq(&[
                    &describe(oid::AD_OCSP, RESPONDER),
                    &describe(oid::AD_CA_ISSUERS, CA_URI),
                ]),
            ));
        let leaf: CertificateDer<'static> = leaf_params
            .signed_by(&key, &issuer)
            .unwrap()
            .der()
            .to_vec()
            .into();
        let log_key = KeyPair::generate().unwrap();
        let log_spki = log_key.subject_public_key_info();
        let scts = signed_sct_list(&log_key, &log_spki, leaf.as_ref());

        let ca_cert = Cert::try_from(&ca).unwrap();
        let leaf_cert = Cert::try_from(&leaf).unwrap();
        let digests = RevocationDigests::native();
        let cert_id = CertId::new(
            CertIdHash::Sha1,
            &hashers(digests),
            &leaf_cert,
            &ca_cert.subject_public_key_info(),
        )
        .unwrap();
        let responder_hash = (digests.sha1.unwrap())(issuer.key().public_key_raw());
        let mut single = Single::for_cert(&cert_id, THIS_UPDATE, NEXT_UPDATE);
        single.extensions.push(wire::extension(
            browntls_pki::sct::OCSP_SCT_LIST_OID,
            false,
            &tlv(0x04, &scts),
        ));
        let response = Response {
            version: None,
            responder_id: tlv(0xa2, &tlv(0x04, &responder_hash)),
            produced_at: THIS_UPDATE,
            singles: vec![single],
            extensions: Vec::new(),
            certs: Vec::new(),
        }
        .signed_by(issuer.key());

        Self {
            ca,
            leaf,
            response,
            log_spki,
            scts,
            key: key.serialize_der(),
        }
    }

    pub(super) fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        Arc::new(roots)
    }

    pub(super) fn key(&self) -> PrivatePkcs8KeyDer<'static> {
        self.key.clone().into()
    }

    pub(super) fn certified_key(&self, provider: &CryptoProvider) -> CertifiedKey {
        CertifiedKey::from_der(vec![self.leaf.clone()], self.key().into(), provider).unwrap()
    }
}

fn signed_sct_list(key: &KeyPair, spki: &[u8], cert: &[u8]) -> Vec<u8> {
    let mut signed = vec![0, 0]; // SCT v1, certificate_timestamp signature
    signed.extend(SCT_TIME.to_be_bytes());
    signed.extend([0, 0]); // X.509 entry
    signed.extend(&u32::try_from(cert.len()).unwrap().to_be_bytes()[1..]);
    signed.extend(cert);
    signed.extend([0, 0]); // no extensions
    let signature = key.sign(&signed).unwrap();

    let mut sct = vec![0];
    sct.extend((RevocationDigests::native().sha256)(spki));
    sct.extend(SCT_TIME.to_be_bytes());
    sct.extend([0, 0, 4, 3]); // no extensions, SHA-256 with ECDSA
    sct.extend(u16::try_from(signature.len()).unwrap().to_be_bytes());
    sct.extend(signature);

    let len = u16::try_from(sct.len()).unwrap();
    [&(len + 2).to_be_bytes()[..], &len.to_be_bytes(), &sct].concat()
}
