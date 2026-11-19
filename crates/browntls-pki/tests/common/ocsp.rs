//! Fixtures shared by the OCSP tests: digests, a DER writer, a generated
//! certificate chain and OCSP responses signed at run time.
//!
//! `ocsp.rs` and `ocsp_delegate.rs` include this file as a module beside
//! `common`.

#![allow(
    dead_code,
    unreachable_pub,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub use core::time::Duration;

pub use crate::common::*;
pub use browntls_pki::ocsp::{
    CertId, CertIdHash, CertIdHashers, CertStatus, MAX_RESPONSE_CERTS, OcspError, OcspIssuer,
    OcspPolicy, OcspResponse, OcspSigner, ResponderId, ResponseStatus, VerifiedOcspStatus,
    ca_issuer_uris, encode_request, has_ocsp_nocheck, must_staple, ocsp_responder_uris, oid,
    verify_response,
};
pub use browntls_pki::{
    BorrowedCertRevocationList, Cert, CertRevocationList, CertificateDer, Error, RevocationReason,
    UnixTime, alg_id, anchor_from_trusted_cert,
};
pub use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertifiedIssuer, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SerialNumber,
};
use sha2::Digest as _;

pub const EE_SERIAL: &[u8] = &[0x7a, 0x01, 0x02, 0x03];
pub const OTHER_SERIAL: &[u8] = &[0x7c, 0x07];
pub const DELEGATE_SERIAL: &[u8] = &[0x7d, 0x09];

pub const NOW_SECS: u64 = 1_717_200_000;
pub const HOUR: u64 = 3600;
pub const DAY: u64 = 24 * HOUR;
pub const THIS_UPDATE: u64 = NOW_SECS - HOUR;
pub const NEXT_UPDATE: u64 = NOW_SECS + 3 * DAY;

pub const NOCHECK_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5];
pub const TLS_FEATURE_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 24];
pub const AIA_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// SHA-1 (FIPS 180-4), for test fixtures only.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *state = state.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = word.to_be_bytes();
    }
    out
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub const HASHERS: CertIdHashers = CertIdHashers {
    sha1: Some(sha1),
    sha256: Some(sha256_digest),
};

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

#[path = "ocsp_wire.rs"]
mod wire;
pub use wire::*;

impl Single {
    pub fn good(cert_id: &CertId) -> Self {
        Self::for_cert(cert_id, THIS_UPDATE, NEXT_UPDATE)
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

pub fn alg() -> &'static rcgen::SignatureAlgorithm {
    &rcgen::PKCS_ECDSA_P256_SHA256
}

/// `root -> issuing ca -> end entity`, with the DER the tests parse.
pub struct Fixture {
    pub chain: Chain,
    pub ee_der: CertificateDer<'static>,
    pub ca_der: CertificateDer<'static>,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_ee(ee_params(&["example.com"]))
    }

    pub fn with_ee(mut ee: CertificateParams) -> Self {
        ee.serial_number = Some(SerialNumber::from_slice(EE_SERIAL));
        let chain = Chain::build(alg(), ca_params("root"), vec![ca_params("issuing ca")], &ee);
        let ee_der = chain.ee_der();
        let ca_der = chain.intermediates[0].der().to_vec().into();
        Self {
            chain,
            ee_der,
            ca_der,
        }
    }

    pub fn ee(&self) -> Cert<'_> {
        Cert::try_from(&self.ee_der).unwrap()
    }

    pub fn ca(&self) -> Cert<'_> {
        Cert::try_from(&self.ca_der).unwrap()
    }

    pub fn ca_issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.chain.intermediates[0]
    }

    pub fn ca_key(&self) -> &KeyPair {
        self.ca_issuer().key()
    }

    pub fn cert_id(&self, hash: CertIdHash) -> CertId {
        let ca = self.ca();
        CertId::new(hash, &HASHERS, &self.ee(), &ca.subject_public_key_info()).unwrap()
    }

    /// A response for the end entity with one `good` single response,
    /// identifying the CA as responder by key.
    pub fn response(&self) -> Response {
        Response {
            version: None,
            responder_id: by_key(self.ca_key()),
            produced_at: THIS_UPDATE,
            singles: vec![Single::good(&self.cert_id(CertIdHash::Sha1))],
            extensions: Vec::new(),
            certs: Vec::new(),
        }
    }

    pub fn verify<'r>(
        &self,
        response: &'r [u8],
        policy: &OcspPolicy<'_>,
    ) -> Result<VerifiedOcspStatus<'r>, OcspError> {
        let (ee, ca) = (self.ee(), self.ca());
        verify_response(response, &ee, &OcspIssuer::from_cert(&ca), policy)
    }

    /// A responder certificate issued by the CA, with `id-kp-OCSPSigning`
    /// and `id-pkix-ocsp-nocheck` unless `customize` changes them.
    pub fn delegate(&self, customize: impl FnOnce(&mut CertificateParams)) -> Delegate {
        Delegate::issue(self.ca_issuer(), customize)
    }
}

pub struct Delegate {
    pub der: CertificateDer<'static>,
    pub key: KeyPair,
}

impl Delegate {
    pub fn issue(
        issuer: &Issuer<'_, KeyPair>,
        customize: impl FnOnce(&mut CertificateParams),
    ) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "ocsp responder");
        params.is_ca = IsCa::ExplicitNoCa;
        params.serial_number = Some(SerialNumber::from_slice(DELEGATE_SERIAL));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            NOCHECK_OID,
            vec![0x05, 0x00],
        )];
        customize(&mut params);
        let key = key_for(alg());
        let der = params
            .signed_by(&key, issuer)
            .unwrap()
            .der()
            .to_vec()
            .into();
        Self { der, key }
    }

    pub fn cert(&self) -> Cert<'_> {
        Cert::try_from(&self.der).unwrap()
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `byKey`: the SHA-1 hash of the responder's public key.
pub fn by_key(key: &KeyPair) -> Vec<u8> {
    tlv(0xa2, &tlv(0x04, &sha1(key.public_key_raw())))
}

/// `byName`: the responder's subject.
pub fn by_name(cert: &Cert<'_>) -> Vec<u8> {
    tlv(0xa1, &tlv(0x30, cert.subject()))
}

pub fn stapled<'a>() -> OcspPolicy<'a> {
    OcspPolicy::stapled(ALGS, HASHERS, NOW)
}

pub fn fetched<'a>() -> OcspPolicy<'a> {
    OcspPolicy::fetched(ALGS, HASHERS, NOW)
}

pub fn at_time(mut policy: OcspPolicy<'_>, time: u64) -> OcspPolicy<'_> {
    policy.time = secs(time);
    policy
}
