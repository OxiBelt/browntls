//! Certificate Transparency 2.0 (RFC 9162) fixtures for the TLS tests:
//! logs with keys generated at run time, the signed structures encoded
//! independently of `browntls-pki` from the RFC presentation language (as
//! `crates/browntls-pki/tests/common/ct_v2.rs` does), a certificate issuer
//! that can embed a Transparency Information extension, and OCSP responses
//! carrying one.
//!
//! Included as `mod ct_v2` beside `mod common` by the targets that need it.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use browntls_core::RootCertStore;
use browntls_core::pki_types::CertificateDer;
use browntls_core::transparency::CtV2LogConfig;
use browntls_pki::Cert;
use browntls_pki::ocsp::{CertId, CertIdHash, CertIdHashers};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData as _, SerialNumber,
    SigningKey as _,
};

use crate::common::{Chain, KeyType};

#[path = "../../../browntls-pki/tests/common/ocsp_wire.rs"]
mod wire;

/// SHA-256, from the provider under test.
pub type Sha256 = fn(&[u8]) -> [u8; 32];

/// Arcs of the Transparency Information extension, 1.3.101.75.
pub const TRANSPARENCY_ARCS: &[u64] = &[1, 3, 101, 75];

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An SCT timestamp an hour ago, in milliseconds.
pub fn sct_time_ms() -> u64 {
    (now_secs() - 3600) * 1000
}

fn vec8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

fn vec16(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

/// A DER `OCTET STRING`.
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    wire::tlv(0x04, value)
}

/// A serialized `x509_entry_v2` or `precert_entry_v2` (RFC 9162 §4.7):
/// what an SCT signs and a Merkle leaf hashes. No extensions.
pub fn entry(sha256: Sha256, precert: bool, ts_ms: u64, issuer_spki: &[u8], tbs: &[u8]) -> Vec<u8> {
    let mut out = if precert { vec![1, 1] } else { vec![1, 0] };
    out.extend(ts_ms.to_be_bytes());
    vec8(&mut out, &sha256(issuer_spki));
    out.extend(&u32::try_from(tbs.len()).unwrap().to_be_bytes()[1..]);
    out.extend_from_slice(tbs);
    vec16(&mut out, &[]);
    out
}

/// A `TransItemList` (§6.3) of serialized items.
pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for item in items {
        vec16(&mut entries, item);
    }
    let mut out = Vec::new();
    vec16(&mut out, &entries);
    out
}

/// `HASH(0x00 || entry)` (§2.1.1).
pub fn leaf_hash(sha256: Sha256, entry: &[u8]) -> [u8; 32] {
    sha256(&[&[0u8][..], entry].concat())
}

/// `HASH(0x01 || left || right)` (§2.1.1).
pub fn node_hash(sha256: Sha256, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[1u8][..], left, right].concat())
}

/// A CT version 2 log and its signing key.
pub struct Log {
    pub id: Vec<u8>,
    pub spki: Vec<u8>,
    key: KeyPair,
}

impl Log {
    /// An `ecdsa_secp256r1_sha256` log with ID 1.3.101.80.`n`.
    pub fn ecdsa(n: u8) -> Self {
        Self::new(&rcgen::PKCS_ECDSA_P256_SHA256, n)
    }

    /// An `ed25519` log with ID 1.3.101.80.`n`.
    pub fn ed25519(n: u8) -> Self {
        Self::new(&rcgen::PKCS_ED25519, n)
    }

    fn new(alg: &'static rcgen::SignatureAlgorithm, n: u8) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        Self {
            id: vec![0x2b, 0x65, 0x50, n],
            spki: key.subject_public_key_info(),
            key,
        }
    }

    /// The log as a client trusts it.
    pub fn config(&self) -> CtV2LogConfig {
        CtV2LogConfig::new(self.id.clone(), self.spki.clone())
    }

    /// A serialized SCT of this log over `entry` (§4.8).
    pub fn sct(&self, precert: bool, ts_ms: u64, entry: &[u8]) -> Vec<u8> {
        let signature = self.key.sign(entry).unwrap();
        let mut out = if precert { vec![1, 3] } else { vec![1, 2] };
        vec8(&mut out, &self.id);
        out.extend(ts_ms.to_be_bytes());
        vec16(&mut out, &[]);
        vec16(&mut out, &signature);
        out
    }

    /// The `TreeHeadDataV2` it signs (§4.9).
    pub fn tree_head(ts_ms: u64, tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
        let mut out = ts_ms.to_be_bytes().to_vec();
        out.extend(tree_size.to_be_bytes());
        vec8(&mut out, root);
        vec16(&mut out, &[]);
        out
    }

    /// A serialized `signed_tree_head_v2` (§4.10).
    pub fn sth(&self, ts_ms: u64, tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
        let head = Self::tree_head(ts_ms, tree_size, root);
        let signature = self.key.sign(&head).unwrap();
        let mut out = vec![1, 4];
        vec8(&mut out, &self.id);
        out.extend(head);
        vec16(&mut out, &signature);
        out
    }

    /// A serialized `inclusion_proof_v2` (§4.12).
    pub fn inclusion(&self, tree_size: u64, leaf_index: u64, path: &[[u8; 32]]) -> Vec<u8> {
        let mut out = vec![1, 6];
        vec8(&mut out, &self.id);
        out.extend(tree_size.to_be_bytes());
        out.extend(leaf_index.to_be_bytes());
        let mut nodes = Vec::new();
        for node in path {
            vec8(&mut nodes, node);
        }
        vec16(&mut out, &nodes);
        out
    }
}

/// A CA issuing one server certificate (P-256), possibly with extensions,
/// and possibly through an intermediate CA.
pub struct CtPki {
    pub sha256: Sha256,
    /// The CA that issues the server certificate.
    issuer: CertifiedIssuer<'static, KeyPair>,
    /// The issuing CA's certificate: the root, or the intermediate.
    pub ca: CertificateDer<'static>,
    /// The issuing CA's key, which SCTs bind (RFC 9162 §4.7).
    pub ca_spki: Vec<u8>,
    /// The trust anchor's certificate and key; the issuing CA's without an
    /// intermediate.
    pub root: CertificateDer<'static>,
    pub root_spki: Vec<u8>,
    ee_key: KeyPair,
    params: CertificateParams,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, name);
    params
}

impl CtPki {
    pub fn new(sha256: Sha256) -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_spki = ca_key.subject_public_key_info();
        let issuer =
            CertifiedIssuer::self_signed(ca_params("browntls CT 2.0 test CA"), ca_key).unwrap();
        let ca = CertificateDer::from(issuer.der().to_vec());
        Self::issued_by(sha256, issuer, ca.clone(), ca_spki.clone(), ca, ca_spki)
    }

    /// A root CA, an intermediate CA it issued, and the server certificate
    /// the intermediate issues.
    pub fn with_intermediate(sha256: Sha256) -> Self {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_spki = root_key.subject_public_key_info();
        let root =
            CertifiedIssuer::self_signed(ca_params("browntls CT 2.0 test root"), root_key).unwrap();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let spki = key.subject_public_key_info();
        let params = ca_params("browntls CT 2.0 test intermediate");
        let issuer = CertifiedIssuer::signed_by(params, key, &root).unwrap();
        let ca = CertificateDer::from(issuer.der().to_vec());
        let root_der = CertificateDer::from(root.der().to_vec());
        Self::issued_by(sha256, issuer, ca, spki, root_der, root_spki)
    }

    fn issued_by(
        sha256: Sha256,
        issuer: CertifiedIssuer<'static, KeyPair>,
        ca: CertificateDer<'static>,
        ca_spki: Vec<u8>,
        root: CertificateDer<'static>,
        root_spki: Vec<u8>,
    ) -> Self {
        let names = ["localhost", "testserver.example"];
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        // Fixed, so that the certificate with and without extensions has
        // the same `TBSCertificate` otherwise.
        params.serial_number = Some(SerialNumber::from_slice(&[0x5c, 0x02, 0x03]));
        Self {
            sha256,
            issuer,
            ca,
            ca_spki,
            root,
            root_spki,
            ee_key: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
            params,
        }
    }

    /// The server chain, its end entity with `extensions` (arcs, value).
    pub fn chain_with(&self, extensions: &[(&[u64], Vec<u8>)]) -> Chain {
        let mut params = self.params.clone();
        for (arcs, value) in extensions {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(arcs, value.clone()));
        }
        let ee = params.signed_by(&self.ee_key, &*self.issuer).unwrap();
        Chain {
            key_type: KeyType::EcdsaP256,
            ca: self.ca.clone(),
            end_entity: CertificateDer::from(ee.der().to_vec()),
            end_entity_key: self.ee_key.serialize_der(),
            end_entity_spki: self.ee_key.subject_public_key_info(),
        }
    }

    /// The server chain without transparency extensions.
    pub fn chain(&self) -> Chain {
        self.chain_with(&[])
    }

    /// The chain with `items` in the end entity's Transparency
    /// Information extension (§7.1.2).
    pub fn embedded(&self, items: &[Vec<u8>]) -> Chain {
        self.chain_with(&[(TRANSPARENCY_ARCS, octet_string(&list(items)))])
    }

    /// The `TBSCertificate` of `cert`.
    pub fn tbs(cert: &CertificateDer<'_>) -> Vec<u8> {
        Cert::try_from(cert)
            .unwrap()
            .signed_data()
            .message()
            .to_vec()
    }

    /// The `x509_entry_v2` an SCT for `cert` signs.
    pub fn x509_entry(&self, cert: &CertificateDer<'_>, ts_ms: u64) -> Vec<u8> {
        entry(self.sha256, false, ts_ms, &self.ca_spki, &Self::tbs(cert))
    }

    /// An `x509_sct_v2` of `log` for `cert`.
    pub fn x509_sct(&self, log: &Log, cert: &CertificateDer<'_>) -> Vec<u8> {
        let ts = sct_time_ms();
        log.sct(false, ts, &self.x509_entry(cert, ts))
    }

    /// A `precert_sct_v2` of `log` for the precertificate: the end entity
    /// without transparency extensions (§8.1.2).
    pub fn precert_sct(&self, log: &Log) -> Vec<u8> {
        let ts = sct_time_ms();
        let tbs = Self::tbs(&self.chain().end_entity);
        log.sct(true, ts, &entry(self.sha256, true, ts, &self.ca_spki, &tbs))
    }

    /// A trust store with the root CA.
    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        Arc::new(roots)
    }

    /// A "good" OCSP response for `cert`, signed by the CA, with `info` in
    /// its Transparency Information single extension (§7.1.1).
    pub fn ocsp(&self, cert: &CertificateDer<'_>, info: Option<&[u8]>) -> Vec<u8> {
        let hashers = CertIdHashers {
            sha1: None,
            sha256: Some(self.sha256),
        };
        let leaf = Cert::try_from(cert).unwrap();
        let ca = Cert::try_from(&self.ca).unwrap();
        let cert_id = CertId::new(
            CertIdHash::Sha256,
            &hashers,
            &leaf,
            ca.subject_public_key_info().as_ref(),
        )
        .unwrap();
        let now = now_secs();
        let mut single = wire::Single::for_cert(&cert_id, now - 3600, now + 86400);
        if let Some(info) = info {
            single.extensions.push(wire::extension(
                browntls_pki::transparency::TRANSPARENCY_INFO_OID,
                false,
                &octet_string(info),
            ));
        }
        wire::Response {
            version: None,
            responder_id: wire::tlv(0xa1, &wire::tlv(0x30, ca.subject())),
            produced_at: now - 3600,
            singles: vec![single],
            extensions: Vec::new(),
            certs: Vec::new(),
        }
        .signed_by(self.issuer.key())
    }
}
