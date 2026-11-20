//! Fixtures shared by the RFC 9162 tests: CT version 2 logs with keys
//! generated at run time, an encoding of the signed structures written
//! independently of the implementation, a reference Merkle tree built from
//! the RFC 9162 §2.1 definitions, and a certificate issuer.
//!
//! `transparency.rs` and `transparency_merkle.rs` include this file as a
//! module beside `common`.

#![allow(
    dead_code,
    unreachable_pub,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub use crate::common::*;
pub use browntls_pki::transparency::*;
pub use browntls_pki::{Cert, CertificateDer, SignatureVerificationAlgorithm, UnixTime};
pub use rcgen::{
    CertificateParams, CertifiedIssuer, CustomExtension, KeyPair, PublicKeyData as _, SerialNumber,
    SigningKey as _,
};
use sha2::Digest as _;

/// 2024-05-01T00:00:00Z in milliseconds: before `NOW`.
pub const TIMESTAMP_MS: u64 = 1_714_521_600_000;

/// Arcs of the Transparency Information extension, 1.3.101.75.
pub const TRANSPARENCY_ARCS: &[u64] = &[1, 3, 101, 75];
/// Arcs of the version 1 embedded SCT list extension.
pub const SCT_LIST_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

pub fn digest(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// A DER `OCTET STRING` (contents shorter than 64 KiB).
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

// ---------------------------------------------------------------------------
// Encoding, written from the RFC 9162 presentation language
// ---------------------------------------------------------------------------

fn vec8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

fn vec16(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

/// A serialized `x509_entry_v2` or `precert_entry_v2` (§4.7): what an SCT
/// signs and a leaf hashes.
pub fn entry(
    precert: bool,
    timestamp_ms: u64,
    issuer_spki: &[u8],
    tbs: &[u8],
    ext: &[u8],
) -> Vec<u8> {
    let mut out = if precert { vec![1, 1] } else { vec![1, 0] };
    out.extend(timestamp_ms.to_be_bytes());
    vec8(&mut out, &digest(issuer_spki));
    out.extend(&(tbs.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(tbs);
    vec16(&mut out, ext);
    out
}

/// A serialized SCT item (§4.8).
pub fn sct_item(
    precert: bool,
    log_id: &[u8],
    timestamp_ms: u64,
    ext: &[u8],
    sig: &[u8],
) -> Vec<u8> {
    let mut out = if precert { vec![1, 3] } else { vec![1, 2] };
    vec8(&mut out, log_id);
    out.extend(timestamp_ms.to_be_bytes());
    vec16(&mut out, ext);
    vec16(&mut out, sig);
    out
}

/// A `TreeHeadDataV2` (§4.9).
pub fn tree_head(timestamp_ms: u64, tree_size: u64, root: &[u8; 32], ext: &[u8]) -> Vec<u8> {
    let mut out = timestamp_ms.to_be_bytes().to_vec();
    out.extend(tree_size.to_be_bytes());
    vec8(&mut out, root);
    vec16(&mut out, ext);
    out
}

fn path_vector(out: &mut Vec<u8>, path: &[[u8; 32]]) {
    let mut nodes = Vec::new();
    for node in path {
        vec8(&mut nodes, node);
    }
    vec16(out, &nodes);
}

/// A serialized `inclusion_proof_v2` (§4.12).
pub fn inclusion_item(
    log_id: &[u8],
    tree_size: u64,
    leaf_index: u64,
    path: &[[u8; 32]],
) -> Vec<u8> {
    let mut out = vec![1, 6];
    vec8(&mut out, log_id);
    out.extend(tree_size.to_be_bytes());
    out.extend(leaf_index.to_be_bytes());
    path_vector(&mut out, path);
    out
}

/// A serialized `consistency_proof_v2` (§4.11).
pub fn consistency_item(log_id: &[u8], first: u64, second: u64, path: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![1, 5];
    vec8(&mut out, log_id);
    out.extend(first.to_be_bytes());
    out.extend(second.to_be_bytes());
    path_vector(&mut out, path);
    out
}

/// A `TransItemList` (§6.3).
pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for item in items {
        vec16(&mut entries, item);
    }
    let mut out = Vec::new();
    vec16(&mut out, &entries);
    out
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

/// A CT version 2 log with its signing key.
pub struct Log {
    pub key: KeyPair,
    pub spki: Vec<u8>,
    /// The log ID: contents of 1.3.101.80.n.
    pub id: Vec<u8>,
}

impl Log {
    pub fn ecdsa(n: u8) -> Self {
        Self::new(&rcgen::PKCS_ECDSA_P256_SHA256, n)
    }

    pub fn ed25519(n: u8) -> Self {
        Self::new(&rcgen::PKCS_ED25519, n)
    }

    pub fn new(alg: &'static rcgen::SignatureAlgorithm, n: u8) -> Self {
        assert!(n < 0x80);
        let key = key_for(alg);
        let spki = key.subject_public_key_info();
        Self {
            key,
            spki,
            id: vec![0x2b, 0x65, 0x50, n],
        }
    }

    pub fn trusted(&self) -> CtV2Log<'_> {
        CtV2Log::new(&self.id, &self.spki).unwrap()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).unwrap()
    }

    /// A serialized SCT of this log over the entry.
    pub fn sct(
        &self,
        precert: bool,
        timestamp_ms: u64,
        issuer_spki: &[u8],
        tbs: &[u8],
        ext: &[u8],
    ) -> Vec<u8> {
        let signature = self.sign(&entry(precert, timestamp_ms, issuer_spki, tbs, ext));
        sct_item(precert, &self.id, timestamp_ms, ext, &signature)
    }

    /// A serialized signed tree head.
    pub fn sth(&self, timestamp_ms: u64, tree_size: u64, root: &[u8; 32], ext: &[u8]) -> Vec<u8> {
        let head = tree_head(timestamp_ms, tree_size, root, ext);
        let signature = self.sign(&head);
        let mut out = vec![1, 4];
        vec8(&mut out, &self.id);
        out.extend(head);
        vec16(&mut out, &signature);
        out
    }

    pub fn inclusion(&self, tree_size: u64, leaf_index: u64, path: &[[u8; 32]]) -> Vec<u8> {
        inclusion_item(&self.id, tree_size, leaf_index, path)
    }
}

// ---------------------------------------------------------------------------
// Reference Merkle tree (RFC 9162 §2.1.1, §2.1.3.1, §2.1.4.1)
// ---------------------------------------------------------------------------

pub fn leaf(data: &[u8]) -> [u8; 32] {
    digest(&[&[0u8][..], data].concat())
}

pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    digest(&[&[1u8][..], left, right].concat())
}

/// The largest power of two smaller than `n` (`n > 1`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// `MTH(D_n)`, recursively as §2.1.1 defines it.
pub fn mth(d: &[Vec<u8>]) -> [u8; 32] {
    match d.len() {
        0 => digest(&[]),
        1 => leaf(&d[0]),
        n => {
            let k = split(n);
            node(&mth(&d[..k]), &mth(&d[k..]))
        }
    }
}

/// `PATH(m, D_n)` (§2.1.3.1).
pub fn path(m: usize, d: &[Vec<u8>]) -> Vec<[u8; 32]> {
    let n = d.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut out = path(m, &d[..k]);
        out.push(mth(&d[k..]));
        out
    } else {
        let mut out = path(m - k, &d[k..]);
        out.push(mth(&d[..k]));
        out
    }
}

/// `PROOF(m, D_n)` (§2.1.4.1).
pub fn proof(m: usize, d: &[Vec<u8>]) -> Vec<[u8; 32]> {
    subproof(m, d, true)
}

fn subproof(m: usize, d: &[Vec<u8>], b: bool) -> Vec<[u8; 32]> {
    let n = d.len();
    if m == n {
        return if b { Vec::new() } else { vec![mth(d)] };
    }
    let k = split(n);
    if m <= k {
        let mut out = subproof(m, &d[..k], b);
        out.push(mth(&d[k..]));
        out
    } else {
        let mut out = subproof(m - k, &d[k..], false);
        out.push(mth(&d[..k]));
        out
    }
}

/// `n` distinct entries.
pub fn entries(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("entry {i}").into_bytes()).collect()
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// An issuer and an end-entity key, to issue the same certificate with and
/// without transparency extensions.
pub struct Ca {
    pub issuer: CertifiedIssuer<'static, KeyPair>,
    pub issuer_spki: Vec<u8>,
    pub ee_key: KeyPair,
    pub params: CertificateParams,
}

impl Ca {
    pub fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let issuer = CertifiedIssuer::self_signed(ca_params("ct v2 issuer"), key_for(alg)).unwrap();
        let issuer_spki = issuer.key().subject_public_key_info();
        let mut params = ee_params(&["ct2.example.com"]);
        params.serial_number = Some(SerialNumber::from_slice(&[0x5c, 0x02, 0x03]));
        Self {
            issuer,
            issuer_spki,
            ee_key: key_for(alg),
            params,
        }
    }

    pub fn issue(&self, params: &CertificateParams) -> CertificateDer<'static> {
        let cert = params.signed_by(&self.ee_key, &self.issuer).unwrap();
        cert.der().to_vec().into()
    }

    /// The certificate without transparency extensions.
    pub fn plain(&self) -> CertificateDer<'static> {
        self.issue(&self.params)
    }

    /// The `TBSCertificate` of a certificate.
    pub fn tbs(der: &CertificateDer<'_>) -> Vec<u8> {
        Cert::try_from(der)
            .unwrap()
            .signed_data()
            .message()
            .to_vec()
    }

    /// The `TBSCertificate` a log signs for the precertificate.
    pub fn precert_tbs(&self) -> Vec<u8> {
        Self::tbs(&self.plain())
    }

    /// The certificate with the given extensions (arcs, `extnValue`).
    pub fn with_extensions(&self, extensions: &[(&[u64], Vec<u8>)]) -> CertificateDer<'static> {
        let mut params = self.params.clone();
        for (arcs, value) in extensions {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(arcs, value.clone()));
        }
        self.issue(&params)
    }

    /// A `precert_sct_v2` of `log` for this certificate.
    pub fn precert_sct(&self, log: &Log, timestamp_ms: u64) -> Vec<u8> {
        log.sct(
            true,
            timestamp_ms,
            &self.issuer_spki,
            &self.precert_tbs(),
            b"",
        )
    }

    /// The certificate with `items` in its Transparency Information
    /// extension.
    pub fn with_embedded(&self, items: &[Vec<u8>]) -> CertificateDer<'static> {
        self.with_extensions(&[(TRANSPARENCY_ARCS, octet_string(&list(items)))])
    }
}

pub fn policy<'a>(logs: &'a [CtV2Log<'a>], options: CtV2Options) -> CtV2Policy<'a> {
    CtV2Policy {
        logs,
        trusted_tree_heads: &[],
        supported_sig_algs: ALGS,
        sha256: digest,
        options,
    }
}

/// The default options, edited: `CtV2Options` is non-exhaustive.
pub fn options(edit: impl FnOnce(&mut CtV2Options)) -> CtV2Options {
    let mut options = CtV2Options::default();
    edit(&mut options);
    options
}

pub fn report(edit: impl FnOnce(&mut CtV2Report)) -> CtV2Report {
    let mut report = CtV2Report::default();
    edit(&mut report);
    report
}
