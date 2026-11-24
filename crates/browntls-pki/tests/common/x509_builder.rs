//! A small test-only DER builder for X.509 v3 certificates and v2 CRLs
//! (RFC 5280 §4.1 and §5.1), for keys `rcgen` cannot certify (ML-DSA,
//! RFC 9881) and for deliberately wrong encodings.
//!
//! Every field is plain data, so a test can replace any part before
//! signing (an algorithm identifier with parameters, a key of the wrong
//! length, an arbitrary OID), and [`Signed`] keeps the three parts of the
//! signed structure apart so the signature or its `BIT STRING` can be
//! altered afterwards. Only what the tests need is supported: names are a
//! single `commonName`, times are `GeneralizedTime`, and extensions are
//! basicConstraints, keyUsage, extKeyUsage, subjectAltName (dNSName),
//! subject and authority key identifiers, plus raw extensions.
//!
//! Include it together with `common/ml_dsa.rs` (as `crate::ml_dsa`).

#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::expect_used)]

use crate::ml_dsa::Key;

// ---------------------------------------------------------------------------
// DER primitives
// ---------------------------------------------------------------------------

/// A DER element with definite, minimal length (contents below 16 MiB).
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        0x100..=0xffff => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        _ => out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A `BIT STRING` with no unused bits.
pub fn bit_string(octets: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8][..], octets].concat())
}

/// An `INTEGER` from big-endian magnitude octets, made minimal and
/// non-negative.
pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len().saturating_sub(1));
    let mut v = magnitude[start..].to_vec();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

pub fn oid(arcs_encoded: &[u8]) -> Vec<u8> {
    tlv(0x06, arcs_encoded)
}

/// `GeneralizedTime` for a Unix timestamp.
pub fn time(secs: u64) -> Vec<u8> {
    let t = rcgen::date_time_ymd(1970, 1, 1) + core::time::Duration::from_secs(secs);
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    tlv(0x18, text.as_bytes())
}

/// A `Name` with one `commonName` (UTF8String).
pub fn name(common_name: &str) -> Vec<u8> {
    let atv = seq(&[
        &oid(&[0x55, 0x04, 0x03]),
        &tlv(0x0c, common_name.as_bytes()),
    ]);
    seq(&[&tlv(0x31, &atv)])
}

/// An `AlgorithmIdentifier` from its contents (OID and any parameters), as
/// the `alg_id` constants hold them.
pub fn alg(contents: &[u8]) -> Vec<u8> {
    tlv(0x30, contents)
}

/// A `SubjectPublicKeyInfo` from algorithm contents and raw key octets.
pub fn spki(alg_contents: &[u8], key: &[u8]) -> Vec<u8> {
    seq(&[&alg(alg_contents), &bit_string(key)])
}

/// The `SubjectPublicKeyInfo` of `key`.
pub fn spki_of(key: &Key) -> Vec<u8> {
    spki(key.key_alg().as_bytes(), &key.public_key())
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

/// `Extension { extnID, critical, extnValue }`.
pub fn extension(extn_id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut contents = oid(extn_id);
    if critical {
        contents.extend_from_slice(&[0x01, 0x01, 0xff]);
    }
    contents.extend_from_slice(&tlv(0x04, value));
    tlv(0x30, &contents)
}

/// `basicConstraints` (critical); `cA` FALSE is the DEFAULT, so omitted.
pub fn basic_constraints(ca: bool, path_len: Option<u8>) -> Vec<u8> {
    let mut contents = Vec::new();
    if ca {
        contents.extend_from_slice(&[0x01, 0x01, 0xff]);
    }
    if let Some(n) = path_len {
        contents.extend_from_slice(&integer(&[n]));
    }
    extension(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &contents))
}

/// `KeyUsage` bit numbers (RFC 5280 §4.2.1.3).
pub mod ku {
    pub const DIGITAL_SIGNATURE: u8 = 0;
    pub const NON_REPUDIATION: u8 = 1;
    pub const KEY_ENCIPHERMENT: u8 = 2;
    pub const DATA_ENCIPHERMENT: u8 = 3;
    pub const KEY_AGREEMENT: u8 = 4;
    pub const KEY_CERT_SIGN: u8 = 5;
    pub const CRL_SIGN: u8 = 6;
    pub const ENCIPHER_ONLY: u8 = 7;
    pub const DECIPHER_ONLY: u8 = 8;

    pub const NAMES: [&str; 9] = [
        "digitalSignature",
        "nonRepudiation",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
        "decipherOnly",
    ];
}

/// The DER `KeyUsage` `BIT STRING` contents for a set of bit numbers:
/// trailing zero bits removed and the unused-bit count set (X.690
/// §11.2.2). An empty set is `03 01 00`.
pub fn key_usage_bits(bits: &[u8]) -> Vec<u8> {
    let mut octets = [0u8; 2];
    for &bit in bits {
        octets[usize::from(bit / 8)] |= 0x80 >> (bit % 8);
    }
    let used = if octets[1] != 0 {
        2
    } else if octets[0] != 0 {
        1
    } else {
        0
    };
    let octets = &octets[..used];
    let unused = octets.last().map_or(0, |last| last.trailing_zeros() as u8);
    [&[unused][..], octets].concat()
}

/// `keyUsage` (critical) with the given bit numbers.
pub fn key_usage(bits: &[u8]) -> Vec<u8> {
    extension(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &key_usage_bits(bits)))
}

/// `id-kp-serverAuth` and `id-kp-clientAuth` (encoded arcs).
pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// `extKeyUsage` (not critical) with the given purposes.
pub fn ext_key_usage(purposes: &[&[u8]]) -> Vec<u8> {
    let oids: Vec<Vec<u8>> = purposes.iter().map(|p| oid(p)).collect();
    extension(&[0x55, 0x1d, 0x25], false, &tlv(0x30, &oids.concat()))
}

/// `subjectAltName` (not critical) with `dNSName` entries.
pub fn san_dns(names: &[&str]) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = names.iter().map(|n| tlv(0x82, n.as_bytes())).collect();
    extension(&[0x55, 0x1d, 0x11], false, &tlv(0x30, &entries.concat()))
}

/// `subjectKeyIdentifier`.
pub fn subject_key_id(id: &[u8]) -> Vec<u8> {
    extension(&[0x55, 0x1d, 0x0e], false, &tlv(0x04, id))
}

/// `authorityKeyIdentifier` with a `keyIdentifier` only.
pub fn authority_key_id(id: &[u8]) -> Vec<u8> {
    extension(&[0x55, 0x1d, 0x23], false, &seq(&[&tlv(0x80, id)]))
}

// ---------------------------------------------------------------------------
// Signed structures
// ---------------------------------------------------------------------------

/// The three parts of `SIGNED{ToBeSigned}`, kept apart so that tests can
/// alter any of them after signing.
#[derive(Clone, Debug)]
pub struct Signed {
    /// The complete DER `tbsCertificate` or `tbsCertList`.
    pub tbs: Vec<u8>,
    /// The outer `signatureAlgorithm` contents.
    pub alg: Vec<u8>,
    /// The signature `BIT STRING` contents, including the unused-bit
    /// count octet.
    pub bits: Vec<u8>,
}

impl Signed {
    /// Signs `tbs` with `key` and labels it with `alg`.
    pub fn new(tbs: Vec<u8>, alg: Vec<u8>, key: &Key) -> Self {
        let sig = key.sign(&tbs);
        Self {
            tbs,
            alg,
            bits: [&[0u8][..], &sig].concat(),
        }
    }

    /// The signature octets (without the unused-bit count).
    pub fn signature(&self) -> &[u8] {
        &self.bits[1..]
    }

    pub fn set_signature(&mut self, sig: &[u8]) {
        self.bits = [&[0u8][..], sig].concat();
    }

    pub fn der(&self) -> Vec<u8> {
        seq(&[&self.tbs, &alg(&self.alg), &tlv(0x03, &self.bits)])
    }
}

/// Flips the low bit of `bytes[index]`.
pub fn flip(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
    bytes[index] ^= 1;
    bytes
}

/// The offset of `needle` in `haystack` (first occurrence).
pub fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present")
}

/// Default validity: 2024-01-01 to 2034-01-01, around `common::NOW`.
pub const NOT_BEFORE: u64 = 1_704_067_200;
pub const NOT_AFTER: u64 = 2_019_686_400;

/// A v3 certificate to be signed by an issuer key. Every field is the DER
/// that goes into `tbsCertificate`, except `inner_alg`, which holds the
/// contents of the `signature` field (`None`: the issuer key's algorithm).
#[derive(Clone, Debug)]
pub struct CertSpec {
    pub serial: Vec<u8>,
    pub inner_alg: Option<Vec<u8>>,
    pub issuer: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub extensions: Vec<Vec<u8>>,
}

impl CertSpec {
    /// A CA certificate: `basicConstraints` cA TRUE without a path length
    /// and `keyUsage` keyCertSign and cRLSign.
    pub fn ca(subject: &str, issuer: &str, key: &Key) -> Self {
        Self::bare(subject, issuer, key).with(vec![
            basic_constraints(true, None),
            key_usage(&[ku::KEY_CERT_SIGN, ku::CRL_SIGN]),
        ])
    }

    /// An end-entity certificate for `example.com`: `basicConstraints`
    /// cA FALSE, `keyUsage` digitalSignature, `serverAuth` and a dNSName.
    pub fn ee(subject: &str, issuer: &str, key: &Key) -> Self {
        Self::bare(subject, issuer, key).with(vec![
            basic_constraints(false, None),
            key_usage(&[ku::DIGITAL_SIGNATURE]),
            ext_key_usage(&[SERVER_AUTH]),
            san_dns(&["example.com"]),
        ])
    }

    /// A certificate without extensions.
    pub fn bare(subject: &str, issuer: &str, key: &Key) -> Self {
        use sha2::Digest as _;
        let serial = sha2::Sha256::digest(subject.as_bytes())[..8].to_vec();
        Self {
            serial: integer(&serial),
            inner_alg: None,
            issuer: name(issuer),
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject: name(subject),
            spki: spki_of(key),
            extensions: Vec::new(),
        }
    }

    pub fn with(mut self, extensions: Vec<Vec<u8>>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Replaces the `keyUsage` extension (`None` removes it).
    pub fn key_usage(mut self, bits: Option<&[u8]>) -> Self {
        let ku_id = oid(&[0x55, 0x1d, 0x0f]);
        self.extensions.retain(|ext| !ext[2..].starts_with(&ku_id));
        if let Some(bits) = bits {
            self.extensions.push(key_usage(bits));
        }
        self
    }

    pub fn serial(mut self, magnitude: &[u8]) -> Self {
        self.serial = integer(magnitude);
        self
    }

    pub fn tbs(&self, issuer_key: &Key) -> Vec<u8> {
        let inner = self
            .inner_alg
            .clone()
            .unwrap_or_else(|| issuer_key.sig_alg().as_bytes().to_vec());
        let mut contents = [
            &tlv(0xa0, &[0x02, 0x01, 0x02])[..],
            &self.serial,
            &alg(&inner),
            &self.issuer,
            &seq(&[&time(self.not_before), &time(self.not_after)]),
            &self.subject,
            &self.spki,
        ]
        .concat();
        if !self.extensions.is_empty() {
            contents.extend_from_slice(&tlv(0xa3, &tlv(0x30, &self.extensions.concat())));
        }
        tlv(0x30, &contents)
    }

    /// Signs with `issuer_key`; the outer algorithm is the key's own.
    pub fn signed(&self, issuer_key: &Key) -> Signed {
        let outer = issuer_key.sig_alg().as_bytes().to_vec();
        Signed::new(self.tbs(issuer_key), outer, issuer_key)
    }

    pub fn sign(&self, issuer_key: &Key) -> Vec<u8> {
        self.signed(issuer_key).der()
    }
}

/// A v2 CRL to be signed by an issuer key (RFC 5280 §5.1), with the CRL
/// number extension this crate requires.
#[derive(Clone, Debug)]
pub struct CrlSpec {
    pub inner_alg: Option<Vec<u8>>,
    pub issuer: Vec<u8>,
    pub this_update: u64,
    pub next_update: u64,
    /// `(serial magnitude, revocation date)`.
    pub revoked: Vec<(Vec<u8>, u64)>,
    pub crl_number: u8,
}

impl CrlSpec {
    pub fn new(issuer: &str, this_update: u64, next_update: u64) -> Self {
        Self {
            inner_alg: None,
            issuer: name(issuer),
            this_update,
            next_update,
            revoked: Vec::new(),
            crl_number: 1,
        }
    }

    pub fn revoke(mut self, serial: &[u8], when: u64) -> Self {
        self.revoked.push((serial.to_vec(), when));
        self
    }

    pub fn tbs(&self, issuer_key: &Key) -> Vec<u8> {
        let inner = self
            .inner_alg
            .clone()
            .unwrap_or_else(|| issuer_key.sig_alg().as_bytes().to_vec());
        let mut contents = [
            &[0x02, 0x01, 0x01][..],
            &alg(&inner),
            &self.issuer,
            &time(self.this_update),
            &time(self.next_update),
        ]
        .concat();
        if !self.revoked.is_empty() {
            let entries: Vec<Vec<u8>> = self
                .revoked
                .iter()
                .map(|(serial, when)| seq(&[&integer(serial), &time(*when)]))
                .collect();
            contents.extend_from_slice(&tlv(0x30, &entries.concat()));
        }
        let crl_number = extension(&[0x55, 0x1d, 0x14], false, &integer(&[self.crl_number]));
        contents.extend_from_slice(&tlv(0xa0, &seq(&[&crl_number])));
        tlv(0x30, &contents)
    }

    pub fn signed(&self, issuer_key: &Key) -> Signed {
        let outer = issuer_key.sig_alg().as_bytes().to_vec();
        Signed::new(self.tbs(issuer_key), outer, issuer_key)
    }

    pub fn sign(&self, issuer_key: &Key) -> Vec<u8> {
        self.signed(issuer_key).der()
    }
}
