//! Shared fixture encoder for issuer-signed OCSP responses.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use core::time::Duration;

use browntls_pki::{
    alg_id,
    ocsp::{CertId, oid},
};
use rcgen::{KeyPair, SigningKey as _};

pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match contents.len() {
        len @ 0..=0x7f => out.push(len as u8),
        len @ 0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        len @ 0x100..=0xffff => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        len => out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn generalized_time(secs: u64) -> Vec<u8> {
    let t = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(secs);
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

/// `Extension { extnID, critical, extnValue }`.
pub fn extension(extn_id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut contents = tlv(0x06, extn_id);
    if critical {
        contents.extend_from_slice(&[0x01, 0x01, 0xff]);
    }
    contents.extend_from_slice(&tlv(0x04, value));
    tlv(0x30, &contents)
}

pub const GOOD: &[u8] = &[0x80, 0x00];
pub const UNKNOWN: &[u8] = &[0x82, 0x00];

pub fn revoked(time: u64, reason: Option<u8>) -> Vec<u8> {
    let mut info = generalized_time(time);
    if let Some(reason) = reason {
        info.extend_from_slice(&tlv(0xa0, &[0x0a, 0x01, reason]));
    }
    tlv(0xa1, &info)
}

#[derive(Clone)]
pub struct Single {
    pub cert_id: Vec<u8>,
    pub status: Vec<u8>,
    pub this_update: Vec<u8>,
    pub next_update: Option<u64>,
    pub extensions: Vec<Vec<u8>>,
}

impl Single {
    pub fn for_cert(cert_id: &CertId, this_update: u64, next_update: u64) -> Self {
        Self {
            cert_id: cert_id.to_der(),
            status: GOOD.to_vec(),
            this_update: generalized_time(this_update),
            next_update: Some(next_update),
            extensions: Vec::new(),
        }
    }

    pub fn der(&self) -> Vec<u8> {
        let mut contents = [&self.cert_id[..], &self.status, &self.this_update].concat();
        if let Some(next_update) = self.next_update {
            contents.extend_from_slice(&tlv(0xa0, &generalized_time(next_update)));
        }
        if !self.extensions.is_empty() {
            contents.extend_from_slice(&tlv(0xa1, &tlv(0x30, &self.extensions.concat())));
        }
        tlv(0x30, &contents)
    }
}

#[derive(Clone)]
pub struct Response {
    pub version: Option<u8>,
    pub responder_id: Vec<u8>,
    pub produced_at: u64,
    pub singles: Vec<Single>,
    pub extensions: Vec<Vec<u8>>,
    pub certs: Vec<Vec<u8>>,
}

impl Response {
    pub fn tbs(&self) -> Vec<u8> {
        let mut contents = Vec::new();
        if let Some(version) = self.version {
            contents.extend_from_slice(&tlv(0xa0, &[0x02, 0x01, version]));
        }
        contents.extend_from_slice(&self.responder_id);
        contents.extend_from_slice(&generalized_time(self.produced_at));
        let singles: Vec<Vec<u8>> = self.singles.iter().map(Single::der).collect();
        contents.extend_from_slice(&tlv(0x30, &singles.concat()));
        if !self.extensions.is_empty() {
            contents.extend_from_slice(&tlv(0xa1, &tlv(0x30, &self.extensions.concat())));
        }
        tlv(0x30, &contents)
    }

    /// The complete `OCSPResponse`, signed with ECDSA P-256 and SHA-256.
    pub fn signed_by(&self, key: &KeyPair) -> Vec<u8> {
        let tbs = self.tbs();
        let signature = [&[0u8][..], &key.sign(&tbs).unwrap()].concat();
        let mut basic = [
            &tbs[..],
            &tlv(0x30, alg_id::ECDSA_SHA256.as_bytes()),
            &tlv(0x03, &signature),
        ]
        .concat();
        if !self.certs.is_empty() {
            basic.extend_from_slice(&tlv(0xa0, &tlv(0x30, &self.certs.concat())));
        }
        successful(&tlv(0x30, &basic))
    }
}

/// Wraps a `BasicOCSPResponse` in a successful `OCSPResponse`.
pub fn successful(basic: &[u8]) -> Vec<u8> {
    let bytes = seq(&[&tlv(0x06, oid::BASIC_RESPONSE), &tlv(0x04, basic)]);
    seq(&[&[0x0a, 0x01, 0x00], &tlv(0xa0, &bytes)])
}
