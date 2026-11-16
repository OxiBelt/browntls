//! `browntls-pki` public API (`fuzz_targets/pki_api.rs`): the functions the
//! parser targets (`pki_cert`, `pki_pem`, `pki_crl`) do not reach, or reach
//! only with stand-in signature algorithms.
//!
//! Reaches `server_name.rs` (`ServerName`, `DnsName`, `IpAddr`), `time.rs`,
//! `alg_id.rs` (with the `id-RSASSA-PSS` canonical forms), the DER and
//! secret key containers of `types.rs`, the `PemObject` impls of `pem.rs`,
//! and `verify.rs` and `crl.rs` with the real signature algorithms of both
//! `browntls` providers.
//!
//! Input: up to 64 operations, each an operation byte followed by that
//! operation's arguments (bytes, 16-bit length-prefixed fields, 8-bit
//! length-prefixed short fields), until the input or a cost budget runs
//! out. Checked properties:
//!
//! * `IpAddr` parsing and formatting agree with `std::net` (IPv4-mapped
//!   addresses aside, which `std` prints in mixed notation); `DnsName`
//!   accepts exactly the documented syntax; `ServerName` prefers an IP
//!   address; owned, borrowed, lower-cased and re-parsed forms compare and
//!   hash equal;
//! * `UnixTime` keeps whole seconds and orders like them;
//! * `id-RSASSA-PSS` parameters built field by field canonicalise as a
//!   model of RFC 4055 and the module's rules predicts, and
//!   `matches_public_key`/`matches_signature` follow the canonical forms;
//! * DER and key containers keep their bytes through every conversion, and
//!   PEM written by an independent Base64 encoder decodes to them by kind;
//! * `EndEntityCert::verify_for_usage` over the fixture chains (roots,
//!   intermediates, times, usages, algorithm subsets, CRLs and revocation
//!   policies, path callbacks) succeeds exactly when a model of RFC 5280
//!   path validation says so, and a corrupted certificate never verifies;
//! * signatures by both providers' signing keys verify through
//!   `RawPublicKeyEntity` and the key's certificate alike, with the
//!   scheme's algorithms, never with another key type's, never tampered;
//! * the fixture CRLs read the same borrowed and owned, verify with their
//!   issuer's key only, and never verify once corrupted.
//!
//! Keys, certificates and CRLs come from the `tls_config` fixtures,
//! generated once per process.

use crate::input::Input;
use crate::input::{put_field, put_short_field};

mod chains;
mod names;
mod values;

/// An operation: its harness and its cost against the per-input budget, in
/// units of about 100 µs of release-build time (the slowest seed).
type Op = (fn(&mut Input<'_>), u32);

const OPS: &[Op] = &[
    (names::name_op, 1),
    (values::time_op, 1),
    (values::alg_id_op, 1),
    (values::pss_op, 1),
    (values::types_op, 1),
    (values::pem_op, 1),
    (chains::cert_op, 1),
    (chains::path_op, 7),
    (chains::signature_op, 25),
    (chains::crl_op, 12),
];

/// Operation numbers, in [`OPS`] order.
mod op {
    pub const NAME: u8 = 0;
    pub const TIME: u8 = 1;
    pub const ALG_ID: u8 = 2;
    pub const PSS: u8 = 3;
    pub const TYPES: u8 = 4;
    pub const PEM: u8 = 5;
    pub const CERT: u8 = 6;
    pub const PATH: u8 = 7;
    pub const SIGNATURE: u8 = 8;
    pub const CRL: u8 = 9;
}

/// The `pki_api` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    // About 6 ms per input.
    let mut budget = 60u32;
    for _ in 0..64 {
        if input.is_empty() {
            break;
        }
        let (op, cost) = OPS[input.choose(OPS.len())];
        if cost > budget {
            break;
        }
        budget -= cost;
        op(&mut input);
    }
}

/// Splits one DER TLV off `data`: its tag, contents and what follows.
fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Encodes a DER TLV (contents shorter than 64 KiB).
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// Seconds from the epoch to midnight UTC of a proleptic Gregorian date
/// (Howard Hinnant's `days_from_civil`), for dates from 1970.
const fn unix_date(year: i64, month: i64, day: i64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    ((era * 146_097 + doe - 719_468) * 86_400) as u64
}

fn field(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_field(&mut out, bytes);
    out
}

fn short(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_short_field(&mut out, bytes);
    out
}

/// The arguments of [`values::pss_op`].
#[allow(clippy::too_many_arguments)]
fn pss_args(
    hash: u8,
    null: bool,
    mgf: u8,
    mgf_hash: u8,
    salt: Option<u16>,
    trailer: Option<u8>,
    corrupt: Option<[u8; 2]>,
) -> Vec<u8> {
    let mut out = vec![1, hash, u8::from(null), mgf, mgf_hash, u8::from(null)];
    out.push(u8::from(salt.is_some()));
    out.extend(salt.map(u16::to_be_bytes).into_iter().flatten());
    out.push(u8::from(trailer.is_some()));
    out.extend(trailer);
    out.push(u8::from(corrupt.is_some()));
    out.extend(corrupt.into_iter().flatten());
    out
}

/// Starting inputs for `pki_api`: each operation with interesting
/// arguments, one operation per seed.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let mut add = |op: u8, parts: &[&[u8]]| {
        let mut seed = vec![op];
        for part in parts {
            seed.extend_from_slice(part);
        }
        seeds.push(seed);
    };

    // Names: raw strings, then generated IPv6 (flags, group count, groups,
    // `::` position, IPv4 tail), IPv4 (flags, octets, edits) and DNS
    // names (flags, label count, label lengths and characters).
    for name in [
        &b"localhost"[..],
        b"Example.COM.",
        b"a_b.example",
        b"-bad.example",
        b"1.2.3.4",
        b"01.2.3.4",
        b"::1",
        b"::ffff:192.0.2.1",
        b"2001:db8::8:800:200c:417a",
        b"1:2:3:4:5:6:7::",
        b"fe80::1%eth0",
        b"\xff\xfe",
        b"123",
        b"",
    ] {
        add(op::NAME, &[&[0], &short(name)]);
    }
    let groups: Vec<u8> = (1..=16).collect();
    add(op::NAME, &[&[1, 0, 8], &groups]);
    add(op::NAME, &[&[1, 4, 8], &groups]);
    add(op::NAME, &[&[1, 8, 6], &groups[..12], &[192, 0, 2, 1]]);
    add(op::NAME, &[&[1, 2, 3], &groups[..6], &[1]]);
    add(op::NAME, &[&[1, 3, 1, 0xff, 0xff, 1, 192, 0, 2, 1]]);
    add(op::NAME, &[&[1, 2, 2, 0, 0, 0, 0, 1]]);
    add(op::NAME, &[&[1, 2, 0, 0]]);
    add(op::NAME, &[&[1, 0x12, 2, 0, 1, 0, 2, 1, 3, 0]]);
    for flags in [0u8, 1, 2, 4] {
        add(op::NAME, &[&[2, flags, 192, 0, 2, 1, 3, 7, 3, 1]]);
    }
    for flags in [0u8, 1, 2, 4, 8] {
        add(op::NAME, &[&[3, flags, 2, 3, 0, 1, 2, 4, 9, 10, 3, 4]]);
    }

    // Times: (choice, fuzzed seconds, nanoseconds) twice.
    add(op::TIME, &[&[2, 0x3b, 0x9a, 0xc9, 0xff, 3, 0, 0, 0, 0]]);
    add(
        op::TIME,
        &[&[5], &u64::MAX.to_be_bytes(), &[0, 0, 0, 1, 0, 0, 0, 0, 0]],
    );

    // Algorithm identifiers: every constant against another, then fuzzed
    // identifiers after the RSASSA-PSS OID.
    for a in 0..values::ALG_IDS.len() as u8 {
        add(op::ALG_ID, &[&[a, 13 - a % 3], &short(&[]), &[0]]);
    }
    add(
        op::ALG_ID,
        &[&[10, 10], &short(&[0x30, 0x03, 0xa2, 0x01, 0x00]), &[1]],
    );

    // RSASSA-PSS parameters: hash and MGF hash (1 SHA-1 .. 5 SHA-512),
    // NULL parameters, MGF (1 MGF1, 2 other), salt, trailer, corruption.
    for args in [
        pss_args(3, true, 1, 3, Some(32), None, None),
        pss_args(4, false, 1, 4, Some(48), Some(1), None),
        pss_args(5, true, 1, 5, None, None, None),
        pss_args(3, true, 1, 3, Some(20), None, None),
        pss_args(3, true, 1, 4, Some(32), None, None),
        pss_args(1, true, 1, 1, None, None, None),
        pss_args(3, true, 2, 3, Some(32), None, None),
        pss_args(5, true, 1, 5, Some(260), None, None),
        pss_args(3, true, 1, 3, Some(16), Some(2), None),
        pss_args(3, true, 1, 3, Some(33), None, None),
        pss_args(3, true, 1, 3, Some(32), None, Some([12, 0x10])),
        pss_args(0, false, 0, 0, None, None, None),
    ] {
        add(op::PSS, &[&args]);
    }
    add(op::PSS, &[&[0; 9]]);

    // Containers, then PEM: label, wrapping, damage, bytes.
    add(op::TYPES, &[&field(b"\x30\x03\x02\x01\x05")]);
    add(op::TYPES, &[&field(&[0xa5; 300])]);
    for kind in 0..8u8 {
        add(op::PEM, &[&[kind, kind % 3, kind % 5], &field(&[kind; 50])]);
    }
    add(op::PEM, &[&[0, 0, 0], &field(b"")]);

    // Certificates: each fixture certificate with a name, then corrupted.
    for c in 0..6u8 {
        add(op::CERT, &[&[c, 0, c]]);
    }
    add(op::CERT, &[&[0, 0, 9], &short(b"x.wild.example")]);
    add(op::CERT, &[&[0, 1, 0, 40, 3, 0]]);

    // Paths: end entity, corrupted, roots, intermediates, time, usage,
    // algorithms, CRLs (only with a provider's algorithms), owned, depth,
    // unknown status, expiry, callback.
    let paths: &[&[u8]] = &[
        &[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 1, 1, 0, 2, 1, 0, 0, 0, 0, 0, 1],
        &[1, 0, 4, 0, 0, 0, 1, 1, 0, 1, 1, 0, 3],
        &[1, 0, 5, 9, 0, 1, 0, 1, 3, 0, 1, 0, 3],
        &[2, 0, 3, 2, 3, 5, 0, 0, 0, 0, 0, 0, 0],
        &[3, 0, 1, 0, 4, 4, 1, 3, 1, 1, 0, 0, 1],
        &[0, 0, 1, 0, 0, 3, 0, 2, 0, 1, 0, 0, 2],
        &[2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        &[3, 0, 1, 0, 3, 1, 1, 1, 1, 1, 0, 0, 0],
        &[0, 0, 1, 0, 6, 0, 0, 1, 1, 0, 0, 1, 0],
        &[0, 0, 1, 0, 5, 0, 0, 3, 0, 0, 0, 1, 0],
        &[4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[5, 0, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0, 1, 0, 9, 0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 1, 5, 0, 30, 7, 0, 2, 0, 0, 0, 0, 0, 0],
        &[0, 0, 1, 0, 0, 0, 0, 4, 1, 0, 30, 3, 0, 0, 0, 0, 0],
    ];
    for path in paths {
        add(op::PATH, &[path]);
    }
    add(
        op::PATH,
        &[&[0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0x08], &[0, 0, 0, 0, 0]],
    );
    add(
        op::PATH,
        &[&[3, 0, 1, 0, 9], &[0; 8], &[0, 2, 0, 0, 0, 2, 0, 0, 0, 0]],
    );

    // Signatures: every key and scheme, then tampered and fuzzed.
    for s in 0..chains::signature_count() as u8 {
        add(op::SIGNATURE, &[&[s, 0, s & 1]]);
    }
    for tamper in 1..5u8 {
        add(
            op::SIGNATURE,
            &[&[tamper * 3, tamper, 0, 9, 4], &field(&[0x30, 2, 1, 1])],
        );
    }
    add(
        op::SIGNATURE,
        &[
            &[0, 5],
            &field(&[0x30, 0x03, 0x30, 0x01, 0x00]),
            &field(b"sig"),
        ],
    );

    // CRLs: both fixture CRLs borrowed and owned, a fuzzed serial number,
    // a provider; then corrupted.
    for c in 0..4u8 {
        add(
            op::CRL,
            &[&[c, 0], &short(&[0x11, 0x22, 0x33, 0x44]), &[c >> 1]],
        );
    }
    add(op::CRL, &[&[1, 0], &short(&[0x7b, 4, 5, 6]), &[1]]);
    add(op::CRL, &[&[1, 1, 0, 30, 1], &short(&[]), &[0]]);
    add(op::CRL, &[&[2, 1, 0, 200, 4], &short(&[]), &[1]]);

    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(unix_date(1970, 1, 1), 0);
        assert_eq!(unix_date(2000, 3, 1), 951_868_800);
        assert_eq!(unix_date(2026, 11, 15), 1_794_700_800);
    }

    #[test]
    fn der_lengths() {
        for n in [0usize, 0x7f, 0x80, 0xff, 0x100, 0x1234] {
            let v = vec![7u8; n];
            let enc = der(0x04, &v);
            assert_eq!(tlv(&enc), Some((0x04, &v[..], &[][..])));
        }
    }
}
