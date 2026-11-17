//! X.501 names (`Name`, `RelativeDistinguishedName`,
//! `AttributeTypeAndValue`): names encoded from the input by a model DER
//! encoder, and the issuers and subjects of the inspected certificates,
//! mutated. A name is accepted exactly when the model of `Name`'s rules
//! accepts it (DER structure and minimal lengths, sets in strictly
//! ascending DER order, value tags in their X.690 form; value contents are
//! not parsed), and an accepted name re-encodes to its input.

use std::cmp::Ordering;

use browntls_pki::name::attribute_type;
use browntls_pki::{AttributeTypeAndValue, Cert, Name};

use super::chains::corrupt;
use super::{der, inspect};
use crate::input::Input;

/// An attribute: type OID contents, value tag, value contents.
pub(super) type Attr = (Vec<u8>, u8, Vec<u8>);

/// X.690 §11.6: encodings compare as octet strings, the shorter padded
/// with zero octets.
fn der_order(a: &[u8], b: &[u8]) -> Ordering {
    (0..a.len().max(b.len()))
        .map(|i| {
            let (x, y) = (
                a.get(i).copied().unwrap_or(0),
                b.get(i).copied().unwrap_or(0),
            );
            x.cmp(&y)
        })
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

fn encode_attr((oid, tag, value): &Attr) -> Vec<u8> {
    let mut body = der(0x06, oid);
    body.extend(der(*tag, value));
    der(0x30, &body)
}

/// The contents of a `RelativeDistinguishedName` `SET OF`, in DER order.
pub(super) fn encode_rdn(attrs: &[Attr]) -> Vec<u8> {
    let mut encodings: Vec<_> = attrs.iter().map(encode_attr).collect();
    encodings.sort_by(|a, b| der_order(a, b));
    encodings.concat()
}

/// The contents of a `Name` `SEQUENCE`.
pub(super) fn encode(rdns: &[Vec<Attr>]) -> Vec<u8> {
    rdns.iter()
        .flat_map(|rdn| der(0x31, &encode_rdn(rdn)))
        .collect()
}

/// A parsed name encoded again from its parts.
fn reencode(name: &Name<'_>) -> Vec<u8> {
    name.iter()
        .flat_map(|rdn| {
            let attrs: Vec<u8> = rdn.iter().flat_map(|a| encode_attr(&parts(&a))).collect();
            der(0x31, &attrs)
        })
        .collect()
}

fn parts(a: &AttributeTypeAndValue<'_>) -> Attr {
    (a.oid().to_vec(), a.value_tag(), a.value().to_vec())
}

/// Well-formed `OBJECT IDENTIFIER` contents (X.690 §8.19).
fn oid_ok(oid: &[u8]) -> bool {
    let mut start = true;
    for &b in oid {
        if start && b == 0x80 {
            return false;
        }
        start = b & 0x80 == 0;
    }
    !oid.is_empty() && start
}

/// A value tag strict DER allows: low tag number, not universal 0, and the
/// form universal types require.
fn tag_ok(tag: u8) -> bool {
    if tag & 0x1f == 0x1f {
        return false;
    }
    if tag & 0xc0 != 0 {
        return true;
    }
    let constructed = tag & 0x20 != 0;
    match tag & 0x1f {
        0 => false,
        8 | 11 | 16 | 17 | 29 => constructed,
        _ => !constructed,
    }
}

/// The string a value decodes to, per X.680.
fn model_str(tag: u8, value: &[u8]) -> Option<&str> {
    let printable = |b: &u8| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b);
    let ok = match tag {
        0x0c => true,
        0x12 => value.iter().all(|b| b.is_ascii_digit() || *b == b' '),
        0x13 => value.iter().all(printable),
        0x16 => value.iter().all(u8::is_ascii),
        0x1a => value.iter().all(|b| (0x20..0x7f).contains(b)),
        _ => false,
    };
    ok.then(|| std::str::from_utf8(value).ok()).flatten()
}

/// Name contents from anywhere: parsing agrees with and without the outer
/// `SEQUENCE`, and an accepted name re-encodes to its input (minimal
/// lengths, nothing left over; attribute values are compared as elements,
/// their contents are not parsed), keeps its sets in strictly ascending DER
/// order (no repeated attribute) and decodes strings like the model.
pub(super) fn check_contents(contents: &[u8]) {
    let parsed = Name::from_contents(contents);
    if contents.len() <= 0xffff {
        let wrapped = der(0x30, contents);
        assert_eq!(Name::from_der(&wrapped).is_ok(), parsed.is_ok());
    }
    let Ok(name) = parsed else {
        return;
    };
    assert_eq!(reencode(&name), contents);
    let mut count = 0;
    for rdn in &name {
        let attrs: Vec<_> = rdn.iter().collect();
        assert!(!attrs.is_empty());
        for pair in attrs.windows(2) {
            let (a, b) = (encode_attr(&parts(&pair[0])), encode_attr(&parts(&pair[1])));
            assert!(der_order(&a, &b).is_lt(), "ordered, no repeat");
        }
        for a in &attrs {
            assert!(oid_ok(a.oid()) && tag_ok(a.value_tag()));
            assert_eq!(a.as_str(), model_str(a.value_tag(), a.value()));
        }
        count += attrs.len();
    }
    assert_eq!(name.attributes().count(), count);
    let _ = format!("{name:?}");
}

const OIDS: [&[u8]; 6] = [
    attribute_type::COMMON_NAME,
    attribute_type::COUNTRY_NAME,
    attribute_type::ORGANIZATION_NAME,
    attribute_type::DOMAIN_COMPONENT,
    attribute_type::EMAIL_ADDRESS,
    attribute_type::SERIAL_NUMBER,
];

/// Value tags: the string types, structured and context-specific values,
/// and forms strict DER forbids (constructed string, primitive SEQUENCE,
/// universal 0, high tag number).
const TAGS: [u8; 14] = [
    0x0c, 0x12, 0x13, 0x16, 0x1a, 0x14, 0x1e, 0x1c, 0x30, 0xa0, 0x2c, 0x10, 0x00, 0x1f,
];

const VALUES: [&[u8]; 6] = [b"FI", b"a b", "é".as_bytes(), b"a&b", b"1 2", b""];

/// A name: generated from the input (RDN count, then per RDN an attribute
/// count, whether to reverse the DER order, and each attribute's type, tag
/// and value), or a certificate's issuer or subject, mutated.
pub(super) fn dn_op(input: &mut Input<'_>) {
    if input.bool() {
        return mutated(input);
    }
    let mut rdns: Vec<Vec<Attr>> = Vec::new();
    let mut valid = true;
    let mut contents = Vec::new();
    for _ in 0..input.choose(5) {
        let count = input.choose(4);
        let reverse = input.bool();
        let attrs: Vec<Attr> = (0..count)
            .map(|_| {
                let oid = match input.choose(OIDS.len() + 1) {
                    i if i < OIDS.len() => OIDS[i].to_vec(),
                    _ => input.short_field().to_vec(),
                };
                let tag = match input.choose(TAGS.len() + 1) {
                    i if i < TAGS.len() => TAGS[i],
                    _ => input.byte(),
                };
                let value = match input.choose(VALUES.len() + 1) {
                    i if i < VALUES.len() => VALUES[i].to_vec(),
                    _ => input.short_field().to_vec(),
                };
                valid &= oid_ok(&oid) && tag_ok(tag);
                (oid, tag, value)
            })
            .collect();
        valid &= !attrs.is_empty();
        let mut encodings: Vec<_> = attrs.iter().map(encode_attr).collect();
        encodings.sort_by(|a, b| der_order(a, b));
        let mut order: Vec<usize> = (0..attrs.len()).collect();
        order.sort_by(|&a, &b| der_order(&encode_attr(&attrs[a]), &encode_attr(&attrs[b])));
        if reverse {
            encodings.reverse();
            order.reverse();
        }
        // Strictly ascending: in DER order, and no attribute repeated.
        valid &= encodings
            .windows(2)
            .all(|w| der_order(&w[0], &w[1]).is_lt());
        contents.extend(der(0x31, &encodings.concat()));
        rdns.push(order.into_iter().map(|i| attrs[i].clone()).collect());
    }

    let parsed = Name::from_contents(&contents);
    assert_eq!(parsed.is_ok(), valid, "{contents:02x?}");
    if let Ok(name) = parsed {
        let read: Vec<Vec<Attr>> = name
            .iter()
            .map(|rdn| rdn.iter().map(|a| parts(&a)).collect())
            .collect();
        assert_eq!(read, rdns);
    }
    check_contents(&contents);
    // A valid name is the model's canonical encoding of its attributes.
    if valid {
        assert_eq!(encode(&rdns), contents);
    }
}

/// An inspected certificate's issuer or subject: corrupted, truncated,
/// extended, or as it is (then it parses).
fn mutated(input: &mut Input<'_>) {
    let cert = Cert::try_from(inspect::cert(input.choose(inspect::CERT_COUNT)))
        .expect("inspected certificates parse");
    let mut bytes = if input.bool() {
        cert.issuer()
    } else {
        cert.subject()
    }
    .to_vec();
    match input.choose(4) {
        0 if !bytes.is_empty() => corrupt(input, &mut bytes),
        1 => bytes.truncate(usize::from(input.u16()) % (bytes.len() + 1)),
        2 => {
            let at = usize::from(input.u16()) % (bytes.len() + 1);
            bytes.insert(at, input.byte());
        }
        _ => assert!(Name::from_contents(&bytes).is_ok()),
    }
    check_contents(&bytes);
}
