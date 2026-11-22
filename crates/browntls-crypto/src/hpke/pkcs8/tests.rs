//! Synthetic PKCS#8 and BER fixtures for the HPKE import boundary.
#![allow(clippy::unwrap_used)]

use std::vec;
use std::vec::Vec;

use super::*;
use crate::der;

fn tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![t];
    match u16::try_from(value.len()).unwrap().to_be_bytes() {
        [0, n @ 0..=127] => out.push(n),
        [0, n] => out.extend([0x81, n]),
        [high, low] => out.extend([0x82, high, low]),
    }
    out.extend(value);
    out
}

fn indefinite(t: u8, children: &[u8]) -> Vec<u8> {
    [[t, 0x80].as_slice(), children, &[0, 0]].concat()
}

fn algorithm(oid: &[u8], params: &[u8]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &[&tlv(tag::OID, oid)[..], params].concat())
}

fn key_info(version: u8, alg: &[u8], private: &[u8], optional: &[u8]) -> Vec<u8> {
    tlv(
        tag::SEQUENCE,
        &[&[tag::INTEGER, 1, version], alg, private, optional].concat(),
    )
}

fn ec_value(scalar: &[u8], optional: &[u8]) -> Vec<u8> {
    tlv(
        tag::SEQUENCE,
        &[
            &[tag::INTEGER, 1, 1],
            &tlv(tag::OCTET_STRING, scalar)[..],
            optional,
        ]
        .concat(),
    )
}

fn bit_string(t: u8, public: &[u8]) -> Vec<u8> {
    tlv(t, &[&[0][..], public].concat())
}

fn segmented_octets(bytes: &[u8]) -> Vec<u8> {
    let mid = bytes.len() / 2;
    // Mix definite and indefinite lengths, including non-minimal BER length.
    let segment = [
        &[tag::OCTET_STRING, 0x82, 0, u8::try_from(mid).unwrap()][..],
        &bytes[..mid],
    ]
    .concat();
    indefinite(
        0x24,
        &[segment, tlv(0x24, &tlv(tag::OCTET_STRING, &bytes[mid..]))].concat(),
    )
}

fn segmented_public(t: u8, public: &[u8]) -> Vec<u8> {
    let mid = public.len() / 2;
    indefinite(
        t,
        &[
            bit_string(tag::BIT_STRING, &public[..mid]),
            tlv(0x23, &bit_string(tag::BIT_STRING, &public[mid..])),
        ]
        .concat(),
    )
}

fn fixture(kem: Kem) -> (PrivateKey, Vec<u8>, Vec<u8>) {
    let n = kem.private_key_len();
    if let Some(curve) = named_curve(kem) {
        let mut raw = vec![0; n];
        raw[n - 1] = 1;
        (
            PrivateKey::from_bytes(kem, &raw).unwrap(),
            algorithm(ID_EC_PUBLIC_KEY, &tlv(tag::OID, curve)),
            raw,
        )
    } else {
        let raw = vec![0xff; n];
        let oid = if kem == Kem::DhX25519HkdfSha256 {
            ID_X25519
        } else {
            ID_X448
        };
        (
            PrivateKey::from_bytes(kem, &raw).unwrap(),
            algorithm(oid, &[]),
            raw,
        )
    }
}

fn encoded(key: &PrivateKey) -> Vec<u8> {
    let mut out = vec![0; MAX_PKCS8_DER_LEN];
    let len = key.to_pkcs8_der(&mut out).unwrap();
    out.truncate(len);
    out
}

fn assert_key(input: &[u8], expected: &PrivateKey) {
    let actual = PrivateKey::from_pkcs8_der_or_ber(input).unwrap();
    assert_eq!(actual.kem(), expected.kem());
    assert_eq!(actual.public_key(), expected.public_key());
    assert_eq!(actual.pkcs8_uses_ecdh_oid(), expected.pkcs8_uses_ecdh_oid());
    assert_eq!(encoded(&actual), encoded(expected));
}

fn rejected(input: &[u8]) {
    assert!(PrivateKey::from_pkcs8_der_or_ber(input).is_err());
}

#[test]
fn canonical_der_all_kems() {
    for kem in Kem::ALL {
        let (key, alg, mut raw) = fixture(kem);
        let inner = if let Some(curve) = named_curve(kem) {
            let params = tlv(PARAMETERS, &tlv(tag::OID, curve));
            let pk = tlv(
                INNER_PUBLIC,
                &bit_string(tag::BIT_STRING, key.public_key().as_bytes()),
            );
            ec_value(&raw, &[params, pk].concat())
        } else {
            let n = raw.len();
            if kem == Kem::DhX25519HkdfSha256 {
                raw[0] = 0xf8;
                raw[n - 1] = 0x7f;
            } else {
                raw[0] = 0xfc;
            }
            tlv(tag::OCTET_STRING, &raw)
        };
        let expected = key_info(0, &alg, &tlv(tag::OCTET_STRING, &inner), &[]);
        let actual = encoded(&key);
        assert_eq!(actual, expected);
        assert_key(&actual, &key);
        der::parse_sequence(&actual, |r| {
            assert_eq!(r.read_small_integer()?, 0);
            assert_eq!(
                r.read(tag::SEQUENCE)?,
                der::Reader::new(&alg).read(tag::SEQUENCE)?
            );
            assert_eq!(r.read_octet_string()?, inner);
            Ok(())
        })
        .unwrap();

        if kem == Kem::DhP521HkdfSha512 {
            assert_eq!(actual.len(), MAX_PKCS8_DER_LEN);
        }
        let mut short = vec![0xa5; actual.len() - 1];
        assert_eq!(key.to_pkcs8_der(&mut short), Err(Error::InvalidLength));
        assert!(short.iter().all(|&b| b == 0xa5));
        let mut surplus = vec![0xa5; actual.len() + 1];
        assert_eq!(key.to_pkcs8_der(&mut surplus).unwrap(), actual.len());
        assert_eq!(&surplus[..actual.len()], actual);
        assert_eq!(surplus[actual.len()], 0xa5);
    }
}

#[test]
fn preserves_nist_algorithm_oids_and_leaves_x_oids_intact() {
    for kem in Kem::ALL {
        let (key, _, raw) = fixture(kem);
        assert!(!key.pkcs8_uses_ecdh_oid());
        let ordinary_der = encoded(&key);
        let selected = key.with_pkcs8_ecdh_oid();
        let Some(curve) = named_curve(kem) else {
            assert!(!selected.pkcs8_uses_ecdh_oid());
            assert_eq!(encoded(&selected), ordinary_der);
            assert_key(&ordinary_der, &selected);
            continue;
        };

        assert!(selected.pkcs8_uses_ecdh_oid());
        let restricted_der = encoded(&selected);
        let private = tlv(tag::OCTET_STRING, &ec_value(&raw, &[]));
        for (oid, output) in [(ID_EC_PUBLIC_KEY, ordinary_der), (ID_EC_DH, restricted_der)] {
            let mut outer = der::Reader::new(&output).read_sequence().unwrap();
            assert_eq!(outer.read_small_integer().unwrap(), 0);
            let mut alg = outer.read_sequence().unwrap();
            assert_eq!(alg.read_oid().unwrap(), oid);
            assert_eq!(alg.read_oid().unwrap(), curve);
            alg.finish().unwrap();

            let alg = algorithm(oid, &tlv(tag::OID, curve));
            let input = key_info(0, &alg, &private, &[]);
            let imported = PrivateKey::from_pkcs8_der_or_ber(&input).unwrap();
            assert_eq!(imported.pkcs8_uses_ecdh_oid(), oid == ID_EC_DH);
            assert_eq!(encoded(&imported), output);
            assert_key(&output, &imported);
        }
    }
}

#[test]
fn indefinite_and_segmented_ber_all_kems() {
    for kem in Kem::ALL {
        let (key, der_alg, raw) = fixture(kem);
        let public = key.public_key().as_bytes();
        let (alg, inner) = if let Some(curve) = named_curve(kem) {
            let curve = tlv(tag::OID, curve);
            let alg = indefinite(
                tag::SEQUENCE,
                &[tlv(tag::OID, ID_EC_DH), curve.clone()].concat(),
            );
            let inner = indefinite(
                tag::SEQUENCE,
                &[
                    vec![tag::INTEGER, 0x81, 1, 1],
                    segmented_octets(&[1]),
                    indefinite(PARAMETERS, &curve),
                    indefinite(INNER_PUBLIC, &segmented_public(0x23, public)),
                ]
                .concat(),
            );
            (alg, inner)
        } else {
            (der_alg, segmented_octets(&raw))
        };
        let attr = indefinite(
            ATTRIBUTES,
            &indefinite(
                tag::SEQUENCE,
                &[
                    tlv(tag::OID, &[0x2a, 0x03]),
                    indefinite(
                        SET,
                        &[
                            segmented_octets(b"note"),
                            indefinite(0x2c, &tlv(tag::OCTET_STRING, b"UTF8String")),
                            vec![0x9f, 0x20, 1, 0],
                        ]
                        .concat(),
                    ),
                ]
                .concat(),
            ),
        );
        let outer = indefinite(
            tag::SEQUENCE,
            &[
                vec![tag::INTEGER, 1, 1],
                alg,
                segmented_octets(&inner),
                attr,
                segmented_public(OUTER_PUBLIC_CONSTRUCTED, public),
            ]
            .concat(),
        );
        assert_key(&outer, &key.with_pkcs8_ecdh_oid());
    }
}

#[test]
fn nist_compressed_public_and_short_scalar() {
    for kem in [
        Kem::DhP256HkdfSha256,
        Kem::DhP384HkdfSha384,
        Kem::DhP521HkdfSha512,
    ] {
        let (key, alg, _) = fixture(kem);
        let public = key.public_key().as_bytes();
        let width = kem.private_key_len();
        let mut compressed = public[..=width].to_vec();
        compressed[0] = 2 | (public[2 * width] & 1);
        let inner = ec_value(
            &[1],
            &tlv(INNER_PUBLIC, &bit_string(tag::BIT_STRING, &compressed)),
        );
        let private = tlv(tag::OCTET_STRING, &inner);
        assert_key(&key_info(0, &alg, &private, &[]), &key);
        assert_key(
            &key_info(1, &alg, &private, &bit_string(OUTER_PUBLIC, public)),
            &key,
        );
        assert_key(
            &key_info(1, &alg, &private, &bit_string(OUTER_PUBLIC, &compressed)),
            &key,
        );

        compressed[0] ^= 1;
        rejected(&key_info(
            1,
            &alg,
            &private,
            &bit_string(OUTER_PUBLIC, &compressed),
        ));
        let inner = ec_value(
            &[1],
            &tlv(INNER_PUBLIC, &bit_string(tag::BIT_STRING, &compressed)),
        );
        rejected(&key_info(
            1,
            &alg,
            &tlv(tag::OCTET_STRING, &inner),
            &bit_string(OUTER_PUBLIC, public),
        ));
    }
}

#[test]
fn rejects_wrong_algorithms_parameters_scalars_and_public_keys() {
    for (kem, oid) in [
        (Kem::DhX25519HkdfSha256, ID_X25519),
        (Kem::DhX448HkdfSha512, ID_X448),
    ] {
        let (_, alg, raw) = fixture(kem);
        let private = tlv(tag::OCTET_STRING, &tlv(tag::OCTET_STRING, &raw));
        for params in [tlv(tag::NULL, &[]), tlv(tag::OID, p256::OID)] {
            rejected(&key_info(0, &algorithm(oid, &params), &private, &[]));
        }
        rejected(&key_info(0, &alg, &tlv(tag::OCTET_STRING, &raw), &[]));
        rejected(&key_info(
            0,
            &alg,
            &tlv(tag::OCTET_STRING, &tlv(tag::OCTET_STRING, &raw[1..])),
            &[],
        ));
        rejected(&key_info(
            1,
            &alg,
            &private,
            &bit_string(OUTER_PUBLIC, &vec![0; kem.public_key_len()]),
        ));
    }
    let (key, alg, _) = fixture(Kem::DhP256HkdfSha256);
    let private = tlv(tag::OCTET_STRING, &ec_value(&[1], &[]));
    for oid in [
        &[0x2b, 0x65, 0x70][..],
        &[0x2a, 0x03],
        &[0x80, 0x01],
        &[0x81],
    ] {
        rejected(&key_info(0, &algorithm(oid, &[]), &private, &[]));
    }
    for params in [
        vec![],
        tlv(tag::NULL, &[]),
        tlv(tag::SEQUENCE, &[]),
        tlv(tag::OID, &[0x2a, 0x03]),
    ] {
        for oid in [ID_EC_PUBLIC_KEY, ID_EC_DH] {
            rejected(&key_info(0, &algorithm(oid, &params), &private, &[]));
        }
    }
    for scalar in [&[][..], &[0], &[0xff; 32], &[1; 33]] {
        rejected(&key_info(
            0,
            &alg,
            &tlv(tag::OCTET_STRING, &ec_value(scalar, &[])),
            &[],
        ));
    }
    let wrong_curve = tlv(PARAMETERS, &tlv(tag::OID, p384::OID));
    rejected(&key_info(
        0,
        &alg,
        &tlv(tag::OCTET_STRING, &ec_value(&[1], &wrong_curve)),
        &[],
    ));

    let public = bit_string(OUTER_PUBLIC, key.public_key().as_bytes());
    rejected(&key_info(0, &alg, &private, &public));
    rejected(&key_info(1, &alg, &private, &[]));
    rejected(&key_info(2, &alg, &private, &public));
    rejected(&key_info(
        1,
        &alg,
        &private,
        &[&public[..], &public[..]].concat(),
    ));
    rejected(&key_info(
        1,
        &alg,
        &private,
        &tlv(OUTER_PUBLIC_CONSTRUCTED, &public),
    ));
    let params = tlv(PARAMETERS, &tlv(tag::OID, p256::OID));
    let inner_pk = tlv(
        INNER_PUBLIC,
        &bit_string(tag::BIT_STRING, key.public_key().as_bytes()),
    );
    for fields in [
        [&params[..], &params[..]].concat(),
        [&inner_pk[..], &inner_pk[..]].concat(),
        [&inner_pk[..], &params[..]].concat(),
        vec![0xa2, 0],
    ] {
        rejected(&key_info(
            0,
            &alg,
            &tlv(tag::OCTET_STRING, &ec_value(&[1], &fields)),
            &[],
        ));
    }
    let attr = tlv(ATTRIBUTES, &[]);
    rejected(&key_info(0, &alg, &private, &[&attr[..], &attr].concat()));
    rejected(&key_info(1, &alg, &private, &[public, attr].concat()));
}

fn attribute_set(values: &[u8]) -> Vec<u8> {
    tlv(
        ATTRIBUTES,
        &tlv(
            tag::SEQUENCE,
            &[&[tag::OID, 1, 0x2a][..], &tlv(SET, values)].concat(),
        ),
    )
}

#[test]
fn empty_attribute_values_are_discarded() {
    let (key, alg, raw) = fixture(Kem::DhX25519HkdfSha256);
    let private = tlv(tag::OCTET_STRING, &tlv(tag::OCTET_STRING, &raw));
    assert_key(&key_info(0, &alg, &private, &attribute_set(&[])), &key);
    let attr = tlv(
        ATTRIBUTES,
        &tlv(tag::SEQUENCE, &[tag::OID, 1, 0x2a, SET, 0x80, 0, 0]),
    );
    assert_key(&key_info(0, &alg, &private, &attr), &key);
}

#[test]
fn constructed_opaque_string_attributes_require_octet_segments() {
    let (key, alg, raw) = fixture(Kem::DhX25519HkdfSha256);
    let private = tlv(tag::OCTET_STRING, &tlv(tag::OCTET_STRING, &raw));
    for (t, bytes) in [
        (7, b"ObjectDescriptor".as_slice()),
        (23, b"261121120000Z".as_slice()),
        (24, b"20261121120000Z".as_slice()),
    ] {
        let mut value = segmented_octets(bytes);
        value[0] = t | 0x20;
        assert_key(&key_info(0, &alg, &private, &attribute_set(&value)), &key);

        let wrong_tag = indefinite(t | 0x20, &tlv(t, bytes));
        rejected(&key_info(0, &alg, &private, &attribute_set(&wrong_tag)));
    }
}

#[test]
fn rejects_malformed_ber() {
    let (key, alg, raw) = fixture(Kem::DhX25519HkdfSha256);
    let inner = tlv(tag::OCTET_STRING, &raw);
    let private = tlv(tag::OCTET_STRING, &inner);
    let der = encoded(&key);
    for end in 0..der.len() {
        rejected(&der[..end]);
    }
    rejected(&[&der[..], &[0, 0]].concat());
    rejected(&indefinite(tag::SEQUENCE, &[&der[2..], &[0, 0]].concat()));
    let ber = indefinite(tag::SEQUENCE, &der[2..]);
    for end in 0..ber.len() {
        rejected(&ber[..end]);
    }
    for invalid in [
        vec![tag::SEQUENCE, 0xff],
        vec![tag::SEQUENCE, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![tag::SEQUENCE, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        tlv(
            tag::SEQUENCE,
            &[&[tag::INTEGER, 2, 0, 0], &der[5..]].concat(),
        ),
        tlv(
            tag::SEQUENCE,
            &[&[tag::INTEGER, 1, 0xff], &der[5..]].concat(),
        ),
        tlv(
            tag::SEQUENCE,
            &[&[tag::INTEGER, 0x80, 0, 0], &der[5..]].concat(),
        ),
        tlv(tag::SEQUENCE, &[&[0x22, 1, 0], &der[5..]].concat()),
    ] {
        rejected(&invalid);
    }
    for invalid in [
        vec![0x24, 2, 0, 0],
        vec![0x24, 0x80, tag::OCTET_STRING, 0],
        vec![tag::OCTET_STRING, 0x80, 0, 0],
        indefinite(0x24, &tlv(tag::BIT_STRING, &[0])),
        tlv(tag::OCTET_STRING, &[&inner[..], &[0, 0]].concat()),
        tlv(
            tag::OCTET_STRING,
            &indefinite(0x24, &[tag::OCTET_STRING, 0x81]),
        ),
    ] {
        rejected(&key_info(0, &alg, &invalid, &[]));
    }
    // The inner indefinite length must close within its definite parent.
    let crossed_boundary = &[0x24, 2, 0x24, 0x80, 0, 0];
    rejected(&key_info(0, &alg, crossed_boundary, &[]));

    let public = key.public_key().as_bytes();
    for invalid in [
        tlv(OUTER_PUBLIC, &[]),
        tlv(OUTER_PUBLIC, &[&[1][..], public].concat()),
        indefinite(OUTER_PUBLIC_CONSTRUCTED, &tlv(tag::OCTET_STRING, public)),
        indefinite(OUTER_PUBLIC_CONSTRUCTED, &tlv(tag::BIT_STRING, &[8, 0])),
        indefinite(OUTER_PUBLIC_CONSTRUCTED, &tlv(tag::BIT_STRING, &[1])),
        indefinite(
            OUTER_PUBLIC_CONSTRUCTED,
            &[
                tlv(tag::BIT_STRING, &[1, public[0]]),
                bit_string(tag::BIT_STRING, &public[1..]),
            ]
            .concat(),
        ),
    ] {
        rejected(&key_info(1, &alg, &private, &invalid));
    }

    for invalid in [
        tlv(ATTRIBUTES, &tlv(SET, &[])),
        tlv(ATTRIBUTES, &tlv(tag::SEQUENCE, &[tag::OID, 1, 0x2a])),
        tlv(
            ATTRIBUTES,
            &tlv(tag::SEQUENCE, &[tag::OID, 1, 0x2a, tag::SEQUENCE, 0]),
        ),
        tlv(
            ATTRIBUTES,
            &tlv(tag::SEQUENCE, &[tag::OID, 1, 0x2a, SET, 0x80]),
        ),
        attribute_set(&[tag::OCTET_STRING, 0x80, 0, 0]),
        attribute_set(&[0, 0]),
        attribute_set(&[0x9f, 0x80, 0x20, 0]),
        attribute_set(&[0x9f, 0x1e, 0]),
        attribute_set(&[0x9f, 0x81]),
        attribute_set(&[0x02, 2, 0, 0]),
        attribute_set(&[0x23, 2, 0x04, 0]),
        attribute_set(&[0x24, 2, 0x02, 0]),
        attribute_set(&[0x2c, 2, 0x02, 0]),
        attribute_set(&[0x30, 2, 0, 0]),
        attribute_set(&[0x11, 0]),
        tlv(
            ATTRIBUTES,
            &tlv(tag::SEQUENCE, &[tag::OID, 1, 0x80, SET, 2, tag::NULL, 0]),
        ),
    ] {
        rejected(&key_info(0, &alg, &private, &invalid));
    }
}

#[test]
fn exact_input_depth_and_tlv_limits() {
    let (key, alg, raw) = fixture(Kem::DhX25519HkdfSha256);
    let private = tlv(tag::OCTET_STRING, &tlv(tag::OCTET_STRING, &raw));
    let info = |value: &[u8]| key_info(0, &alg, &private, &attribute_set(value));
    let mut contents = vec![0u8; MAX_BYTES - 100];
    let overhead = info(&tlv(tag::OCTET_STRING, &contents)).len() - contents.len();
    contents.resize(MAX_BYTES - overhead, 0);
    let max = info(&tlv(tag::OCTET_STRING, &contents));
    assert_eq!(max.len(), MAX_BYTES);
    assert_key(&max, &key);
    contents.push(0);
    rejected(&info(&tlv(tag::OCTET_STRING, &contents)));

    let nested = (0..11).fold(tlv(tag::NULL, &[]), |bytes, _| {
        indefinite(tag::SEQUENCE, &bytes)
    });
    assert_key(&info(&nested), &key);
    rejected(&info(&indefinite(tag::SEQUENCE, &nested)));

    // Count the encapsulated OCTET STRING and its segments at their depth
    // inside the outer PKCS#8 sequence and privateKey field.
    let nested = (0..13).fold(tlv(tag::OCTET_STRING, &raw), |bytes, _| {
        indefinite(0x24, &bytes)
    });
    let encapsulate = |inner: &[u8]| key_info(0, &alg, &tlv(tag::OCTET_STRING, inner), &[]);
    assert_key(&encapsulate(&nested), &key);
    rejected(&encapsulate(&indefinite(0x24, &nested)));

    // The container, algorithm, both private OCTET STRINGs, and attribute
    // envelopes consume ten TLVs before the 4086 NULL values.
    let values = [tag::NULL, 0].repeat(4086);
    assert_key(&info(&values), &key);
    rejected(&info(&[&values[..], &[tag::NULL, 0]].concat()));
}

#[test]
fn total_flattened_limit_counts_both_private_wrappers() {
    let (key, alg, raw) = fixture(Kem::DhX448HkdfSha512);
    let mut segments = tlv(tag::OCTET_STRING, &raw);
    // Many empty segments with legal, padded BER lengths keep the encoded
    // inner OCTET STRING large while its decoded value is a 56-byte key.
    let mut padding = vec![tag::OCTET_STRING, 0xfd];
    padding.resize(127, 0);
    segments.extend(padding.repeat(128));
    for delta in 0..=1 {
        let mut content = segments.clone();
        let target = MAX_BYTES - raw.len() - 4 + delta;
        let last = target - content.len();
        content.extend([tag::OCTET_STRING, 0x80 | u8::try_from(last - 2).unwrap()]);
        content.resize(target, 0);

        let inner = tlv(0x24, &content);
        assert_eq!(inner.len() + raw.len(), MAX_BYTES + delta);
        let outer = tlv(0x24, &tlv(tag::OCTET_STRING, &inner));
        let input = key_info(0, &alg, &outer, &[]);
        assert!(input.len() < MAX_BYTES);
        if delta == 0 {
            assert_key(&input, &key);
        } else {
            rejected(&input);
        }
    }
}
