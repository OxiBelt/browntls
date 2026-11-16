//! The DER reader and writer (`der`) of the `crypto_util` target, checked
//! against a reference TLV parser and reference encodings.

use browntls_crypto::Error;
use browntls_crypto::der::{self, Reader, Writer, tag};

use super::{MAX_READS, MAX_WRITES};
use crate::input::Input;

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

/// A reference TLV parser: `(tag, header length, value length)` of the
/// first TLV of `der`, or `None` if it is not definite-length DER with a
/// single-byte tag and a length of at most four bytes.
fn reference_tlv(der: &[u8]) -> Option<(u8, usize, usize)> {
    let (&t, rest) = der.split_first()?;
    if t & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (header, len) = if first & 0x80 == 0 {
        (2, usize::from(first))
    } else {
        let n = usize::from(first & 0x7f);
        if !(1..=4).contains(&n) || rest.len() < n || rest[0] == 0 {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| acc * 256 + usize::from(b));
        if len < 0x80 {
            return None;
        }
        (2 + n, len)
    };
    (der.len() - header >= len).then_some((t, header, len))
}

/// The reference encoding of a definite length.
fn reference_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![u8::try_from(len).expect("below 0x80")];
    }
    let bytes = (len as u64).to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = vec![0x80 | u8::try_from(8 - skip).expect("at most 8")];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// The reference encoding of a non-negative INTEGER with this magnitude.
fn reference_integer(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let mut content = magnitude[skip..].to_vec();
    if content.first().is_none_or(|&b| b & 0x80 != 0) {
        content.insert(0, 0);
    }
    let mut out = vec![tag::INTEGER];
    out.extend(reference_length(content.len()));
    out.extend(content);
    out
}

/// `tag || length || value` encoded by `Writer::tlv`, checked against the
/// reference encoding.
fn write_tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; der::header_len(value.len()) + value.len()];
    let mut w = Writer::new(&mut buf);
    w.tlv(t, value).expect("exact capacity");
    assert_eq!(w.len(), w.finish().len());
    let out = buf.clone();
    let mut expected = vec![t];
    expected.extend(reference_length(value.len()));
    expected.extend_from_slice(value);
    assert_eq!(out, expected);
    out
}

/// A tag chosen by the input: one of the named tags or any byte.
fn fuzzed_tag(input: &mut Input<'_>) -> u8 {
    match input.choose(10) {
        0 => tag::BOOLEAN,
        1 => tag::INTEGER,
        2 => tag::BIT_STRING,
        3 => tag::OCTET_STRING,
        4 => tag::NULL,
        5 => tag::OID,
        6 => tag::SEQUENCE,
        7 => tag::context_constructed(input.byte() & 0x1f),
        8 => tag::context_primitive(input.byte() & 0x1f),
        _ => input.byte(),
    }
}

/// Whether `v` is the content of a valid OBJECT IDENTIFIER (X.690 §8.19).
fn oid_valid(v: &[u8]) -> bool {
    let mut start = true;
    for &b in v {
        if start && b == 0x80 {
            return false;
        }
        start = b & 0x80 == 0;
    }
    !v.is_empty() && start
}

/// Runs fuzzed reader calls on `reader`, checking each against the
/// reference parser.
pub(super) fn walk(
    reader: &mut Reader<'_>,
    input: &mut Input<'_>,
    budget: &mut usize,
    depth: usize,
) {
    while *budget > 0 && !input.is_empty() {
        *budget -= 1;
        let before = reader.remaining();
        assert_eq!(reader.is_empty(), before.is_empty());
        assert_eq!(reader.peek_tag(), before.first().copied());
        let reference = reference_tlv(before);
        // The TLV that a successful read consumes.
        let consumed = |after: &[u8]| &before[..before.len() - after.len()];
        match input.choose(12) {
            0 => {
                let result = reader.read_any();
                match (result, reference) {
                    (Ok((t, v)), Some((rt, rh, rl))) => {
                        assert_eq!((t, v), (rt, &before[rh..rh + rl]));
                        assert_eq!(write_tlv(t, v), consumed(reader.remaining()));
                        assert_eq!(der::header_len(v.len()), rh);
                    }
                    (Err(e), None) => {
                        assert_eq!(e, Error::InvalidEncoding);
                        assert_eq!(reader.remaining(), before, "failed read consumed input");
                    }
                    (result, reference) => {
                        panic!("read_any {result:?} vs reference {reference:?} on {before:02x?}")
                    }
                }
            }
            1 => {
                let expected = fuzzed_tag(input);
                let result = reader.read(expected);
                match reference {
                    Some((t, h, l)) if t == expected => {
                        assert_eq!(result, Ok(&before[h..h + l]));
                    }
                    _ => assert_eq!(result, Err(Error::InvalidEncoding)),
                }
            }
            2 => {
                let expected = fuzzed_tag(input);
                let result = reader.read_optional(expected);
                if before.first() != Some(&expected) {
                    assert_eq!(result, Ok(None));
                    assert_eq!(reader.remaining(), before);
                } else {
                    match reference {
                        Some((_, h, l)) => assert_eq!(result, Ok(Some(&before[h..h + l]))),
                        None => assert_eq!(result, Err(Error::InvalidEncoding)),
                    }
                }
            }
            3 => {
                let result = reader.read_sequence();
                match reference {
                    Some((tag::SEQUENCE, h, l)) => {
                        let mut inner = result.expect("a SEQUENCE");
                        assert_eq!(inner.remaining(), &before[h..h + l]);
                        if depth < 4 {
                            walk(&mut inner, input, budget, depth + 1);
                        }
                    }
                    _ => assert_eq!(result.err(), Some(Error::InvalidEncoding)),
                }
            }
            4 => {
                let result = reader.read_positive_integer();
                let content = match reference {
                    Some((tag::INTEGER, h, l)) => Some(&before[h..h + l]),
                    _ => None,
                };
                let valid = content.is_some_and(|c| match c {
                    [] => false,
                    [b] => b & 0x80 == 0,
                    [0, b, ..] => b & 0x80 != 0,
                    [b, ..] => b & 0x80 == 0,
                });
                assert_eq!(result.is_ok(), valid, "{before:02x?}");
                if let Ok(magnitude) = result {
                    // The magnitude re-encodes to exactly the input.
                    let tlv = consumed(reader.remaining());
                    assert_eq!(reference_integer(magnitude), tlv);
                    assert_eq!(Writer::positive_integer_len(magnitude), tlv.len());
                    let mut buf = vec![0u8; tlv.len()];
                    let mut w = Writer::new(&mut buf);
                    w.positive_integer(magnitude).expect("exact capacity");
                    assert_eq!(w.finish(), tlv);
                    assert!(magnitude.len() == 1 || magnitude[0] != 0);
                }
            }
            5 => {
                let mut probe = *reader;
                let magnitude = probe.read_positive_integer();
                let result = reader.read_small_integer();
                match magnitude {
                    Ok(m) if m.len() <= 8 => {
                        let value = m.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
                        assert_eq!(result, Ok(value));
                        assert_eq!(reader.remaining(), probe.remaining());
                    }
                    _ => assert_eq!(result, Err(Error::InvalidEncoding)),
                }
            }
            6 => {
                let result = reader.read_bit_string_octets();
                match reference {
                    Some((tag::BIT_STRING, h, l)) if l > 0 && before[h] == 0 => {
                        assert_eq!(result, Ok(&before[h + 1..h + l]));
                    }
                    _ => assert_eq!(result, Err(Error::InvalidEncoding)),
                }
            }
            7 => {
                let result = reader.read_octet_string();
                match reference {
                    Some((tag::OCTET_STRING, h, l)) => assert_eq!(result, Ok(&before[h..h + l])),
                    _ => assert_eq!(result, Err(Error::InvalidEncoding)),
                }
            }
            8 => {
                let result = reader.read_oid();
                match reference {
                    Some((tag::OID, h, l)) if oid_valid(&before[h..h + l]) => {
                        assert_eq!(result, Ok(&before[h..h + l]));
                    }
                    _ => assert_eq!(result, Err(Error::InvalidEncoding)),
                }
            }
            9 => {
                let result = reader.finish();
                assert_eq!(result.is_ok(), before.is_empty());
                if let Err(e) = result {
                    assert_eq!(e, Error::InvalidEncoding);
                }
            }
            10 => {
                // A fresh reader over a suffix.
                let skip = input.choose(before.len() + 1);
                let fresh = Reader::new(&before[skip..]);
                assert_eq!(fresh.remaining(), &before[skip..]);
            }
            _ => return,
        }
    }
}

/// `parse_sequence` with a fuzzed walk of the contents.
pub(super) fn parse_sequence(input: &mut Input<'_>) {
    let der = input.field();
    let reads = input.field();
    let mut outer = Reader::new(der);
    let expected_ok = outer.read_sequence().is_ok() && outer.is_empty();
    let mut entered = false;
    let result = der::parse_sequence(der, |inner| {
        entered = true;
        let mut sub = Input::new(reads);
        let mut budget = MAX_READS;
        walk(inner, &mut sub, &mut budget, 1);
        if sub.remaining().first() == Some(&0xff) {
            return Err(Error::InvalidSignature);
        }
        Ok(inner.remaining().len())
    });
    match result {
        Ok(left) => {
            assert!(expected_ok);
            assert_eq!(left, 0, "contents left over");
        }
        Err(Error::InvalidSignature) => assert!(entered),
        Err(e) => {
            assert_eq!(e, Error::InvalidEncoding);
            if !entered {
                assert!(!expected_ok);
            }
        }
    }
}

/// A fuzzed list of writes into a buffer of fuzzed capacity.
pub(super) fn der_write(input: &mut Input<'_>) {
    let capacity = usize::from(input.u16()) % 1024;
    let mut buf = vec![0u8; capacity];
    let mut expected = Vec::new();
    // Items that read back: (tag, value).
    let mut items = Vec::new();
    let mut readable = true;
    let mut w = Writer::new(&mut buf);
    assert!(w.is_empty());
    for _ in 0..MAX_WRITES {
        if input.is_empty() {
            break;
        }
        let mut encoding;
        let result = match input.choose(3) {
            0 => {
                let t = fuzzed_tag(input);
                let value = input.field();
                encoding = vec![t];
                encoding.extend(reference_length(value.len()));
                encoding.extend_from_slice(value);
                readable &= t & 0x1f != 0x1f;
                items.push((t, value.to_vec()));
                w.tlv(t, value)
            }
            1 => {
                let t = fuzzed_tag(input);
                let len = match input.choose(4) {
                    0 => usize::try_from(input.u64()).unwrap_or(usize::MAX),
                    1 => usize::try_from(input.u32()).unwrap_or(usize::MAX),
                    _ => usize::from(input.u16()),
                };
                encoding = vec![t];
                encoding.extend(reference_length(len));
                assert_eq!(der::header_len(len), encoding.len());
                readable = false;
                w.header(t, len)
            }
            _ => {
                let magnitude = input.short_field();
                encoding = reference_integer(magnitude);
                assert_eq!(Writer::positive_integer_len(magnitude), encoding.len());
                let skip = magnitude.iter().take_while(|&&b| b == 0).count();
                let canonical = if skip == magnitude.len() {
                    vec![0]
                } else {
                    magnitude[skip..].to_vec()
                };
                items.push((tag::INTEGER, canonical));
                w.positive_integer(magnitude)
            }
        };
        if expected.len() + encoding.len() <= capacity {
            assert_eq!(result, Ok(()));
            expected.extend(encoding);
            assert_eq!(w.len(), expected.len());
            assert!(!w.is_empty());
        } else {
            // The writer's state is unspecified after an error.
            assert_eq!(result, Err(Error::InvalidLength));
            return;
        }
    }
    let out = w.finish();
    assert_eq!(out, expected.as_slice());
    if !readable {
        return;
    }
    let mut r = Reader::new(out);
    for (t, value) in &items {
        if *t == tag::INTEGER && r.peek_tag() == Some(tag::INTEGER) {
            let mut probe = r;
            if probe.read_positive_integer() == Ok(value.as_slice()) {
                r = probe;
                continue;
            }
        }
        // Lengths beyond four bytes are not readable; nothing written here
        // is that long.
        assert_eq!(r.read_any(), Ok((*t, value.as_slice())));
    }
    assert_eq!(r.finish(), Ok(()));
}
