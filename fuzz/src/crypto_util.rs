//! `browntls-crypto` support modules: DER (`der`), constant-time helpers
//! (`ct`), zeroisation (`zeroize`), randomness sources (`rand`), CPU feature
//! detection (`cpu`), acceleration policies (`accel`) and `Error`.
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments:
//!
//! - DER reading: fuzzed bytes walked by a fuzzed sequence of reader calls
//!   (nested through `read_sequence` and `parse_sequence`). Every result is
//!   checked against a reference TLV parser written here, and every value
//!   read re-encodes with `Writer` to exactly the bytes consumed.
//! - DER writing: a fuzzed list of TLVs, headers and integers into a buffer
//!   of fuzzed capacity; the output equals a reference encoding, lengths
//!   agree with `header_len` and `positive_integer_len`, overflow is an error
//!   and the output reads back.
//! - `ct`: every helper on fuzzed values against the obvious
//!   non-constant-time result.
//! - `zeroize` and `rand`: buffers are zeroed; `FixedRng` replays exactly its
//!   bytes and then fails; `OsRng` works.
//! - `cpu`: features are stable, `without` removes exactly the masked bits,
//!   accessors agree with `std` detection and are false on other
//!   architectures.
//! - `accel`: fuzzed policies set per algorithm, per kind and for all
//!   algorithms; success, failure (`Required` without hardware leaves the
//!   policy unchanged) and the reported status must be consistent. Every
//!   policy is restored to `Policy::PREFERRED` before `run` returns.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Kind, Policy, Uses};
use browntls_crypto::cpu::{self, Features};
use browntls_crypto::ct::{self, Choice};
use browntls_crypto::der::{self, Reader, Writer, tag};
use browntls_crypto::rand::{self, FixedRng, OsRng};
use browntls_crypto::zeroize::{self, Zeroize, Zeroizing};

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 32;
/// Reader calls per DER walk, across all nesting levels.
const MAX_READS: usize = 64;
/// Writer calls per DER write.
const MAX_WRITES: usize = 16;

const OP_DER_READ: u8 = 0;
const OP_DER_PARSE_SEQUENCE: u8 = 1;
const OP_DER_WRITE: u8 = 2;
const OP_CT: u8 = 3;
const OP_ZEROIZE: u8 = 4;
const OP_RAND: u8 = 5;
const OP_CPU: u8 = 6;
const OP_ACCEL: u8 = 7;
const OP_ERROR: u8 = 8;
const OPS: usize = 9;

const LEVELS: [Acceleration; 3] = [
    Acceleration::Required,
    Acceleration::Preferred,
    Acceleration::None,
];

/// The `crypto_util` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match u8::try_from(input.choose(OPS)).unwrap_or(0) {
            OP_DER_READ => {
                let der = input.field();
                let mut budget = MAX_READS;
                let mut reader = Reader::new(der);
                walk(&mut reader, &mut input, &mut budget, 0);
            }
            OP_DER_PARSE_SEQUENCE => parse_sequence(&mut input),
            OP_DER_WRITE => der_write(&mut input),
            OP_CT => ct_op(&mut input),
            OP_ZEROIZE => zeroize_op(&mut input),
            OP_RAND => rand_op(&mut input),
            OP_CPU => cpu_op(&mut input),
            OP_ACCEL => accel_op(&mut input),
            _ => error_op(),
        }
    }
    accel::set_policy_all(Policy::PREFERRED).expect("PREFERRED is always satisfiable");
}

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
fn walk(reader: &mut Reader<'_>, input: &mut Input<'_>, budget: &mut usize, depth: usize) {
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
fn parse_sequence(input: &mut Input<'_>) {
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
fn der_write(input: &mut Input<'_>) {
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

// ---------------------------------------------------------------------------
// ct, zeroize, rand
// ---------------------------------------------------------------------------

fn choice(b: bool) -> Choice {
    Choice::from_bit(u64::from(b))
}

fn ct_op(input: &mut Input<'_>) {
    let a = input.u64();
    let b = if input.bool() { a } else { input.u64() };
    let bit = input.u64();
    let c = Choice::from_bit(bit);
    let cb = bit & 1 == 1;
    assert_eq!(c.mask(), if cb { u64::MAX } else { 0 });
    assert_eq!(c.declassify(), cb);
    assert_eq!((!c).declassify(), !cb);
    let d = choice(a & 1 == 1);
    assert_eq!(c.and(d).declassify(), cb && a & 1 == 1);
    assert_eq!(c.or(d).declassify(), cb || a & 1 == 1);
    assert_eq!(Choice::TRUE.mask(), u64::MAX);
    assert_eq!(Choice::FALSE.mask(), 0);

    assert_eq!(ct::is_zero_u64(a).declassify(), a == 0);
    assert_eq!(ct::eq_u64(a, b).declassify(), a == b);
    assert_eq!(ct::lt_u64(a, b).declassify(), a < b);
    assert_eq!(ct::select_u64(c, a, b), if cb { a } else { b });
    let (x, y) = (a.to_le_bytes()[0], b.to_le_bytes()[0]);
    assert_eq!(ct::select_u8(c, x, y), if cb { x } else { y });

    let src = input.short_field();
    let mut dst = exact(input, src.len());
    let original = dst.clone();
    ct::conditional_copy(c, &mut dst, src);
    assert_eq!(dst, if cb { src } else { &original[..] });

    let words: Vec<u64> = (0..input.choose(8)).map(|_| input.u64()).collect();
    let mut p = words.clone();
    let mut q: Vec<u64> = words.iter().map(|w| w.rotate_left(17) ^ a).collect();
    let q0 = q.clone();
    ct::conditional_swap_u64(c, &mut p, &mut q);
    if cb {
        assert_eq!((p, q), (q0, words));
    } else {
        assert_eq!((p, q), (words, q0));
    }

    let l = input.short_field();
    let r = if input.bool() { l } else { input.short_field() };
    assert_eq!(ct::eq_bytes(l, r).declassify(), l == r);
    assert_eq!(ct::eq(l, r), l == r);
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
}

fn zeroize_op(input: &mut Input<'_>) {
    let bytes = input.field();
    let words = |n: usize| bytes.chunks(n).count().max(1);

    let mut b = bytes.to_vec();
    zeroize::zeroize_bytes(&mut b);
    assert!(b.iter().all(|&x| x == 0));
    let mut b = bytes.to_vec();
    b.zeroize();
    assert!(b.is_empty(), "Vec::zeroize clears");
    let mut b = bytes.to_vec();
    b.as_mut_slice().zeroize();
    assert_eq!(b.len(), bytes.len());
    assert!(b.iter().all(|&x| x == 0));

    let mut w32 = vec![u32::MAX; words(4)];
    zeroize::zeroize_u32(&mut w32);
    assert!(w32.iter().all(|&x| x == 0));
    let mut w64 = vec![u64::MAX; words(8)];
    zeroize::zeroize_u64(&mut w64);
    assert!(w64.iter().all(|&x| x == 0));
    let mut w16 = vec![-1i16; words(2)];
    zeroize::zeroize_i16(&mut w16);
    assert!(w16.iter().all(|&x| x == 0));

    let mut a8: [u8; 7] = input.array();
    a8.zeroize();
    assert_eq!(a8, [0; 7]);
    let mut a32 = [input.u32(); 3];
    a32.zeroize();
    assert_eq!(a32, [0; 3]);
    let mut a64 = [input.u64(); 2];
    a64.zeroize();
    assert_eq!(a64, [0; 2]);
    let mut a16 = [i16::from_be_bytes(input.array()); 5];
    a16.zeroize();
    assert_eq!(a16, [0; 5]);
    let mut s32 = vec![7u32; 3];
    s32.as_mut_slice().zeroize();
    let mut s64 = vec![7u64; 3];
    s64.as_mut_slice().zeroize();
    let mut s16 = vec![7i16; 3];
    s16.as_mut_slice().zeroize();
    assert!(s32.iter().all(|&x| x == 0) && s64.iter().all(|&x| x == 0));
    assert!(s16.iter().all(|&x| x == 0));

    let mut z = Zeroizing(input.array::<16>());
    let original = *z;
    z[0] ^= 1;
    assert_eq!(z.0[0], original[0] ^ 1);
    assert_eq!(format!("{z:?}"), "Zeroizing(..)");
    let copy = z.clone();
    assert_eq!(copy.0, z.0);
}

fn rand_op(input: &mut Input<'_>) {
    let bytes = input.field();
    let rng = FixedRng::new(bytes);
    // Fixed draws replay the bytes in order, then fail without consuming.
    let mut offset = 0;
    for _ in 0..input.choose(6) {
        let result = match input.choose(3) {
            0 => rand::array::<1>(&rng).map(|a| a.to_vec()),
            1 => rand::array::<16>(&&rng).map(|a| a.to_vec()),
            _ => rand::array::<32>(&rng).map(|a| a.to_vec()),
        };
        match result {
            Ok(out) => {
                assert_eq!(out, bytes[offset..offset + out.len()]);
                offset += out.len();
            }
            Err(e) => {
                assert_eq!(e, Error::RandomFailure);
                assert!(bytes.len() - offset < 32);
            }
        }
    }
    let rest = rand::array::<0>(&rng);
    assert_eq!(rest, Ok([]));
    if input.bool() {
        let a = rand::array::<32>(&OsRng).expect("OS randomness");
        let b = rand::array::<32>(&OsRng).expect("OS randomness");
        assert_ne!(a, b, "OS randomness repeated");
    }
}

// ---------------------------------------------------------------------------
// cpu, accel, error
// ---------------------------------------------------------------------------

/// Every accessor of `f`, with its name and architecture.
fn accessors(f: Features) -> Vec<(&'static str, &'static str, bool)> {
    vec![
        ("x86_64", "x86_v3", f.x86_v3()),
        ("x86_64", "x86_ssse3", f.x86_ssse3()),
        ("x86_64", "x86_sse41", f.x86_sse41()),
        ("x86_64", "x86_avx", f.x86_avx()),
        ("x86_64", "x86_avx2", f.x86_avx2()),
        ("x86_64", "x86_bmi2", f.x86_bmi2()),
        ("x86_64", "x86_aes", f.x86_aes()),
        ("x86_64", "x86_pclmulqdq", f.x86_pclmulqdq()),
        ("x86_64", "x86_sha", f.x86_sha()),
        ("x86_64", "x86_sha512", f.x86_sha512()),
        ("x86_64", "x86_vaes", f.x86_vaes()),
        ("x86_64", "x86_vpclmulqdq", f.x86_vpclmulqdq()),
        ("x86_64", "x86_avx512", f.x86_avx512()),
        ("x86_64", "x86_avx512_ifma", f.x86_avx512_ifma()),
        ("x86_64", "x86_avx512_vbmi", f.x86_avx512_vbmi()),
        ("x86_64", "x86_adx", f.x86_adx()),
        ("x86_64", "x86_gfni", f.x86_gfni()),
        ("aarch64", "arm_neon", f.arm_neon()),
        ("aarch64", "arm_aes", f.arm_aes()),
        ("aarch64", "arm_sha2", f.arm_sha2()),
        ("aarch64", "arm_sha3", f.arm_sha3()),
        ("riscv64", "rv_v", f.rv_v()),
        ("riscv64", "rv_zvkned", f.rv_zvkned()),
        ("riscv64", "rv_zvknha", f.rv_zvknha()),
        ("riscv64", "rv_zvknhb", f.rv_zvknhb()),
        ("riscv64", "rv_zvkg", f.rv_zvkg()),
        ("riscv64", "rv_zvbc", f.rv_zvbc()),
        ("riscv64", "rv_zvbb", f.rv_zvbb()),
        ("riscv64", "rv_zvkb", f.rv_zvkb()),
        ("riscv64", "rv_zbb", f.rv_zbb()),
        ("riscv64", "rv_zbc", f.rv_zbc()),
        ("riscv64", "rv_zbkb", f.rv_zbkb()),
        ("riscv64", "rv_zbkc", f.rv_zbkc()),
        ("riscv64", "rv_zknh", f.rv_zknh()),
        ("riscv64", "rv_zkne", f.rv_zkne()),
        ("riscv64", "rv_zknd", f.rv_zknd()),
    ]
}

fn cpu_op(input: &mut Input<'_>) {
    let f = cpu::features();
    assert_eq!(cpu::features(), f, "detection is not stable");
    assert_eq!(f.bits() >> 63, 0);
    assert_eq!(Features::NONE.bits(), 0);
    assert_eq!(f.without(Features::NONE), f);
    assert_eq!(f.without(f), Features::NONE);
    assert_eq!(Features::NONE.without(f), Features::NONE);

    // Masks reachable through the API: none, all, or what remains after
    // removing either.
    let mask = match input.choose(3) {
        0 => Features::NONE,
        1 => f,
        _ => f.without(f),
    };
    let g = f.without(mask);
    assert_eq!(g.bits(), f.bits() & !mask.bits());
    let debug = format!("{g:?}");
    for ((arch, name, fv), ((_, _, mv), (_, _, gv))) in accessors(f)
        .into_iter()
        .zip(accessors(mask).into_iter().zip(accessors(g)))
    {
        assert_eq!(gv, fv && !mv, "{name}");
        if arch != std::env::consts::ARCH {
            assert!(!fv, "{name} on {}", std::env::consts::ARCH);
        }
        assert_eq!(
            debug.contains(&format!("\"{name}\"")),
            gv,
            "{name} in {debug}"
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(f.x86_aes(), std::is_x86_feature_detected!("aes"));
        assert_eq!(
            f.x86_pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(f.x86_sha(), std::is_x86_feature_detected!("sha"));
        assert_eq!(f.x86_adx(), std::is_x86_feature_detected!("adx"));
        assert_eq!(f.x86_bmi2(), std::is_x86_feature_detected!("bmi2"));
        assert_eq!(f.x86_avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(f.x86_avx(), std::is_x86_feature_detected!("avx"));
        assert_eq!(f.x86_ssse3(), std::is_x86_feature_detected!("ssse3"));
        assert_eq!(f.x86_sse41(), std::is_x86_feature_detected!("sse4.1"));
    }
    let vlenb = cpu::riscv_vlenb();
    if cfg!(target_arch = "riscv64") && f.rv_v() {
        assert!(vlenb >= 16 && vlenb.is_power_of_two());
    } else {
        assert_eq!(vlenb, 0);
    }
}

fn uses(simd: bool, dedicated: bool) -> Uses {
    Uses { simd, dedicated }
}

/// The kinds a policy requires, as a `Uses`.
fn required(p: Policy) -> Uses {
    uses(
        p.simd == Acceleration::Required,
        p.dedicated == Acceleration::Required,
    )
}

/// Whether `want` is a subset of `have`.
fn subset(want: Uses, have: Uses) -> bool {
    (!want.simd || have.simd) && (!want.dedicated || have.dedicated)
}

/// Checks the outcome of setting `next` over `before` for one algorithm.
fn check_set(alg: Algorithm, before: Policy, next: Policy, result: Result<(), Error>) {
    let status = accel::status(alg);
    assert_eq!(status.algorithm, alg);
    match result {
        Ok(()) => {
            assert_eq!(accel::policy(alg), next, "{alg}");
            assert_eq!(status.policy, next);
            assert!(next.permits(status.uses), "{status}");
            assert!(subset(required(next), status.uses), "{status}");
        }
        Err(e) => {
            assert_eq!(e, Error::Unsupported);
            assert_eq!(accel::policy(alg), before, "failed set changed the policy");
            assert!(
                required(next).any(),
                "{alg}: {next} without Required failed"
            );
        }
    }
    if !subset(required(next), status.available) {
        assert!(result.is_err(), "{alg}: {next} accepted without hardware");
    }
    if !required(next).any() {
        assert!(result.is_ok(), "{alg}: {next} rejected");
    }
}

/// Every status report agrees with the others.
fn check_status() {
    let all = accel::status_all();
    for (alg, s) in Algorithm::ALL.into_iter().zip(all) {
        assert_eq!(s, accel::status(alg));
        assert_eq!(s.algorithm, alg);
        assert_eq!(s.policy, accel::policy(alg));
        assert_eq!(s.accelerated(), s.uses.any());
        assert_eq!(s.accelerated(), s.backend != "portable", "{s}");
        assert!(subset(s.uses, s.available), "{s}");
        assert!(s.policy.permits(s.uses), "{s}");
        assert!(!s.to_string().is_empty());
    }
    let accelerated: Vec<_> = accel::accelerated().map(|s| s.algorithm).collect();
    let expected: Vec<_> = all
        .iter()
        .filter(|s| s.uses.any())
        .map(|s| s.algorithm)
        .collect();
    assert_eq!(accelerated, expected);
    for kind in Kind::ALL {
        let by: Vec<_> = accel::accelerated_by(kind).map(|s| s.algorithm).collect();
        let expected: Vec<_> = all
            .iter()
            .filter(|s| s.uses.get(kind))
            .map(|s| s.algorithm)
            .collect();
        assert_eq!(by, expected, "{kind}");
    }
}

fn accel_op(input: &mut Input<'_>) {
    let alg = *input.pick(&Algorithm::ALL);
    let kind = *input.pick(&Kind::ALL);
    let level = *input.pick(&LEVELS);
    let policy = Policy::new(*input.pick(&LEVELS), *input.pick(&LEVELS));
    match input.choose(6) {
        0 => {
            let before = accel::policy(alg);
            let result = accel::set_policy(alg, policy);
            check_set(alg, before, policy, result);
        }
        1 => {
            let before = accel::policy(alg);
            let result = accel::set_kind(alg, kind, level);
            check_set(alg, before, before.with(kind, level), result);
        }
        2 => {
            let before = Algorithm::ALL.map(accel::policy);
            let result = accel::set_policy_all(policy);
            let after = Algorithm::ALL.map(accel::policy);
            match result {
                Ok(()) => assert!(after.iter().all(|p| *p == policy)),
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert_eq!(after, before, "failed set_policy_all changed policies");
                    // Some algorithm cannot satisfy it alone either.
                    let unsatisfiable = Algorithm::ALL.into_iter().any(|a| {
                        let old = accel::policy(a);
                        let ok = accel::set_policy(a, policy).is_ok();
                        accel::set_policy(a, old).expect("was set before");
                        !ok
                    });
                    assert!(unsatisfiable);
                }
            }
        }
        3 => {
            let before = Algorithm::ALL.map(accel::policy);
            let result = accel::set_kind_all(kind, level);
            let after = Algorithm::ALL.map(accel::policy);
            match result {
                Ok(()) => {
                    for (b, a) in before.iter().zip(after) {
                        assert_eq!(a, b.with(kind, level));
                    }
                }
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert_eq!(after, before, "failed set_kind_all changed policies");
                    assert!(
                        before.iter().any(|p| required(p.with(kind, level)).any()),
                        "set_kind_all failed without a Required kind"
                    );
                }
            }
        }
        4 => {
            // Pure policy algebra against a truth table.
            let u = uses(input.bool(), input.bool());
            let allowed = |l: Acceleration, used: bool| match l {
                Acceleration::Required => used,
                Acceleration::Preferred => true,
                Acceleration::None => !used,
            };
            assert_eq!(
                policy.permits(u),
                allowed(policy.simd, u.simd) && allowed(policy.dedicated, u.dedicated)
            );
            let with = policy.with(kind, level);
            assert_eq!(with.get(kind), level);
            for other in Kind::ALL {
                if other != kind {
                    assert_eq!(with.get(other), policy.get(other));
                }
            }
            assert_eq!(policy.get(Kind::Simd), policy.simd);
            assert_eq!(policy.get(Kind::Dedicated), policy.dedicated);
            assert_eq!(u.get(Kind::Simd), u.simd);
            assert_eq!(u.get(Kind::Dedicated), u.dedicated);
            assert_eq!(u.any(), u.simd || u.dedicated);
            assert_eq!(u.bits(), u8::from(u.simd) | u8::from(u.dedicated) << 1);
            assert!(Policy::PREFERRED.permits(u));
            assert_eq!(Policy::NONE.permits(u), !u.any());
            assert_eq!(Policy::default(), Policy::PREFERRED);
            assert!(!format!("{policy} {u}").is_empty());
        }
        _ => {
            // Names and parsing.
            assert_eq!(kind.name(), kind.to_string());
            assert_eq!(level.name(), level.to_string());
            assert_eq!(alg.name(), alg.to_string());
            assert_eq!(level.name().parse::<Acceleration>(), Ok(level));
            assert_eq!(
                level.name().to_ascii_uppercase().parse::<Acceleration>(),
                Ok(level)
            );
            let text = String::from_utf8_lossy(input.short_field()).into_owned();
            let expected = if text.eq_ignore_ascii_case("required") {
                Ok(Acceleration::Required)
            } else if text.eq_ignore_ascii_case("preferred")
                || text.eq_ignore_ascii_case("prefered")
            {
                Ok(Acceleration::Preferred)
            } else if text.eq_ignore_ascii_case("none") {
                Ok(Acceleration::None)
            } else {
                Err(Error::Unsupported)
            };
            assert_eq!(text.parse::<Acceleration>(), expected, "{text:?}");
        }
    }
    check_status();
}

fn error_op() {
    let all = [
        Error::InvalidKey,
        Error::InvalidLength,
        Error::InvalidEncoding,
        Error::InvalidSignature,
        Error::DecryptFailed,
        Error::KeyAgreementFailed,
        Error::RandomFailure,
        Error::Unsupported,
    ];
    let texts: Vec<String> = all.iter().map(ToString::to_string).collect();
    for (i, t) in texts.iter().enumerate() {
        assert!(!t.is_empty());
        assert!(!texts[..i].contains(t), "duplicate message {t}");
        let e: &dyn std::error::Error = &all[i];
        assert!(e.source().is_none());
    }
}

/// Starting inputs for `crypto_util`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    // DER: a structure with every universal type, walked with every call.
    let mut body = Vec::new();
    body.extend_from_slice(&[0x02, 0x02, 0x00, 0x80]); // INTEGER 128
    body.extend_from_slice(&[0x02, 0x01, 0x05]); // INTEGER 5
    body.extend_from_slice(&[0x03, 0x03, 0x00, 0xaa, 0xbb]); // BIT STRING
    body.extend_from_slice(&[0x04, 0x02, 0x01, 0x02]); // OCTET STRING
    body.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID 1.3.101.112
    body.extend_from_slice(&[0x05, 0x00]); // NULL
    body.extend_from_slice(&[0xa0, 0x03, 0x01, 0x01, 0xff]); // [0] { TRUE }
    body.extend_from_slice(&[0x04, 0x81, 0x80]); // long-form length
    body.extend_from_slice(&[0x5a; 0x80]);
    let mut der = vec![0x30, 0x81, u8::try_from(body.len()).expect("short")];
    der.extend_from_slice(&body);

    // read_sequence, then each reader in turn, then finish
    let walk_all = [
        3, 9, 4, 5, 6, 7, 8, 2, 0x05, 2, 7, 0x03, 1, 0x04, 0, 9, 10, 1, 11,
    ];
    let mut seed = vec![OP_DER_READ];
    put_field(&mut seed, &der);
    seed.extend_from_slice(&walk_all);
    seeds.push(seed);
    // the same calls on non-matching or malformed input
    for bad in [
        &[0x02, 0x01, 0x80][..],                     // negative INTEGER
        &[0x02, 0x02, 0x00, 0x01],                   // non-minimal INTEGER
        &[0x02, 0x00],                               // empty INTEGER
        &[0x02, 0x81, 0x01, 0x00],                   // non-minimal length
        &[0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], // too large for u64
        &[0x03, 0x02, 0x01, 0xff],                   // unused bits
        &[0x06, 0x02, 0x80, 0x01],                   // padded OID
        &[0x06, 0x01, 0x81],                         // truncated OID
        &[0x1f, 0x01, 0x00],                         // multi-byte tag
        &[0x04, 0x85, 1, 0, 0, 0, 0],                // five length bytes
        &[0x04, 0x05, 0x00],                         // truncated value
        &[],
    ] {
        for call in [0u8, 3, 4, 5, 6, 7, 8, 9] {
            let mut seed = vec![OP_DER_READ];
            put_field(&mut seed, bad);
            seed.push(call);
            seeds.push(seed);
        }
    }
    // parse_sequence: whole, failing closure, trailing data, not a sequence
    for (input, reads) in [
        (&der[..], &[4u8, 4, 6, 7, 8, 11][..]),
        (&der[..], &[4u8, 11, 0xff]),
        (&[0x30, 0x00, 0x00][..], &[]),
        (&[0x30, 0x03, 0x02, 0x01, 0x01][..], &[11]),
        (&[0x31, 0x00][..], &[]),
    ] {
        let mut seed = vec![OP_DER_PARSE_SEQUENCE];
        put_field(&mut seed, input);
        put_field(&mut seed, reads);
        seeds.push(seed);
    }
    // DER writing: TLVs, a long header, integers; then too little room
    let mut writes = vec![0u8, 3];
    put_field(&mut writes, b"value");
    writes.extend_from_slice(&[0, 0, 0]);
    put_field(&mut writes, &[0x33; 200]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0, 0, 0x80, 1]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0, 0]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0x12]);
    seeds.push([&[OP_DER_WRITE, 0x01, 0x00][..], &writes].concat());
    seeds.push([&[OP_DER_WRITE, 0x00, 0x40][..], &writes].concat());
    seeds.push(vec![
        OP_DER_WRITE,
        0x01,
        0x00,
        1,
        6,
        1,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
    ]);
    seeds.push(vec![
        OP_DER_WRITE,
        0x03,
        0xff,
        1,
        6,
        0,
        0xff,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);

    // ct: equal and different values, both choices
    for (same, bit) in [(1u8, 1u8), (0, 0)] {
        let mut seed = vec![OP_CT];
        seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7, same]);
        if same == 0 {
            seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 9]);
        }
        seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, bit]);
        put_short_field(&mut seed, b"src");
        seed.extend_from_slice(b"dst");
        seed.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        put_short_field(&mut seed, b"abc");
        seed.push(same);
        if same == 0 {
            put_short_field(&mut seed, b"abd");
        }
        seeds.push(seed);
    }
    // zeroize
    let mut seed = vec![OP_ZEROIZE];
    put_field(&mut seed, b"secret key bytes");
    seed.extend_from_slice(&[0x55; 40]);
    seeds.push(seed);
    // rand: draws of every size until the bytes run out, OsRng
    let mut seed = vec![OP_RAND];
    put_field(&mut seed, &[0x42; 40]);
    seed.extend_from_slice(&[5, 0, 1, 2, 2, 1, 1]);
    seeds.push(seed);
    // cpu: every mask
    for mask in 0..3u8 {
        seeds.push(vec![OP_CPU, mask]);
    }
    // accel: every call; Required for every algorithm and kind
    for op in 0..6u8 {
        for level in 0..3u8 {
            seeds.push(vec![OP_ACCEL, 11, level % 2, level, level, 2 - level, op]);
        }
    }
    for alg in 0..15u8 {
        for kind in 0..2u8 {
            seeds.push(vec![OP_ACCEL, alg, kind, 0, 0, 0, 1]);
        }
        seeds.push(vec![OP_ACCEL, alg, 0, 0, 0, 0, 0]);
        seeds.push(vec![
            OP_ACCEL, alg, 0, 0, 2, 2, 0, OP_ACCEL, alg, 0, 1, 1, 1, 0,
        ]);
    }
    for text in [&b"PreFered"[..], b"required", b"NONE", b"fast", b""] {
        let mut seed = vec![OP_ACCEL, 0, 0, 0, 0, 0, 5];
        put_short_field(&mut seed, text);
        seeds.push(seed);
    }
    seeds.push(vec![OP_ACCEL, 0, 1, 0, 1, 1, 4, 1, 0]);
    seeds.push(vec![OP_ERROR]);
    seeds
}
