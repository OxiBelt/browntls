//! FFDHE tests: the RFC 7919 moduli against the Appendix A construction,
//! key agreement in both directions for every group, the fixed-length
//! encodings of RFC 9846 §4.3.8.1 and §7.4.1, peer-value validation, and a
//! differential check of both exponentiations against `num-bigint`.
//!
//! The safe-prime property (with the crate's Miller–Rabin test) and every
//! Montgomery kernel are covered by the unit tests in `src/ffdhe/tests.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::ffdhe::{GENERATOR, Group, MAX_ELEMENT_LEN, MAX_EXPONENT_LEN, PrivateKey};
use browntls_crypto::rand::{FixedRng, OsRng, SecureRandom};
use num_bigint::BigUint;

/// `X` of RFC 7919 Appendix A.1 to A.5, in [`Group::ALL`] order.
const RFC_X: [u32; 5] = [560_316, 2_625_351, 5_736_041, 15_705_020, 10_965_728];

/// `floor(2^k e)`, exactly, from `e = sum 1/n!` with 64 guard bits.
fn floor_pow2_e(k: usize) -> BigUint {
    let guard = 64;
    let mut term = BigUint::from(1u8) << (k + guard);
    let mut sum = BigUint::from(0u8);
    let mut n = 0u32;
    while term != BigUint::from(0u8) {
        sum += &term;
        n += 1;
        term /= n;
    }
    // Each of the n terms was truncated by less than one unit and the
    // remaining tail is below one unit: the exact value is in [sum, sum + n + 1).
    let lo = &sum >> guard;
    let hi = (sum + n + 1u32) >> guard;
    assert_eq!(lo, hi, "not enough guard bits");
    lo
}

fn be_padded(v: &BigUint, len: usize) -> Vec<u8> {
    let raw = v.to_bytes_be();
    assert!(raw.len() <= len);
    let mut out = vec![0u8; len];
    out[len - raw.len()..].copy_from_slice(&raw);
    out
}

fn prime(group: Group) -> BigUint {
    BigUint::from_bytes_be(group.prime_be())
}

/// An exponent for [`PrivateKey::from_exponent_be`] with value `x`.
fn key(group: Group, x: &BigUint) -> PrivateKey {
    PrivateKey::from_exponent_be(group, &be_padded(x, group.exponent_len())).unwrap()
}

fn public(key: &PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; key.group().element_len()];
    key.public_key(&mut out).unwrap();
    out
}

fn agree(key: &PrivateKey, peer: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; key.group().element_len()];
    key.diffie_hellman(peer, &mut out)?;
    Ok(out)
}

#[test]
fn primes_match_the_rfc_construction() {
    assert_eq!(GENERATOR, 2);
    for (group, x) in Group::ALL.into_iter().zip(RFC_X) {
        let b = group.prime_bits();
        let p = group.prime_be();
        assert_eq!(p.len(), b / 8, "{group:?}");
        assert_eq!(group.element_len(), b / 8);
        // RFC 7919 §2: the high and low 64 bits are all ones.
        assert_eq!(&p[..8], &[0xff; 8], "{group:?}");
        assert_eq!(&p[p.len() - 8..], &[0xff; 8], "{group:?}");
        // RFC 7919 Appendix A: p = 2^b - 2^(b-64) + ([2^(b-130) e] + X) 2^64 - 1.
        let one = BigUint::from(1u8);
        let expected =
            (&one << b) - (&one << (b - 64)) + ((floor_pow2_e(b - 130) + x) << 64) - &one;
        assert_eq!(prime(group), expected, "{group:?}");
        assert_eq!(group.name(), format!("ffdhe{b}"));
        // A safe prime p = 2q + 1 with q odd is 3 mod 4 (and 7 mod 8 since
        // 2 generates the subgroup of order q, a quadratic residue).
        assert_eq!(prime(group) % 8u8, BigUint::from(7u8), "{group:?}");
    }
    assert_eq!(
        Group::ALL.map(Group::prime_bits),
        [2048, 3072, 4096, 6144, 8192]
    );
    assert_eq!(MAX_ELEMENT_LEN, Group::Ffdhe8192.element_len());
}

#[test]
fn exponent_lengths_follow_rfc_7919() {
    for group in Group::ALL {
        let m = group.exponent_bits();
        // An m-bit exponent with m at least the Appendix A bound (§5.2),
        // whole limbs, and with the forced top bit still at least as many
        // random bits as the bound and twice the estimated strength.
        let random_bits = m - 1;
        assert!(m >= group.min_exponent_bits(), "{group:?}");
        assert!(random_bits >= group.min_exponent_bits(), "{group:?}");
        assert!(random_bits >= 2 * group.security_bits(), "{group:?}");
        assert_eq!(m % 64, 0);
        assert!(m - group.min_exponent_bits() < 64);
        assert_eq!(group.exponent_len() * 8, m);
        assert!(group.exponent_len() <= MAX_EXPONENT_LEN);
    }
    assert_eq!(
        Group::ALL.map(Group::exponent_bits),
        [256, 320, 384, 384, 448]
    );
    assert_eq!(
        Group::ALL.map(Group::min_exponent_bits),
        [225, 275, 325, 375, 400]
    );
    assert_eq!(
        Group::ALL.map(Group::security_bits),
        [103, 125, 150, 175, 192]
    );
}

#[test]
fn generated_exponents_are_m_bit_integers_from_the_rng() {
    // With a fixed byte source the exponent is the drawn bytes with the
    // top bit forced, x in [2^(m-1), 2^m).
    for group in Group::ALL {
        let n = group.exponent_len();
        let p = prime(group);
        for fill in [0x00u8, 0x5a, 0xff] {
            let bytes = vec![fill; n];
            let key = PrivateKey::generate(group, &FixedRng::new(&bytes)).unwrap();
            let mut x = BigUint::from_bytes_be(&bytes);
            x |= BigUint::from(1u8) << (8 * n - 1);
            let y = BigUint::from(GENERATOR).modpow(&x, &p);
            assert_eq!(public(&key), be_padded(&y, group.element_len()));
        }
        // The source is asked for exactly the exponent length.
        let short = vec![1u8; n - 1];
        assert_eq!(
            PrivateKey::generate(group, &FixedRng::new(&short)).unwrap_err(),
            Error::RandomFailure
        );
    }
}

#[test]
fn agreement_in_both_directions_for_every_group() {
    for group in Group::ALL {
        for _ in 0..3 {
            let a = PrivateKey::generate(group, &OsRng).unwrap();
            let b = PrivateKey::generate(group, &OsRng).unwrap();
            assert_eq!(a.group(), group);
            let (a_pub, b_pub) = (public(&a), public(&b));
            assert_eq!(a_pub.len(), group.element_len());
            group.validate_public_key(&a_pub).unwrap();
            group.validate_public_key(&b_pub).unwrap();
            let z_ab = agree(&a, &b_pub).unwrap();
            let z_ba = agree(&b, &a_pub).unwrap();
            assert_eq!(z_ab, z_ba, "{group:?}");
            assert_eq!(z_ab.len(), group.element_len());
            assert_ne!(a_pub, b_pub);
            // The public value is a pure function of the key.
            assert_eq!(public(&a), a_pub);
        }
    }
}

#[test]
fn encodings_are_left_padded_to_the_prime_length() {
    for group in Group::ALL {
        let n = group.element_len();
        let bits = group.prime_bits();
        // x = 2 gives Y = 4: n - 1 leading zero bytes.
        let y = public(&key(group, &BigUint::from(2u8)));
        let mut expect = vec![0u8; n];
        expect[n - 1] = 4;
        assert_eq!(y, expect, "{group:?}");
        // x = 8n - 9 gives Y = 2^(8n - 9) < p: exactly one leading zero byte.
        let y = public(&key(group, &BigUint::from(bits as u32 - 9)));
        assert_eq!((y[0], y[1]), (0x00, 0x80), "{group:?}");
        assert!(y[2..].iter().all(|&b| b == 0));
        // Z = 4^3 = 64 (n - 1 leading zero bytes) and Z = 4^(4n - 12) =
        // 2^(8n - 24) (two leading zero bytes, then 0x01).
        let mut four = vec![0u8; n];
        four[n - 1] = 4;
        let z = agree(&key(group, &BigUint::from(3u8)), &four).unwrap();
        let mut expect = vec![0u8; n];
        expect[n - 1] = 64;
        assert_eq!(z, expect, "{group:?}");
        let x = BigUint::from(bits as u32 / 2 - 12);
        let z = agree(&key(group, &x), &four).unwrap();
        assert_eq!((z[0], z[1], z[2]), (0, 0, 1), "{group:?}");
        assert!(z[3..].iter().all(|&b| b == 0));
        // A generated key also accepts peer values with leading zero bytes:
        // Z = 4^x = (2^x)^2 = Y^2 mod p.
        let a = PrivateKey::generate(group, &OsRng).unwrap();
        let z = agree(&a, &four).unwrap();
        let y = BigUint::from_bytes_be(&public(&a));
        assert_eq!(z, be_padded(&(&y * &y % prime(group)), n), "{group:?}");
    }
}

#[test]
fn shared_secrets_with_a_leading_zero_byte_agree() {
    // Random exchanges reach Z < 2^(8n - 8) with probability about 1/256;
    // both sides must keep the zero byte.
    let group = Group::Ffdhe2048;
    let a = PrivateKey::generate(group, &OsRng).unwrap();
    let a_pub = public(&a);
    for _ in 0..4096 {
        let b = PrivateKey::generate(group, &OsRng).unwrap();
        let z = agree(&b, &a_pub).unwrap();
        if z[0] == 0 {
            assert_eq!(agree(&a, &public(&b)).unwrap(), z);
            assert_eq!(z.len(), group.element_len());
            return;
        }
    }
    panic!("no shared secret with a leading zero byte in 4096 exchanges");
}

#[test]
fn invalid_peer_values_are_rejected() {
    for group in Group::ALL {
        let n = group.element_len();
        let p = prime(group);
        let one = BigUint::from(1u8);
        let a = PrivateKey::generate(group, &OsRng).unwrap();
        let reject = |value: &[u8], what: &str| {
            assert_eq!(
                group.validate_public_key(value).unwrap_err(),
                Error::InvalidKey,
                "{group:?} accepted {what}"
            );
            let mut out = vec![0xa5u8; n];
            assert_eq!(
                a.diffie_hellman(value, &mut out).unwrap_err(),
                Error::InvalidKey,
                "{group:?} agreed with {what}"
            );
            assert!(out.iter().all(|&b| b == 0xa5), "output written on error");
        };
        // Out of range: 0, 1, p - 1, p, p + 1, and the largest n-byte value.
        reject(&vec![0u8; n], "0");
        reject(&be_padded(&one, n), "1");
        reject(&be_padded(&(&p - 1u8), n), "p - 1");
        reject(group.prime_be(), "p");
        reject(&be_padded(&(&p + 1u8), n), "p + 1");
        reject(&vec![0xffu8; n], "2^(8n) - 1");
        // Wrong lengths, even when the value would be in range.
        let good = public(&PrivateKey::generate(group, &OsRng).unwrap());
        reject(&[], "an empty value");
        reject(&good[1..], "n - 1 bytes");
        reject(&good[..n - 1], "a truncated value");
        let mut padded = vec![0u8];
        padded.extend_from_slice(&good);
        reject(&padded, "n + 1 bytes with a leading zero");
        let mut four = vec![0u8; n - 1];
        four[n - 2] = 4;
        reject(&four, "4 without full padding");
        // The extremes of the valid range are accepted.
        for v in [BigUint::from(2u8), &p - 2u8] {
            let bytes = be_padded(&v, n);
            group.validate_public_key(&bytes).unwrap();
            let z = agree(&a, &bytes).unwrap();
            assert_eq!(z.len(), n);
        }
        group.validate_public_key(&good).unwrap();
        // Output buffers of the wrong size are refused before any work.
        for len in [0, n - 1, n + 1] {
            let mut out = vec![0u8; len];
            assert_eq!(
                a.diffie_hellman(&good, &mut out).unwrap_err(),
                Error::InvalidLength
            );
            assert_eq!(a.public_key(&mut out).unwrap_err(), Error::InvalidLength);
        }
    }
}

#[test]
fn exponent_import_rules() {
    for group in Group::ALL {
        let n = group.exponent_len();
        let mut x = vec![0u8; n];
        for small in [0u8, 1] {
            x[n - 1] = small;
            assert_eq!(
                PrivateKey::from_exponent_be(group, &x).unwrap_err(),
                Error::InvalidKey
            );
        }
        x[n - 1] = 2;
        PrivateKey::from_exponent_be(group, &x).unwrap();
        for len in [0, n - 1, n + 1] {
            assert_eq!(
                PrivateKey::from_exponent_be(group, &vec![7u8; len]).unwrap_err(),
                Error::InvalidKey
            );
        }
        let key = PrivateKey::from_exponent_be(group, &vec![0xffu8; n]).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("Ffdhe") && !debug.contains("255"), "{debug}");
    }
}

#[test]
fn exponentiation_matches_num_bigint() {
    // Random exponents and peer values, plus exponent edge cases: 2, the
    // smallest and largest m-bit values, and alternating bit patterns.
    let mut rng_bytes = vec![0u8; 4 * MAX_EXPONENT_LEN + 8 * MAX_ELEMENT_LEN];
    for group in Group::ALL {
        let n = group.element_len();
        let m = group.exponent_bits();
        let p = prime(group);
        let g = BigUint::from(GENERATOR);
        let one = BigUint::from(1u8);
        let mut exponents = vec![
            BigUint::from(2u8),
            &one << (m - 1),
            (&one << m) - 1u8,
            BigUint::from_bytes_be(&vec![0xaa; m / 8]),
            BigUint::from_bytes_be(&vec![0x55; m / 8]),
        ];
        OsRng.fill(&mut rng_bytes).unwrap();
        for chunk in rng_bytes[..4 * (m / 8)].chunks(m / 8) {
            exponents.push(BigUint::from_bytes_be(chunk) | BigUint::from(2u8));
        }
        let peers: Vec<BigUint> = rng_bytes[4 * MAX_EXPONENT_LEN..]
            .chunks(MAX_ELEMENT_LEN)
            .take(4)
            .map(|c| BigUint::from_bytes_be(&c[..n]) % (&p - 3u8) + 2u8)
            .chain([BigUint::from(2u8), &p - 2u8])
            .collect();
        for x in &exponents {
            let k = key(group, x);
            assert_eq!(
                BigUint::from_bytes_be(&public(&k)),
                g.modpow(x, &p),
                "{group:?} g^{x:x}"
            );
            for y in &peers {
                let z = agree(&k, &be_padded(y, n)).unwrap();
                assert_eq!(BigUint::from_bytes_be(&z), y.modpow(x, &p), "{group:?}");
            }
        }
    }
}
