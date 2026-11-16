//! Finite-field Diffie-Hellman (`ffdhe`) operations of the `crypto_kem`
//! target: peer validation, exponentiation and agreement against
//! `num-bigint` and between the Montgomery kernels.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::ffdhe::{self, Group};
use browntls_crypto::rand::{FixedRng, OsRng};
use num_bigint::BigUint;

use super::{Budget, OP_FFDHE_AGREE, OP_FFDHE_EXPONENT, OP_FFDHE_VALIDATE, exact};
use crate::input::Input;

fn prime(group: Group) -> BigUint {
    BigUint::from_bytes_be(group.prime_be())
}

/// `v` big-endian, left-padded to `len` bytes (longer if `v` needs it).
fn be_padded(v: &BigUint, len: usize) -> Vec<u8> {
    let raw = v.to_bytes_be();
    let mut out = vec![0u8; len.max(raw.len())];
    let at = out.len() - raw.len();
    out[at..].copy_from_slice(&raw);
    out
}

/// Checks the group's constant accessors against each other and RFC 7919.
fn check_group(group: Group) {
    let p = group.prime_be();
    assert_eq!(p.len(), group.element_len());
    assert_eq!(group.element_len() * 8, group.prime_bits());
    assert_eq!(&p[..8], &[0xff; 8]);
    assert_eq!(&p[p.len() - 8..], &[0xff; 8]);
    assert!(group.min_exponent_bits() >= 2 * group.security_bits());
    assert!(group.exponent_bits() >= group.min_exponent_bits());
    assert!(group.exponent_bits() < group.min_exponent_bits() + 64);
    assert_eq!(group.exponent_bits() % 64, 0);
    assert_eq!(group.exponent_len() * 8, group.exponent_bits());
    assert!(group.exponent_len() <= ffdhe::MAX_EXPONENT_LEN);
    assert!(group.element_len() <= ffdhe::MAX_ELEMENT_LEN);
    assert_eq!(group.name(), format!("ffdhe{}", group.prime_bits()));
}

/// A peer value for `group`: fuzzed bytes, or a boundary value (0, 2,
/// p - 2, p, 2^bits - 1) moved by a small fuzzed offset (reaching 1,
/// p - 1, p + 1 ...), with an optional length error.
fn peer_value(input: &mut Input<'_>, group: Group) -> Vec<u8> {
    let len = group.element_len();
    let p = prime(group);
    let mut bytes = match input.choose(4) {
        0 => exact(input, len),
        1 => input.field().to_vec(),
        _ => {
            let base = match input.choose(5) {
                0 => BigUint::from(0u8),
                1 => &p - 2u8,
                2 => p.clone(),
                3 => (BigUint::from(1u8) << group.prime_bits()) - 1u8,
                _ => BigUint::from(2u8),
            };
            let delta = BigUint::from(input.byte() % 4);
            let v = if input.bool() {
                base + delta
            } else if base >= delta {
                base - delta
            } else {
                base
            };
            be_padded(&v, len)
        }
    };
    match input.choose(8) {
        0 => bytes.insert(0, 0),
        1 if !bytes.is_empty() => {
            bytes.remove(0);
        }
        _ => {}
    }
    bytes
}

/// Whether `peer` is a valid public value: the right length and in
/// `(1, p - 1)`.
fn peer_valid(group: Group, peer: &[u8]) -> bool {
    let y = BigUint::from_bytes_be(peer);
    peer.len() == group.element_len() && y > BigUint::from(1u8) && y < prime(group) - 1u8
}

/// A private exponent: fuzzed bytes of the right or a fuzzed length, or a
/// small value.
fn exponent(input: &mut Input<'_>, group: Group) -> Vec<u8> {
    let len = group.exponent_len();
    match input.choose(4) {
        0 => input.field().to_vec(),
        1 => {
            let mut e = vec![0u8; len];
            e[len - 1] = input.byte() % 4;
            e
        }
        _ => exact(input, len),
    }
}

fn public_key(key: &ffdhe::PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; key.group().element_len()];
    key.public_key(&mut out).expect("right length");
    out
}

/// `f` with the RSA Montgomery kernels restricted to portable code.
fn portable<T>(f: impl FnOnce() -> T) -> T {
    accel::set_policy(Algorithm::Rsa, Policy::NONE).expect("portable is always available");
    let out = f();
    accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).expect("always satisfiable");
    out
}

pub(super) fn ffdhe_op(op: u8, input: &mut Input<'_>, budget: &mut Budget) {
    let group = *input.pick(&Group::ALL);
    check_group(group);
    let len = group.element_len();
    match op {
        OP_FFDHE_VALIDATE => {
            let peer = peer_value(input, group);
            let result = group.validate_public_key(&peer);
            assert_eq!(
                result.is_ok(),
                peer_valid(group, &peer),
                "{} peer of {} bytes",
                group.name(),
                peer.len()
            );
            if let Err(e) = result {
                assert_eq!(e, Error::InvalidKey);
            }
        }
        OP_FFDHE_EXPONENT => {
            let e = exponent(input, group);
            let x = BigUint::from_bytes_be(&e);
            let key = match ffdhe::PrivateKey::from_exponent_be(group, &e) {
                Ok(key) => {
                    assert_eq!(e.len(), group.exponent_len());
                    assert!(x >= BigUint::from(2u8));
                    key
                }
                Err(err) => {
                    assert_eq!(err, Error::InvalidKey);
                    assert!(e.len() != group.exponent_len() || x < BigUint::from(2u8));
                    return;
                }
            };
            assert_eq!(key.group(), group);
            for wrong in [len - 1, len + 1, 0] {
                let mut out = vec![0u8; wrong];
                assert_eq!(key.public_key(&mut out), Err(Error::InvalidLength));
                assert_eq!(
                    key.diffie_hellman(&[2], &mut out),
                    Err(Error::InvalidLength)
                );
            }
            // Each exponentiation (ours, the oracle's, the portable
            // kernel's) is taken from the budget separately, so the largest
            // groups still run g^x.
            if !budget.ffdhe(group, 1) {
                return;
            }
            let y = public_key(&key);
            assert_eq!(group.validate_public_key(&y), Ok(()));
            if budget.ffdhe(group, 1) {
                let expected = BigUint::from(ffdhe::GENERATOR).modpow(&x, &prime(group));
                assert_eq!(y, be_padded(&expected, len), "{} g^x", group.name());
            }
            if budget.ffdhe(group, 1) {
                assert_eq!(
                    portable(|| public_key(&key)),
                    y,
                    "{} portable vs accelerated",
                    group.name()
                );
            }
        }
        OP_FFDHE_AGREE => {
            let ea = exact(input, group.exponent_len());
            let Ok(a) = ffdhe::PrivateKey::from_exponent_be(group, &ea) else {
                return;
            };
            if input.bool() {
                // A genuine exchange is symmetric.
                let eb = exact(input, group.exponent_len());
                let Ok(b) = ffdhe::PrivateKey::from_exponent_be(group, &eb) else {
                    return;
                };
                if !budget.ffdhe(group, 4) {
                    return;
                }
                let (ya, yb) = (public_key(&a), public_key(&b));
                let (mut za, mut zb) = (vec![0u8; len], vec![0u8; len]);
                a.diffie_hellman(&yb, &mut za).expect("valid peer");
                b.diffie_hellman(&ya, &mut zb).expect("valid peer");
                assert_eq!(za, zb, "{} agreement is not symmetric", group.name());
                return;
            }
            let peer = peer_value(input, group);
            let compare_portable = input.bool();
            let mut out = vec![0xa5u8; len];
            if !peer_valid(group, &peer) {
                assert_eq!(a.diffie_hellman(&peer, &mut out), Err(Error::InvalidKey));
                assert!(out.iter().all(|&b| b == 0xa5), "output written on error");
                return;
            }
            if !budget.ffdhe(group, 1) {
                return;
            }
            let result = a.diffie_hellman(&peer, &mut out);
            if budget.ffdhe(group, 1) {
                let p = prime(group);
                let z = BigUint::from_bytes_be(&peer).modpow(&BigUint::from_bytes_be(&ea), &p);
                let degenerate = z <= BigUint::from(1u8) || z == &p - 1u8;
                if degenerate {
                    assert_eq!(result, Err(Error::KeyAgreementFailed));
                } else {
                    assert_eq!(result, Ok(()));
                    assert_eq!(out, be_padded(&z, len), "{} Y^x", group.name());
                }
            }
            match result {
                Ok(()) => {}
                Err(e) => {
                    assert_eq!(e, Error::KeyAgreementFailed);
                    assert!(out.iter().all(|&b| b == 0xa5), "output written on error");
                }
            }
            if compare_portable && budget.ffdhe(group, 1) {
                let mut out2 = vec![0xa5u8; len];
                let result2 = portable(|| a.diffie_hellman(&peer, &mut out2));
                assert_eq!(result2, result);
                assert_eq!(out2, out, "{} portable vs accelerated", group.name());
            }
        }
        _ => {
            // Generation draws exactly exponent_len bytes and sets the top bit.
            let n = group.exponent_len();
            let mut bytes = input.field().to_vec();
            bytes.truncate(n + 8);
            match ffdhe::PrivateKey::generate(group, &FixedRng::new(&bytes)) {
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(bytes.len() < n);
                }
                Ok(key) => {
                    assert!(bytes.len() >= n);
                    assert_eq!(key.group(), group);
                    let mut e = bytes[..n].to_vec();
                    e[0] |= 0x80;
                    let same = ffdhe::PrivateKey::from_exponent_be(group, &e).expect("top bit set");
                    if budget.ffdhe(group, 2) {
                        assert_eq!(public_key(&key), public_key(&same));
                    }
                }
            }
            if input.bool() && budget.ffdhe(group, 1) {
                let key = ffdhe::PrivateKey::generate(group, &OsRng).expect("OS randomness");
                assert_eq!(group.validate_public_key(&public_key(&key)), Ok(()));
            }
        }
    }
}
