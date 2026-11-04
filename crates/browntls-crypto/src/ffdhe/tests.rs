//! Unit tests that need the crate internals: the safe-prime property of
//! every modulus (with the crate's Miller–Rabin test) and every Montgomery
//! kernel against `num-bigint`.

use num_bigint::BigUint;
use std::vec;
use std::vec::Vec;

use super::*;
use crate::rand::OsRng;
use crate::rsa::keygen::miller_rabin;

/// `(p, q = (p - 1) / 2)` as limbs.
fn p_and_q(group: Group) -> (Vec<u64>, Vec<u64>) {
    let mut p = vec![0u64; group.limbs()];
    group.load_prime(&mut p).unwrap();
    let mut q = p.clone();
    // p is odd: shifting right drops the 1 and halves p - 1.
    assert_eq!(bigint::shr1(&mut q), 1);
    (p, q)
}

fn is_probable_prime(n: &[u64]) -> bool {
    let kernel = Kernel::detect();
    if n.len() <= HALF_LIMBS {
        miller_rabin::<HALF_LIMBS>(n, &OsRng, kernel).unwrap()
    } else {
        miller_rabin::<MAX_LIMBS>(n, &OsRng, kernel).unwrap()
    }
}

fn check_safe_prime(group: Group) {
    let (p, q) = p_and_q(group);
    assert_eq!(bigint::bit_len_vartime(&p), group.prime_bits());
    assert_eq!(bigint::bit_len_vartime(&q), group.prime_bits() - 1);
    assert!(is_probable_prime(&p), "{group:?}: p");
    assert!(is_probable_prime(&q), "{group:?}: (p - 1) / 2");
}

#[test]
fn small_moduli_are_safe_primes() {
    check_safe_prime(Group::Ffdhe2048);
    check_safe_prime(Group::Ffdhe3072);
    // The test is not vacuous at this size: 3 q is composite.
    let (_, q) = p_and_q(Group::Ffdhe2048);
    let mut three_q = vec![0u64; q.len() + 1];
    bigint::mul_word(&mut three_q, &q, 3);
    assert!(!is_probable_prime(&three_q));
}

/// About six seconds with the BMI2/ADX kernel in the test profile; run with
/// `cargo test -p browntls-crypto --lib -- --ignored ffdhe`.
#[test]
#[ignore = "slow: Miller-Rabin on 4096- to 8192-bit moduli"]
fn large_moduli_are_safe_primes() {
    check_safe_prime(Group::Ffdhe4096);
    check_safe_prime(Group::Ffdhe6144);
    check_safe_prime(Group::Ffdhe8192);
    // A 6143-bit composite exercises the 128-limb capacity.
    let (_, q4096) = p_and_q(Group::Ffdhe4096);
    let (_, q2048) = p_and_q(Group::Ffdhe2048);
    let mut product = vec![0u64; q4096.len() + q2048.len()];
    bigint::mul(&mut product, &q4096, &q2048);
    assert!(!is_probable_prime(&product));
}

fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed >> 12;
    *seed ^= *seed << 25;
    *seed ^= *seed >> 27;
    seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn random_bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng(seed) as u8).collect()
}

#[test]
fn every_kernel_matches_num_bigint() {
    // A fixed, arbitrary seed for the xorshift generator.
    let mut seed = 0x0ffd_4e20_4830_7219u64;
    for group in Group::ALL {
        let n = group.element_len();
        let p = BigUint::from_bytes_be(group.prime_be());
        let two = BigUint::from(2u8);
        for round in 0..3 {
            let mut x_bytes = random_bytes(&mut seed, group.exponent_len());
            if round == 0 {
                x_bytes.fill(0xff);
            }
            let key = PrivateKey::from_exponent_be(group, &x_bytes).unwrap();
            let x = BigUint::from_bytes_be(&x_bytes);
            // A peer value in [2, p - 2]: reduce random bytes, then clamp.
            let peer = BigUint::from_bytes_be(&random_bytes(&mut seed, n)) % (&p - 3u8) + 2u8;
            let mut peer_be = vec![0u8; n];
            let raw = peer.to_bytes_be();
            peer_be[n - raw.len()..].copy_from_slice(&raw);

            let expect_y = two.modpow(&x, &p);
            let expect_z = peer.modpow(&x, &p);
            for kernel in Kernel::available().into_iter().flatten() {
                let mut y = vec![0u8; n];
                key.public_key_with(&mut y, kernel).unwrap();
                assert_eq!(
                    BigUint::from_bytes_be(&y),
                    expect_y,
                    "{group:?} {}",
                    kernel.name()
                );
                let mut z = vec![0u8; n];
                key.diffie_hellman_with(&peer_be, &mut z, kernel).unwrap();
                assert_eq!(
                    BigUint::from_bytes_be(&z),
                    expect_z,
                    "{group:?} {}",
                    kernel.name()
                );
            }
        }
    }
}

#[test]
fn degenerate_shared_secrets_are_detected() {
    for group in Group::ALL {
        let len = group.limbs();
        let mut z = vec![0u64; len];
        assert!(is_degenerate(group, &z).unwrap().declassify());
        z[0] = 1;
        assert!(is_degenerate(group, &z).unwrap().declassify());
        z[0] = 2;
        assert!(!is_degenerate(group, &z).unwrap().declassify());
        group.load_prime_minus_one(&mut z).unwrap();
        assert!(is_degenerate(group, &z).unwrap().declassify());
        bigint::sub_word(&mut z, 1);
        assert!(!is_degenerate(group, &z).unwrap().declassify());
    }
}
