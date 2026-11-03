//! RSA key generation with probable primes (FIPS 186-5, appendix A.1.3).
//!
//! Each prime candidate has its two top bits set (so `p q` has exactly the
//! requested size and `p, q > sqrt(2) 2^(bits/2 - 1)`), is sieved by trial
//! division against the odd primes below 2048 with incrementally updated
//! residues, must satisfy `p mod e != 1`, and is accepted after
//! [`MR_ROUNDS`] Miller–Rabin rounds with random bases. Primes closer than
//! `2^(bits/2 - 100)` are rejected. The private exponent is
//! `d = e^-1 mod (p-1)(q-1)` and `dP`, `dQ` are computed directly as
//! `e^-1 mod (p-1)` and `e^-1 mod (q-1)` using the small-exponent identity
//! `d = (1 + k phi) / e` with `k = -phi^-1 mod e`; `qInv` is `q^(p-2) mod p`.
//!
//! Timing: trial division and candidate rejection depend on the candidates,
//! and the small divisions use hardware division. The Miller–Rabin
//! exponentiations use the constant-time ladder.

use super::bigint::mont::{Kernel, Mont};
use super::bigint::{self, HALF_LIMBS, MAX_LIMBS};
use super::{MAX_MODULUS_BYTES, RsaPublicKey, private::RsaPrivateKey};
use crate::Error;
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// The public exponent used for generated keys.
pub const PUBLIC_EXPONENT: u64 = 65537;

/// Miller–Rabin rounds. FIPS 186-5 table B.1 needs at most 5 for the
/// supported sizes; 8 adds margin at negligible cost.
const MR_ROUNDS: usize = 8;

/// Trial division bound (exclusive).
const SIEVE_LIMIT: usize = 2048;
/// Capacity for the odd primes below [`SIEVE_LIMIT`] (there are 308).
const SIEVE_CAP: usize = 320;

/// Candidate increments tried per random start before drawing a new one.
const STEPS_PER_START: usize = 1 << 14;
/// Random starts tried per prime before giving up.
const STARTS_PER_PRIME: usize = 64;

/// Returns the odd primes below [`SIEVE_LIMIT`].
fn small_primes() -> ([u16; SIEVE_CAP], usize) {
    let mut composite = [false; SIEVE_LIMIT];
    let mut out = [0u16; SIEVE_CAP];
    let mut n = 0;
    for i in (3..SIEVE_LIMIT).step_by(2) {
        if !composite[i] {
            if n < SIEVE_CAP {
                out[n] = i as u16;
                n += 1;
            }
            let mut j = i * i;
            while j < SIEVE_LIMIT {
                composite[j] = true;
                j += 2 * i;
            }
        }
    }
    (out, n)
}

/// `x^-1 mod e` for prime `e` and `0 < x < e` (Fermat on `u64`).
fn inv_mod_e(x: u64) -> u64 {
    let e = PUBLIC_EXPONENT;
    let mut acc = 1u64;
    let mut base = x % e;
    let mut exp = e - 2;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = ((u128::from(acc) * u128::from(base)) % u128::from(e)) as u64;
        }
        base = ((u128::from(base) * u128::from(base)) % u128::from(e)) as u64;
        exp >>= 1;
    }
    acc
}

/// `out = e^-1 mod phi` where `gcd(e, phi) = 1`, via
/// `d = (1 + k phi) / e` with `k = -phi^-1 mod e`.
#[inline(never)]
fn inverse_of_e(phi: &[u64], out: &mut [u64]) -> Result<(), Error> {
    debug_assert_eq!(phi.len(), out.len());
    let e = PUBLIC_EXPONENT;
    let t = bigint::rem_word_vartime(phi, e);
    if t == 0 {
        return Err(Error::InvalidKey);
    }
    let k = (e - inv_mod_e(t)) % e;
    let mut tmp = [0u64; MAX_LIMBS + 1];
    let tmp = &mut tmp[..phi.len() + 1];
    bigint::mul_word(tmp, phi, k);
    bigint::add_word(tmp, 1);
    let rem = bigint::div_rem_word_vartime(tmp, e);
    let result = if rem != 0 || tmp[phi.len()] != 0 {
        Err(Error::InvalidKey)
    } else {
        out.copy_from_slice(&tmp[..phi.len()]);
        Ok(())
    };
    tmp.zeroize();
    result
}

/// Miller–Rabin test of the odd candidate `n` with random bases.
#[inline(never)]
fn miller_rabin(n: &[u64], rng: &dyn SecureRandom, kernel: Kernel) -> Result<bool, Error> {
    let len = n.len();
    let ctx = Mont::<HALF_LIMBS>::new(n, kernel)?;
    let mut nm1 = [0u64; HALF_LIMBS];
    nm1[..len].copy_from_slice(n);
    bigint::sub_word(&mut nm1[..len], 1);
    let mut d = nm1;
    let mut s = 0usize;
    while d[0] & 1 == 0 {
        bigint::shr1(&mut d[..len]);
        s += 1;
    }
    let mut nm1_m = [0u64; HALF_LIMBS];
    ctx.to_mont(&mut nm1_m[..len], &nm1[..len]);
    let one = ctx.one();
    // Bases are sampled with the candidate's bit length so that rejection
    // (a >= n - 1) is rare even for candidates that do not fill their limbs.
    let nbits = bigint::bit_len_vartime(n);

    let mut bytes = [0u8; MAX_MODULUS_BYTES / 2];
    let mut a = [0u64; HALF_LIMBS];
    let mut x = [0u64; HALF_LIMBS];
    let mut y = [0u64; HALF_LIMBS];
    let mut probably_prime = true;
    'rounds: for _ in 0..MR_ROUNDS {
        // Base in [2, n - 2].
        loop {
            rng.fill(&mut bytes[..len * 8])?;
            let _ = bigint::from_be_bytes(&mut a[..len], &bytes[..len * 8]);
            if !nbits.is_multiple_of(64) {
                a[len - 1] &= (1u64 << (nbits % 64)) - 1;
            }
            let small = a[..len].iter().skip(1).all(|&l| l == 0) && a[0] < 2;
            if !small && bigint::ct_lt(&a[..len], &nm1[..len]).declassify() {
                break;
            }
        }
        ctx.to_mont(&mut x[..len], &a[..len]);
        ctx.exp_ct(&mut y[..len], &x[..len], &d[..len]);
        if y[..len] == one[..] || y[..len] == nm1_m[..len] {
            continue;
        }
        for _ in 1..s {
            ctx.mul(&mut x[..len], &y[..len], &y[..len]);
            y[..len].copy_from_slice(&x[..len]);
            if y[..len] == nm1_m[..len] {
                continue 'rounds;
            }
            if y[..len] == one[..] {
                probably_prime = false;
                break 'rounds;
            }
        }
        probably_prime = false;
        break;
    }
    bytes.zeroize();
    a.zeroize();
    x.zeroize();
    y.zeroize();
    d.zeroize();
    nm1.zeroize();
    nm1_m.zeroize();
    Ok(probably_prime)
}

/// Generates a probable prime of exactly `bits` bits (a multiple of 64) with
/// its two top bits set and `p mod e != 1`.
#[inline(never)]
fn random_prime(
    bits: usize,
    rng: &dyn SecureRandom,
    kernel: Kernel,
    primes: &[u16],
    out: &mut [u64],
) -> Result<(), Error> {
    let len = bits / 64;
    debug_assert_eq!(out.len(), len);
    let mut bytes = [0u8; MAX_MODULUS_BYTES / 2];
    let mut cand = [0u64; HALF_LIMBS];
    let mut residues = [0u16; SIEVE_CAP];
    let result = 'search: {
        for _ in 0..STARTS_PER_PRIME {
            rng.fill(&mut bytes[..bits / 8])?;
            let _ = bigint::from_be_bytes(&mut cand[..len], &bytes[..bits / 8]);
            cand[len - 1] |= 0b11 << 62;
            cand[0] |= 1;
            for (r, &p) in residues.iter_mut().zip(primes) {
                *r = bigint::rem_word_vartime(&cand[..len], u64::from(p)) as u16;
            }
            for _ in 0..STEPS_PER_START {
                let sieved = residues[..primes.len()].iter().all(|&r| r != 0);
                if sieved
                    && bigint::rem_word_vartime(&cand[..len], PUBLIC_EXPONENT) != 1
                    && miller_rabin(&cand[..len], rng, kernel)?
                {
                    out.copy_from_slice(&cand[..len]);
                    break 'search Ok(());
                }
                if bigint::add_word(&mut cand[..len], 2) != 0 {
                    break; // overflowed the size: draw a new start
                }
                for (r, &p) in residues.iter_mut().zip(primes) {
                    *r = (*r + 2) % p;
                }
            }
        }
        Err(Error::RandomFailure)
    };
    bytes.zeroize();
    cand.zeroize();
    result
}

/// See [`RsaPrivateKey::generate`].
pub(super) fn generate(bits: usize, rng: &dyn SecureRandom) -> Result<RsaPrivateKey, Error> {
    if !matches!(bits, 2048 | 3072 | 4096) {
        return Err(Error::Unsupported);
    }
    let half_bits = bits / 2;
    let half = half_bits / 64;
    let l = bits / 64;
    let kernel = Kernel::detect();
    let (primes, n_primes) = small_primes();
    let primes = &primes[..n_primes];

    let mut p = [0u64; HALF_LIMBS];
    let mut q = [0u64; HALF_LIMBS];
    let mut diff = [0u64; HALF_LIMBS];
    let mut n = [0u64; MAX_LIMBS];
    let mut phi = [0u64; MAX_LIMBS];
    let mut pm1 = [0u64; HALF_LIMBS];
    let mut qm1 = [0u64; HALF_LIMBS];
    let mut d = [0u64; MAX_LIMBS];
    let mut dp = [0u64; HALF_LIMBS];
    let mut dq = [0u64; HALF_LIMBS];
    let mut qinv = [0u64; HALF_LIMBS];
    let mut tmp = [0u64; HALF_LIMBS];
    let mut n_bytes = [0u8; MAX_MODULUS_BYTES];

    let result = 'attempts: {
        for _ in 0..8 {
            random_prime(half_bits, rng, kernel, primes, &mut p[..half])?;
            random_prime(half_bits, rng, kernel, primes, &mut q[..half])?;

            // |p - q| > 2^(bits/2 - 100)
            if bigint::sub(&mut diff[..half], &p[..half], &q[..half]) != 0 {
                bigint::sub(&mut diff[..half], &q[..half], &p[..half]);
            }
            if bigint::bit_len_vartime(&diff[..half]) <= half_bits - 100 {
                continue;
            }

            bigint::mul(&mut n[..l], &p[..half], &q[..half]);
            debug_assert_eq!(bigint::bit_len_vartime(&n[..l]), bits);

            pm1[..half].copy_from_slice(&p[..half]);
            bigint::sub_word(&mut pm1[..half], 1);
            qm1[..half].copy_from_slice(&q[..half]);
            bigint::sub_word(&mut qm1[..half], 1);
            bigint::mul(&mut phi[..l], &pm1[..half], &qm1[..half]);
            if inverse_of_e(&phi[..l], &mut d[..l]).is_err()
                || inverse_of_e(&pm1[..half], &mut dp[..half]).is_err()
                || inverse_of_e(&qm1[..half], &mut dq[..half]).is_err()
            {
                continue;
            }
            // FIPS 186-5 A.1.1: d > 2^(bits/2).
            if bigint::bit_len_vartime(&d[..l]) <= half_bits {
                continue;
            }

            // qInv = q^(p-2) mod p.
            let p_ctx = Mont::<HALF_LIMBS>::new(&p[..half], kernel)?;
            p_ctx.to_mont(&mut tmp[..half], &q[..half]);
            let mut pm2 = [0u64; HALF_LIMBS];
            pm2[..half].copy_from_slice(&p[..half]);
            bigint::sub_word(&mut pm2[..half], 2);
            p_ctx.exp_ct(&mut qinv[..half], &tmp[..half], &pm2[..half]);
            p_ctx.demont(&mut tmp[..half], &qinv[..half]);
            qinv[..half].copy_from_slice(&tmp[..half]);
            pm2.zeroize();

            bigint::to_be_bytes(&n[..l], &mut n_bytes[..bits / 8]);
            let public = RsaPublicKey::from_components(
                &n_bytes[..bits / 8],
                &PUBLIC_EXPONENT.to_be_bytes(),
            )?;
            break 'attempts RsaPrivateKey::from_limbs(
                public,
                &d[..l],
                &p[..half],
                &q[..half],
                &dp[..half],
                &dq[..half],
                &qinv[..half],
            );
        }
        Err(Error::RandomFailure)
    };
    p.zeroize();
    q.zeroize();
    diff.zeroize();
    phi.zeroize();
    pm1.zeroize();
    qm1.zeroize();
    d.zeroize();
    dp.zeroize();
    dq.zeroize();
    qinv.zeroize();
    tmp.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sieve_lists_odd_primes() {
        let (primes, n) = small_primes();
        assert_eq!(n, 308);
        assert_eq!(&primes[..5], &[3, 5, 7, 11, 13]);
        assert_eq!(primes[n - 1], 2039);
        for &p in &primes[..n] {
            assert!((3..p).all(|d| p % d != 0 || d == 1));
        }
    }

    #[test]
    fn small_inverse() {
        for x in [1u64, 2, 3, 65535, 65536, 12345] {
            let inv = inv_mod_e(x);
            assert_eq!(
                (u128::from(x) * u128::from(inv)) % u128::from(PUBLIC_EXPONENT),
                1
            );
        }
    }

    #[test]
    fn inverse_of_e_matches_definition() {
        // phi = 2^127 - 2 (even), gcd(e, phi) = 1 for e = 65537.
        let phi = [u64::MAX - 1, u64::MAX >> 1];
        let mut d = [0u64; 2];
        inverse_of_e(&phi, &mut d).unwrap();
        // e d mod phi == 1: compute e d (3 limbs) and reduce.
        let mut ed = [0u64; 3];
        bigint::mul_word(&mut ed, &d, PUBLIC_EXPONENT);
        let mut r = [0u64; 2];
        bigint::ct_mod(&mut r, &ed, &phi);
        assert_eq!(r, [1, 0]);
    }

    #[test]
    fn miller_rabin_known_values() {
        let rng = crate::rand::OsRng;
        let kernel = Kernel::detect();
        // 2^127 - 1 is prime.
        assert!(miller_rabin(&[u64::MAX, u64::MAX >> 1], &rng, kernel).unwrap());
        // 2^127 - 3? Compose a known composite: (2^64 - 59) * (2^64 - 83)
        // (both prime) is odd.
        let mut prod = [0u64; 2];
        bigint::mul(&mut prod, &[u64::MAX - 58], &[u64::MAX - 82]);
        assert!(!miller_rabin(&prod, &rng, kernel).unwrap());
        // A Carmichael-like composite: 2^89 - 1 = 618970019642690137449562111 is
        // prime; 2^89 + 1 is composite (divisible by 3).
        let mut c = [1u64, 1 << 25];
        c[0] = 1;
        assert!(!miller_rabin(&c, &rng, kernel).unwrap());
    }
}
