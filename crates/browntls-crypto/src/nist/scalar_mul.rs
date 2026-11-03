//! Scalar multiplication.
//!
//! * [`mul`]: constant-time variable-base multiplication (ECDH) with signed
//!   5-bit fixed windows and a masked table scan.
//! * [`mul_base`]: constant-time fixed-base multiplication (key generation,
//!   ECDSA signing) using the precomputed comb table and signed 4-bit digits.
//! * [`mul_double_vartime`]: variable-time `u1 * G + u2 * Q` for signature
//!   verification only (all inputs are public there), using interleaved
//!   width-6 (base point) and width-5 (public key) wNAF.
//!
//! Scalars are plain little-endian limbs `< n`. Booth recoding is used for both
//! constant-time variants: the `(w + 1)`-bit window starting one bit below the
//! digit's position is mapped to a signed digit in `[-2^(w-1), 2^(w-1)]`, so
//! tables only need positive multiples and negation is a masked `Y` flip.

use super::curve::{Affine, Curve, Projective, add, add_mixed, double, fe_neg};
use super::jacobian::{self, Jacobian};
use super::mont;
use super::table::{INTERLEAVE, comb_digits, comb_positions};

/// Booth digit `i` of width `w` (`w <= 6`) of `k`: `(magnitude, negate_mask)`.
///
/// `i` and `w` are public; the result depends on `k` only through arithmetic.
#[inline]
fn booth<const N: usize>(k: &[u64; N], i: usize, w: usize) -> (u64, u64) {
    let start = w * i;
    let raw = if start == 0 {
        mont::bits(k, 0, w) << 1
    } else {
        mont::bits(k, start - 1, w + 1)
    };
    let neg = mont::barrier(((raw >> w) & 1).wrapping_neg());
    // For negative digits take the (w + 1)-bit complement.
    let d = raw ^ (neg & ((1u64 << (w + 1)) - 1));
    ((d >> 1) + (d & 1), neg)
}

/// Masked scan of an affine table: returns `table[index - 1]` for `index` in
/// `1..=table.len()` and `Affine::ZERO` for `index == 0`, in constant time.
#[inline]
fn lookup_affine<const N: usize>(table: &[Affine<N>], index: u64) -> Affine<N> {
    let mut out = Affine::<N>::ZERO;
    for (j, entry) in table.iter().enumerate() {
        let mask = mont::barrier(mont::zero_mask_u64(index ^ (j as u64 + 1)));
        for l in 0..N {
            out.x[l] |= mask & entry.x[l];
            out.y[l] |= mask & entry.y[l];
        }
    }
    out
}

/// Masked scan of a projective table indexed from zero, in constant time.
#[inline]
fn lookup_projective<const N: usize>(table: &[Projective<N>], index: u64) -> Projective<N> {
    let mut out = Projective::<N>::ZERO;
    for (j, entry) in table.iter().enumerate() {
        let mask = mont::barrier(mont::zero_mask_u64(index ^ j as u64));
        for l in 0..N {
            out.x[l] |= mask & entry.x[l];
            out.y[l] |= mask & entry.y[l];
            out.z[l] |= mask & entry.z[l];
        }
    }
    out
}

/// Constant-time `k * P` for an affine `P` and a scalar `k < n`.
pub(crate) fn mul<C: Curve<N>, const N: usize>(p: &Affine<N>, k: &[u64; N]) -> Projective<N> {
    const W: usize = 5;
    // table[m] = m * P for m in 0..=16 (table[0] is the identity).
    let mut table = [Projective::<N>::ZERO; 17];
    table[0] = Projective::identity::<C>();
    table[1] = Projective::from_affine::<C>(p);
    for m in 2..17 {
        table[m] = if m % 2 == 0 {
            double::<C, N>(&table[m / 2])
        } else {
            add_mixed::<C, N>(&table[m - 1], p)
        };
    }
    let digits = C::BITS / W + 1;
    let mut acc = Projective::identity::<C>();
    for i in (0..digits).rev() {
        if i + 1 != digits {
            // The doublings run in Jacobian coordinates (cheaper, and
            // exception-free on a prime-order curve); the additions stay
            // complete.
            let mut j = jacobian::from_projective_ct::<C, N>(&acc);
            for _ in 0..W {
                j = jacobian::double::<C, N>(&j);
            }
            acc = jacobian::to_projective::<C, N>(&j);
        }
        let (mag, neg) = booth(k, i, W);
        let mut t = lookup_projective(&table, mag);
        t.y = mont::select(neg, &fe_neg::<C, N>(&t.y), &t.y);
        acc = add::<C, N>(&acc, &t);
    }
    acc
}

/// One comb step: adds the signed digit `(mag, neg)` times the table position.
#[inline]
fn comb_step<C: Curve<N>, const N: usize>(
    acc: &Projective<N>,
    entries: &[Affine<N>; 8],
    mag: u64,
    neg: u64,
) -> Projective<N> {
    let mut t = lookup_affine(entries, mag);
    t.y = mont::select(neg, &fe_neg::<C, N>(&t.y), &t.y);
    let sum = add_mixed::<C, N>(acc, &t);
    // A zero digit selected garbage; keep the accumulator in that case.
    Projective::select(mont::zero_mask_u64(mag), acc, &sum)
}

/// Constant-time `k * G` using the precomputed comb table.
///
/// With Booth digits `d_i` (width 4), `s = INTERLEAVE` and `T_j = 2^(4 s j) G`:
/// `k G = sum_{r < s} 16^r * sum_j d_{s j + r} T_j`, evaluated Horner-style
/// from the highest phase `r` down, with four doublings between phases.
pub(crate) fn mul_base<C: Curve<N>, const N: usize>(k: &[u64; N]) -> Projective<N> {
    let table = C::BASE_TABLE;
    let digits = comb_digits(C::BITS);
    debug_assert_eq!(table.len(), comb_positions(C::BITS));
    let mut acc = Projective::identity::<C>();
    for phase in (0..INTERLEAVE).rev() {
        if phase + 1 != INTERLEAVE {
            for _ in 0..4 {
                acc = double::<C, N>(&acc);
            }
        }
        let mut i = phase;
        while i < digits {
            let (mag, neg) = booth(k, i, 4);
            acc = comb_step::<C, N>(&acc, &table[i / INTERLEAVE], mag, neg);
            i += INTERLEAVE;
        }
    }
    acc
}

/// Width-`w` non-adjacent form of `k` (variable time; `k` must be public).
/// Writes `out.len()` digits and returns the index after the last non-zero one.
fn wnaf<const N: usize>(k: &[u64; N], w: u32, out: &mut [i8]) -> usize {
    let mut k = *k;
    let mut len = 0;
    for (i, d) in out.iter_mut().enumerate() {
        *d = 0;
        if mont::is_zero(&k) != 0 {
            break;
        }
        if k[0] & 1 == 1 {
            let window = (k[0] & ((1u64 << w) - 1)) as i32;
            let digit = if window >= 1 << (w - 1) {
                window - (1 << w)
            } else {
                window
            };
            // |digit| < 2^(w-1) <= 32 fits in i8 and in one limb.
            #[allow(clippy::cast_possible_truncation)]
            {
                *d = digit as i8;
            }
            let mut m = [0u64; N];
            m[0] = u64::from(digit.unsigned_abs());
            k = if digit > 0 {
                mont::sub(&k, &m).0
            } else {
                mont::add(&k, &m).0
            };
            len = i + 1;
        }
        k = mont::shr_small(&k, 1);
    }
    len
}

/// Variable-time `u1 * G + u2 * Q` for signature verification, in Jacobian
/// coordinates. All inputs are public; this function is **not** constant time.
pub(crate) fn mul_double_vartime<C: Curve<N>, const N: usize>(
    u1: &[u64; N],
    u2: &[u64; N],
    q: &Affine<N>,
) -> Jacobian<N> {
    // Odd multiples of Q: table[i] = (2i + 1) Q.
    let qj = Jacobian::from_affine::<C>(q);
    let q2 = jacobian::double::<C, N>(&qj);
    let mut tq = [qj; 8];
    for i in 1..8 {
        tq[i] = jacobian::add::<C, N>(&tq[i - 1], &q2);
    }
    // 64 * 9 + 1 digits suffice for every supported curve.
    let mut n1 = [0i8; 577];
    let mut n2 = [0i8; 577];
    let l1 = wnaf(u1, 6, &mut n1[..64 * N + 1]);
    let l2 = wnaf(u2, 5, &mut n2[..64 * N + 1]);
    let len = l1.max(l2);
    let mut acc = Jacobian::identity::<C>();
    for i in (0..len).rev() {
        if !acc.is_identity() {
            acc = jacobian::double::<C, N>(&acc);
        }
        let d1 = n1[i];
        if d1 != 0 {
            let mut t = C::G_ODD[usize::from(d1.unsigned_abs()) / 2];
            if d1 < 0 {
                t.y = fe_neg::<C, N>(&t.y);
            }
            acc = jacobian::add_mixed::<C, N>(&acc, &t);
        }
        let d2 = n2[i];
        if d2 != 0 {
            let mut t = tq[usize::from(d2.unsigned_abs()) / 2];
            if d2 < 0 {
                t.y = fe_neg::<C, N>(&t.y);
            }
            acc = jacobian::add::<C, N>(&acc, &t);
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::super::curve::to_affine;
    use super::super::params::{P256, P384, P521};
    use super::*;

    #[test]
    fn booth_digits_reconstruct_scalar() {
        // Sum of d_i * 2^(w i) over all Booth digits must equal k.
        let k: [u64; 4] = [0x8f3a_1c2b_e9d7_0645, u64::MAX, 0, 0xf000_0000_0000_0001];
        for w in [4usize, 5] {
            let digits = 256 / w + 1;
            let mut acc = [0u64; 5];
            for i in 0..digits {
                let (mag, neg) = booth(&k, i, w);
                assert!(mag <= 1 << (w - 1));
                let shift = w * i;
                let mut term = [0u64; 5];
                term[shift / 64] |= mag << (shift % 64);
                if shift % 64 + w > 64 && shift / 64 + 1 < 5 {
                    term[shift / 64 + 1] |= mag >> (64 - shift % 64);
                }
                acc = if neg != 0 {
                    mont::sub(&acc, &term).0
                } else {
                    mont::add(&acc, &term).0
                };
            }
            assert_eq!(acc, [k[0], k[1], k[2], k[3], 0], "w = {w}");
        }
    }

    #[test]
    fn wnaf_reconstructs_scalar() {
        let k: [u64; 4] = [0x8f3a_1c2b_e9d7_0645, u64::MAX, 7, 0xf000_0000_0000_0001];
        let mut out = [0i8; 257];
        let len = wnaf(&k, 5, &mut out);
        assert!(len <= 257);
        let mut acc = [0u64; 5];
        for i in (0..len).rev() {
            acc = mont::add(&acc, &acc).0;
            let d = out[i];
            let m = [u64::from(d.unsigned_abs()), 0, 0, 0, 0];
            acc = if d >= 0 {
                mont::add(&acc, &m).0
            } else {
                mont::sub(&acc, &m).0
            };
            if d != 0 {
                assert!(d % 2 != 0 && d.abs() < 16);
            }
        }
        assert_eq!(acc, [k[0], k[1], k[2], k[3], 0]);
        // Non-adjacency: a non-zero digit is followed by w - 1 zeros.
        for i in 0..len {
            if out[i] != 0 {
                for j in 1..5 {
                    if i + j < len {
                        assert_eq!(out[i + j], 0);
                    }
                }
            }
        }
    }

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn random_scalar<C: Curve<N>, const N: usize>(seed: &mut u64) -> [u64; N] {
        loop {
            let mut k = [0u64; N];
            for l in &mut k {
                *l = xorshift(seed);
            }
            k[N - 1] &= u64::MAX >> ((64 * N - C::BITS) % 64);
            if mont::lt(&k, &C::ORDER) != 0 && mont::is_zero(&k) == 0 {
                return k;
            }
        }
    }

    /// Fixed-base, variable-base and double-scalar multiplication must agree,
    /// including on edge scalars.
    fn agree<C: Curve<N>, const N: usize>() {
        let mut seed = 0x1234_5678_9abc_def0;
        let mut scalars = std::vec::Vec::new();
        let mut one = [0u64; N];
        one[0] = 1;
        scalars.push(one);
        scalars.push(mont::sub(&C::ORDER, &one).0);
        scalars.push(mont::sub(&C::ORDER, &mont::add(&one, &one).0).0);
        let mut small = [0u64; N];
        small[0] = 8;
        scalars.push(small);
        small[0] = 9;
        scalars.push(small);
        for _ in 0..6 {
            scalars.push(random_scalar::<C, N>(&mut seed));
        }
        for k in &scalars {
            let fixed = to_affine::<C, N>(&mul_base::<C, N>(k)).unwrap();
            let var = to_affine::<C, N>(&mul::<C, N>(&C::G, k)).unwrap();
            assert_eq!(fixed, var);
            // u1 G + u2 Q with Q = 2G and u1 + 2 u2 = k (mod n).
            let two_g =
                to_affine::<C, N>(&double::<C, N>(&Projective::from_affine::<C>(&C::G))).unwrap();
            let u2 = random_scalar::<C, N>(&mut seed);
            let u1 = mont::sub_mod(k, &mont::add_mod(&u2, &u2, &C::ORDER), &C::ORDER);
            let dbl = mul_double_vartime::<C, N>(&u1, &u2, &two_g);
            assert!(jacobian::x_equals::<C, N>(&dbl, &var.x));
            // The y-coordinate: Y == y Z^3.
            let z3 = C::mul(&C::sqr(&dbl.z), &dbl.z);
            assert_eq!(C::mul(&var.y, &z3), dbl.y);
        }
        // k = n gives the identity; n = 0 digit handling in the comb.
        assert!(to_affine::<C, N>(&mul_base::<C, N>(&C::ORDER)).is_none());
        assert!(to_affine::<C, N>(&mul::<C, N>(&C::G, &C::ORDER)).is_none());
    }

    #[test]
    fn p256_scalar_multiplications_agree() {
        agree::<P256, 4>();
    }

    #[test]
    fn p384_scalar_multiplications_agree() {
        agree::<P384, 6>();
    }

    #[test]
    fn p521_scalar_multiplications_agree() {
        agree::<P521, 9>();
    }
}
