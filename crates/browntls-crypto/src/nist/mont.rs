//! Constant-time multi-precision arithmetic on little-endian 64-bit limbs.
//!
//! Modular routines take the modulus (and, for Montgomery multiplication, the
//! constant `-m^-1 mod 2^64`) explicitly. Secret-dependent control flow is
//! avoided: loop bounds are the limb count, conditional reductions use masks,
//! and the only `if` on data is on *public* exponent bits in [`pow_pubexp`].
//!
//! # Masks and the optimisation barrier
//!
//! A mask is `0` or `u64::MAX`. The compiler can prove that for masks built
//! from comparisons and may lower `b ^ (mask & (a ^ b))` to a select and then
//! to a branch or a conditional load. Every mask consumed at run time therefore
//! passes through [`barrier`] (`core::hint::black_box`) first. `black_box` is
//! not a `const fn`, so the routines that derive curve constants at compile
//! time exist in `*_const` variants without the barrier; those are used only
//! for public constants.
//!
//! `const fn` cannot call trait methods, which is why the widening casts below
//! are written with `as` instead of `u128::from`.
#![allow(clippy::cast_lossless)]

/// Hides the value of a mask from the optimiser (identity at run time).
#[inline(always)]
pub(crate) fn barrier(mask: u64) -> u64 {
    core::hint::black_box(mask)
}

/// `a + b + carry` with `carry` in `{0, 1}`; returns `(sum, carry_out)`.
#[inline(always)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow` with `borrow` in `{0, 1}`; returns `(difference, borrow_out)`.
#[inline(always)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

/// `a + b * c + carry`; returns `(low, high)`. Cannot overflow 128 bits.
#[inline(always)]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + (b as u128) * (c as u128) + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// Multi-limb addition; returns `(sum mod 2^(64N), carry)`.
#[inline]
pub(crate) const fn add<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut r = [0u64; N];
    let mut c = 0;
    let mut i = 0;
    while i < N {
        let (s, c1) = adc(a[i], b[i], c);
        r[i] = s;
        c = c1;
        i += 1;
    }
    (r, c)
}

/// Multi-limb subtraction; returns `(difference mod 2^(64N), borrow)`.
#[inline]
pub(crate) const fn sub<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut r = [0u64; N];
    let mut bw = 0;
    let mut i = 0;
    while i < N {
        let (d, b1) = sbb(a[i], b[i], bw);
        r[i] = d;
        bw = b1;
        i += 1;
    }
    (r, bw)
}

/// Returns `a` when `mask` is all ones and `b` when it is zero. At run time the
/// mask must have passed through [`barrier`].
#[inline(always)]
pub(crate) const fn select<const N: usize>(mask: u64, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut i = 0;
    while i < N {
        r[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    r
}

/// All-ones when `x == 0`, zero otherwise (not barriered).
#[inline(always)]
pub(crate) const fn zero_mask_u64(x: u64) -> u64 {
    // (x | -x) has its top bit set iff x != 0.
    (((x | x.wrapping_neg()) >> 63) ^ 1).wrapping_neg()
}

/// All-ones when every limb is zero.
#[inline]
pub(crate) const fn is_zero<const N: usize>(a: &[u64; N]) -> u64 {
    let mut acc = 0;
    let mut i = 0;
    while i < N {
        acc |= a[i];
        i += 1;
    }
    zero_mask_u64(acc)
}

/// All-ones when `a == b`.
#[inline]
pub(crate) const fn eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> u64 {
    let mut acc = 0;
    let mut i = 0;
    while i < N {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    zero_mask_u64(acc)
}

/// All-ones when `a < b` (unsigned).
#[inline]
pub(crate) const fn lt<const N: usize>(a: &[u64; N], b: &[u64; N]) -> u64 {
    let (_, borrow) = sub(a, b);
    borrow.wrapping_neg()
}

/// `a + b` and `a + b - m` with the mask selecting the reduced value.
#[inline(always)]
const fn add_mod_parts<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
) -> ([u64; N], [u64; N], u64) {
    let (s, carry) = add(a, b);
    let (d, borrow) = sub(&s, m);
    // Use the reduced value when the sum overflowed or did not borrow.
    (s, d, (carry | (borrow ^ 1)).wrapping_neg())
}

/// `a + b mod m` for `a, b < m` (compile-time constants only).
pub(crate) const fn add_mod_const<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
) -> [u64; N] {
    let (s, d, mask) = add_mod_parts(a, b, m);
    select(mask, &d, &s)
}

/// `a + b mod m` for `a, b < m`.
#[inline]
pub(crate) fn add_mod<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let (s, d, mask) = add_mod_parts(a, b, m);
    select(barrier(mask), &d, &s)
}

/// `a - b mod m` for `a, b < m`.
#[inline]
pub(crate) fn sub_mod<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let (d, borrow) = sub(a, b);
    let (e, _) = add(&d, m);
    select(barrier(borrow.wrapping_neg()), &e, &d)
}

/// `-a mod m` for `a < m` (zero maps to zero).
#[inline]
pub(crate) fn neg_mod<const N: usize>(a: &[u64; N], m: &[u64; N]) -> [u64; N] {
    sub_mod(&[0u64; N], a, m)
}

/// Word-by-word CIOS Montgomery multiplication without the final reduction:
/// returns `t < 2m` as `N` limbs plus its top bit.
#[inline(always)]
const fn mont_mul_core<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
) -> ([u64; N], u64) {
    let mut t = [0u64; N];
    let mut t_n = 0u64;
    let mut i = 0;
    while i < N {
        // t += a * b[i]
        let bi = b[i];
        let mut c = 0;
        let mut j = 0;
        while j < N {
            let (lo, hi) = mac(t[j], a[j], bi, c);
            t[j] = lo;
            c = hi;
            j += 1;
        }
        let (s, t_n1) = adc(t_n, c, 0);
        t_n = s;
        // t = (t + q * m) / 2^64, with q chosen so the low limb cancels.
        let q = t[0].wrapping_mul(m_inv);
        let (_, mut c) = mac(t[0], q, m[0], 0);
        let mut j = 1;
        while j < N {
            let (lo, hi) = mac(t[j], q, m[j], c);
            t[j - 1] = lo;
            c = hi;
            j += 1;
        }
        let (s, c2) = adc(t_n, c, 0);
        t[N - 1] = s;
        t_n = t_n1 + c2;
        i += 1;
    }
    (t, t_n)
}

/// Montgomery multiplication `a * b * R^-1 mod m` with `R = 2^(64N)`. Requires
/// `a, b < m`, `m` odd and `m_inv = -m^-1 mod 2^64`; the result is fully
/// reduced. Compile-time constants only.
pub(crate) const fn mont_mul_const<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
) -> [u64; N] {
    let (t, t_n) = mont_mul_core(a, b, m, m_inv);
    let (d, borrow) = sub(&t, m);
    select((t_n | (borrow ^ 1)).wrapping_neg(), &d, &t)
}

/// Montgomery multiplication `a * b * R^-1 mod m` (see [`mont_mul_const`]).
#[inline]
pub(crate) fn mont_mul<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
) -> [u64; N] {
    let (t, t_n) = mont_mul_core(a, b, m, m_inv);
    // t < 2m: one masked subtraction completes the reduction.
    let (d, borrow) = sub(&t, m);
    select(barrier((t_n | (borrow ^ 1)).wrapping_neg()), &d, &t)
}

/// `-m^-1 mod 2^64` for odd `m` (Newton iteration).
pub(crate) const fn neg_inv(m0: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// `2^bits mod m` by repeated modular doubling of one (`m > 1`).
pub(crate) const fn pow2_mod<const N: usize>(bits: usize, m: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    r[0] = 1;
    let mut i = 0;
    while i < bits {
        r = add_mod_const(&r, &r, m);
        i += 1;
    }
    r
}

/// `R mod m` with `R = 2^(64N)`: the Montgomery form of one.
pub(crate) const fn r_mod<const N: usize>(m: &[u64; N]) -> [u64; N] {
    pow2_mod(64 * N, m)
}

/// `R^2 mod m`: the constant that converts into Montgomery form.
pub(crate) const fn r2_mod<const N: usize>(m: &[u64; N]) -> [u64; N] {
    pow2_mod(128 * N, m)
}

/// Converts `a < m` into Montgomery form (compile-time constants only).
pub(crate) const fn to_mont_const<const N: usize>(
    a: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
    r2: &[u64; N],
) -> [u64; N] {
    mont_mul_const(a, r2, m, m_inv)
}

/// Converts `a < m` into Montgomery form.
#[inline]
pub(crate) fn to_mont<const N: usize>(
    a: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
    r2: &[u64; N],
) -> [u64; N] {
    mont_mul(a, r2, m, m_inv)
}

/// Converts `a` out of Montgomery form.
#[inline]
pub(crate) fn from_mont<const N: usize>(a: &[u64; N], m: &[u64; N], m_inv: u64) -> [u64; N] {
    let mut one = [0u64; N];
    one[0] = 1;
    mont_mul(a, &one, m, m_inv)
}

/// `count <= 57` consecutive bits of `a` starting at bit `start`, as an integer.
/// Bits beyond the top limb read as zero. `start` and `count` must be public.
#[inline]
pub(crate) const fn bits<const N: usize>(a: &[u64; N], start: usize, count: usize) -> u64 {
    let limb = start / 64;
    let off = start % 64;
    let mut v = if limb < N { a[limb] >> off } else { 0 };
    if off + count > 64 && limb + 1 < N {
        v |= a[limb + 1] << (64 - off);
    }
    v & ((1u64 << count) - 1)
}

/// `base^exp` in the Montgomery domain of `m`, where `one` is `R mod m`.
///
/// The exponent is **public** (a curve constant such as `p - 2`): the operation
/// sequence depends only on it, never on `base`. Left-to-right with 4-bit windows.
pub(crate) fn pow_pubexp<const N: usize>(
    base: &[u64; N],
    exp: &[u64; N],
    m: &[u64; N],
    m_inv: u64,
    one: &[u64; N],
) -> [u64; N] {
    let mut table = [[0u64; N]; 16];
    table[0] = *one;
    for i in 1..16 {
        table[i] = mont_mul(&table[i - 1], base, m, m_inv);
    }
    // Skip leading all-zero windows of the public exponent.
    let mut w = 16 * N;
    while w > 0 && bits(exp, 4 * (w - 1), 4) == 0 {
        w -= 1;
    }
    let mut acc = *one;
    while w > 0 {
        w -= 1;
        for _ in 0..4 {
            acc = mont_mul(&acc, &acc, m, m_inv);
        }
        let d = bits(exp, 4 * w, 4) as usize;
        if d != 0 {
            acc = mont_mul(&acc, &table[d], m, m_inv);
        }
    }
    acc
}

/// Parses a big-endian hexadecimal constant (at most `16 N` digits).
pub(crate) const fn from_hex<const N: usize>(s: &str) -> [u64; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() <= 16 * N, "hex constant too long");
    let mut r = [0u64; N];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[bytes.len() - 1 - i];
        assert!(c.is_ascii_hexdigit(), "invalid hex digit");
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        };
        r[i / 16] |= (v as u64) << (4 * (i % 16));
        i += 1;
    }
    r
}

/// Loads a big-endian byte string of at most `8 N` bytes.
#[inline]
pub(crate) fn from_be_bytes<const N: usize>(bytes: &[u8]) -> Option<[u64; N]> {
    if bytes.len() > 8 * N {
        return None;
    }
    let mut r = [0u64; N];
    for (i, b) in bytes.iter().rev().enumerate() {
        r[i / 8] |= u64::from(*b) << (8 * (i % 8));
    }
    Some(r)
}

/// Writes the low `out.len()` bytes of `a` big-endian (`out.len() <= 8 N`).
/// Higher bytes of `a` must be zero.
#[inline]
pub(crate) fn to_be_bytes<const N: usize>(a: &[u64; N], out: &mut [u8]) {
    debug_assert!(out.len() <= 8 * N);
    let len = out.len();
    for (i, o) in out.iter_mut().enumerate() {
        let byte = len - 1 - i;
        // byte / 8 < N because len <= 8 N.
        *o = (a[byte / 8] >> (8 * (byte % 8))) as u8;
    }
}

/// Shifts right by `n < 64` bits (public shift count).
#[inline]
pub(crate) fn shr_small<const N: usize>(a: &[u64; N], n: u32) -> [u64; N] {
    if n == 0 {
        return *a;
    }
    let mut r = [0u64; N];
    for i in 0..N {
        r[i] = a[i] >> n;
        if i + 1 < N {
            r[i] |= a[i + 1] << (64 - n);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256: [u64; 4] =
        from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    /// Bit `i` of `a`.
    fn bit<const N: usize>(a: &[u64; N], i: usize) -> u64 {
        (a[i / 64] >> (i % 64)) & 1
    }

    /// Schoolbook `a * b mod m` on 4 limbs using shift-and-add, as an oracle.
    fn slow_mul_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        let mut acc = [0u64; 4];
        for i in (0..256).rev() {
            acc = add_mod(&acc, &acc, m);
            if bit(b, i) == 1 {
                acc = add_mod(&acc, a, m);
            }
        }
        acc
    }

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn rand_mod(seed: &mut u64, m: &[u64; 4]) -> [u64; 4] {
        loop {
            let v = [rng(seed), rng(seed), rng(seed), rng(seed)];
            if lt(&v, m) != 0 {
                return v;
            }
        }
    }

    #[test]
    fn constants() {
        assert_eq!(neg_inv(P256[0]), 1);
        assert_eq!(
            neg_inv(0xf3b9_cac2_fc63_2551).wrapping_mul(0xf3b9_cac2_fc63_2551),
            u64::MAX
        );
        let one = r_mod(&P256);
        assert_eq!(
            one,
            from_hex("fffffffeffffffffffffffffffffffff000000000000000000000001")
        );
        let r2 = r2_mod(&P256);
        assert_eq!(mont_mul(&one, &one, &P256, 1), one);
        assert_eq!(mont_mul_const(&one, &one, &P256, 1), one);
        assert_eq!(to_mont(&[1, 0, 0, 0], &P256, 1, &r2), one);
        assert_eq!(to_mont_const(&[1, 0, 0, 0], &P256, 1, &r2), one);
    }

    #[test]
    fn montgomery_matches_oracle() {
        let m_inv = neg_inv(P256[0]);
        let r2 = r2_mod(&P256);
        let mut seed = 0x9e37_79b9_7f4a_7c15;
        let mut inputs = std::vec::Vec::new();
        for _ in 0..40 {
            inputs.push(rand_mod(&mut seed, &P256));
        }
        let (pm1, _) = sub(&P256, &[1, 0, 0, 0]);
        inputs.push([0; 4]);
        inputs.push([1, 0, 0, 0]);
        inputs.push(pm1);
        inputs.push([u64::MAX, u64::MAX, 0, 0]);
        inputs.push([0, 0, 0, 0xffff_ffff_0000_0000]);
        for a in &inputs {
            for b in &inputs {
                let am = to_mont(a, &P256, m_inv, &r2);
                let bm = to_mont(b, &P256, m_inv, &r2);
                let prod = mont_mul(&am, &bm, &P256, m_inv);
                assert_eq!(prod, mont_mul_const(&am, &bm, &P256, m_inv));
                assert_eq!(from_mont(&prod, &P256, m_inv), slow_mul_mod(a, b, &P256));
                let s = add_mod(a, b, &P256);
                assert_eq!(s, add_mod_const(a, b, &P256));
                assert_eq!(s, {
                    let (t, c) = add(a, b);
                    let (d, bw) = sub(&t, &P256);
                    if c == 1 || bw == 0 { d } else { t }
                });
                assert_eq!(
                    add_mod(&sub_mod(a, b, &P256), b, &P256),
                    *a,
                    "sub/add roundtrip"
                );
            }
        }
    }

    #[test]
    fn inversion_by_fermat() {
        let m_inv = neg_inv(P256[0]);
        let r2 = r2_mod(&P256);
        let one = r_mod(&P256);
        let (pm2, _) = sub(&P256, &[2, 0, 0, 0]);
        let mut seed = 42;
        for _ in 0..8 {
            let a = rand_mod(&mut seed, &P256);
            let am = to_mont(&a, &P256, m_inv, &r2);
            let inv = pow_pubexp(&am, &pm2, &P256, m_inv, &one);
            assert_eq!(mont_mul(&am, &inv, &P256, m_inv), one);
        }
    }

    #[test]
    fn bytes_and_bits() {
        let v = from_hex::<4>("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let mut out = [0u8; 32];
        to_be_bytes(&v, &mut out);
        assert_eq!(out[0], 1);
        assert_eq!(out[31], 0x20);
        assert_eq!(from_be_bytes::<4>(&out), Some(v));
        assert_eq!(from_be_bytes::<4>(&[1u8; 33]), None);
        assert_eq!(from_be_bytes::<4>(&[0x20]), Some([0x20, 0, 0, 0]));
        assert_eq!(bits(&v, 0, 8), 0x20);
        assert_eq!(bits(&v, 60, 8), (v[0] >> 60) | ((v[1] & 0xf) << 4));
        assert_eq!(bits(&v, 254, 6), v[3] >> 62);
        assert_eq!(bits(&v, 256, 4), 0);
        assert_eq!(shr_small(&v, 4)[0], (v[0] >> 4) | (v[1] << 60));
        assert_eq!(is_zero(&[0u64; 4]), u64::MAX);
        assert_eq!(is_zero(&[0, 0, 1, 0]), 0);
        assert_eq!(lt(&[1, 0, 0, 0], &[2, 0, 0, 0]), u64::MAX);
        assert_eq!(lt(&[2, 0, 0, 0], &[2, 0, 0, 0]), 0);
    }
}
