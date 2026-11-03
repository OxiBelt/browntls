//! AVX-512 IFMA (`vpmadd52luq`/`vpmadd52huq`) CRT exponentiation: both
//! half-size exponentiations of an RSA signature run in lockstep in radix
//! 2^52, with their Montgomery multiplications interleaved so that one
//! multiplication's serial reduction latency hides behind the other's.
//!
//! # Representation
//!
//! A value modulo a prime `m` of `len` 64-bit limbs is held in `K =
//! ceil((64 len + 2) / 52)` lanes of 52 bits (zero-padded to `8 V` lanes,
//! `V` vectors of eight 64-bit lanes). The multiplication is the
//! almost-Montgomery product `AMM(a, b) = (a b + y m) / R` with `R = 2^(52 K)`
//! (word-serial: per lane of `b`, add `a b_i` and `m y_i` with the low and
//! high 52-bit halves from IFMA, then shift down one lane). Since `4 m < R`,
//! inputs below `2 m` give outputs below `2 m`; values are reduced fully only
//! when converted back.
//!
//! The exponentiation domain uses `x R mod m`. Entry and exit go through the
//! caller's radix-2^64 Montgomery form `x R64` (`R64 = 2^(64 len)`):
//! `AMM(x R64, R^2 / R64) = x R` and `AMM(x R, R64) = x R64`, so each prime
//! stores `m`, `R^2 / R64 mod m` and `R64 mod m` in radix 2^52.
//!
//! # Timing
//!
//! The 4-bit fixed window, the number of squarings and multiplications, and
//! the full scan of the 16-entry table with masks match
//! [`super::mont::Mont::exp_ct`]; all loop counts depend only on `len`.
//! Carry normalisation uses masked vector adds driven by a carry-lookahead
//! word computed with plain integer arithmetic. No branch or memory index
//! depends on secret data.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m512i, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_extract_epi64, _mm512_add_epi64,
    _mm512_alignr_epi64, _mm512_and_si512, _mm512_castsi512_si128, _mm512_cmpeq_epu64_mask,
    _mm512_cmpgt_epu64_mask, _mm512_loadu_si512, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64,
    _mm512_mask_add_epi64, _mm512_mask_mov_epi64, _mm512_or_si512, _mm512_set1_epi64,
    _mm512_setzero_si512, _mm512_srli_epi64, _mm512_storeu_si512, _mm512_zextsi128_si512,
};
use core::hint::black_box;

use super::HALF_LIMBS;
use super::mont::Mont;
use crate::ct;
use crate::zeroize::Zeroize;

/// Mask of the low 52 bits.
const MASK52: u64 = (1 << 52) - 1;

/// Largest vector count: [`HALF_LIMBS`] limbs need `ceil((64 · 64 + 2) / 52)
/// = 79` lanes.
const VMAX: usize = 10;

/// A radix-2^52 number in `V` vectors of eight lanes.
type Num<const V: usize> = [[u64; 8]; V];

/// Lanes used for a `len`-limb modulus.
const fn lanes(len: usize) -> usize {
    (64 * len + 2).div_ceil(52)
}

/// Proof that the running CPU supports AVX-512F and AVX-512 IFMA; the only
/// way to reach the vector code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ifma(());

impl Ifma {
    /// Returns a token when `features()` reports AVX-512 (F/VL/BW/DQ with OS
    /// support) and IFMA.
    pub(crate) fn detect() -> Option<Self> {
        let f = crate::cpu::features();
        (f.x86_avx512() && f.x86_avx512_ifma()).then_some(Self(()))
    }
}

/// Converts radix-2^64 limbs to radix-2^52 lanes (`out` must have room for
/// the value). Constant time.
fn to_radix52(out: &mut [[u64; 8]], x: &[u64]) {
    for (i, l) in out.as_flattened_mut().iter_mut().enumerate() {
        let bit = 52 * i;
        let (w, s) = (bit / 64, bit % 64);
        let lo = x.get(w).copied().unwrap_or(0) >> s;
        let hi = if s > 12 {
            x.get(w + 1).copied().unwrap_or(0) << (64 - s)
        } else {
            0
        };
        *l = (lo | hi) & MASK52;
    }
}

/// Converts normalised radix-2^52 lanes to radix-2^64 limbs (bits beyond
/// `out` are dropped). Constant time.
fn from_radix52(out: &mut [u64], x: &[[u64; 8]]) {
    out.fill(0);
    for (i, &l) in x.as_flattened().iter().enumerate() {
        let bit = 52 * i;
        let (w, s) = (bit / 64, bit % 64);
        if w < out.len() {
            out[w] |= l << s;
        }
        if s > 12 && w + 1 < out.len() {
            out[w + 1] |= l >> (64 - s);
        }
    }
}

/// Radix-2^52 constants of one prime.
#[derive(Clone)]
struct Prime52 {
    /// The prime.
    m: [[u64; 8]; VMAX],
    /// `R^2 / R64 mod m` (entry into the exponentiation domain).
    enter: [[u64; 8]; VMAX],
    /// `R64 mod m` (exit back to radix-2^64 Montgomery form).
    exit: [[u64; 8]; VMAX],
    /// `-m^-1 mod 2^52`.
    k0: u64,
}

impl Prime52 {
    fn new(ctx: &Mont<HALF_LIMBS>) -> Self {
        let len = ctx.len();
        let k = lanes(len);
        // 2^(104 k) mod m, then divided by R64 with a Montgomery reduction.
        let mut pow = [0u64; 2 * HALF_LIMBS + 2];
        let pow_len = 104 * k / 64 + 1;
        pow[104 * k / 64] = 1 << (104 * k % 64);
        let mut t = [0u64; HALF_LIMBS];
        let mut u = [0u64; HALF_LIMBS];
        super::ct_mod(&mut t[..len], &pow[..pow_len], ctx.modulus());
        ctx.demont(&mut u[..len], &t[..len]);
        let mut p = Self {
            m: [[0; 8]; VMAX],
            enter: [[0; 8]; VMAX],
            exit: [[0; 8]; VMAX],
            k0: 0,
        };
        to_radix52(&mut p.m, ctx.modulus());
        to_radix52(&mut p.enter, &u[..len]);
        to_radix52(&mut p.exit, ctx.one());
        let m0 = ctx.modulus()[0];
        let mut inv = m0;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        p.k0 = inv.wrapping_neg() & MASK52;
        t.zeroize();
        u.zeroize();
        p
    }
}

impl Zeroize for Prime52 {
    fn zeroize(&mut self) {
        self.m.as_flattened_mut().zeroize();
        self.enter.as_flattened_mut().zeroize();
        self.exit.as_flattened_mut().zeroize();
        self.k0 = 0;
    }
}

/// Precomputed radix-2^52 data for the two primes of a key.
#[derive(Clone)]
pub(crate) struct CrtIfma {
    token: Ifma,
    primes: [Prime52; 2],
    /// Limbs of each prime (both primes have the same limb count).
    len: usize,
}

impl Drop for CrtIfma {
    fn drop(&mut self) {
        self.primes[0].zeroize();
        self.primes[1].zeroize();
    }
}

impl CrtIfma {
    /// Builds the constants for `p` and `q` (equal limb counts of at most
    /// [`HALF_LIMBS`]). Constant time.
    pub(crate) fn new(token: Ifma, p: &Mont<HALF_LIMBS>, q: &Mont<HALF_LIMBS>) -> Option<Self> {
        if p.len() != q.len() || p.len() == 0 || lanes(p.len()) > 8 * VMAX {
            return None;
        }
        Some(Self {
            token,
            primes: [Prime52::new(p), Prime52::new(q)],
            len: p.len(),
        })
    }

    /// `out_c = base_c^exp_c` modulo prime `c` for `c = 0, 1`, with bases
    /// and results in radix-2^64 Montgomery form (`len` limbs, results
    /// fully reduced) and exponents of `len` limbs. Constant time.
    pub(crate) fn exp(&self, out: [&mut [u64]; 2], base: [&[u64]; 2], exp: [&[u64]; 2]) {
        let k = lanes(self.len);
        let v = k.div_ceil(8);
        // Vector counts that are instantiated; a larger count than needed
        // only adds zero lanes (the iteration count stays `k`). In every arm
        // the token proves the AVX-512F and IFMA support `exp_v` requires.
        match v {
            // SAFETY: see above.
            0..=3 => unsafe { self.exp_v::<3>(out, base, exp) },
            // SAFETY: see above.
            4 => unsafe { self.exp_v::<4>(out, base, exp) },
            // SAFETY: see above.
            5 => unsafe { self.exp_v::<5>(out, base, exp) },
            // SAFETY: see above.
            6 => unsafe { self.exp_v::<6>(out, base, exp) },
            // SAFETY: see above.
            7 | 8 => unsafe { self.exp_v::<8>(out, base, exp) },
            // SAFETY: see above.
            _ => unsafe { self.exp_v::<VMAX>(out, base, exp) },
        }
    }

    /// [`Self::exp`] with `V` vectors per value.
    ///
    /// Callers must have confirmed that the CPU supports AVX-512F and IFMA.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn exp_v<const V: usize>(&self, out: [&mut [u64]; 2], base: [&[u64]; 2], exp: [&[u64]; 2]) {
        let _ = self.token;
        let len = self.len;
        let k = lanes(len);
        assert!(k <= 8 * V && V <= VMAX);
        assert!(exp[0].len() == len && exp[1].len() == len);
        assert!(base[0].len() == len && base[1].len() == len);
        let rows = |x: &[[u64; 8]; VMAX]| -> Num<V> { core::array::from_fn(|i| x[i]) };
        let ctx = Amm::<V, 2> {
            m: [rows(&self.primes[0].m), rows(&self.primes[1].m)],
            k0: [self.primes[0].k0, self.primes[1].k0],
            k,
        };
        let enter = [rows(&self.primes[0].enter), rows(&self.primes[1].enter)];
        let exit = [rows(&self.primes[0].exit), rows(&self.primes[1].exit)];

        // Entry: x R = AMM(x R64, R^2 / R64); one = R = AMM(R^2 / R64, R64).
        let mut x = [[[0u64; 8]; V]; 2];
        to_radix52(&mut x[0], base[0]);
        to_radix52(&mut x[1], base[1]);
        let x = ctx.mul([&x[0], &x[1]], [&enter[0], &enter[1]]);
        let one = ctx.mul([&enter[0], &enter[1]], [&exit[0], &exit[1]]);

        // table[j] = x^j for j < 16.
        let mut table = [[[[0u64; 8]; V]; 2]; 16];
        table[0] = one;
        table[1] = x;
        for j in 2..16 {
            table[j] = ctx.mul([&table[j - 1][0], &table[j - 1][1]], [&x[0], &x[1]]);
        }

        let mut acc = one;
        let mut sel = [[[0u64; 8]; V]; 2];
        let mut top = 64 * len;
        while top > 0 {
            for _ in 0..4 {
                acc = ctx.mul([&acc[0], &acc[1]], [&acc[0], &acc[1]]);
            }
            for c in 0..2 {
                let w = super::window(exp[c], top, 4);
                select(&mut sel[c], &table, c, w);
            }
            acc = ctx.mul([&acc[0], &acc[1]], [&sel[0], &sel[1]]);
            top -= 4;
        }

        // Exit: x^e R64 = AMM(x^e R, R64), below 2 m; reduce once more.
        let mut res = ctx.mul([&acc[0], &acc[1]], [&exit[0], &exit[1]]);
        let mut wide = [0u64; HALF_LIMBS + 1];
        let mut m64 = [0u64; HALF_LIMBS + 1];
        for (c, o) in out.into_iter().enumerate() {
            from_radix52(&mut wide[..len + 1], &res[c]);
            from_radix52(&mut m64[..len], &ctx.m[c]);
            o.copy_from_slice(&wide[..len]);
            super::cond_sub_mod(o, wide[len], &m64[..len]);
        }

        for t in table.iter_mut() {
            t.as_flattened_mut().as_flattened_mut().zeroize();
        }
        acc.as_flattened_mut().as_flattened_mut().zeroize();
        sel.as_flattened_mut().as_flattened_mut().zeroize();
        res.as_flattened_mut().as_flattened_mut().zeroize();
        wide.zeroize();
    }
}

/// `sel = table[w][c]`, reading every entry (constant time).
#[target_feature(enable = "avx512f")]
fn select<const V: usize>(sel: &mut Num<V>, table: &[[Num<V>; 2]; 16], c: usize, w: u64) {
    let mut acc = [_mm512_setzero_si512(); V];
    for (j, entry) in table.iter().enumerate() {
        let mask = _mm512_set1_epi64(black_box(ct::eq_u64(j as u64, w).mask()) as i64);
        let e = load(&entry[c]);
        for v in 0..V {
            acc[v] = _mm512_or_si512(acc[v], _mm512_and_si512(e[v], mask));
        }
    }
    store(sel, &acc);
}

/// Loads `V` rows into vectors.
#[target_feature(enable = "avx512f")]
fn load<const V: usize>(x: &Num<V>) -> [__m512i; V] {
    // SAFETY: each row is eight `u64` (64 readable bytes); the load is
    // unaligned.
    core::array::from_fn(|v| unsafe { _mm512_loadu_si512(x[v].as_ptr().cast()) })
}

/// Stores `V` vectors into rows.
#[target_feature(enable = "avx512f")]
fn store<const V: usize>(out: &mut Num<V>, x: &[__m512i; V]) {
    for (row, &v) in out.iter_mut().zip(x) {
        // SAFETY: each row is eight `u64` (64 writable bytes); the store is
        // unaligned.
        unsafe { _mm512_storeu_si512(row.as_mut_ptr().cast(), v) };
    }
}

/// `C` radix-2^52 almost-Montgomery contexts multiplied in lockstep.
struct Amm<const V: usize, const C: usize> {
    m: [Num<V>; C],
    k0: [u64; C],
    /// Lanes in use (`R = 2^(52 k)`).
    k: usize,
}

impl<const V: usize, const C: usize> Amm<V, C> {
    /// `AMM(a_c, b_c) = a_c b_c / R mod m_c` (below `2 m_c` for inputs below
    /// `2 m_c`), normalised to 52-bit lanes, for every context: picks
    /// [`Self::mul_shadow`] where it is faster on the CPUs measured (up to
    /// four vectors; it needs one spare lane above `k`), otherwise
    /// [`Self::mul_shift`]. Both compute the same value; the choice depends
    /// only on the (public) sizes.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mul(&self, a: [&Num<V>; C], b: [&Num<V>; C]) -> [Num<V>; C] {
        if V <= 4 && self.k < 8 * V {
            self.mul_shadow(a, b)
        } else {
            self.mul_shift(a, b)
        }
    }

    /// Word-serial AMM with the high halves added at the shifted-in
    /// position through operands pre-shifted up by one lane (`a ↑`, `m ↑`)
    /// and lane 0 tracked by a scalar shadow `s`, which takes the vector
    /// extraction and the carry out of the critical path. Requires `k < 8 V`.
    ///
    /// Per lane `i < k`, with `x` the accumulator (lanes 1 and up exact,
    /// lane 0 superseded by `s`):
    /// `x += lo(a b_i) + hi(a↑ b_i)`, `t0 = s + lo(a_0 b_i)`,
    /// `y = t0 k0 mod 2^52`, `x += lo(m y) + hi(m↑ y)`, then `x` shifts
    /// down one lane and `s` becomes the new lane 0, computed in scalar as
    /// `x_1 + lo(a_1 b_i) + hi(a_0 b_i) + lo(m_1 y) + hi(m_0 y) +
    /// (t0 + lo(m_0 y)) / 2^52`. At the end `s` is written into lane 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mul_shadow(&self, a: [&Num<V>; C], b: [&Num<V>; C]) -> [Num<V>; C] {
        let zero = _mm512_setzero_si512();
        let av: [[__m512i; V]; C] = core::array::from_fn(|c| load(a[c]));
        let mv: [[__m512i; V]; C] = core::array::from_fn(|c| load(&self.m[c]));
        let up = |x: &[__m512i; V]| -> [__m512i; V] {
            core::array::from_fn(|v| {
                _mm512_alignr_epi64::<7>(x[v], if v == 0 { zero } else { x[v - 1] })
            })
        };
        let au: [[__m512i; V]; C] = core::array::from_fn(|c| up(&av[c]));
        let mu: [[__m512i; V]; C] = core::array::from_fn(|c| up(&mv[c]));
        let a0: [u64; C] = core::array::from_fn(|c| a[c][0][0]);
        let a1: [u64; C] = core::array::from_fn(|c| a[c][0][1]);
        let m0: [u64; C] = core::array::from_fn(|c| self.m[c][0][0]);
        let m1: [u64; C] = core::array::from_fn(|c| self.m[c][0][1]);
        let mut x = [[zero; V]; C];
        let mut s = [0u64; C];
        for i in 0..self.k {
            for c in 0..C {
                let bi = b[c][i / 8][i % 8];
                let bv = _mm512_set1_epi64(bi as i64);
                let x1 = _mm_extract_epi64::<1>(_mm512_castsi512_si128(x[c][0])) as u64;
                for v in 0..V {
                    x[c][v] = _mm512_madd52lo_epu64(x[c][v], av[c][v], bv);
                    x[c][v] = _mm512_madd52hi_epu64(x[c][v], au[c][v], bv);
                }
                let t0 = s[c] + (a0[c].wrapping_mul(bi) & MASK52);
                let y = t0.wrapping_mul(self.k0[c]) & MASK52;
                let yv = _mm512_set1_epi64(y as i64);
                for v in 0..V {
                    x[c][v] = _mm512_madd52lo_epu64(x[c][v], mv[c][v], yv);
                    x[c][v] = _mm512_madd52hi_epu64(x[c][v], mu[c][v], yv);
                }
                let carry = (t0 + (m0[c].wrapping_mul(y) & MASK52)) >> 52;
                let hi = |p: u64, q: u64| ((u128::from(p) * u128::from(q)) >> 52) as u64;
                s[c] = x1
                    + (a1[c].wrapping_mul(bi) & MASK52)
                    + hi(a0[c], bi)
                    + (m1[c].wrapping_mul(y) & MASK52)
                    + hi(m0[c], y)
                    + carry;
                for v in 0..V - 1 {
                    x[c][v] = _mm512_alignr_epi64::<1>(x[c][v + 1], x[c][v]);
                }
                x[c][V - 1] = _mm512_alignr_epi64::<1>(zero, x[c][V - 1]);
            }
        }
        let mut out = [[[0u64; 8]; V]; C];
        for c in 0..C {
            x[c][0] = _mm512_mask_mov_epi64(x[c][0], 1, _mm512_set1_epi64(s[c] as i64));
            normalize(&mut x[c]);
            store(&mut out[c], &x[c]);
        }
        out
    }

    /// Word-serial AMM with a shift after the low halves.
    ///
    /// For each lane `i < k`: `acc += a b_i` (low halves), `y = acc_0 k0 mod
    /// 2^52`, `acc += m y` (low halves; lane 0 becomes a multiple of 2^52),
    /// shift the lanes down by one adding lane 0's carry, then add the high
    /// halves of `a b_i` and `m y`, which belong one lane up. Lane values
    /// stay below `4 k 2^52 + 2^12 < 2^62`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mul_shift(&self, a: [&Num<V>; C], b: [&Num<V>; C]) -> [Num<V>; C] {
        let av: [[__m512i; V]; C] = core::array::from_fn(|c| load(a[c]));
        let mv: [[__m512i; V]; C] = core::array::from_fn(|c| load(&self.m[c]));
        let m0: [u64; C] = core::array::from_fn(|c| self.m[c][0][0]);
        let zero = _mm512_setzero_si512();
        let mut acc = [[zero; V]; C];
        for i in 0..self.k {
            let mut bv = [zero; C];
            let mut yv = [zero; C];
            let mut carry = [0u64; C];
            for c in 0..C {
                bv[c] = _mm512_set1_epi64(b[c][i / 8][i % 8] as i64);
                for v in 0..V {
                    acc[c][v] = _mm512_madd52lo_epu64(acc[c][v], av[c][v], bv[c]);
                }
            }
            for c in 0..C {
                let t0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(acc[c][0])) as u64;
                let y = t0.wrapping_mul(self.k0[c]) & MASK52;
                yv[c] = _mm512_set1_epi64(y as i64);
                // Lane 0 after adding the low half of m_0 y (exact; below 2^63).
                carry[c] = (t0 + (m0[c].wrapping_mul(y) & MASK52)) >> 52;
                for v in 0..V {
                    acc[c][v] = _mm512_madd52lo_epu64(acc[c][v], mv[c][v], yv[c]);
                }
            }
            for c in 0..C {
                for v in 0..V - 1 {
                    acc[c][v] = _mm512_alignr_epi64::<1>(acc[c][v + 1], acc[c][v]);
                }
                acc[c][V - 1] = _mm512_alignr_epi64::<1>(zero, acc[c][V - 1]);
                acc[c][0] = _mm512_add_epi64(
                    acc[c][0],
                    _mm512_zextsi128_si512(_mm_cvtsi64_si128(carry[c] as i64)),
                );
                for v in 0..V {
                    acc[c][v] = _mm512_madd52hi_epu64(acc[c][v], av[c][v], bv[c]);
                    acc[c][v] = _mm512_madd52hi_epu64(acc[c][v], mv[c][v], yv[c]);
                }
            }
        }
        let mut out = [[[0u64; 8]; V]; C];
        for c in 0..C {
            normalize(&mut acc[c]);
            store(&mut out[c], &acc[c]);
        }
        out
    }
}

/// Carries lanes (each below `2^63`) into 52-bit digits; the value must fit
/// in `8 V` digits. Constant time.
#[target_feature(enable = "avx512f")]
fn normalize<const V: usize>(x: &mut [__m512i; V]) {
    let mask = _mm512_set1_epi64(MASK52 as i64);
    let zero = _mm512_setzero_si512();
    // Move each lane's bits above 52 one lane up: lanes become < 2^52 + 2^11.
    let hi: [__m512i; V] = core::array::from_fn(|v| _mm512_srli_epi64::<52>(x[v]));
    for v in 0..V {
        let below = if v == 0 { zero } else { hi[v - 1] };
        x[v] = _mm512_add_epi64(
            _mm512_and_si512(x[v], mask),
            _mm512_alignr_epi64::<7>(hi[v], below),
        );
    }
    // Remaining carries are single bits: lanes above 2^52 - 1 generate one,
    // lanes equal to 2^52 - 1 propagate one. Resolve them like an adder:
    // the carries into each lane are ((G << 1) + P) ^ P.
    let mut g = 0u128;
    let mut p = 0u128;
    for v in 0..V {
        g |= u128::from(_mm512_cmpgt_epu64_mask(x[v], mask)) << (8 * v);
        p |= u128::from(_mm512_cmpeq_epu64_mask(x[v], mask)) << (8 * v);
    }
    let cin = black_box(((g << 1).wrapping_add(p)) ^ p);
    let one = _mm512_set1_epi64(1);
    for v in 0..V {
        let k = (cin >> (8 * v)) as u8;
        x[v] = _mm512_and_si512(_mm512_mask_add_epi64(x[v], k, x[v], one), mask);
    }
}

/// Times `C` interleaved multiplications (temporary benchmark hook).
#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn bench_amm<const V: usize, const C: usize>(iters: usize) -> f64 {
    let mut m = [[0u64; 8]; V];
    for (i, l) in m.as_flattened_mut().iter_mut().enumerate() {
        *l = (0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1)) & MASK52;
    }
    m[0][0] |= 1;
    let k = 8 * V - 4;
    for l in &mut m.as_flattened_mut()[k - 1..] {
        *l = 0;
    }
    m.as_flattened_mut()[k - 2] |= 1 << 40;
    let ctx = Amm::<V, C> {
        m: [m; C],
        k0: [0x1234_5678_9abc & MASK52; C],
        k,
    };
    let mut x = [m; C];
    let t = std::time::Instant::now();
    for _ in 0..iters {
        let r: [&Num<V>; C] = core::array::from_fn(|c| &x[c]);
        x = ctx.mul_shift(r, r);
    }
    black_box(&x);
    let t1 = t.elapsed().as_nanos() as f64 / iters as f64;
    let mut x2 = [m; C];
    let t = std::time::Instant::now();
    for _ in 0..iters {
        let r: [&Num<V>; C] = core::array::from_fn(|c| &x2[c]);
        x2 = ctx.mul_shadow(r, r);
    }
    black_box(&x2);
    let t2 = t.elapsed().as_nanos() as f64 / iters as f64;
    assert_eq!(x, x2);
    std::println!("V{V} C{C} k{k}: mul {t1:.0} ns, mul2 {t2:.0} ns");
    t1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::bigint::{self, mont::Kernel};
    use std::vec;
    use std::vec::Vec;

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn random_odd(seed: &mut u64, len: usize, top: u64) -> Vec<u64> {
        let mut m: Vec<u64> = (0..len).map(|_| rng(seed)).collect();
        m[len - 1] |= top;
        m[0] |= 1;
        m
    }

    fn below(seed: &mut u64, m: &[u64]) -> Vec<u64> {
        let mut x: Vec<u64> = (0..m.len()).map(|_| rng(seed)).collect();
        let top = m.len() - 1;
        x[top] %= m[top];
        x
    }

    #[test]
    fn radix_conversion_roundtrip() {
        let mut seed = 9u64;
        for len in 1..=HALF_LIMBS {
            let x: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
            let mut r = [[0u64; 8]; VMAX];
            to_radix52(&mut r, &x);
            assert!(r.as_flattened().iter().all(|&l| l <= MASK52));
            let mut back = vec![0u64; len];
            from_radix52(&mut back, &r);
            assert_eq!(back, x);
        }
    }

    #[test]
    fn normalize_resolves_carry_chains() {
        let Some(_) = Ifma::detect() else { return };
        // Lanes of 2^52 - 1 with a carry entering at the bottom, large lanes
        // and random lanes; compare with a scalar carry loop.
        let mut seed = 21u64;
        for case in 0..64 {
            let mut lanes = [[0u64; 8]; 4];
            for (i, l) in lanes.as_flattened_mut().iter_mut().enumerate() {
                *l = match case % 4 {
                    0 => MASK52,
                    1 => rng(&mut seed) >> 2,
                    2 => MASK52 + u64::from(i % 5 == 0),
                    _ => rng(&mut seed) & MASK52 | u64::from(i % 3 == 0) * MASK52,
                };
            }
            // Keep the value below 2^(52 * 32).
            lanes[3][7] &= MASK52 >> 4;
            let mut expect = lanes;
            let mut carry = 0u64;
            for l in expect.as_flattened_mut() {
                carry += *l;
                *l = carry & MASK52;
                carry >>= 52;
            }
            // SAFETY: AVX-512F was detected above.
            let got = unsafe { normalize_for_test(&lanes) };
            assert_eq!(got, expect, "case {case}");
        }
    }

    /// Both AMM variants against each other and against the definition
    /// `out R = a b (mod m)`, `out < 2 m`, for inputs below `2 m`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn amm_variants_case<const V: usize>(seed: &mut u64, len: usize) {
        let k = lanes(len);
        assert!(k <= 8 * V);
        let mut m = random_odd(seed, len, 1 << 63);
        if *seed % 3 == 0 {
            m.fill(u64::MAX);
        }
        let mut m52 = [[0u64; 8]; V];
        to_radix52(&mut m52, &m);
        let mut inv = m[0];
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let ctx = Amm::<V, 1> {
            m: [m52],
            k0: [inv.wrapping_neg() & MASK52],
            k,
        };
        // Inputs: random below m, m - 1, 2 m - 1, 0, 1.
        let mut twice = vec![0u64; len + 1];
        twice[..len].copy_from_slice(&m);
        bigint::shl1(&mut twice);
        bigint::sub_word(&mut twice, 1);
        let mut mm1 = m.clone();
        bigint::sub_word(&mut mm1, 1);
        let mut one = vec![0u64; len];
        one[0] = 1;
        let inputs = [
            below(seed, &m),
            below(seed, &m),
            mm1,
            twice.clone(),
            vec![0u64; len],
            one,
        ];
        for x in &inputs {
            for y in &inputs {
                let (mut x52, mut y52) = ([[0u64; 8]; V], [[0u64; 8]; V]);
                to_radix52(&mut x52, x);
                to_radix52(&mut y52, y);
                let r1 = ctx.mul_shift([&x52], [&y52]);
                let r2 = if k < 8 * V {
                    ctx.mul_shadow([&x52], [&y52])
                } else {
                    r1
                };
                assert_eq!(r1, r2, "len {len}");
                // r R == x y (mod m) and r < 2 m.
                let mut r = vec![0u64; len + 1];
                from_radix52(&mut r, &r1[0]);
                assert!(bigint::ct_lt(&r, &twice).declassify() || r == twice);
                let shift = 52 * k;
                let mut big = vec![0u64; len + 2 + shift / 64];
                for (i, &l) in r.iter().enumerate() {
                    big[i + shift / 64] |= l << (shift % 64);
                    if shift % 64 != 0 {
                        big[i + shift / 64 + 1] |= l >> (64 - shift % 64);
                    }
                }
                let mut lhs = vec![0u64; len];
                bigint::ct_mod(&mut lhs, &big, &m);
                let mut xr = vec![0u64; len];
                let mut yr = vec![0u64; len];
                bigint::ct_mod(&mut xr, x, &m);
                bigint::ct_mod(&mut yr, y, &m);
                let mut prod = vec![0u64; 2 * len];
                bigint::mul(&mut prod, &xr, &yr);
                let mut rhs = vec![0u64; len];
                bigint::ct_mod(&mut rhs, &prod, &m);
                assert_eq!(lhs, rhs, "len {len}");
            }
        }
    }

    #[test]
    fn amm_variants_agree() {
        let Some(_) = Ifma::detect() else { return };
        let mut seed = 0x0123_4567_u64;
        for _ in 0..2 {
            // SAFETY: AVX-512F and IFMA were detected above.
            unsafe {
                amm_variants_case::<3>(&mut seed, 16);
                amm_variants_case::<3>(&mut seed, 18);
                amm_variants_case::<3>(&mut seed, 19);
                amm_variants_case::<4>(&mut seed, 24);
                amm_variants_case::<5>(&mut seed, 32);
                amm_variants_case::<6>(&mut seed, 32);
                amm_variants_case::<10>(&mut seed, 64);
            }
        }
    }

    #[target_feature(enable = "avx512f")]
    fn normalize_for_test(x: &Num<4>) -> Num<4> {
        let mut v = load(x);
        normalize(&mut v);
        let mut out = [[0u64; 8]; 4];
        store(&mut out, &v);
        out
    }

    /// Compares the dual IFMA exponentiation with two `exp_ct` calls on
    /// random odd moduli, edge bases and edge exponents.
    #[test]
    fn exp_matches_exp_ct() {
        let Some(token) = Ifma::detect() else { return };
        let mut seed = 0xfeed_u64;
        // 1024-, 1536-, 2048- and 4096-bit primes, plus every length that
        // selects a different vector count and some odd lengths.
        for len in [
            16usize, 17, 19, 20, 24, 25, 29, 32, 36, 40, 45, 48, 52, 63, 64,
        ] {
            for it in 0..3 {
                let top = if it == 1 { 1 } else { 1 << 63 };
                let p = random_odd(&mut seed, len, top);
                let q = random_odd(&mut seed, len, 1 << 63);
                let pc = Mont::<HALF_LIMBS>::new(&p, Kernel::Soft).unwrap();
                let qc = Mont::<HALF_LIMBS>::new(&q, Kernel::Soft).unwrap();
                let crt = CrtIfma::new(token, &pc, &qc).unwrap();
                let mut bases = [below(&mut seed, &p), below(&mut seed, &q)];
                let mut exps = [
                    (0..len).map(|_| rng(&mut seed)).collect::<Vec<u64>>(),
                    (0..len).map(|_| rng(&mut seed)).collect::<Vec<u64>>(),
                ];
                match it {
                    1 => {
                        // Base 0 and m - 1; exponent 0 and all ones.
                        bases[0].fill(0);
                        bases[1].copy_from_slice(&q);
                        bigint::sub_word(&mut bases[1], 1);
                        exps[0].fill(0);
                        exps[1].fill(u64::MAX);
                    }
                    2 => {
                        exps[0].fill(0);
                        exps[0][0] = 1;
                    }
                    _ => {}
                }
                let mut bm = [vec![0u64; len], vec![0u64; len]];
                pc.to_mont(&mut bm[0], &bases[0]);
                qc.to_mont(&mut bm[1], &bases[1]);
                let mut expect = [vec![0u64; len], vec![0u64; len]];
                pc.exp_ct(&mut expect[0], &bm[0], &exps[0]);
                qc.exp_ct(&mut expect[1], &bm[1], &exps[1]);
                let mut got = [vec![0u64; len], vec![0u64; len]];
                let [g0, g1] = &mut got;
                crt.exp([g0, g1], [&bm[0], &bm[1]], [&exps[0], &exps[1]]);
                assert_eq!(got, expect, "len {len} it {it}");
            }
        }
    }
}
