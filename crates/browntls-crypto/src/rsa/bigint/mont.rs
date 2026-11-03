//! Montgomery arithmetic contexts and modular exponentiation.
//!
//! A [`Mont`] holds an odd modulus `m` of `len` limbs (top limb non-zero),
//! `R = 2^(64 len)`, and the constants `R mod m` and `R^2 mod m`. Values in
//! "Montgomery form" are `x R mod m`.
//!
//! [`Mont::mul`] computes `a b R^-1 mod m`, fully reduced, whenever
//! `a < R` and `b < m` (in particular for any pair of reduced operands). The
//! bound follows from the CIOS identity `result = (a b + M m) / R` with
//! `M < R`, so `result < a b / R + m < 2 m`, and the per-step accumulator
//! stays below `a + m + 1 < 2 R`, which fits in `len + 1` limbs.
//!
//! Secret-exponent exponentiation ([`Mont::exp_ct`]) uses a fixed 4-bit
//! window with constant-time table selection and a fixed number of squarings
//! and multiplications (`64 * exp.len()` squarings, `16 * exp.len()`
//! multiplications). Public-exponent exponentiation ([`Mont::exp_pub_vartime`])
//! is variable time in the (public) exponent only.

use super::{HALF_LIMBS, MAX_LIMBS, soft};
use crate::Error;
use crate::ct;
use crate::zeroize::Zeroize;

/// Montgomery multiplication kernel selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// Portable `u128` code.
    Soft,
    /// BMI2 `mulx` + ADX `adcx`/`adox` assembly.
    #[cfg(target_arch = "x86_64")]
    MulxAdx(super::x86_64::MulxAdx),
}

impl Kernel {
    /// Picks the best kernel for this CPU.
    pub(crate) fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        if matches!(
            crate::accel::select::<crate::rsa::RsaBackend>(),
            crate::rsa::RsaBackend::Ifma | crate::rsa::RsaBackend::MulxAdx
        ) && let Some(token) = super::x86_64::MulxAdx::detect()
        {
            return Self::MulxAdx(token);
        }
        Self::Soft
    }

    /// Every kernel usable on this CPU (for differential tests).
    #[cfg(test)]
    pub(crate) fn available() -> [Option<Self>; 2] {
        let best = Self::detect();
        if best == Self::Soft {
            [Some(Self::Soft), None]
        } else {
            [Some(Self::Soft), Some(best)]
        }
    }

    /// Short name for diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Soft => "soft",
            #[cfg(target_arch = "x86_64")]
            Self::MulxAdx(_) => "mulx-adx",
        }
    }

    #[inline]
    fn step(self, w: &mut [u64], a: &[u64], bi: u64, m: &[u64], m0inv: u64) {
        match self {
            Self::Soft => soft::step(w, a, bi, m, m0inv),
            #[cfg(target_arch = "x86_64")]
            Self::MulxAdx(token) => token.step(w, a, bi, m, m0inv),
        }
    }
}

/// Computes `-m0^-1 mod 2^64` for odd `m0` (Newton iteration, constant time).
fn neg_inv_word(m0: u64) -> u64 {
    debug_assert_eq!(m0 & 1, 1);
    // m0 * m0 == 1 (mod 8), so m0 is its own inverse to 3 bits; each
    // iteration doubles the number of correct bits: 3, 6, 12, 24, 48, 96.
    let mut inv = m0;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// Montgomery context for a modulus of at most `CAP` limbs.
#[derive(Clone)]
pub(crate) struct Mont<const CAP: usize> {
    m: [u64; CAP],
    rr: [u64; CAP],
    one: [u64; CAP],
    len: usize,
    m0inv: u64,
    kernel: Kernel,
}

impl<const CAP: usize> core::fmt::Debug for Mont<CAP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Mont {{ len: {}, kernel: {} }}",
            self.len,
            self.kernel.name()
        )
    }
}

impl<const CAP: usize> Zeroize for Mont<CAP> {
    fn zeroize(&mut self) {
        self.m.zeroize();
        self.rr.zeroize();
        self.one.zeroize();
        self.m0inv = 0;
    }
}

impl<const CAP: usize> Drop for Mont<CAP> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const CAP: usize> Mont<CAP> {
    /// Builds a context for `m`, which must be odd with a non-zero top limb
    /// and at most `CAP` limbs.
    ///
    /// Constant time apart from the length checks.
    #[inline(never)]
    pub(crate) fn new(modulus: &[u64], kernel: Kernel) -> Result<Self, Error> {
        let len = modulus.len();
        if len == 0 || len > CAP || len > MAX_LIMBS {
            return Err(Error::InvalidKey);
        }
        if modulus[0] & 1 == 0 || modulus[len - 1] == 0 {
            return Err(Error::InvalidKey);
        }
        let mut m = [0u64; CAP];
        m[..len].copy_from_slice(modulus);
        let mut ctx = Self {
            m,
            rr: [0; CAP],
            one: [0; CAP],
            len,
            m0inv: neg_inv_word(modulus[0]),
            kernel,
        };

        // one = R mod m. Start from 2^(64 (len - 1)) <= m - 1 (top limb is
        // non-zero and m is odd) and double 64 times with reduction.
        let mut x = [0u64; CAP];
        x[len - 1] = 1;
        for _ in 0..64 {
            let hi = super::shl1(&mut x[..len]);
            super::cond_sub_mod(&mut x[..len], hi, &ctx.m[..len]);
        }
        ctx.one = x;

        // rr = R^2 mod m. With x = 2^(64 len + t) mod m, a Montgomery squaring
        // doubles t and a modular doubling adds one; build t = 64 len from
        // its binary expansion starting at t = 1.
        let target = 64 * len;
        let nbits = usize::BITS - target.leading_zeros();
        let hi = super::shl1(&mut x[..len]);
        super::cond_sub_mod(&mut x[..len], hi, &ctx.m[..len]);
        let mut scratch = [0u64; MAX_LIMBS * 2 + 2];
        let mut tmp = [0u64; CAP];
        for i in (0..nbits - 1).rev() {
            ctx.mul_into(&mut tmp[..len], &x[..len], &x[..len], &mut scratch);
            x[..len].copy_from_slice(&tmp[..len]);
            if (target >> i) & 1 == 1 {
                let hi = super::shl1(&mut x[..len]);
                super::cond_sub_mod(&mut x[..len], hi, &ctx.m[..len]);
            }
        }
        ctx.rr = x;
        Ok(ctx)
    }

    /// Number of limbs of the modulus.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The modulus.
    pub(crate) fn modulus(&self) -> &[u64] {
        &self.m[..self.len]
    }

    /// `R mod m`: the Montgomery form of 1.
    pub(crate) fn one(&self) -> &[u64] {
        &self.one[..self.len]
    }

    /// The kernel in use.
    pub(crate) fn kernel(&self) -> Kernel {
        self.kernel
    }

    /// `out = a b R^-1 mod m` for `a < R`, `b < m` (all `len` limbs). The
    /// product is accumulated in `scratch` and copied out at the end.
    fn mul_into(&self, out: &mut [u64], a: &[u64], b: &[u64], scratch: &mut [u64]) {
        let len = self.len;
        debug_assert!(out.len() == len && a.len() == len && b.len() == len);
        debug_assert!(scratch.len() >= 2 * len + 2);
        let m = &self.m[..len];
        #[cfg(target_arch = "x86_64")]
        if let Kernel::MulxAdx(token) = self.kernel
            && len.is_multiple_of(4)
        {
            let t = &mut scratch[..len + 2];
            t.fill(0);
            token.mont_mul4(t, a, b, m, self.m0inv);
            let hi = t[len + 1];
            out.copy_from_slice(&t[1..=len]);
            super::cond_sub_mod_with(out, hi, m, &mut t[..len]);
            return;
        }
        if self.kernel == Kernel::Soft {
            let t = &mut scratch[..len + 1];
            t.fill(0);
            soft::mont_mul(t, a, b, m, self.m0inv);
            let hi = t[len];
            out.copy_from_slice(&t[..len]);
            super::cond_sub_mod_with(out, hi, m, &mut scratch[len + 1..2 * len + 1]);
            return;
        }
        let t = &mut scratch[..2 * len + 2];
        t[..len + 2].fill(0);
        for i in 0..len {
            self.kernel
                .step(&mut t[i..i + len + 2], a, b[i], m, self.m0inv);
        }
        // The reduced value is t[len .. 2 len + 1]: len limbs plus a top limb
        // in {0, 1}; it is below 2 m, so one conditional subtraction remains.
        let hi = t[2 * len];
        out.copy_from_slice(&t[len..2 * len]);
        super::cond_sub_mod_with(out, hi, m, &mut t[..len]);
    }

    /// `out = a b R^-1 mod m` (see [`Self::mul_into`] for the operand bounds).
    pub(crate) fn mul(&self, out: &mut [u64], a: &[u64], b: &[u64]) {
        let mut scratch = [0u64; MAX_LIMBS * 2 + 2];
        self.mul_into(out, a, b, &mut scratch);
    }

    /// Converts `a < R` to Montgomery form (`a R mod m`), reducing it.
    pub(crate) fn to_mont(&self, out: &mut [u64], a: &[u64]) {
        self.mul(out, a, &self.rr[..self.len]);
    }

    /// Converts out of Montgomery form (`a R^-1 mod m`).
    pub(crate) fn demont(&self, out: &mut [u64], a: &[u64]) {
        let mut one = [0u64; CAP];
        one[0] = 1;
        self.mul(out, a, &one[..self.len]);
    }

    /// Constant-time exponentiation with a secret exponent.
    ///
    /// `base` is in Montgomery form; `out` receives `base^exp` in Montgomery
    /// form. All `64 * exp.len()` exponent bits are processed, so the running
    /// time depends only on the lengths. Available for contexts of at most
    /// [`HALF_LIMBS`] limbs (the 16-entry table is `16 * HALF_LIMBS` limbs,
    /// 8 KiB, the largest stack object in this module).
    #[inline(never)]
    pub(crate) fn exp_ct(&self, out: &mut [u64], base: &[u64], exp: &[u64]) {
        const { assert!(CAP <= HALF_LIMBS) };
        let len = self.len;
        debug_assert!(out.len() == len && base.len() == len);
        let mut scratch = [0u64; HALF_LIMBS * 2 + 2];
        let mut table = [0u64; 16 * HALF_LIMBS];
        let mut acc = [0u64; CAP];
        let mut tmp = [0u64; CAP];
        let mut sel = [0u64; CAP];

        const STRIDE: usize = HALF_LIMBS;
        table[..len].copy_from_slice(self.one());
        table[STRIDE..STRIDE + len].copy_from_slice(base);
        for i in 2..16 {
            let (prev, cur) = table.split_at_mut(i * STRIDE);
            self.mul_into(
                &mut cur[..len],
                &prev[(i - 1) * STRIDE..(i - 1) * STRIDE + len],
                base,
                &mut scratch,
            );
        }

        acc[..len].copy_from_slice(self.one());
        let nbits = 64 * exp.len();
        let mut top = nbits;
        while top > 0 {
            let w = super::window(exp, top, 4);
            for _ in 0..4 {
                self.mul_into(&mut tmp[..len], &acc[..len], &acc[..len], &mut scratch);
                acc[..len].copy_from_slice(&tmp[..len]);
            }
            // Constant-time table lookup: touch every entry.
            sel[..len].fill(0);
            for (j, entry) in table.as_chunks::<STRIDE>().0.iter().enumerate() {
                let mask = core::hint::black_box(ct::eq_u64(j as u64, w).mask());
                for (s, e) in sel[..len].iter_mut().zip(&entry[..len]) {
                    *s |= mask & e;
                }
            }
            self.mul_into(&mut tmp[..len], &acc[..len], &sel[..len], &mut scratch);
            acc[..len].copy_from_slice(&tmp[..len]);
            top -= 4;
        }
        out.copy_from_slice(&acc[..len]);
        table.zeroize();
        acc.zeroize();
        tmp.zeroize();
        sel.zeroize();
        scratch.zeroize();
    }

    /// Exponentiation by a small *public* exponent `e >= 1` (variable time in
    /// `e` only; the base is handled in constant time).
    #[inline(never)]
    pub(crate) fn exp_pub_vartime(&self, out: &mut [u64], base: &[u64], e: u64) {
        debug_assert!(e >= 1);
        let len = self.len;
        let mut scratch = [0u64; MAX_LIMBS * 2 + 2];
        let mut acc = [0u64; CAP];
        let mut tmp = [0u64; CAP];
        acc[..len].copy_from_slice(base);
        let nbits = 64 - e.leading_zeros();
        for i in (0..nbits - 1).rev() {
            self.mul_into(&mut tmp[..len], &acc[..len], &acc[..len], &mut scratch);
            if (e >> i) & 1 == 1 {
                self.mul_into(&mut acc[..len], &tmp[..len], base, &mut scratch);
            } else {
                acc[..len].copy_from_slice(&tmp[..len]);
            }
        }
        out.copy_from_slice(&acc[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::bigint;
    use std::vec;
    use std::vec::Vec;

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn random_modulus(seed: &mut u64, len: usize) -> Vec<u64> {
        let mut m: Vec<u64> = (0..len).map(|_| rng(seed)).collect();
        // Vary the top limb: sometimes small, sometimes full.
        match rng(seed) % 3 {
            0 => m[len - 1] = 1 + (m[len - 1] & 0xff),
            1 => m[len - 1] |= 1 << 63,
            _ => m[len - 1] |= 1,
        }
        m[0] |= 1;
        m
    }

    fn random_below(seed: &mut u64, m: &[u64]) -> Vec<u64> {
        loop {
            let v: Vec<u64> = (0..m.len()).map(|_| rng(seed)).collect();
            if bigint::ct_lt(&v, m).declassify() {
                return v;
            }
            // Reduce the top limb to make convergence fast.
            let mut v = v;
            v[m.len() - 1] %= m[m.len() - 1].max(1);
            if bigint::ct_lt(&v, m).declassify() {
                return v;
            }
        }
    }

    const LENS: &[usize] = &[
        1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 48, 64, 65, 96, 127, 128,
    ];

    #[test]
    fn neg_inv_word_is_inverse() {
        let mut seed = 42u64;
        for _ in 0..1000 {
            let m0 = rng(&mut seed) | 1;
            assert_eq!(m0.wrapping_mul(neg_inv_word(m0)), u64::MAX);
        }
    }

    #[test]
    fn rejects_bad_moduli() {
        assert!(Mont::<4>::new(&[2, 0, 0, 1], Kernel::Soft).is_err());
        assert!(Mont::<4>::new(&[1, 0, 0, 0], Kernel::Soft).is_err());
        assert!(Mont::<4>::new(&[1, 0, 0, 0, 1], Kernel::Soft).is_err());
        assert!(Mont::<4>::new(&[], Kernel::Soft).is_err());
        assert!(Mont::<4>::new(&[3], Kernel::Soft).is_ok());
    }

    #[test]
    fn constants_and_conversions() {
        let mut seed = 7u64;
        for &len in LENS {
            for kernel in Kernel::available().into_iter().flatten() {
                let m = random_modulus(&mut seed, len);
                let ctx = Mont::<MAX_LIMBS>::new(&m, kernel).unwrap();
                let mut one = vec![0u64; len];
                one[0] = 1;
                let mut out = vec![0u64; len];
                ctx.to_mont(&mut out, &one);
                assert_eq!(out, ctx.one(), "len {len} kernel {}", kernel.name());
                ctx.demont(&mut out, ctx.one());
                assert_eq!(out, one);
                // rr is the Montgomery form of R mod m (= one).
                ctx.to_mont(&mut out, ctx.one());
                assert_eq!(out, &ctx.rr[..len]);
                // Round trip of a random value, and of an unreduced one (< R).
                let a = random_below(&mut seed, &m);
                let mut am = vec![0u64; len];
                ctx.to_mont(&mut am, &a);
                ctx.demont(&mut out, &am);
                assert_eq!(out, a);
                let big: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
                ctx.to_mont(&mut am, &big);
                ctx.demont(&mut out, &am);
                let mut expect = vec![0u64; len];
                bigint::ct_mod(&mut expect, &big, &m);
                assert_eq!(out, expect, "unreduced input, len {len}");
            }
        }
    }

    #[test]
    fn mul_matches_schoolbook_and_kernels_agree() {
        let mut seed = 99u64;
        for &len in LENS {
            let iters = if len > 64 { 2 } else { 6 };
            for _ in 0..iters {
                let m = random_modulus(&mut seed, len);
                let a = random_below(&mut seed, &m);
                let b = random_below(&mut seed, &m);
                let mut prod = vec![0u64; 2 * len];
                bigint::mul(&mut prod, &a, &b);
                let mut expect = vec![0u64; len];
                bigint::ct_mod(&mut expect, &prod, &m);
                let mut results = Vec::new();
                for kernel in Kernel::available().into_iter().flatten() {
                    let ctx = Mont::<MAX_LIMBS>::new(&m, kernel).unwrap();
                    let (mut am, mut bm, mut r, mut out) = (
                        vec![0u64; len],
                        vec![0u64; len],
                        vec![0u64; len],
                        vec![0u64; len],
                    );
                    ctx.to_mont(&mut am, &a);
                    ctx.to_mont(&mut bm, &b);
                    ctx.mul(&mut r, &am, &bm);
                    ctx.demont(&mut out, &r);
                    assert_eq!(out, expect, "len {len} kernel {}", kernel.name());
                    results.push(r);
                }
                for r in &results {
                    assert_eq!(r, &results[0]);
                }
            }
        }
    }

    #[test]
    fn kernels_agree_on_edge_operands() {
        // Operands with all-ones limbs stress the carry chains.
        let kernels: Vec<Kernel> = Kernel::available().into_iter().flatten().collect();
        for &len in LENS {
            let mut m = vec![u64::MAX; len];
            m[0] = u64::MAX; // odd
            let cases = [
                vec![u64::MAX - 1; len],
                {
                    let mut v = vec![0u64; len];
                    v[0] = 1;
                    v
                },
                {
                    let mut v = vec![u64::MAX; len];
                    v[len - 1] = u64::MAX - 1;
                    v
                },
            ];
            let mut outs = Vec::new();
            for &k in &kernels {
                let ctx = Mont::<MAX_LIMBS>::new(&m, k).unwrap();
                for a in &cases {
                    for b in &cases {
                        let mut r = vec![0u64; len];
                        ctx.mul(&mut r, a, b);
                        assert!(bigint::ct_lt(&r, &m).declassify());
                        outs.push(r);
                    }
                }
            }
            let per = cases.len() * cases.len();
            for k in 1..kernels.len() {
                assert_eq!(&outs[k * per..(k + 1) * per], &outs[..per], "len {len}");
            }
        }
    }

    fn mersenne(bits: usize) -> Vec<u64> {
        let len = bits.div_ceil(64);
        let mut p = vec![u64::MAX; len];
        let rem = bits % 64;
        if rem != 0 {
            p[len - 1] = (1u64 << rem) - 1;
        }
        p
    }

    #[test]
    fn exponentiation_fermat_and_consistency() {
        let mut seed = 2024u64;
        for bits in [127usize, 521] {
            let p = mersenne(bits);
            let len = p.len();
            for kernel in Kernel::available().into_iter().flatten() {
                let ctx = Mont::<HALF_LIMBS>::new(&p, kernel).unwrap();
                for _ in 0..4 {
                    let a = random_below(&mut seed, &p);
                    let mut am = vec![0u64; len];
                    ctx.to_mont(&mut am, &a);
                    // a^(p-1) == 1
                    let mut e = p.clone();
                    bigint::sub_word(&mut e, 1);
                    let mut r = vec![0u64; len];
                    ctx.exp_ct(&mut r, &am, &e);
                    assert_eq!(r, ctx.one(), "fermat {bits} {}", kernel.name());
                    // a^(p-2) * a == 1
                    bigint::sub_word(&mut e, 1);
                    ctx.exp_ct(&mut r, &am, &e);
                    let mut t = vec![0u64; len];
                    ctx.mul(&mut t, &r, &am);
                    assert_eq!(t, ctx.one());
                    // Small exponents: constant-time and public paths agree.
                    let small = rng(&mut seed) >> 31;
                    let small = small.max(1);
                    let mut e_limbs = vec![0u64; len];
                    e_limbs[0] = small;
                    ctx.exp_ct(&mut r, &am, &e_limbs);
                    ctx.exp_pub_vartime(&mut t, &am, small);
                    assert_eq!(r, t);
                    // Exponent 1 and exponent 0 (ct path only).
                    e_limbs[0] = 1;
                    ctx.exp_ct(&mut r, &am, &e_limbs);
                    assert_eq!(r, am);
                    e_limbs[0] = 0;
                    ctx.exp_ct(&mut r, &am, &e_limbs);
                    assert_eq!(r, ctx.one());
                }
            }
        }
    }

    #[test]
    fn exp_ct_matches_square_and_multiply() {
        // Compare against a naive left-to-right ladder on a random odd modulus
        // for a random 256-bit exponent.
        let mut seed = 55u64;
        let m = random_modulus(&mut seed, 6);
        let ctx = Mont::<HALF_LIMBS>::new(&m, Kernel::detect()).unwrap();
        let a = random_below(&mut seed, &m);
        let mut am = vec![0u64; 6];
        ctx.to_mont(&mut am, &a);
        let e: Vec<u64> = (0..6)
            .map(|i| if i < 4 { rng(&mut seed) } else { 0 })
            .collect();
        let mut acc = ctx.one().to_vec();
        let mut t = vec![0u64; 6];
        for i in (0..256).rev() {
            ctx.mul(&mut t, &acc, &acc);
            if bigint::bit(&e, i) == 1 {
                ctx.mul(&mut acc, &t, &am);
            } else {
                acc.copy_from_slice(&t);
            }
        }
        let mut r = vec![0u64; 6];
        ctx.exp_ct(&mut r, &am, &e);
        assert_eq!(r, acc);
    }
}
