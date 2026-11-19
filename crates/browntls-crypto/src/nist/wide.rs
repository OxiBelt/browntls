//! Full-width products for the curves with a specialised reduction (P-384,
//! P-521) and the constant-time safegcd inversion they share.
//!
//! [`mul`] returns the `2N`-limb product of two `N`-limb values as a
//! row-wise schoolbook multiplication built from `64x64->128`-bit products
//! (squaring uses it too); `wide_x86` provides BMI2/ADX multiplication and
//! squaring kernels for six and nine limbs. Neither the instruction sequence nor the memory
//! accesses depend on the operands.
//!
//! [`invert`] wraps the generic Bernstein–Yang inversion of
//! `rsa::bigint::inv`, whose running time depends only on the limb count.
//!
//! `W` must be `2 * N`; the const generics cannot express that on stable
//! Rust, so it is checked at compile time where the functions are
//! instantiated.

use super::mont::{self, mac};

/// `a * b` as `W = 2N` little-endian limbs.
#[inline(always)]
pub(crate) fn mul<const N: usize, const W: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; W] {
    const { assert!(W == 2 * N) };
    let mut t = [0u64; W];
    for i in 0..N {
        let mut c = 0;
        for j in 0..N {
            let (lo, hi) = mac(t[i + j], a[j], b[i], c);
            t[i + j] = lo;
            c = hi;
        }
        t[i + N] = c;
    }
    t
}

/// `x^-1 mod m` for an odd prime `m` and `x < m`; zero maps to zero.
///
/// Constant time in `x`: the divstep count depends only on `N`, and the zero
/// case is a mask, not a branch.
pub(crate) fn invert<const N: usize>(x: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    crate::rsa::bigint::inv::mod_inverse(&mut out, x, m);
    // gcd(0, m) = m: the routine's output is unspecified, so force zero.
    let nonzero = mont::barrier(!mont::is_zero(x));
    for o in &mut out {
        *o &= nonzero;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// `a * b mod 2^64 - 1` computed limb by limb (`2^64 = 1`), a check that
    /// is independent of the limb order of the product.
    fn mod_m64<const N: usize>(a: &[u64; N]) -> u128 {
        a.iter().map(|&x| u128::from(x)).sum::<u128>() % u128::from(u64::MAX)
    }

    #[test]
    fn product_edges_and_residues() {
        let mut seed = 0x1357_9bdf_0246_8aceu64;
        // (2^576 - 1)^2 = 2^1152 - 2^577 + 1.
        let max = [u64::MAX; 9];
        let mut want = [u64::MAX; 18];
        want[0] = 1;
        want[1..9].fill(0);
        want[9] = u64::MAX - 1;
        assert_eq!(mul::<9, 18>(&max, &max), want);
        assert_eq!(mul::<9, 18>(&max, &[0; 9]), [0; 18]);
        let mut one = [0u64; 6];
        one[0] = 1;
        let x: [u64; 6] = core::array::from_fn(|_| xorshift(&mut seed));
        let mut lifted = [0u64; 12];
        lifted[..6].copy_from_slice(&x);
        assert_eq!(mul::<6, 12>(&x, &one), lifted);
        for _ in 0..200 {
            let a: [u64; 9] = core::array::from_fn(|_| xorshift(&mut seed));
            let b: [u64; 9] = core::array::from_fn(|_| xorshift(&mut seed));
            let t = mul::<9, 18>(&a, &b);
            let m = u128::from(u64::MAX);
            assert_eq!(mod_m64(&t), mod_m64(&a) * mod_m64(&b) % m);
            assert_eq!(t, mul::<9, 18>(&b, &a));
        }
    }

    #[test]
    fn inversion_maps_zero_to_zero() {
        use super::super::curve::Curve;
        use super::super::params::{P384, P521};
        assert_eq!(invert(&[0; 6], &P384::P), [0; 6]);
        assert_eq!(invert(&[0; 9], &P521::ORDER), [0; 9]);
        let mut one = [0u64; 9];
        one[0] = 1;
        assert_eq!(invert(&one, &P521::P), one);
    }
}
