//! Domain parameters of P-256, P-384 and P-521 (FIPS 186-5 / SEC 2) and the
//! portable [`Curve`] implementations.
//!
//! Only the standard hexadecimal constants are written down; the Montgomery
//! factors and inversion exponents are derived from them at compile time. The
//! base-point tables live in `tables/` (generated, validated by `table::tests`).

use super::curve::{Affine, Curve, Fe, fe_from_canonical, fe_mul_soft};
use super::mont;
use super::tables;

/// DER contents of `id-ecPublicKey` (1.2.840.10045.2.1).
pub(crate) const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

const fn two<const N: usize>() -> [u64; N] {
    let mut t = [0u64; N];
    t[0] = 2;
    t
}

/// Implements [`Curve`] for a parameter type. The multiplication is the
/// portable Montgomery CIOS; accelerated backends wrap the same constants.
macro_rules! define_curve {
    (
        $(#[$m:meta])*
        $name:ident, $n:literal, $bits:literal, $field_len:literal, $tables:ident,
        oid = $oid:expr,
        p = $p:literal, n = $order:literal, b = $b:literal, gx = $gx:literal, gy = $gy:literal
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name;

        impl Curve<$n> for $name {
            const BITS: usize = $bits;
            const FIELD_LEN: usize = $field_len;
            const P: [u64; $n] = mont::from_hex($p);
            const P_INV: u64 = mont::neg_inv(Self::P[0]);
            const ONE: Fe<$n> = mont::r_mod(&Self::P);
            const R2: Fe<$n> = mont::r2_mod(&Self::P);
            const P_MINUS_2: [u64; $n] = mont::sub(&Self::P, &two()).0;
            const ORDER: [u64; $n] = mont::from_hex($order);
            const ORDER_INV: u64 = mont::neg_inv(Self::ORDER[0]);
            const ORDER_ONE: [u64; $n] = mont::r_mod(&Self::ORDER);
            const ORDER_R2: [u64; $n] = mont::r2_mod(&Self::ORDER);
            const ORDER_MINUS_2: [u64; $n] = mont::sub(&Self::ORDER, &two()).0;
            const B: Fe<$n> = fe_from_canonical::<Self, $n>(&mont::from_hex($b));
            const G: Affine<$n> = Affine {
                x: fe_from_canonical::<Self, $n>(&mont::from_hex($gx)),
                y: fe_from_canonical::<Self, $n>(&mont::from_hex($gy)),
            };
            const OID: &'static [u8] = $oid;
            const BASE_TABLE: &'static [[Affine<$n>; 8]] = &tables::$tables::BASE;
            const G_ODD: &'static [Affine<$n>; 16] = &tables::$tables::ODD;

            #[inline]
            fn mul(a: &Fe<$n>, b: &Fe<$n>) -> Fe<$n> {
                fe_mul_soft::<Self, $n>(a, b)
            }
        }
    };
}

define_curve! {
    /// NIST P-256 / secp256r1 / prime256v1 on the portable backend.
    P256, 4, 256, 32, p256,
    oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
}

define_curve! {
    /// NIST P-384 / secp384r1 on the portable backend.
    P384, 6, 384, 48, p384,
    oid = &[0x2b, 0x81, 0x04, 0x00, 0x22],
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    b = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    gx = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
}

define_curve! {
    /// NIST P-521 / secp521r1 on the portable backend.
    P521, 9, 521, 66, p521,
    oid = &[0x2b, 0x81, 0x04, 0x00, 0x23],
    p = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    n = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    b = "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    gx = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    gy = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
}

#[cfg(test)]
mod tests {
    use super::super::curve::{fe_neg, is_on_curve, to_affine};
    use super::super::scalar_mul;
    use super::*;

    fn one<const N: usize>() -> [u64; N] {
        let mut t = [0u64; N];
        t[0] = 1;
        t
    }

    fn check<C: Curve<N>, const N: usize>() {
        assert!(is_on_curve::<C, N>(&C::G));
        assert_eq!(C::P_INV.wrapping_mul(C::P[0]), u64::MAX);
        assert_eq!(C::ORDER_INV.wrapping_mul(C::ORDER[0]), u64::MAX);
        assert_eq!(mont::to_mont(&one(), &C::P, C::P_INV, &C::R2), C::ONE);
        assert_eq!(
            mont::to_mont(&one(), &C::ORDER, C::ORDER_INV, &C::ORDER_R2),
            C::ORDER_ONE
        );
        assert_eq!(mont::bits(&C::P, C::BITS - 1, 1), 1);
        assert_eq!(mont::bits(&C::ORDER, C::BITS - 1, 1), 1);
        // (n - 1) * G = -G with both scalar multiplications.
        let n_minus_1 = mont::sub(&C::ORDER, &one()).0;
        let expect = Affine {
            x: C::G.x,
            y: fe_neg::<C, N>(&C::G.y),
        };
        let var = to_affine::<C, N>(&scalar_mul::mul::<C, N>(&C::G, &n_minus_1)).unwrap();
        assert_eq!(var, expect);
        let fixed = to_affine::<C, N>(&scalar_mul::mul_base::<C, N>(&n_minus_1)).unwrap();
        assert_eq!(fixed, expect);
    }

    #[test]
    fn p256_parameters() {
        check::<P256, 4>();
    }

    #[test]
    fn p384_parameters() {
        check::<P384, 6>();
    }

    #[test]
    fn p521_parameters() {
        check::<P521, 9>();
    }
}
