//! Field and scalar arithmetic of P-256, P-384 and P-521 (`FieldElement`,
//! `Scalar`) for the `crypto_ecc` target, checked against num-bigint (the
//! field) and the RustCrypto `Scalar` types, and between the default and
//! the portable backend (acceleration policy `NONE`).
//!
//! One operation per curve, [`arith_ops`]`::arith`. Arguments: two field
//! candidates and two scalar candidates ([`candidate`]), a big-endian
//! integer to reduce (short field) and a byte source for scalar generation
//! (short field). A candidate the decoder rejects is replaced by a small
//! value, so every operation runs on every input.

use num_bigint::BigUint;

use crate::input::Input;

/// A candidate encoding modulo `modulus_hex` of `len` bytes: fuzzed bytes, a
/// small value, `modulus - small` (the modulus itself when `small` is 0), or
/// bytes of a fuzzed length.
pub fn candidate(input: &mut Input<'_>, modulus_hex: &str, len: usize) -> Vec<u8> {
    match input.choose(4) {
        0 => {
            let mut v = input.bytes(len).to_vec();
            v.resize(len, 0);
            v
        }
        1 => {
            let mut v = vec![0u8; len - 2];
            v.extend_from_slice(&input.u16().to_be_bytes());
            v
        }
        2 => super::nist::order_minus(modulus_hex, u64::from(input.u16()), len),
        _ => input.short_field().to_vec(),
    }
}

/// `v` as exactly `len` big-endian bytes.
pub fn be(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(&b);
    out
}

macro_rules! arith_ops {
    ($m:ident, $ours:ident, $rc:ident, $fl:literal, $alg:ident, p = $p:literal, n = $n:literal) => {
        pub mod $m {
            use ::$rc::elliptic_curve::ff::PrimeField as _;
            use browntls_crypto::Error;
            use browntls_crypto::accel::Algorithm;
            use browntls_crypto::nist::$ours as ours;
            use browntls_crypto::rand::FixedRng;
            use browntls_crypto::zeroize::{Zeroize as _, Zeroizing};
            use num_bigint::BigUint;
            use ours::{FieldElement, Scalar};

            use super::{be, candidate};
            use crate::crypto_ecc::nist::portable;
            use crate::input::Input;

            const FL: usize = $fl;
            const ALG: Algorithm = Algorithm::$alg;

            fn modulus(hex: &str) -> BigUint {
                BigUint::parse_bytes(hex.as_bytes(), 16).expect("modulus")
            }

            fn big(bytes: &[u8]) -> BigUint {
                BigUint::from_bytes_be(bytes)
            }

            /// The arguments of one operation.
            struct Args<'a> {
                fields: [Vec<u8>; 2],
                scalars: [Vec<u8>; 2],
                wide: &'a [u8],
                seed: &'a [u8],
            }

            /// Op: field and scalar arithmetic, on the default backend and
            /// on the portable one, which must agree byte for byte.
            pub fn arith(input: &mut Input<'_>) {
                let args = Args {
                    fields: [candidate(input, $p, FL), candidate(input, $p, FL)],
                    scalars: [candidate(input, $n, FL), candidate(input, $n, FL)],
                    wide: input.short_field(),
                    seed: input.short_field(),
                };
                let fast = transcript(&args);
                let slow = portable(ALG, || transcript(&args));
                assert_eq!(fast, slow, "portable backend");
            }

            /// Every result, as bytes.
            fn transcript(args: &Args<'_>) -> Vec<Vec<u8>> {
                let mut out = Vec::new();
                field(args, &mut out);
                scalar(args, &mut out);
                out
            }

            /// Decodes a field candidate, checking the verdict; a rejected
            /// one becomes its length as a small value.
            fn field_element(bytes: &[u8], p: &BigUint) -> FieldElement {
                let r = FieldElement::from_bytes(bytes);
                if bytes.len() != FL {
                    assert_eq!(r, Err(Error::InvalidLength));
                } else if big(bytes) >= *p {
                    assert_eq!(r, Err(Error::InvalidEncoding));
                } else {
                    let a = r.expect("canonical field element");
                    assert_eq!(a.to_bytes()[..], bytes[..]);
                    return a;
                }
                FieldElement::from(bytes.len() as u64)
            }

            fn field(args: &Args<'_>, out: &mut Vec<Vec<u8>>) {
                let p = modulus($p);
                let a = field_element(&args.fields[0], &p);
                let b = field_element(&args.fields[1], &p);
                let (x, y) = (big(&a.to_bytes()), big(&b.to_bytes()));
                let fe = |v: &BigUint| FieldElement::from_bytes(&be(v, FL)).expect("reduced");
                assert_eq!(a.add(&b), fe(&((&x + &y) % &p)), "add");
                assert_eq!(a.sub(&b), fe(&((&x + &p - &y) % &p)), "sub");
                assert_eq!(a.mul(&b), fe(&((&x * &y) % &p)), "mul");
                assert_eq!(a.neg(), fe(&((&p - &x) % &p)), "neg");
                assert_eq!(a.square(), fe(&((&x * &x) % &p)), "square");
                assert_eq!(a.double(), fe(&((&x * 2u8) % &p)), "double");
                // The operator traits agree with the methods.
                assert_eq!(a + b, a.add(&b));
                assert_eq!(&a - &b, a.sub(&b));
                assert_eq!(a * &b, a.mul(&b));
                assert_eq!(-a, a.neg());
                let mut c = a;
                c += &b;
                c -= b;
                c *= b;
                assert_eq!(c, a.mul(&b));
                let zero = x == BigUint::from(0u8);
                assert_eq!(a.is_zero().declassify(), zero);
                assert_eq!(a.is_odd().declassify(), x.bit(0));
                assert_eq!(a.ct_eq(&b).declassify(), x == y);
                assert_eq!(a == b, x == y);
                match a.invert() {
                    None => assert!(zero, "inverse of a non-zero element missing"),
                    Some(inv) => {
                        assert!(!zero);
                        assert_eq!(a * inv, FieldElement::ONE, "invert");
                        out.push(inv.to_bytes().to_vec());
                    }
                }
                let euler = x.modpow(&((&p - 1u8) >> 1), &p);
                match a.sqrt() {
                    None => assert_eq!(euler, &p - 1u8, "square root missing"),
                    Some(r) => {
                        assert_ne!(euler, &p - 1u8, "root of a non-square");
                        assert_eq!(r.square(), a, "sqrt");
                        out.push(r.to_bytes().to_vec());
                    }
                }
                assert_eq!(FieldElement::default(), FieldElement::ZERO);
                assert_eq!(
                    FieldElement::ONE.to_bytes()[..],
                    be(&BigUint::from(1u8), FL)[..]
                );
                assert_eq!(format!("{a:?}"), "FieldElement(..)");
                let mut z = Zeroizing(a);
                z.zeroize();
                assert_eq!(*z, FieldElement::ZERO);
                for v in [a.add(&b), a.sub(&b), a.mul(&b), a.square()] {
                    out.push(v.to_bytes().to_vec());
                }
            }

            /// The oracle's scalar of the same value.
            fn theirs(s: &Scalar) -> ::$rc::Scalar {
                let bytes = ::$rc::FieldBytes::try_from(&s.to_bytes()[..]).expect("length");
                Option::from(::$rc::Scalar::from_repr(bytes)).expect("reduced")
            }

            fn same(s: &Scalar, t: &::$rc::Scalar) -> bool {
                s.to_bytes()[..] == t.to_repr()[..]
            }

            /// Decodes a scalar candidate, checking the verdict against the
            /// oracle; a rejected one becomes its length as a small value.
            fn scalar_value(bytes: &[u8], n: &BigUint) -> Scalar {
                let r = Scalar::from_bytes(bytes);
                if bytes.len() != FL {
                    assert_eq!(r, Err(Error::InvalidLength));
                    return Scalar::from(bytes.len() as u64);
                }
                let fb = ::$rc::FieldBytes::try_from(bytes).expect("length");
                let accepted = bool::from(::$rc::Scalar::from_repr(fb).is_some());
                assert_eq!(r.is_ok(), accepted, "scalar acceptance");
                assert_eq!(accepted, big(bytes) < *n);
                match r {
                    Ok(s) => {
                        assert_eq!(s.to_bytes()[..], bytes[..]);
                        s
                    }
                    Err(e) => {
                        assert_eq!(e, Error::InvalidEncoding);
                        Scalar::from(bytes.len() as u64)
                    }
                }
            }

            fn scalar(args: &Args<'_>, out: &mut Vec<Vec<u8>>) {
                let n = modulus($n);
                let a = scalar_value(&args.scalars[0], &n);
                let b = scalar_value(&args.scalars[1], &n);
                let (s, t) = (theirs(&a), theirs(&b));
                assert!(same(&a.add(&b), &(s + t)), "add");
                assert!(same(&a.sub(&b), &(s - t)), "sub");
                assert!(same(&a.mul(&b), &(s * t)), "mul");
                assert!(same(&a.neg(), &-s), "neg");
                assert!(same(&a.square(), &(s * s)), "square");
                assert!(same(&a.double(), &(s + s)), "double");
                assert_eq!(&a + &b, a.add(&b));
                assert_eq!(a.clone() - b.clone(), a.sub(&b));
                assert_eq!(&a * b.clone(), a.mul(&b));
                assert_eq!(-&a, a.neg());
                let mut c = a.clone();
                c += b.clone();
                c -= &b;
                c *= &b;
                assert_eq!(c, a.mul(&b));
                assert_eq!(
                    a.is_zero().declassify(),
                    bool::from(::$rc::elliptic_curve::ff::Field::is_zero(&s))
                );
                assert_eq!(a.ct_eq(&b).declassify(), s == t);
                let their_inv =
                    Option::<::$rc::Scalar>::from(::$rc::elliptic_curve::ff::Field::invert(&s));
                match (a.invert(), their_inv) {
                    (None, None) => {}
                    (Some(i), Some(ti)) => {
                        assert!(same(&i, &ti), "invert");
                        out.push(i.to_bytes().to_vec());
                    }
                    _ => panic!("scalar inversion verdicts differ"),
                }
                // Reduction of an integer of a fuzzed length.
                match Scalar::from_bytes_reduced(args.wide) {
                    Ok(r) => {
                        assert!(args.wide.len() <= 2 * FL);
                        assert_eq!(big(&r.to_bytes()[..]), big(args.wide) % &n, "reduction");
                        out.push(r.to_bytes().to_vec());
                    }
                    Err(e) => {
                        assert_eq!(e, Error::InvalidLength);
                        assert!(args.wide.len() > 2 * FL);
                    }
                }
                // Generation draws as private key generation does.
                let ours = Scalar::generate(&FixedRng::new(args.seed));
                let key = ours::SecretKey::generate(&FixedRng::new(args.seed));
                match (&ours, &key) {
                    (Ok(s), Ok(k)) => {
                        assert_eq!(s.to_bytes()[..], k.to_bytes()[..]);
                        assert!(!s.is_zero().declassify());
                    }
                    (Err(e), Err(f)) => {
                        assert_eq!((*e, *f), (Error::RandomFailure, Error::RandomFailure))
                    }
                    _ => panic!("generation verdicts differ"),
                }
                assert_eq!(Scalar::default(), Scalar::ZERO);
                assert!(same(&Scalar::ONE, &::$rc::Scalar::ONE));
                assert!(same(
                    &Scalar::from(0xfedc_ba98u64),
                    &::$rc::Scalar::from(0xfedc_ba98u64)
                ));
                assert_eq!(format!("{a:?}"), "Scalar(..)");
                let mut z = a.clone();
                z.zeroize();
                assert_eq!(z, Scalar::ZERO);
                for v in [a.add(&b), a.sub(&b), a.mul(&b)] {
                    out.push(v.to_bytes().to_vec());
                }
            }
        }
    };
}

arith_ops!(
    p256,
    p256,
    p256,
    32,
    P256,
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
arith_ops!(
    p384,
    p384,
    p384,
    48,
    P384,
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
arith_ops!(
    p521,
    p521,
    p521,
    66,
    P521,
    p = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    n = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);
