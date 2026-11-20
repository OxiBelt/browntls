#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_lossless,
    clippy::cast_possible_truncation
)]
//! NIST field and scalar arithmetic (`FieldElement`, `Scalar` of
//! `nist::{p256, p384, p521}`): differential tests against num-bigint (the
//! field; RustCrypto keeps its field elements private) and the RustCrypto
//! `Scalar` types, on edge and random values, with the operator traits, the
//! encodings and their rejections.
//!
//! The acceleration policy is process-wide, so each curve runs every check
//! in one test function, first under the default policy (the BMI2/ADX
//! kernels where the CPU has them) and then under `Policy::NONE` (portable
//! code), and finally a chain that switches between them at every step;
//! the curves have separate policies and run in parallel.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::rand::FixedRng;
use browntls_crypto::zeroize::{Zeroize, Zeroizing};
use num_bigint::BigUint;

/// Deterministic xorshift64 generator, so failures replay.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn big(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// `v` as exactly `len` big-endian bytes.
fn be(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    assert!(b.len() <= len);
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(&b);
    out
}

/// Edge values below `m` and random ones of every bit length.
fn values(m: &BigUint, len: usize, rng: &mut XorShift) -> Vec<BigUint> {
    let one = BigUint::from(1u8);
    let mut v = vec![
        BigUint::from(0u8),
        one.clone(),
        BigUint::from(2u8),
        BigUint::from(3u8),
        BigUint::from(u64::MAX),
        BigUint::from(u64::MAX) + 1u8,
        m - 1u8,
        m - 2u8,
        m >> 1,
        (m >> 1) + 1u8,
        (one.clone() << (m.bits() - 1)) - 1u8,
        one << (m.bits() - 1),
    ];
    for _ in 0..24 {
        let bits = (rng.next() % m.bits()) + 1;
        let r = big(&rng.bytes(len)) % (BigUint::from(1u8) << bits);
        v.push(r % m);
    }
    v
}

/// Encodings that every canonical decoder must reject: the modulus and
/// above, and wrong lengths.
fn rejected(m: &BigUint, len: usize) -> Vec<(Vec<u8>, Error)> {
    vec![
        (be(m, len), Error::InvalidEncoding),
        (be(&(m + 1u8), len), Error::InvalidEncoding),
        (vec![0xff; len], Error::InvalidEncoding),
        (vec![0; len - 1], Error::InvalidLength),
        (vec![0; len + 1], Error::InvalidLength),
        (Vec::new(), Error::InvalidLength),
    ]
}

macro_rules! curve_arith {
    ($m:ident, $curve:ident, $rc:ident, $fl:literal, $alg:ident, p = $p:literal, n = $n:literal) => {
        mod $m {
            use super::*;
            // `Field` supplies `square`, `double` and `invert` on the P-256
            // scalar only.
            #[allow(unused_imports)]
            use ::$rc::elliptic_curve::ff::{Field as _, PrimeField as _};
            use browntls_crypto::nist::$curve as ours;
            use ours::{FieldElement, Scalar};

            fn p() -> BigUint {
                BigUint::parse_bytes($p.as_bytes(), 16).unwrap()
            }

            fn n() -> BigUint {
                BigUint::parse_bytes($n.as_bytes(), 16).unwrap()
            }

            fn fe(v: &BigUint) -> FieldElement {
                FieldElement::from_bytes(&be(v, $fl)).unwrap()
            }

            fn fe_big(a: &FieldElement) -> BigUint {
                big(&a.to_bytes())
            }

            fn sc(v: &BigUint) -> Scalar {
                Scalar::from_bytes(&be(v, $fl)).unwrap()
            }

            fn theirs(v: &BigUint) -> ::$rc::Scalar {
                let bytes = ::$rc::FieldBytes::try_from(&be(v, $fl)[..]).unwrap();
                Option::from(::$rc::Scalar::from_repr(bytes)).unwrap()
            }

            fn same(a: &Scalar, b: &::$rc::Scalar) -> bool {
                a.to_bytes()[..] == b.to_repr()[..]
            }

            fn field(rng: &mut XorShift) {
                let p = p();
                let vals = values(&p, $fl, rng);
                for (bytes, err) in rejected(&p, $fl) {
                    assert_eq!(FieldElement::from_bytes(&bytes), Err(err));
                }
                assert_eq!(fe_big(&FieldElement::ZERO), BigUint::from(0u8));
                assert_eq!(fe_big(&FieldElement::ONE), BigUint::from(1u8));
                assert_eq!(FieldElement::default(), FieldElement::ZERO);
                assert_eq!(FieldElement::from(7u64), fe(&BigUint::from(7u8)));
                assert_eq!(format!("{:?}", FieldElement::ONE), "FieldElement(..)");
                let legendre = (&p - 1u8) >> 1;
                for x in &vals {
                    let a = fe(x);
                    assert_eq!(fe_big(&a), *x, "round trip");
                    assert_eq!(a.to_bytes().to_vec(), be(x, $fl));
                    assert_eq!(fe_big(&a.neg()), (&p - x) % &p, "neg");
                    assert_eq!(fe_big(&-a), (&p - x) % &p);
                    assert_eq!(fe_big(&a.square()), (x * x) % &p, "square");
                    assert_eq!(fe_big(&a.double()), (x * 2u8) % &p, "double");
                    assert_eq!(a.is_zero().declassify(), *x == BigUint::from(0u8));
                    assert_eq!(a.is_odd().declassify(), x.bit(0));
                    match a.invert() {
                        None => assert_eq!(*x, BigUint::from(0u8)),
                        Some(inv) => {
                            assert_eq!(fe_big(&inv), x.modpow(&(&p - 2u8), &p), "invert");
                            assert_eq!(a * inv, FieldElement::ONE);
                        }
                    }
                    let square = x.modpow(&legendre, &p) != &p - 1u8;
                    match a.sqrt() {
                        None => assert!(!square, "missing root"),
                        Some(r) => {
                            assert!(square, "root of a non-square");
                            assert_eq!(r.square(), a, "sqrt");
                            // The root returned is itself a square.
                            assert!(r.sqrt().is_some());
                            let r = fe_big(&r);
                            assert!(
                                r == BigUint::from(0u8)
                                    || r.modpow(&legendre, &p) == BigUint::from(1u8)
                            );
                        }
                    }
                    // Its square always has a root.
                    assert!(a.square().sqrt().is_some());
                    let mut z = Zeroizing(a);
                    z.zeroize();
                    assert_eq!(*z, FieldElement::ZERO);
                }
                for x in &vals {
                    for y in vals.iter().step_by(3) {
                        let (a, b) = (fe(x), fe(y));
                        let sum = (x + y) % &p;
                        let diff = (x + &p - y) % &p;
                        let prod = (x * y) % &p;
                        assert_eq!(fe_big(&a.add(&b)), sum, "add");
                        assert_eq!(fe_big(&a.sub(&b)), diff, "sub");
                        assert_eq!(fe_big(&a.mul(&b)), prod, "mul");
                        assert_eq!(a + b, a.add(&b));
                        assert_eq!(&a - &b, a.sub(&b));
                        assert_eq!(a * &b, a.mul(&b));
                        let mut c = a;
                        c += b;
                        c -= &b;
                        c *= b;
                        assert_eq!(c, a.mul(&b));
                        assert_eq!(a.ct_eq(&b).declassify(), x == y);
                        assert_eq!(a == b, x == y);
                    }
                }
            }

            fn scalar(rng: &mut XorShift) {
                let n = n();
                let vals = values(&n, $fl, rng);
                for (bytes, err) in rejected(&n, $fl) {
                    assert_eq!(Scalar::from_bytes(&bytes), Err(err));
                    if bytes.len() == $fl {
                        let fb = ::$rc::FieldBytes::try_from(&bytes[..]).unwrap();
                        assert!(bool::from(::$rc::Scalar::from_repr(fb).is_none()));
                    }
                }
                assert!(same(&Scalar::ZERO, &::$rc::Scalar::ZERO));
                assert!(same(&Scalar::ONE, &::$rc::Scalar::ONE));
                assert_eq!(Scalar::default(), Scalar::ZERO);
                assert!(same(
                    &Scalar::from(0x1234_5678u64),
                    &::$rc::Scalar::from(0x1234_5678u64)
                ));
                assert_eq!(format!("{:?}", Scalar::ONE), "Scalar(..)");
                for x in &vals {
                    let (a, t) = (sc(x), theirs(x));
                    assert!(same(&a, &t), "round trip");
                    assert!(same(&a.neg(), &-t), "neg");
                    assert!(same(&-&a, &-t));
                    assert!(same(&a.square(), &t.square()), "square");
                    assert!(same(&a.double(), &t.double()), "double");
                    assert_eq!(a.is_zero().declassify(), bool::from(t.is_zero()));
                    let inv = Option::<::$rc::Scalar>::from(t.invert());
                    match (a.invert(), inv) {
                        (None, None) => {}
                        (Some(i), Some(ti)) => {
                            assert!(same(&i, &ti), "invert");
                            assert_eq!(&a * &i, Scalar::ONE);
                        }
                        _ => panic!("inversion verdicts differ"),
                    }
                    let mut z = a.clone();
                    z.zeroize();
                    assert_eq!(z, Scalar::ZERO);
                }
                for x in &vals {
                    for y in vals.iter().step_by(3) {
                        let (a, b) = (sc(x), sc(y));
                        let (s, t) = (theirs(x), theirs(y));
                        assert!(same(&a.add(&b), &(s + t)), "add");
                        assert!(same(&a.sub(&b), &(s - t)), "sub");
                        assert!(same(&a.mul(&b), &(s * t)), "mul");
                        assert_eq!(&a + &b, a.add(&b));
                        assert_eq!(a.clone() - b.clone(), a.sub(&b));
                        assert_eq!(&a * b.clone(), a.mul(&b));
                        let mut c = a.clone();
                        c += &b;
                        c -= b.clone();
                        c *= &b;
                        assert_eq!(c, a.mul(&b));
                        assert_eq!(a.ct_eq(&b).declassify(), x == y);
                    }
                }
                // Reduction of every length up to twice the scalar length.
                for len in 0..=2 * $fl {
                    for bytes in [rng.bytes(len), vec![0xff; len]] {
                        let want = big(&bytes) % &n;
                        let got = Scalar::from_bytes_reduced(&bytes).unwrap();
                        assert_eq!(big(&got.to_bytes()[..]), want, "reduce {len} bytes");
                    }
                }
                assert_eq!(
                    Scalar::from_bytes_reduced(&[0; 2 * $fl + 1]),
                    Err(Error::InvalidLength)
                );
                assert_eq!(Scalar::from_bytes_reduced(&be(&n, $fl)), Ok(Scalar::ZERO));
                // Generation draws like private keys do, and fails with them.
                let seed = rng.bytes(4 * $fl);
                let ours = Scalar::generate(&FixedRng::new(&seed)).unwrap();
                let key = ours::SecretKey::generate(&FixedRng::new(&seed)).unwrap();
                assert_eq!(ours.to_bytes()[..], key.to_bytes()[..]);
                assert!(!ours.is_zero().declassify());
                assert_eq!(
                    Scalar::generate(&FixedRng::new(&seed[..$fl - 1])),
                    Err(Error::RandomFailure)
                );
            }

            /// Values cross backends: a long chain of field operations in
            /// which every step runs under a policy drawn at random, so the
            /// output of one backend is the input of the other, against
            /// num-bigint. Scalars, whose arithmetic is the same on every
            /// backend, ride along.
            fn chain(rng: &mut XorShift) {
                let (p, n) = (p(), n());
                let mut x = big(&rng.bytes($fl)) % &p;
                let mut a = fe(&x);
                let mut k = big(&rng.bytes($fl)) % &n;
                let mut s = sc(&k);
                let mut switches = 0;
                let mut last = Policy::PREFERRED;
                for step in 0..3000 {
                    let policy = if rng.next() & 1 == 0 {
                        Policy::PREFERRED
                    } else {
                        Policy::NONE
                    };
                    switches += usize::from(policy != last);
                    last = policy;
                    accel::set_policy(Algorithm::$alg, policy).unwrap();
                    let y = big(&rng.bytes($fl)) % &p;
                    let b = fe(&y);
                    match rng.next() % 7 {
                        0 => {
                            a += b;
                            x = (&x + &y) % &p;
                        }
                        1 => {
                            a -= &b;
                            x = (&x + &p - &y) % &p;
                        }
                        2 => {
                            a *= b;
                            x = (&x * &y) % &p;
                        }
                        3 => {
                            a = a.square();
                            x = (&x * &x) % &p;
                        }
                        4 => {
                            a = -a;
                            x = (&p - &x) % &p;
                        }
                        5 => match a.invert() {
                            Some(inv) => {
                                a = inv;
                                x = x.modpow(&(&p - 2u8), &p);
                            }
                            None => assert_eq!(x, BigUint::from(0u8)),
                        },
                        _ => {
                            // A root of the square is the value or its
                            // negation.
                            let r = a.square().sqrt().unwrap();
                            assert!(r == a || r == -a, "step {step}: sqrt");
                            a = r;
                            x = big(&a.to_bytes());
                        }
                    }
                    assert_eq!(big(&a.to_bytes()), x, "step {step}: field");
                    let t = big(&rng.bytes($fl)) % &n;
                    s = &s * &sc(&t) + Scalar::ONE;
                    k = (&k * &t + 1u8) % &n;
                    assert_eq!(big(&s.to_bytes()[..]), k, "step {step}: scalar");
                }
                assert!(switches > 1000, "{switches} backend switches");
                accel::set_policy(Algorithm::$alg, Policy::PREFERRED).unwrap();
            }

            #[test]
            fn field_and_scalar_on_every_backend() {
                let mut rng = XorShift(0x5851_f42d_4c95_7f2d ^ $fl);
                for policy in [Policy::PREFERRED, Policy::NONE] {
                    accel::set_policy(Algorithm::$alg, policy).unwrap();
                    let status = accel::status(Algorithm::$alg);
                    println!("{status}");
                    // A miswired backend choice must not pass silently: the
                    // default policy runs the BMI2/ADX kernels where the CPU
                    // has them.
                    if policy == Policy::NONE || !status.available.dedicated {
                        assert_eq!(status.backend, "portable");
                    } else {
                        assert_eq!(status.backend, "BMI2/ADX");
                    }
                    field(&mut rng);
                    scalar(&mut rng);
                }
                chain(&mut rng);
                accel::set_policy(Algorithm::$alg, Policy::PREFERRED).unwrap();
            }
        }
    };
}

curve_arith!(
    p256_arith,
    p256,
    p256,
    32,
    P256,
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
curve_arith!(
    p384_arith,
    p384,
    p384,
    48,
    P384,
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
curve_arith!(
    p521_arith,
    p521,
    p521,
    66,
    P521,
    p = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    n = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);
