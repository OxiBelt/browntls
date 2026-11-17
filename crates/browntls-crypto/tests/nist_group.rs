#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_lossless,
    clippy::cast_possible_truncation
)]
//! NIST point arithmetic (`AffinePoint`, `ProjectivePoint`, `Sec1Point` of
//! `nist::{p256, p384, p521}`): differential tests against the RustCrypto
//! points and SEC 1 encodings on edge and random scalars and points, the
//! group laws (`P + P = 2P`, `P - P = 0`, `(a + b) G = a G + b G`,
//! `n G = 0`), the identity in every role, rejected encodings and
//! coordinates, and the conversions to and from `PublicKey`.
//!
//! As in `nist_arith.rs`, each curve runs everything in one test function
//! under the default policy and then under `Policy::NONE`.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::rand::FixedRng;
use browntls_crypto::zeroize::Zeroize;
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

/// `v` as exactly `len` big-endian bytes.
fn be(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(&b);
    out
}

macro_rules! curve_group {
    ($m:ident, $curve:ident, $rc:ident, $fl:literal, $alg:ident, p = $p:literal, n = $n:literal) => {
        mod $m {
            use super::*;
            use ::$rc::elliptic_curve::ff::PrimeField as _;
            use ::$rc::elliptic_curve::sec1::{FromSec1Point as _, ToSec1Point as _};
            use browntls_crypto::nist::$curve as ours;
            use ours::{AffinePoint, FieldElement, ProjectivePoint, PublicKey, Scalar};

            fn p() -> BigUint {
                BigUint::parse_bytes($p.as_bytes(), 16).unwrap()
            }

            fn n() -> BigUint {
                BigUint::parse_bytes($n.as_bytes(), 16).unwrap()
            }

            fn sc(v: &BigUint) -> Scalar {
                Scalar::from_bytes(&be(v, $fl)).unwrap()
            }

            fn their_scalar(s: &Scalar) -> ::$rc::Scalar {
                let bytes = ::$rc::FieldBytes::try_from(&s.to_bytes()[..]).unwrap();
                Option::from(::$rc::Scalar::from_repr(bytes)).unwrap()
            }

            /// Our encoding of a point.
            fn enc(p: &ProjectivePoint, compress: bool) -> Vec<u8> {
                p.to_affine().to_sec1_point(compress).as_bytes().to_vec()
            }

            /// RustCrypto's encoding of its point.
            fn their_enc(p: &::$rc::ProjectivePoint, compress: bool) -> Vec<u8> {
                p.to_affine().to_sec1_point(compress).as_bytes().to_vec()
            }

            /// RustCrypto's decoding verdict on `bytes`.
            fn their_decode(bytes: &[u8]) -> Option<::$rc::AffinePoint> {
                let encoded = ::$rc::Sec1Point::from_bytes(bytes).ok()?;
                Option::from(::$rc::AffinePoint::from_sec1_point(&encoded))
            }

            /// RustCrypto's copy of our point.
            fn theirs(p: &ProjectivePoint) -> ::$rc::ProjectivePoint {
                their_decode(&enc(p, false)).unwrap().into()
            }

            /// The point encodes as RustCrypto's in both forms.
            fn check(ours: &ProjectivePoint, theirs: &::$rc::ProjectivePoint, what: &str) {
                for compress in [false, true] {
                    assert_eq!(enc(ours, compress), their_enc(theirs, compress), "{what}");
                }
            }

            fn scalars(rng: &mut XorShift) -> Vec<Scalar> {
                let n = n();
                let mut v: Vec<Scalar> = [0u64, 1, 2, 3, 0xffff_ffff]
                    .into_iter()
                    .map(Scalar::from)
                    .collect();
                for small in [1u8, 2, 3] {
                    v.push(sc(&(&n - small)));
                }
                v.push(sc(&(&n >> 1)));
                for _ in 0..8 {
                    v.push(Scalar::from_bytes_reduced(&rng.bytes(2 * $fl)).unwrap());
                }
                v
            }

            fn constants() {
                let g = ProjectivePoint::GENERATOR;
                check(&g, &::$rc::ProjectivePoint::GENERATOR, "generator");
                check(
                    &ProjectivePoint::IDENTITY,
                    &::$rc::ProjectivePoint::IDENTITY,
                    "identity",
                );
                assert_eq!(enc(&ProjectivePoint::IDENTITY, true), [0]);
                assert_eq!(g.to_affine(), AffinePoint::GENERATOR);
                assert_eq!(ProjectivePoint::from(AffinePoint::GENERATOR), g);
                assert_eq!(ProjectivePoint::IDENTITY.to_affine(), AffinePoint::IDENTITY);
                assert_eq!(
                    ProjectivePoint::from(AffinePoint::IDENTITY),
                    ProjectivePoint::IDENTITY
                );
                assert_eq!(ProjectivePoint::default(), ProjectivePoint::IDENTITY);
                assert_eq!(AffinePoint::default(), AffinePoint::IDENTITY);
                assert!(ProjectivePoint::IDENTITY.is_identity().declassify());
                assert!(AffinePoint::IDENTITY.is_identity().declassify());
                assert!(!g.is_identity().declassify());
                assert!(!AffinePoint::GENERATOR.is_identity().declassify());
                assert_eq!(AffinePoint::IDENTITY.x(), FieldElement::ZERO);
                assert_eq!(AffinePoint::IDENTITY.y(), FieldElement::ZERO);
                assert_eq!(format!("{g:?}"), "ProjectivePoint(..)");
                assert_eq!(format!("{:?}", AffinePoint::GENERATOR), "AffinePoint(..)");
                let mut e = AffinePoint::GENERATOR.to_sec1_point(true);
                assert_eq!(format!("{e:?}"), "Sec1Point(..)");
                e.zeroize();
                assert_eq!(e.as_bytes(), [0]);
                assert_eq!(e, AffinePoint::IDENTITY.to_sec1_point(false));
                assert_eq!(ours::COMPRESSED_LEN, 1 + $fl);
            }

            fn multiplication(rng: &mut XorShift) {
                let base = ProjectivePoint::mul_by_generator(
                    &Scalar::from_bytes_reduced(&rng.bytes(2 * $fl)).unwrap(),
                );
                let their_base = theirs(&base);
                // The base has Z != 1 (a comb output); this identity is not
                // the representative (0 : 1 : 0).
                let zero = base.double() - base - base;
                assert_eq!(zero, ProjectivePoint::IDENTITY);
                for k in &scalars(rng) {
                    let t = their_scalar(k);
                    let kg = ProjectivePoint::mul_by_generator(k);
                    check(&kg, &(::$rc::ProjectivePoint::GENERATOR * t), "k G");
                    assert_eq!(
                        ProjectivePoint::GENERATOR.mul(k),
                        kg,
                        "mul vs mul_by_generator"
                    );
                    assert_eq!(ProjectivePoint::GENERATOR * k, kg);
                    assert_eq!(kg.is_identity().declassify(), k.is_zero().declassify());
                    check(&base.mul(k), &(their_base * t), "k P");
                    let mut acc = base;
                    acc *= k;
                    assert_eq!(acc, base.mul(k));
                    assert!(ProjectivePoint::IDENTITY.mul(k).is_identity().declassify());
                    assert!(zero.mul(k).is_identity().declassify());
                    assert_eq!(zero + kg, kg);
                    // The variable-time double multiplication agrees.
                    let b = Scalar::from_bytes_reduced(&rng.bytes($fl)).unwrap();
                    let want = kg + base.mul(&b);
                    assert_eq!(
                        ProjectivePoint::mul_by_generator_and_mul_add_vartime(k, &b, &base),
                        want
                    );
                    assert_eq!(
                        ProjectivePoint::mul_by_generator_and_mul_add_vartime(
                            k,
                            &b,
                            &ProjectivePoint::IDENTITY
                        ),
                        kg
                    );
                    assert_eq!(
                        ProjectivePoint::mul_by_generator_and_mul_add_vartime(k, &b, &zero),
                        kg
                    );
                    // b B = -k G cancels.
                    let cancel = ProjectivePoint::GENERATOR.mul(&k.neg());
                    assert!(
                        ProjectivePoint::mul_by_generator_and_mul_add_vartime(
                            k,
                            &Scalar::ONE,
                            &cancel
                        )
                        .is_identity()
                        .declassify()
                    );
                }
                // n G is the identity; (n - 1) G = -G.
                let n_minus_1 = sc(&(n() - 1u8));
                let minus_g = ProjectivePoint::mul_by_generator(&n_minus_1);
                assert_eq!(minus_g, -ProjectivePoint::GENERATOR);
                assert!(
                    (minus_g + ProjectivePoint::GENERATOR)
                        .is_identity()
                        .declassify()
                );
                assert!(
                    (ProjectivePoint::GENERATOR.mul(&n_minus_1) + AffinePoint::GENERATOR)
                        .is_identity()
                        .declassify()
                );
            }

            fn group_law(rng: &mut XorShift) {
                let ks = scalars(rng);
                let points: Vec<ProjectivePoint> =
                    ks.iter().map(ProjectivePoint::mul_by_generator).collect();
                let id = ProjectivePoint::IDENTITY;
                for (i, a) in points.iter().enumerate() {
                    let ta = theirs(a);
                    let aa = a.to_affine();
                    check(&a.double(), &(ta + ta), "double");
                    check(&-a, &-ta, "neg");
                    assert_eq!(a.add(a), a.double(), "P + P = 2P");
                    assert!((a - a).is_identity().declassify(), "P - P");
                    assert!(a.add(&a.neg()).is_identity().declassify(), "P + (-P)");
                    assert_eq!(a + id, *a);
                    assert_eq!(id + a, *a);
                    assert_eq!(
                        a + AffinePoint::IDENTITY,
                        *a,
                        "mixed addition of the identity"
                    );
                    assert_eq!(id + aa, *a);
                    assert!((a - aa).is_identity().declassify());
                    assert_eq!(a + aa, a.double(), "mixed doubling");
                    assert_eq!(aa.neg(), (-a).to_affine());
                    assert_eq!(-aa, (-a).to_affine());
                    assert_eq!(AffinePoint::from(a), aa);
                    for (j, b) in points.iter().enumerate().step_by(3) {
                        let sum = a + b;
                        check(&sum, &(ta + theirs(b)), "add");
                        check(&(a - b), &(ta - theirs(b)), "sub");
                        // Another representative of the same point.
                        assert_eq!(sum, b + a);
                        assert_eq!(sum.ct_eq(&(b + a)).declassify(), true);
                        assert_eq!(a + b.to_affine(), sum, "mixed addition");
                        assert_eq!(a - b.to_affine(), a - b);
                        let mut c = *a;
                        c += b;
                        c -= b.to_affine();
                        c += &b.to_affine();
                        c -= *b;
                        assert_eq!(c, *a);
                        // (a + b) G = a G + b G.
                        assert_eq!(ProjectivePoint::mul_by_generator(&(&ks[i] + &ks[j])), sum);
                        assert_eq!(a == b, ks[i] == ks[j]);
                        assert_eq!(a.to_affine() == b.to_affine(), ks[i] == ks[j]);
                    }
                }
            }

            fn encodings(rng: &mut XorShift) {
                let p = p();
                let g = AffinePoint::GENERATOR;
                for _ in 0..6 {
                    let k = Scalar::from_bytes_reduced(&rng.bytes(2 * $fl)).unwrap();
                    let a = ProjectivePoint::mul_by_generator(&k).to_affine();
                    for compress in [false, true] {
                        let e = a.to_sec1_point(compress);
                        assert_eq!(
                            e.as_bytes().len(),
                            if compress {
                                ours::COMPRESSED_LEN
                            } else {
                                ours::UNCOMPRESSED_LEN
                            }
                        );
                        assert_eq!(e.as_ref(), e.as_bytes());
                        assert_eq!(AffinePoint::from_sec1_bytes(e.as_bytes()), Ok(a));
                        assert!(their_decode(e.as_bytes()).is_some());
                    }
                    assert_eq!(AffinePoint::from_coordinates(&a.x(), &a.y()), Ok(a));
                    assert_eq!(
                        a.y().is_odd().declassify(),
                        a.to_sec1_point(true).as_bytes()[0] == 3
                    );
                }
                assert_eq!(
                    AffinePoint::from_sec1_bytes(&[0]),
                    Ok(AffinePoint::IDENTITY)
                );
                assert!(their_decode(&[0]).is_some());
                // Off the curve, coordinates at or above p, no square root.
                let off = AffinePoint::from_coordinates(&g.x(), &g.y().add(&FieldElement::ONE));
                assert_eq!(off, Err(Error::InvalidKey));
                assert_eq!(
                    AffinePoint::from_coordinates(&FieldElement::ZERO, &FieldElement::ZERO),
                    Err(Error::InvalidKey)
                );
                let mut bad = g.to_sec1_point(false).as_bytes().to_vec();
                bad[2 * $fl] ^= 1;
                assert_eq!(AffinePoint::from_sec1_bytes(&bad), Err(Error::InvalidKey));
                assert!(their_decode(&bad).is_none());
                let mut high = vec![4u8];
                high.extend(be(&p, $fl));
                high.extend(g.y().to_bytes());
                assert_eq!(AffinePoint::from_sec1_bytes(&high), Err(Error::InvalidKey));
                assert!(their_decode(&high).is_none());
                // y^2 = x^3 - 3x + b, with b from the generator.
                let rhs = |x: &FieldElement| x.square().mul(x).sub(&x.double().add(x));
                let b = g.y().square().sub(&rhs(&g.x()));
                let x = (0u64..64)
                    .map(FieldElement::from)
                    .find(|x| rhs(x).add(&b).sqrt().is_none())
                    .expect("some x has no point");
                let mut c = vec![2u8];
                c.extend(x.to_bytes());
                assert_eq!(AffinePoint::from_sec1_bytes(&c), Err(Error::InvalidKey));
                assert!(their_decode(&c).is_none());
                // Malformed encodings.
                let unc = g.to_sec1_point(false).as_bytes().to_vec();
                let mut hybrid = unc.clone();
                hybrid[0] = 6;
                for bytes in [
                    &[][..],
                    &[0, 0],
                    &[4],
                    &unc[..unc.len() - 1],
                    &hybrid,
                    &[5; 1 + $fl],
                ] {
                    assert_eq!(
                        AffinePoint::from_sec1_bytes(bytes),
                        Err(Error::InvalidEncoding),
                        "{bytes:02x?}"
                    );
                }
                // Random encodings: the same verdict as RustCrypto.
                for tag in [2u8, 3, 4] {
                    for _ in 0..16 {
                        let len = if tag == 4 { 2 * $fl } else { $fl };
                        let mut bytes = vec![tag];
                        bytes.extend(rng.bytes(len));
                        if $fl == 66 {
                            bytes[1] &= 1;
                            if tag == 4 {
                                bytes[1 + $fl] &= 1;
                            }
                        }
                        let ours = AffinePoint::from_sec1_bytes(&bytes);
                        assert_eq!(ours.is_ok(), their_decode(&bytes).is_some(), "{bytes:02x?}");
                        if let Ok(a) = ours {
                            assert_eq!(a.to_sec1_point(tag != 4).as_bytes(), &bytes[..]);
                        }
                    }
                }
            }

            fn public_keys(rng: &mut XorShift) {
                let seed = rng.bytes(4 * $fl);
                let key = ours::SecretKey::generate(&FixedRng::new(&seed)).unwrap();
                let public = key.public_key();
                let d = Scalar::from_bytes(&key.to_bytes()[..]).unwrap();
                let point = ProjectivePoint::mul_by_generator(&d);
                assert_eq!(public.to_projective(), point);
                assert_eq!(public.to_affine(), point.to_affine());
                assert_eq!(AffinePoint::from(public), point.to_affine());
                assert_eq!(AffinePoint::from(&public), point.to_affine());
                assert_eq!(ProjectivePoint::from(public), point);
                assert_eq!(ProjectivePoint::from(&public), point);
                assert_eq!(PublicKey::from_affine(&point.to_affine()), Ok(public));
                assert_eq!(PublicKey::try_from(point), Ok(public));
                assert_eq!(PublicKey::try_from(&point), Ok(public));
                assert_eq!(PublicKey::try_from(point.to_affine()), Ok(public));
                assert_eq!(PublicKey::try_from(&point.to_affine()), Ok(public));
                assert_eq!(
                    PublicKey::from_affine(&AffinePoint::IDENTITY),
                    Err(Error::InvalidKey)
                );
                assert_eq!(
                    PublicKey::try_from(ProjectivePoint::IDENTITY),
                    Err(Error::InvalidKey)
                );
                assert_eq!(
                    point.to_affine().to_sec1_point(false).as_bytes(),
                    &public.to_uncompressed()[..]
                );
                // ECDH is the x-coordinate of d Q.
                let seed = rng.bytes(4 * $fl);
                let peer = ours::SecretKey::generate(&FixedRng::new(&seed)).unwrap();
                let shared = key.diffie_hellman(&peer.public_key()).unwrap();
                let product = peer.public_key().to_projective().mul(&d);
                assert_eq!(product.to_affine().x().to_bytes(), shared);
            }

            fn wiping() {
                let mut p = ProjectivePoint::GENERATOR.double();
                p.zeroize();
                assert_eq!(p, ProjectivePoint::IDENTITY);
                assert!(p.is_identity().declassify());
                let mut a = AffinePoint::GENERATOR;
                a.zeroize();
                assert_eq!(a, AffinePoint::IDENTITY);
                assert_eq!(ProjectivePoint::from(a), ProjectivePoint::IDENTITY);
            }

            #[test]
            fn points_on_every_backend() {
                let mut rng = XorShift(0x2545_f491_4f6c_dd1d ^ $fl);
                for policy in [Policy::PREFERRED, Policy::NONE] {
                    accel::set_policy(Algorithm::$alg, policy).unwrap();
                    println!("{}", accel::status(Algorithm::$alg));
                    constants();
                    multiplication(&mut rng);
                    group_law(&mut rng);
                    encodings(&mut rng);
                    public_keys(&mut rng);
                    wiping();
                }
                accel::set_policy(Algorithm::$alg, Policy::PREFERRED).unwrap();
            }
        }
    };
}

curve_group!(
    p256_group,
    p256,
    p256,
    32,
    P256,
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
curve_group!(
    p384_group,
    p384,
    p384,
    48,
    P384,
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
curve_group!(
    p521_group,
    p521,
    p521,
    66,
    P521,
    p = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    n = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);
