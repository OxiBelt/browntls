//! Point arithmetic of P-256, P-384 and P-521 (`AffinePoint`,
//! `ProjectivePoint`, `Sec1Point`, the `PublicKey` conversions) for the
//! `crypto_ecc` target, checked against the RustCrypto points and SEC 1
//! decoders, and between the default and the portable backend.
//!
//! One operation per curve, [`group_ops`]`::points`. Arguments: two scalar
//! candidates ([`super::nist_arith::candidate`]; a rejected one is reduced
//! instead), a SEC 1 candidate ([`group_ops`]`::encoding`: raw bytes, a
//! valid point in either form with an edit, the identity, or random
//! coordinates behind a fuzzed tag) and a compression flag. A rejected
//! encoding is replaced by a multiple of the base point, so every operation
//! runs on every input.

macro_rules! group_ops {
    ($m:ident, $ours:ident, $rc:ident, $fl:literal, $alg:ident, n = $n:literal) => {
        pub mod $m {
            use ::$rc::elliptic_curve::ff::PrimeField as _;
            use ::$rc::elliptic_curve::sec1::{FromSec1Point as _, ToSec1Point as _};
            use browntls_crypto::Error;
            use browntls_crypto::accel::Algorithm;
            use browntls_crypto::nist::$ours as ours;
            use browntls_crypto::zeroize::Zeroize as _;
            use ours::{AffinePoint, FieldElement, ProjectivePoint, PublicKey, Scalar};

            use crate::crypto_ecc::edit;
            use crate::crypto_ecc::nist::portable;
            use crate::crypto_ecc::nist_arith::candidate;
            use crate::input::Input;

            const FL: usize = $fl;
            const ALG: Algorithm = Algorithm::$alg;

            /// A scalar from a candidate: decoded, else reduced, else its
            /// length.
            fn scalar(bytes: &[u8]) -> Scalar {
                Scalar::from_bytes(bytes)
                    .or_else(|_| Scalar::from_bytes_reduced(bytes))
                    .unwrap_or_else(|_| Scalar::from(bytes.len() as u64))
            }

            /// A SEC 1 candidate: raw bytes, a valid point in either form
            /// with an edit, the identity, or random coordinates behind a
            /// fuzzed tag.
            fn encoding(input: &mut Input<'_>) -> Vec<u8> {
                match input.choose(4) {
                    0 => input.short_field().to_vec(),
                    1 => {
                        let k = Scalar::from(u64::from(input.u16()));
                        let compress = input.bool();
                        let mut v = ProjectivePoint::mul_by_generator(&k)
                            .to_affine()
                            .to_sec1_point(compress)
                            .as_bytes()
                            .to_vec();
                        edit(&mut v, input);
                        v
                    }
                    2 => vec![0],
                    _ => {
                        let tag = input.choose(8) as u8;
                        let mut v = vec![tag];
                        let coordinates = if tag >= 4 { 2 } else { 1 };
                        for _ in 0..coordinates {
                            let mut c = input.bytes(FL).to_vec();
                            c.resize(FL, 0);
                            v.extend_from_slice(&c);
                        }
                        v
                    }
                }
            }

            /// The arguments of one operation.
            struct Args {
                a: Vec<u8>,
                b: Vec<u8>,
                point: Vec<u8>,
                compress: bool,
            }

            /// Op: point arithmetic on the default and the portable
            /// backend, which must agree byte for byte.
            pub fn points(input: &mut Input<'_>) {
                let args = Args {
                    a: candidate(input, $n, FL),
                    b: candidate(input, $n, FL),
                    point: encoding(input),
                    compress: input.bool(),
                };
                let fast = transcript(&args);
                let slow = portable(ALG, || transcript(&args));
                assert_eq!(fast, slow, "portable backend");
            }

            fn their_scalar(s: &Scalar) -> ::$rc::Scalar {
                let bytes = ::$rc::FieldBytes::try_from(&s.to_bytes()[..]).expect("length");
                Option::from(::$rc::Scalar::from_repr(bytes)).expect("reduced")
            }

            fn their_decode(bytes: &[u8]) -> Option<::$rc::AffinePoint> {
                let encoded = ::$rc::Sec1Point::from_bytes(bytes).ok()?;
                Option::from(::$rc::AffinePoint::from_sec1_point(&encoded))
            }

            fn enc(p: &ProjectivePoint, compress: bool) -> Vec<u8> {
                p.to_affine().to_sec1_point(compress).as_bytes().to_vec()
            }

            fn theirs(p: &ProjectivePoint) -> ::$rc::ProjectivePoint {
                their_decode(&enc(p, false)).expect("valid point").into()
            }

            /// Our point encodes as the oracle's, in both forms.
            fn check(ours: &ProjectivePoint, theirs: &::$rc::ProjectivePoint, what: &str) {
                for compress in [false, true] {
                    let t = theirs.to_affine().to_sec1_point(compress);
                    assert_eq!(enc(ours, compress), t.as_bytes(), "{what}");
                }
            }

            /// Decodes the candidate, checking the verdict against the
            /// oracle for the forms both implement.
            fn decode(bytes: &[u8]) -> Option<AffinePoint> {
                let ours = AffinePoint::from_sec1_bytes(bytes);
                let comparable = bytes == [0] || matches!(bytes.first(), Some(2..=4));
                if comparable {
                    assert_eq!(
                        ours.is_ok(),
                        their_decode(bytes).is_some(),
                        "point acceptance"
                    );
                }
                match ours {
                    Ok(a) => {
                        let compressed = matches!(bytes.first(), Some(2 | 3));
                        assert_eq!(a.to_sec1_point(compressed).as_bytes(), bytes, "canonical");
                        Some(a)
                    }
                    Err(e) => {
                        assert!(
                            matches!(e, Error::InvalidEncoding | Error::InvalidKey),
                            "{e:?}"
                        );
                        if !comparable {
                            assert_eq!(e, Error::InvalidEncoding);
                        }
                        None
                    }
                }
            }

            fn transcript(args: &Args) -> Vec<Vec<u8>> {
                let mut out = Vec::new();
                let (a, b) = (scalar(&args.a), scalar(&args.b));
                let (ta, tb) = (their_scalar(&a), their_scalar(&b));
                let ag = ProjectivePoint::mul_by_generator(&a);
                check(&ag, &(::$rc::ProjectivePoint::GENERATOR * ta), "a G");
                assert_eq!(
                    ProjectivePoint::GENERATOR.mul(&a),
                    ag,
                    "mul vs mul_by_generator"
                );
                let affine = decode(&args.point).unwrap_or_else(|| ag.double().to_affine());
                let p = ProjectivePoint::from(affine);
                let tp = theirs(&p);
                assert_eq!(p.to_affine(), affine);
                // Affine accessors and conversions.
                let identity = affine.is_identity().declassify();
                assert_eq!(p.is_identity().declassify(), identity);
                match AffinePoint::from_coordinates(&affine.x(), &affine.y()) {
                    Ok(back) => assert_eq!(back, affine),
                    Err(e) => assert_eq!((e, identity), (Error::InvalidKey, true)),
                }
                if identity {
                    assert_eq!(
                        (affine.x(), affine.y()),
                        (FieldElement::ZERO, FieldElement::ZERO)
                    );
                }
                assert_eq!(-affine, (-p).to_affine());
                assert_eq!(affine.neg().ct_eq(&affine).declassify(), identity);
                let e = affine.to_sec1_point(args.compress);
                assert_eq!(AffinePoint::from_sec1_bytes(e.as_ref()), Ok(affine));
                assert_eq!(format!("{e:?}"), format!("Sec1Point({:?})", e.as_bytes()));
                out.push(e.as_bytes().to_vec());
                // The group law against the oracle.
                let bp = p.mul(&b);
                check(&bp, &(tp * tb), "b P");
                let mut m = p;
                m *= &b;
                assert_eq!(m, p * b.clone());
                let sum = ag + bp;
                check(
                    &sum,
                    &(::$rc::ProjectivePoint::GENERATOR * ta + tp * tb),
                    "a G + b P",
                );
                assert_eq!(
                    ProjectivePoint::mul_by_generator_and_mul_add_vartime(&a, &b, &p),
                    sum,
                    "variable-time double multiplication"
                );
                check(
                    &(ag + p),
                    &(::$rc::ProjectivePoint::GENERATOR * ta + tp),
                    "add",
                );
                check(
                    &(ag - p),
                    &(::$rc::ProjectivePoint::GENERATOR * ta - tp),
                    "sub",
                );
                check(&p.double(), &(tp + tp), "double");
                check(&p.neg(), &-tp, "neg");
                assert_eq!(p.add(&p), p.double());
                assert!(p.sub(&p).is_identity().declassify());
                assert_eq!(ag + affine, ag + p, "mixed addition");
                assert_eq!(ag - affine, ag - p, "mixed subtraction");
                assert_eq!(p + AffinePoint::IDENTITY, p);
                assert_eq!(p + ProjectivePoint::IDENTITY, p);
                let mut c = ag;
                c += p;
                c -= &affine;
                c += &affine;
                c -= &p;
                assert_eq!(c, ag);
                assert_eq!(c.ct_eq(&ag).declassify(), true);
                assert_eq!(ag == p, ag.to_affine() == affine);
                assert_eq!(&-&p, &p.neg());
                // Public keys are the points other than the identity.
                match PublicKey::from_affine(&affine) {
                    Ok(key) => {
                        assert!(!identity);
                        assert_eq!(key.to_affine(), affine);
                        assert_eq!(key.to_projective(), p);
                        assert_eq!(PublicKey::try_from(p), Ok(key));
                        assert_eq!(key.to_uncompressed()[..], enc(&p, false)[..]);
                    }
                    Err(e) => assert_eq!((e, identity), (Error::InvalidKey, true)),
                }
                assert_eq!(format!("{p:?}"), "ProjectivePoint(..)");
                assert_eq!(format!("{affine:?}"), "AffinePoint(..)");
                let mut wiped = sum;
                wiped.zeroize();
                assert_eq!(wiped, ProjectivePoint::IDENTITY);
                let mut wiped = affine;
                wiped.zeroize();
                assert_eq!(wiped, AffinePoint::IDENTITY);
                for v in [ag, bp, sum, p.double()] {
                    out.push(enc(&v, args.compress));
                }
                out
            }
        }
    };
}

group_ops!(
    p256,
    p256,
    p256,
    32,
    P256,
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
group_ops!(
    p384,
    p384,
    p384,
    48,
    P384,
    n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
group_ops!(
    p521,
    p521,
    p521,
    66,
    P521,
    n = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);
