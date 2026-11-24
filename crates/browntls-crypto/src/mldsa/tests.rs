//! Unit tests of the arithmetic, rounding, sampling and encodings against
//! straightforward reference definitions, so that a failure is localised
//! before the known-answer tests run.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::dsa::{encode_key_from_parts, keygen, sign_mu_z_bound, verify_mu, verify_mu_z_bound};
use super::encode::sig_layout;
use super::encode::{hint_pack, hint_unpack, pack_bits, pack_offset, unpack_bits, unpack_offset};
use super::params::{eta_bits, z_bits};
use super::poly::{
    self, N, Poly, Q, ZETAS, abs_ge, caddq, centre, freeze, invntt_tomont, mont_reduce, norm_ge,
    ntt, pointwise, pointwise_acc, reduce32,
};
use super::rounding::{
    GAMMA2_32, GAMMA2_88, decompose, high_bits, low_bits, make_hint, power2round, use_hint,
};
use super::sample::{expand_mask_poly, rej_bounded_poly, rej_ntt_poly, sample_in_ball};
use super::{MlDsa44, MlDsa65, MlDsa87, ParameterSet, SigningKey};
use crate::Error;

/// xorshift64* (test data only).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `[-bound, bound]`.
    fn coeff(&mut self, bound: i32) -> i32 {
        let span = 2 * u64::from(bound.unsigned_abs()) + 1;
        (self.next() % span) as i32 - bound
    }

    fn poly(&mut self, bound: i32) -> Poly {
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            *c = self.coeff(bound);
        }
        p
    }
}

fn modq(a: i64) -> i64 {
    a.rem_euclid(i64::from(Q))
}

/// `a mod+- m` with the FIPS 204 range `(-m/2, m/2]` (even `m`).
fn mod_pm(a: i64, m: i64) -> i64 {
    let r = a.rem_euclid(m);
    if r > m / 2 { r - m } else { r }
}

#[test]
fn zetas_match_reference_table() {
    // Spot values of the reference implementation's table.
    assert_eq!(ZETAS[0], 0);
    assert_eq!(ZETAS[1], 25847);
    assert_eq!(ZETAS[2], -2_608_894);
    assert_eq!(ZETAS[3], -518_909);
    assert_eq!(ZETAS[255], 1_976_782);
    // ZETAS[1] is zeta^128 in Montgomery form; its square is zeta^256 = -1.
    let r_inv = i64::try_from(modinv(1 << 32)).unwrap();
    let z128 = modq(i64::from(ZETAS[1]) * r_inv);
    assert_eq!(modq(z128 * z128), i64::from(Q) - 1);
}

fn modinv(a: u64) -> u64 {
    // Fermat: a^(q-2) mod q.
    let q = Q as u64;
    let (mut r, mut b, mut e) = (1u64, a % q, q - 2);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % q;
        }
        b = b * b % q;
        e >>= 1;
    }
    r
}

#[test]
fn montgomery_reduction_range() {
    let r_inv = i64::try_from(modinv(1 << 32)).unwrap();
    let bound = (1i64 << 31) * i64::from(Q) - 1;
    let mut rng = Rng(1);
    let mut inputs = std::vec![0, 1, -1, bound, -bound, bound - 1, -bound + 1];
    for _ in 0..100_000 {
        inputs.push((rng.next() as i64) % bound);
    }
    for a in inputs {
        let r = mont_reduce(a);
        assert!(r.abs() < Q, "{a}");
        assert_eq!(modq(i64::from(r)), modq(modq(a) * r_inv), "{a}");
    }
}

#[test]
fn reduce32_freeze_centre_ranges() {
    let max = i32::MAX - (1 << 22);
    let mut rng = Rng(2);
    let mut inputs = std::vec![0, 1, -1, Q, -Q, Q - 1, (Q - 1) / 2, (Q + 1) / 2, max, -max];
    for _ in 0..100_000 {
        inputs.push(((rng.next() as i32) >> 1) & max);
        inputs.push(-(((rng.next() as i32) >> 1) & max));
    }
    for a in inputs {
        let r = reduce32(a);
        assert!(r.abs() <= 6_283_008, "{a}");
        assert_eq!(modq(r.into()), modq(a.into()));
        let f = freeze(a);
        assert!((0..Q).contains(&f));
        assert_eq!(i64::from(f), modq(a.into()));
        let c = centre(a);
        assert_eq!(i64::from(c), mod_pm(a.into(), Q.into()), "{a}");
        assert!(c.abs() <= (Q - 1) / 2);
    }
    for a in [-Q, -1, 0, Q - 1] {
        assert_eq!(i64::from(caddq(a)), modq(a.into()));
    }
}

#[test]
fn norm_checks() {
    for (a, b, ge) in [
        (0, 1, false),
        (5, 5, true),
        (-5, 5, true),
        (4, 5, false),
        (-4, 5, false),
        ((Q - 1) / 2, 1 << 19, true),
        (-(Q - 1) / 2, 1 << 19, true),
    ] {
        assert_eq!(abs_ge(a, b) == -1, ge, "{a} {b}");
        assert!(abs_ge(a, b) == 0 || abs_ge(a, b) == -1);
    }
    let mut p = Poly::ZERO;
    assert_eq!(norm_ge(&p, 1), 0);
    p.0[255] = -7;
    assert_eq!(norm_ge(&p, 7), -1);
    assert_eq!(norm_ge(&p, 8), 0);
}

fn schoolbook(a: &Poly, b: &Poly) -> [i64; N] {
    let mut r = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let p = i64::from(a.0[i]) * i64::from(b.0[j]);
            if i + j < N {
                r[i + j] += p;
            } else {
                r[i + j - N] -= p;
            }
        }
    }
    r
}

#[test]
fn ntt_round_trip_and_multiplication() {
    let mut rng = Rng(3);
    let r = 1i64 << 32;
    for bound in [1, 2, 4, 1 << 12, 1 << 19, (Q - 1) / 2] {
        let a = rng.poly(bound);
        let b = rng.poly(bound.min(1 << 19));
        // invntt(ntt(a)) = a 2^32.
        let mut t = a;
        ntt(&mut t);
        assert!(t.0.iter().all(|c| c.abs() < 9 * Q));
        let mut u = t;
        poly::reduce(&mut u);
        invntt_tomont(&mut u);
        for (x, y) in u.0.iter().zip(a.0.iter()) {
            assert!(x.abs() < Q);
            assert_eq!(modq(i64::from(*x)), modq(i64::from(*y) * r));
        }
        // invntt(ntt(a) o ntt(b)) = a b mod X^256 + 1.
        let mut tb = b;
        ntt(&mut tb);
        let mut p = Poly::ZERO;
        pointwise(&mut p, &t, &tb);
        let mut acc = Poly::ZERO;
        pointwise_acc(&mut acc, &t, &tb);
        assert_eq!(p.0, acc.0);
        invntt_tomont(&mut p);
        let want = schoolbook(&a, &b);
        for (x, y) in p.0.iter().zip(want.iter()) {
            assert!(x.abs() < Q);
            assert_eq!(modq(i64::from(*x)), modq(*y));
        }
    }
}

#[test]
fn power2round_exhaustive() {
    for r in 0..Q {
        let (r1, r0) = power2round(r);
        assert_eq!(i64::from(r0), mod_pm(r.into(), 1 << 13), "{r}");
        assert_eq!(r1 * (1 << 13) + r0, r, "{r}");
        assert!((0..1024).contains(&r1));
    }
}

/// FIPS 204 Algorithm 36, written with `%` and branches.
fn decompose_ref(r: i32, gamma2: i32) -> (i32, i32) {
    let r0 = mod_pm(r.into(), (2 * gamma2).into()) as i32;
    if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * gamma2), r0)
    }
}

#[test]
fn decompose_exhaustive() {
    for gamma2 in [GAMMA2_88, GAMMA2_32] {
        for r in 0..Q {
            let got = decompose(r, gamma2);
            assert_eq!(got, decompose_ref(r, gamma2), "{r} {gamma2}");
            assert_eq!(high_bits(r, gamma2), got.0);
            assert_eq!(low_bits(r, gamma2), got.1);
        }
    }
}

#[test]
fn hints_recover_high_bits() {
    // UseHint(MakeHint(z, r), r) = HighBits(r + z) for ||z|| <= gamma2
    // (FIPS 204 §7.4), over a dense sweep of r and edge values of z.
    let mut rng = Rng(4);
    for gamma2 in [GAMMA2_88, GAMMA2_32] {
        let m = (Q - 1) / (2 * gamma2);
        let mut r = 0;
        while r < Q {
            for z in [0, 1, -1, gamma2, -gamma2, rng.coeff(gamma2)] {
                let rz = freeze(r + z);
                let h = make_hint(r, rz, gamma2);
                assert!(h == 0 || h == 1);
                assert_eq!(h == 1, high_bits(r, gamma2) != high_bits(rz, gamma2));
                let w1 = use_hint(h == 1, r, gamma2);
                assert_eq!(w1, high_bits(rz, gamma2), "{r} {z} {gamma2}");
                assert!((0..m).contains(&w1));
            }
            r += 97;
        }
        // The wrap-around values.
        for r in [0, 1, Q - 1, Q - 2, Q - gamma2, Q - gamma2 - 1] {
            assert_eq!(use_hint(true, r, gamma2), {
                let (r1, r0) = decompose_ref(r, gamma2);
                if r0 > 0 {
                    (r1 + 1) % m
                } else {
                    (r1 - 1).rem_euclid(m)
                }
            });
        }
    }
}

#[test]
fn bit_packing_round_trips() {
    let mut rng = Rng(5);
    for bits in [3, 4, 6, 10, 13, 18, 20] {
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            *c = (rng.next() % (1 << bits)) as i32;
        }
        let mut buf = [0u8; 640];
        let buf = &mut buf[..32 * bits];
        pack_bits(&p, bits, buf);
        let mut q = Poly::ZERO;
        unpack_bits(buf, bits, &mut q);
        assert_eq!(p.0, q.0);
        // Little-endian, least significant bit first.
        let mut first = 0u32;
        for (i, b) in buf.iter().take(4).enumerate() {
            first |= u32::from(*b) << (8 * i);
        }
        assert_eq!((first & ((1 << bits) - 1)) as i32, p.0[0]);

        let off = 1 << (bits - 1);
        let mut s = Poly::ZERO;
        for c in s.0.iter_mut() {
            *c = off - (rng.next() % (1 << bits)) as i32;
        }
        pack_offset(&s, off, bits, buf);
        unpack_offset(buf, off, bits, &mut q);
        assert_eq!(s.0, q.0);
    }
}

#[test]
fn hint_encoding() {
    const K: usize = 4;
    let omega = 80;
    let mut h = [[0u8; N]; K];
    h[0][3] = 1;
    h[0][200] = 1;
    h[2][0] = 1;
    h[3][255] = 1;
    let mut y = [0u8; 84];
    hint_pack(&h, omega, &mut y);
    assert_eq!(&y[..4], &[3, 200, 0, 255]);
    assert_eq!(&y[omega..], &[2, 2, 3, 4]);
    let mut back = [[0u8; N]; K];
    assert!(hint_unpack(&y, omega, &mut back));
    assert_eq!(back, h);

    let reject = |f: &dyn Fn(&mut [u8; 84])| {
        let mut z = y;
        f(&mut z);
        let mut out = [[0u8; N]; K];
        assert!(!hint_unpack(&z, omega, &mut out));
    };
    // Indices not strictly increasing within a row.
    reject(&|z| z[1] = 3);
    reject(&|z| z[1] = 2);
    // Decreasing cumulative count, count above omega.
    reject(&|z| z[omega + 1] = 1);
    reject(&|z| z[omega + 3] = 81);
    // Non-zero padding.
    reject(&|z| z[10] = 1);
    // Wrong length.
    let mut out = [[0u8; N]; K];
    assert!(!hint_unpack(&y[..83], omega, &mut out));
    // Increasing across a row boundary is not required.
    let mut z = y;
    z[2] = 0;
    assert!(hint_unpack(&z, omega, &mut out));
}

#[test]
fn samplers_respect_their_ranges() {
    let rho = [9u8; 32];
    let rho64 = [7u8; 64];
    let mut p = Poly::ZERO;
    rej_ntt_poly(&rho, 1, 2, &mut p);
    assert!(p.0.iter().all(|c| (0..Q).contains(c)));
    for eta in [2, 4] {
        rej_bounded_poly(&rho64, 3, eta, &mut p);
        assert!(p.0.iter().all(|c| c.abs() <= eta as i32));
        // Every value occurs.
        for v in -(eta as i32)..=eta as i32 {
            assert!(p.0.contains(&v), "{eta} {v}");
        }
    }
    for (gamma1, bits) in [(1 << 17, 18), (1 << 19, 20)] {
        expand_mask_poly(&rho64, 65535, gamma1, bits, &mut p);
        assert!(p.0.iter().all(|c| (-gamma1 + 1..=gamma1).contains(c)));
    }
    for tau in [39, 49, 60] {
        for seed in 0u8..20 {
            sample_in_ball(&[seed; 48], tau, &mut p);
            assert_eq!(p.0.iter().filter(|&&c| c != 0).count(), tau);
            assert!(p.0.iter().all(|c| c.abs() <= 1));
        }
    }
}

/// An expanded key whose `s1` or `s2` has one coefficient outside
/// `[-eta, eta]`, but whose `t0` and `tr` are recomputed from those vectors
/// exactly as key generation would, so that only the range check can reject
/// it. Covers every out-of-range code that the packed form can hold.
fn out_of_range_secrets_rejected<P: ParameterSet, const K: usize, const L: usize>() {
    let eta = P::ETA as i32;
    let ebits = eta_bits::<P>();
    let mut rng = Rng(0x5eed_0000 ^ P::K as u64);
    let rho = [0x11u8; 32];
    let key = [0x22u8; 32];
    let s1: [Poly; L] = core::array::from_fn(|_| rng.poly(eta));
    let s2: [Poly; K] = core::array::from_fn(|_| rng.poly(eta));
    let mut pk = [0u8; 2592];
    let mut sk = [0u8; 4896];
    let (pk, sk) = (
        &mut pk[..P::VERIFYING_KEY_LEN],
        &mut sk[..P::SIGNING_KEY_LEN],
    );

    // Control: the same construction with in-range vectors is accepted.
    encode_key_from_parts::<P, K, L>(&rho, &key, &s1, &s2, pk, sk);
    let good = SigningKey::<P>::from_expanded_bytes(sk).unwrap();
    assert_eq!(good.verifying_key().as_bytes(), &pk[..]);

    // Packed codes 2 eta + 1 ..= 2^ebits - 1, i.e. values -eta - 1 down to
    // eta + 1 - 2^ebits.
    for code in 2 * eta + 1..1 << ebits {
        let value = eta - code;
        let at = (code as usize * 37) % N;
        let mut bad1 = s1;
        bad1[code as usize % L].0[at] = value;
        encode_key_from_parts::<P, K, L>(&rho, &key, &bad1, &s2, pk, sk);
        let r = SigningKey::<P>::from_expanded_bytes(sk);
        assert!(r.err() == Some(Error::InvalidKey), "{} s1 {value}", P::NAME);

        let mut bad2 = s2;
        bad2[code as usize % K].0[at] = value;
        encode_key_from_parts::<P, K, L>(&rho, &key, &s1, &bad2, pk, sk);
        let r = SigningKey::<P>::from_expanded_bytes(sk);
        assert!(r.err() == Some(Error::InvalidKey), "{} s2 {value}", P::NAME);
    }
}

#[test]
fn expanded_key_range_check() {
    out_of_range_secrets_rejected::<MlDsa44, 4, 4>();
    out_of_range_secrets_rejected::<MlDsa65, 6, 5>();
    out_of_range_secrets_rejected::<MlDsa87, 8, 7>();
}

/// `||z||_inf` of a signature: the largest `|z|` coefficient.
fn z_norm<P: ParameterSet>(sig: &[u8]) -> i32 {
    let (z_off, z_len, _) = sig_layout::<P>();
    let mut z = Poly::ZERO;
    let mut max = 0;
    for i in 0..P::L {
        let o = z_off + i * z_len;
        unpack_offset(&sig[o..o + z_len], P::GAMMA1 as i32, z_bits::<P>(), &mut z);
        max = z.0.iter().fold(max, |m, c| m.max(c.abs()));
    }
    max
}

/// Boundary of the `z` norm check (`||z|| < gamma1 - beta`).
///
/// A valid signature never has `||z|| = gamma1 - beta`, and flipping bits of
/// a real signature's `z` would also change `w'` and so fail on the
/// challenge, not on the norm. Instead, the signer is run with the bound
/// raised by one: its other rejection conditions are unchanged, so its
/// output is a self-consistent signature (it verifies under the raised
/// bound). Among those, one whose `z` reaches exactly `gamma1 - beta` must be
/// rejected by the real verifier on the norm check alone, and one reaching
/// exactly `gamma1 - beta - 1` must be accepted. The Wycheproof
/// `InfinityNormViolation` and boundary vectors cover the same check from
/// outside.
fn z_norm_boundary<P: ParameterSet, const K: usize, const L: usize>() {
    let bound = (P::GAMMA1 - P::BETA) as i32;
    let mut pk = [0u8; 2592];
    let mut sk = [0u8; 4896];
    let mut sig = [0u8; 4627];
    let (pk, sk) = (
        &mut pk[..P::VERIFYING_KEY_LEN],
        &mut sk[..P::SIGNING_KEY_LEN],
    );
    let sig = &mut sig[..P::SIGNATURE_LEN];
    keygen::<P, K, L>(&[0x33; 32], pk, sk);
    let mut rng = Rng(0xb0_0d ^ P::K as u64);
    let (mut at_bound, mut below) = (false, false);
    for _ in 0..5000 {
        if at_bound && below {
            break;
        }
        let mut mu = [0u8; 64];
        for c in mu.chunks_mut(8) {
            c.copy_from_slice(&rng.next().to_le_bytes());
        }
        sign_mu_z_bound::<P, K, L>(sk, &mu, &[0; 32], sig, bound + 1).unwrap();
        assert!(verify_mu_z_bound::<P, K, L>(pk, &mu, sig, bound + 1));
        let norm = z_norm::<P>(sig);
        if norm == bound {
            at_bound = true;
            assert!(!verify_mu::<P, K, L>(pk, &mu, sig), "{}", P::NAME);
        } else if norm == bound - 1 {
            below = true;
            assert!(verify_mu::<P, K, L>(pk, &mu, sig), "{}", P::NAME);
        }
    }
    assert!(at_bound && below, "{}: boundary not reached", P::NAME);
}

#[test]
fn z_norm_boundary_is_exclusive() {
    z_norm_boundary::<MlDsa44, 4, 4>();
    z_norm_boundary::<MlDsa65, 6, 5>();
    z_norm_boundary::<MlDsa87, 8, 7>();
}
