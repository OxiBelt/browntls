//! The internal ML-DSA algorithms (FIPS 204 §6): `ML-DSA.KeyGen_internal`
//! (Algorithm 6), `ML-DSA.Sign_internal` (Algorithm 7) from `mu` onwards and
//! `ML-DSA.Verify_internal` (Algorithm 8) from `mu` onwards, plus the
//! consistency check of an expanded private key.
//!
//! Each function is instantiated per parameter set with the exact vector
//! dimensions `K` and `L`, so temporaries are sized for the set in use. The
//! public matrix `A` is held in full only while signing (the rejection loop
//! reuses it); key generation and verification sample it one entry at a
//! time.

use super::encode::{
    T0_LEN, T1_LEN, hint_pack, hint_unpack, pack_bits, pack_offset, sig_layout, sk_layout,
    unpack_bits, unpack_offset, w1_len,
};
use super::params::{ParameterSet, ctilde_len, eta_bits, w1_bits, z_bits};
use super::poly::{
    self, D, N, Poly, abs_ge, centre, freeze, freeze_poly, invntt_tomont, norm_ge, ntt, pointwise,
    pointwise_acc, reduce,
};
use super::rounding::{decompose, high_bits, make_hint, power2round, use_hint};
use super::sample::{expand_mask_poly, rej_bounded_poly, rej_ntt_poly, sample_in_ball};
use crate::Error;
use crate::hash::Shake256;
use crate::zeroize::{Zeroize, Zeroizing};

/// `2^(d-1)`: `t0` is packed as `2^(d-1) - t0`.
const T0_OFFSET: i32 = 1 << (D - 1);

/// Row `r` of `t = A s1 + s2` in `[0, q)`, given `s1_hat = NTT(s1)`.
/// `A` is sampled one entry at a time.
fn t_row<const L: usize>(rho: &[u8; 32], s1_hat: &[Poly; L], s2: &Poly, r: usize, t: &mut Poly) {
    let mut a = Poly::ZERO;
    *t = Poly::ZERO;
    for (s, s1) in s1_hat.iter().enumerate() {
        // r < 8 and s < 7.
        rej_ntt_poly(rho, s as u8, r as u8, &mut a);
        pointwise_acc(t, &a, s1);
    }
    reduce(t);
    invntt_tomont(t);
    for (c, &e) in t.0.iter_mut().zip(s2.0.iter()) {
        *c = freeze(*c + e);
    }
}

/// `ExpandS` (Algorithm 33): `s1` from nonces `0..L`, `s2` from `L..L+K`.
fn expand_s<P: ParameterSet, const K: usize, const L: usize>(
    rho_prime: &[u8; 64],
    s1: &mut [Poly; L],
    s2: &mut [Poly; K],
) {
    for (r, p) in s1.iter_mut().enumerate() {
        rej_bounded_poly(rho_prime, r as u16, P::ETA, p);
    }
    for (r, p) in s2.iter_mut().enumerate() {
        rej_bounded_poly(rho_prime, (L + r) as u16, P::ETA, p);
    }
}

/// Secret polynomial vectors of key generation, zeroised on drop.
struct KeyScratch<const K: usize, const L: usize> {
    /// `s1`, then `NTT(s1)` in place.
    s1: [Poly; L],
    s2: [Poly; K],
    t: Poly,
}

impl<const K: usize, const L: usize> KeyScratch<K, L> {
    fn new() -> Self {
        Self {
            s1: [Poly::ZERO; L],
            s2: [Poly::ZERO; K],
            t: Poly::ZERO,
        }
    }
}

impl<const K: usize, const L: usize> Drop for KeyScratch<K, L> {
    fn drop(&mut self) {
        poly::zeroize_vec(&mut self.s1);
        poly::zeroize_vec(&mut self.s2);
        self.t.zeroize();
    }
}

/// The common tail of key generation and the expanded-key check: from `s1`
/// and `s2` in `v`, computes `t = A s1 + s2` row by row and
/// `(t1, t0) <- Power2Round(t)`, writes `pk = pkEncode(rho, t1)` and
/// `tr = H(pk, 64)`, and hands each packed `t0` row to `t0_row`. Transforms
/// `v.s1` to the NTT domain.
fn derive_pk<const K: usize, const L: usize>(
    rho: &[u8; 32],
    v: &mut KeyScratch<K, L>,
    pk: &mut [u8],
    tr: &mut [u8; 64],
    mut t0_row: impl FnMut(usize, &[u8; T0_LEN]),
) {
    v.s1.iter_mut().for_each(ntt);
    pk[..32].copy_from_slice(rho);
    let mut t1 = Poly::ZERO;
    let mut t0 = Zeroizing([0u8; T0_LEN]);
    for r in 0..K {
        t_row(rho, &v.s1, &v.s2[r], r, &mut v.t);
        for (c, h1) in v.t.0.iter_mut().zip(t1.0.iter_mut()) {
            let (hi, lo) = power2round(*c);
            *h1 = hi;
            *c = lo;
        }
        pack_bits(&t1, 10, &mut pk[32 + r * T1_LEN..32 + (r + 1) * T1_LEN]);
        pack_offset(&v.t, T0_OFFSET, 13, &mut t0.0);
        t0_row(r, &t0);
    }
    let mut h = Shake256::new();
    h.update(pk);
    h.finalize_xof().read(tr);
}

/// `ML-DSA.KeyGen_internal(xi)` (Algorithm 6): writes `pk` (`pkEncode`,
/// Algorithm 22) and the expanded `sk` (`skEncode`, Algorithm 24).
pub(crate) fn keygen<P: ParameterSet, const K: usize, const L: usize>(
    xi: &[u8; 32],
    pk: &mut [u8],
    sk: &mut [u8],
) {
    // (rho, rho', K) <- H(xi || k || l, 128).
    let mut seeds = Zeroizing([0u8; 128]);
    let mut h = Shake256::new();
    h.update(xi);
    h.update(&[K as u8, L as u8]);
    h.finalize_xof().read(&mut seeds.0);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&seeds[..32]);
    let mut rho_prime = Zeroizing([0u8; 64]);
    rho_prime.copy_from_slice(&seeds[32..96]);

    let mut v = KeyScratch::<K, L>::new();
    expand_s::<P, K, L>(&rho_prime, &mut v.s1, &mut v.s2);
    let mut key = Zeroizing([0u8; 32]);
    key.copy_from_slice(&seeds[96..]);
    encode_key::<P, K, L>(&rho, &key, &mut v, pk, sk);
}

/// `skEncode` and `pkEncode` (Algorithms 24 and 22) of the key with seeds
/// `rho` and `K` and the vectors `s1`, `s2` in `v`, computing `t0`, `t1` and
/// `tr` from them. Transforms `v.s1` to the NTT domain.
fn encode_key<P: ParameterSet, const K: usize, const L: usize>(
    rho: &[u8; 32],
    key: &[u8; 32],
    v: &mut KeyScratch<K, L>,
    pk: &mut [u8],
    sk: &mut [u8],
) {
    let layout = sk_layout::<P>();
    let ebits = eta_bits::<P>();
    let eta = P::ETA as i32;
    sk[..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(key);
    for (i, s) in v.s1.iter().enumerate() {
        let o = layout.s1 + i * layout.s_len;
        pack_offset(s, eta, ebits, &mut sk[o..o + layout.s_len]);
    }
    for (i, s) in v.s2.iter().enumerate() {
        let o = layout.s2 + i * layout.s_len;
        pack_offset(s, eta, ebits, &mut sk[o..o + layout.s_len]);
    }
    let mut tr = [0u8; 64];
    derive_pk(rho, v, pk, &mut tr, |r, t0| {
        let o = layout.t0 + r * T0_LEN;
        sk[o..o + T0_LEN].copy_from_slice(t0);
    });
    sk[64..128].copy_from_slice(&tr);
}

/// Test helper: the expanded private key (and public key) with chosen `s1`
/// and `s2`, which may lie outside `[-eta, eta]` as far as their packed form
/// allows, and with `t0`, `t1` and `tr` computed consistently from them, as
/// key generation would.
#[cfg(test)]
pub(crate) fn encode_key_from_parts<P: ParameterSet, const K: usize, const L: usize>(
    rho: &[u8; 32],
    key: &[u8; 32],
    s1: &[Poly; L],
    s2: &[Poly; K],
    pk: &mut [u8],
    sk: &mut [u8],
) {
    let mut v = KeyScratch::<K, L>::new();
    v.s1 = *s1;
    v.s2 = *s2;
    encode_key::<P, K, L>(rho, key, &mut v, pk, sk);
}

/// Validates an expanded private key and writes the public key it implies
/// to `pk`: `s1` and `s2` coefficients must be in `[-eta, eta]`, and the
/// stored `t0` and `tr` must equal those recomputed from `rho`, `s1` and
/// `s2`. Every check runs to completion; only the returned bit depends on
/// secret data.
pub(crate) fn check_expanded<P: ParameterSet, const K: usize, const L: usize>(
    sk: &[u8],
    pk: &mut [u8],
) -> bool {
    let layout = sk_layout::<P>();
    let ebits = eta_bits::<P>();
    let eta = P::ETA as i32;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);

    let mut v = KeyScratch::<K, L>::new();
    // Range check: c in [-eta, eta] iff the packed value eta - c <= 2 eta.
    let mut bad = 0i32;
    for (i, s) in v.s1.iter_mut().enumerate() {
        let o = layout.s1 + i * layout.s_len;
        unpack_offset(&sk[o..o + layout.s_len], eta, ebits, s);
        bad |= norm_ge(s, eta + 1);
    }
    for (i, s) in v.s2.iter_mut().enumerate() {
        let o = layout.s2 + i * layout.s_len;
        unpack_offset(&sk[o..o + layout.s_len], eta, ebits, s);
        bad |= norm_ge(s, eta + 1);
    }

    let mut diff = 0u8;
    let mut tr = [0u8; 64];
    derive_pk(&rho, &mut v, pk, &mut tr, |r, t0| {
        let o = layout.t0 + r * T0_LEN;
        for (a, b) in t0.iter().zip(&sk[o..o + T0_LEN]) {
            diff |= a ^ b;
        }
    });
    for (a, b) in tr.iter().zip(&sk[64..128]) {
        diff |= a ^ b;
    }
    // bad is 0 or -1.
    let ok = crate::ct::is_zero_u64(u64::from(diff))
        .and(crate::ct::is_zero_u64(u64::from(bad.unsigned_abs())));
    ok.declassify()
}

/// Secret state of the signing loop, zeroised on drop.
struct SignScratch<const K: usize, const L: usize> {
    s1_hat: [Poly; L],
    s2_hat: [Poly; K],
    t0_hat: [Poly; K],
    /// `y`, then `z = y + c s1` in place.
    yz: [Poly; L],
    w: [Poly; K],
    c_hat: Poly,
    tmp: Poly,
    ct0: Poly,
    hints: [[u8; N]; K],
    rho2: [u8; 64],
}

impl<const K: usize, const L: usize> Drop for SignScratch<K, L> {
    fn drop(&mut self) {
        poly::zeroize_vec(&mut self.s1_hat);
        poly::zeroize_vec(&mut self.s2_hat);
        poly::zeroize_vec(&mut self.t0_hat);
        poly::zeroize_vec(&mut self.yz);
        poly::zeroize_vec(&mut self.w);
        self.c_hat.zeroize();
        self.tmp.zeroize();
        self.ct0.zeroize();
        for row in self.hints.iter_mut() {
            row.zeroize();
        }
        self.rho2.zeroize();
    }
}

/// `ML-DSA.Sign_internal` (Algorithm 7) given `mu = H(tr || M', 64)` and
/// `rnd`. `sk` must have passed [`check_expanded`] or come from
/// [`keygen`].
///
/// Constant time apart from the number of loop iterations: each iteration
/// evaluates every rejection condition (the norms of `z`, `r0` and `c t0`
/// and the hint count) without early exit and branches only on their
/// combined result.
///
/// # Errors
///
/// [`Error::InvalidKey`] if the 16-bit `ExpandMask` counter would overflow,
/// after about 65536 / l rejected iterations. For a valid key that happens
/// only with negligible probability (each iteration is accepted with
/// probability about 1/4 to 1/5); FIPS 204 permits bounding the loop. A
/// caller that sees it should treat the key or the platform as faulty.
pub(crate) fn sign_mu<P: ParameterSet, const K: usize, const L: usize>(
    sk: &[u8],
    mu: &[u8; 64],
    rnd: &[u8; 32],
    sig: &mut [u8],
) -> Result<(), Error> {
    sign_mu_z_bound::<P, K, L>(sk, mu, rnd, sig, (P::GAMMA1 - P::BETA) as i32)
}

/// [`sign_mu`] with the rejection bound on `||z||` as a parameter
/// (`gamma1 - beta` in FIPS 204). Tests use a larger bound to produce
/// self-consistent signatures whose `z` lies exactly on the bound, which the
/// real signer never outputs.
pub(super) fn sign_mu_z_bound<P: ParameterSet, const K: usize, const L: usize>(
    sk: &[u8],
    mu: &[u8; 64],
    rnd: &[u8; 32],
    sig: &mut [u8],
    z_bound: i32,
) -> Result<(), Error> {
    let layout = sk_layout::<P>();
    let ebits = eta_bits::<P>();
    let eta = P::ETA as i32;
    let gamma1 = P::GAMMA1 as i32;
    let gamma2 = P::GAMMA2 as i32;
    let beta = P::BETA as i32;
    let zb = z_bits::<P>();
    let w1b = w1_bits::<P>();
    let ct_len = ctilde_len::<P>();
    let (z_off, z_len, h_off) = sig_layout::<P>();

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);

    let mut v = SignScratch::<K, L> {
        s1_hat: [Poly::ZERO; L],
        s2_hat: [Poly::ZERO; K],
        t0_hat: [Poly::ZERO; K],
        yz: [Poly::ZERO; L],
        w: [Poly::ZERO; K],
        c_hat: Poly::ZERO,
        tmp: Poly::ZERO,
        ct0: Poly::ZERO,
        hints: [[0; N]; K],
        rho2: [0; 64],
    };
    for (i, s) in v.s1_hat.iter_mut().enumerate() {
        let o = layout.s1 + i * layout.s_len;
        unpack_offset(&sk[o..o + layout.s_len], eta, ebits, s);
        ntt(s);
    }
    for (i, s) in v.s2_hat.iter_mut().enumerate() {
        let o = layout.s2 + i * layout.s_len;
        unpack_offset(&sk[o..o + layout.s_len], eta, ebits, s);
        ntt(s);
    }
    for (i, t) in v.t0_hat.iter_mut().enumerate() {
        let o = layout.t0 + i * T0_LEN;
        unpack_offset(&sk[o..o + T0_LEN], T0_OFFSET, 13, t);
        ntt(t);
    }

    // A_hat <- ExpandA(rho) (Algorithm 32); public.
    let mut a_hat = [[Poly::ZERO; L]; K];
    for (r, row) in a_hat.iter_mut().enumerate() {
        for (s, a) in row.iter_mut().enumerate() {
            rej_ntt_poly(&rho, s as u8, r as u8, a);
        }
    }

    // rho'' <- H(K || rnd || mu, 64).
    let mut h = Shake256::new();
    h.update(&sk[32..64]);
    h.update(rnd);
    h.update(mu);
    h.finalize_xof().read(&mut v.rho2);

    // On the error path these hold a rejected iteration's values.
    let mut ctilde = Zeroizing([0u8; 64]);
    let ctilde = &mut ctilde.0[..ct_len];
    let mut w1_buf = Zeroizing([0u8; 192]);
    let w1_buf = &mut w1_buf.0[..w1_len::<P>()];
    let mut kappa = 0usize;
    loop {
        // IntegerToBytes(kappa + r, 2) must not wrap.
        if kappa + L > 1 << 16 {
            return Err(Error::InvalidKey);
        }
        // y <- ExpandMask(rho'', kappa) (Algorithm 34).
        for (r, y) in v.yz.iter_mut().enumerate() {
            expand_mask_poly(&v.rho2, (kappa + r) as u16, gamma1, zb, y);
        }
        kappa += L;

        // w <- NTT^-1(A_hat * NTT(y)), one column of A at a time.
        v.w = [Poly::ZERO; K];
        for (s, y) in v.yz.iter().enumerate() {
            v.tmp = *y;
            ntt(&mut v.tmp);
            for (w, row) in v.w.iter_mut().zip(a_hat.iter()) {
                pointwise_acc(w, &row[s], &v.tmp);
            }
        }
        // c~ <- H(mu || w1Encode(HighBits(w)), lambda / 4).
        let mut h = Shake256::new();
        h.update(mu);
        for w in v.w.iter_mut() {
            reduce(w);
            invntt_tomont(w);
            freeze_poly(w);
            for (o, &c) in v.tmp.0.iter_mut().zip(w.0.iter()) {
                *o = high_bits(c, gamma2);
            }
            pack_bits(&v.tmp, w1b, w1_buf);
            h.update(w1_buf);
        }
        h.finalize_xof().read(ctilde);

        // c <- SampleInBall(c~); c_hat <- NTT(c).
        sample_in_ball(ctilde, P::TAU, &mut v.c_hat);
        ntt(&mut v.c_hat);

        // z <- y + c s1; reject if ||z|| >= gamma1 - beta.
        let mut reject = 0i32;
        for (z, s1) in v.yz.iter_mut().zip(v.s1_hat.iter()) {
            pointwise(&mut v.tmp, &v.c_hat, s1);
            invntt_tomont(&mut v.tmp);
            for (c, &e) in z.0.iter_mut().zip(v.tmp.0.iter()) {
                *c = centre(*c + e);
            }
            reject |= norm_ge(z, z_bound);
        }

        // Per row of w: r0 <- LowBits(w - c s2), c t0, and the hint
        // h <- MakeHint(-c t0, w - c s2 + c t0).
        let mut count = 0i32;
        for r in 0..K {
            pointwise(&mut v.tmp, &v.c_hat, &v.s2_hat[r]);
            invntt_tomont(&mut v.tmp);
            pointwise(&mut v.ct0, &v.c_hat, &v.t0_hat[r]);
            invntt_tomont(&mut v.ct0);
            for i in 0..N {
                let ct0 = centre(v.ct0.0[i]);
                reject |= abs_ge(ct0, gamma2);
                let a = freeze(v.w[r].0[i] - v.tmp.0[i]);
                reject |= abs_ge(decompose(a, gamma2).1, gamma2 - beta);
                let b = freeze(a + ct0);
                let hint = make_hint(b, a, gamma2);
                // hint is 0 or 1.
                v.hints[r][i] = hint as u8;
                count += hint;
            }
        }
        reject |= (P::OMEGA as i32 - count) >> 31;

        // Only the accept/reject decision is revealed.
        if core::hint::black_box(reject) == 0 {
            break;
        }
    }

    // sigEncode(c~, z mod+- q, h) (Algorithm 26).
    sig[..ct_len].copy_from_slice(ctilde);
    for (i, z) in v.yz.iter().enumerate() {
        let o = z_off + i * z_len;
        pack_offset(z, gamma1, zb, &mut sig[o..o + z_len]);
    }
    hint_pack(&v.hints, P::OMEGA, &mut sig[h_off..]);
    Ok(())
}

/// `ML-DSA.Verify_internal` (Algorithm 8) given `mu = H(tr || M', 64)`.
/// `sig` must have the signature length. Public data only.
pub(crate) fn verify_mu<P: ParameterSet, const K: usize, const L: usize>(
    pk: &[u8],
    mu: &[u8; 64],
    sig: &[u8],
) -> bool {
    verify_mu_z_bound::<P, K, L>(pk, mu, sig, (P::GAMMA1 - P::BETA) as i32)
}

/// [`verify_mu`] with the acceptance bound on `||z||` as a parameter
/// (`||z|| < z_bound`, `gamma1 - beta` in FIPS 204), so that tests can show
/// that a boundary signature fails on the norm check alone.
pub(super) fn verify_mu_z_bound<P: ParameterSet, const K: usize, const L: usize>(
    pk: &[u8],
    mu: &[u8; 64],
    sig: &[u8],
    z_bound: i32,
) -> bool {
    let gamma1 = P::GAMMA1 as i32;
    let gamma2 = P::GAMMA2 as i32;
    let zb = z_bits::<P>();
    let w1b = w1_bits::<P>();
    let ct_len = ctilde_len::<P>();
    let (z_off, z_len, h_off) = sig_layout::<P>();
    if sig.len() != h_off + P::OMEGA + K {
        return false;
    }

    // sigDecode (Algorithm 27) with the strict hint checks, and
    // ||z|| < gamma1 - beta.
    let mut hints = [[0u8; N]; K];
    if !hint_unpack(&sig[h_off..], P::OMEGA, &mut hints) {
        return false;
    }
    let mut z_hat = [Poly::ZERO; L];
    for (i, z) in z_hat.iter_mut().enumerate() {
        let o = z_off + i * z_len;
        unpack_offset(&sig[o..o + z_len], gamma1, zb, z);
        if norm_ge(z, z_bound) != 0 {
            return false;
        }
        ntt(z);
    }

    let ctilde = &sig[..ct_len];
    let mut c_hat = Poly::ZERO;
    sample_in_ball(ctilde, P::TAU, &mut c_hat);
    ntt(&mut c_hat);

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut h = Shake256::new();
    h.update(mu);
    let mut a = Poly::ZERO;
    let mut t1 = Poly::ZERO;
    let mut w1_buf = [0u8; 192];
    let w1_buf = &mut w1_buf[..w1_len::<P>()];
    for (r, hint_row) in hints.iter().enumerate() {
        // w'_Approx <- NTT^-1(A_hat * NTT(z) - NTT(c) * NTT(t1 2^d)).
        let mut w = Poly::ZERO;
        for (s, z) in z_hat.iter().enumerate() {
            rej_ntt_poly(&rho, s as u8, r as u8, &mut a);
            pointwise_acc(&mut w, &a, z);
        }
        unpack_bits(&pk[32 + r * T1_LEN..32 + (r + 1) * T1_LEN], 10, &mut t1);
        for c in t1.0.iter_mut() {
            *c <<= D;
        }
        ntt(&mut t1);
        pointwise(&mut a, &c_hat, &t1);
        for (x, &y) in w.0.iter_mut().zip(a.0.iter()) {
            *x -= y;
        }
        reduce(&mut w);
        invntt_tomont(&mut w);
        // w1' <- UseHint(h, w'_Approx).
        for (c, &hb) in w.0.iter_mut().zip(hint_row.iter()) {
            *c = use_hint(hb != 0, freeze(*c), gamma2);
        }
        pack_bits(&w, w1b, w1_buf);
        h.update(w1_buf);
    }
    let mut ctilde2 = [0u8; 64];
    h.finalize_xof().read(&mut ctilde2[..ct_len]);
    crate::ct::eq(ctilde, &ctilde2[..ct_len])
}
