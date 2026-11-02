//! K-PKE (FIPS 203 §5) and the SHAKE-based samplers.
//!
//! Matrix expansion and noise sampling are each funnelled through a single
//! function ([`sample_ntt_lanes`], [`sample_cbd_lanes`]) that receives up to
//! four independent XOF/PRF instances at once, so that a 4-way batched
//! Keccak can be plugged in at one call site. Today each lane runs on the
//! single-lane SHAKE implementation from [`crate::hash`].

use super::backend::Engine;
use super::poly::{self, N, Poly, PolyVec};
use crate::hash::{HashFunction, Sha3_512, Shake128, Shake256};
use crate::zeroize::Zeroize;

/// Run-time view of a parameter set.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Params {
    pub(crate) k: usize,
    pub(crate) eta1: usize,
    pub(crate) eta2: usize,
    pub(crate) du: u32,
    pub(crate) dv: u32,
}

impl Params {
    /// Length of the `u` part of a ciphertext.
    pub(crate) const fn c1_len(self) -> usize {
        32 * self.du as usize * self.k
    }

    /// Ciphertext length.
    pub(crate) const fn ct_len(self) -> usize {
        self.c1_len() + 32 * self.dv as usize
    }
}

/// `k x k` NTT-domain matrix (row-major, only the leading `k x k` used).
type Matrix = [[Poly; 4]; 4];

const SHAKE128_RATE: usize = 168;

/// Expands `Â` (`transposed == false`) or `Âᵀ` from `rho` (FIPS 203
/// Algorithm 13 lines 3-7 / Algorithm 14 lines 4-8).
fn expand_matrix(e: Engine, rho: &[u8; 32], k: usize, transposed: bool, a: &mut Matrix) {
    let mut jobs = [(0usize, 0usize); 16];
    let mut n = 0;
    for i in 0..k {
        for j in 0..k {
            jobs[n] = (i, j);
            n += 1;
        }
    }
    for group in jobs[..n].chunks(4) {
        sample_ntt_lanes(e, rho, group, transposed, a);
    }
}

/// Runs up to four SampleNTT instances (FIPS 203 Algorithm 7):
/// `Â[i][j] = SampleNTT(rho || j || i)`; the transpose swaps the two index
/// bytes. This is the single call site for a future 4-way SHAKE128.
fn sample_ntt_lanes(
    e: Engine,
    rho: &[u8; 32],
    lanes: &[(usize, usize)],
    transposed: bool,
    a: &mut Matrix,
) {
    for &(i, j) in lanes {
        let mut seed = [0u8; 34];
        seed[..32].copy_from_slice(rho);
        let (x, y) = if transposed { (i, j) } else { (j, i) };
        seed[32] = x as u8;
        seed[33] = y as u8;
        sample_ntt(e, &seed, &mut a[i][j]);
    }
}

fn sample_ntt(e: Engine, seed: &[u8; 34], out: &mut Poly) {
    let mut xof = Shake128::new();
    xof.update(seed);
    let mut rd = xof.finalize_xof();
    // Three blocks yield 336 candidates; 256 are needed (acceptance ~81%).
    let mut buf = [0u8; 3 * SHAKE128_RATE];
    rd.read_blocks(&mut buf);
    let mut ctr = e.rej_uniform(&mut out.0, 0, &buf);
    while ctr < N {
        let blk = &mut buf[..SHAKE128_RATE];
        rd.read_blocks(blk);
        ctr = e.rej_uniform(&mut out.0, ctr, blk);
    }
}

/// `out[i] = SamplePolyCBD_eta(PRF_eta(seed, nonce0 + i))` for every `i`
/// (FIPS 203 Algorithm 8 with PRF = SHAKE256).
fn sample_cbd(seed: &[u8; 32], eta: usize, nonce0: usize, out: &mut [Poly]) {
    for (c, chunk) in out.chunks_mut(4).enumerate() {
        sample_cbd_lanes(seed, eta, nonce0 + 4 * c, chunk);
    }
}

/// Up to four PRF + CBD instances with consecutive nonces. This is the single
/// call site for a future 4-way SHAKE256.
fn sample_cbd_lanes(seed: &[u8; 32], eta: usize, nonce0: usize, out: &mut [Poly]) {
    let mut buf = [0u8; 192];
    for (i, p) in out.iter_mut().enumerate() {
        let mut prf = Shake256::new();
        prf.update(seed);
        prf.update(&[(nonce0 + i) as u8]);
        prf.finalize_xof().read(&mut buf[..64 * eta]);
        if eta == 2 {
            let mut b = [0u8; 128];
            b.copy_from_slice(&buf[..128]);
            poly::cbd2(p, &b);
            b.zeroize();
        } else {
            poly::cbd3(p, &buf);
        }
    }
    buf.zeroize();
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13): returns `t̂` (reduced, centred),
/// `ŝ` (reduced, centred) and `rho`.
pub(crate) fn keygen(
    e: Engine,
    p: Params,
    d: &[u8; 32],
    t_hat: &mut PolyVec,
    s_hat: &mut PolyVec,
    rho: &mut [u8; 32],
) {
    let k = p.k;
    let mut g = Sha3_512::new();
    g.update(d);
    g.update(&[k as u8]);
    let mut rs = g.finalize();
    rho.copy_from_slice(&rs[..32]);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&rs[32..]);
    rs.zeroize();

    let mut a = [[Poly::ZERO; 4]; 4];
    expand_matrix(e, rho, k, false, &mut a);

    let mut err = [Poly::ZERO; 4];
    sample_cbd(&sigma, p.eta1, 0, &mut s_hat[..k]);
    sample_cbd(&sigma, p.eta1, k, &mut err[..k]);
    sigma.zeroize();
    for i in 0..k {
        e.ntt(&mut s_hat[i]);
        e.ntt(&mut err[i]);
    }
    for i in 0..k {
        e.basemul_acc(&mut t_hat[i], &a[i][..k], &s_hat[..k]);
        e.tomont(&mut t_hat[i]);
        poly::add_assign(&mut t_hat[i], &err[i]);
        e.reduce(&mut t_hat[i]);
    }
    poly::zeroize_vec(&mut err);
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14) into `ct` (`p.ct_len()` bytes).
/// `t_hat` coefficients must satisfy `|x| < q`.
pub(crate) fn encrypt(
    e: Engine,
    p: Params,
    t_hat: &PolyVec,
    rho: &[u8; 32],
    m: &[u8; 32],
    r: &[u8; 32],
    ct: &mut [u8],
) {
    let k = p.k;
    let mut at = [[Poly::ZERO; 4]; 4];
    expand_matrix(e, rho, k, true, &mut at);

    let mut y = [Poly::ZERO; 4];
    let mut e1 = [Poly::ZERO; 4];
    let mut e2 = [Poly::ZERO; 1];
    sample_cbd(r, p.eta1, 0, &mut y[..k]);
    sample_cbd(r, p.eta2, k, &mut e1[..k]);
    sample_cbd(r, p.eta2, 2 * k, &mut e2);
    for yi in y[..k].iter_mut() {
        e.ntt(yi);
    }

    let mut u = Poly::ZERO;
    let (c1, c2) = ct.split_at_mut(p.c1_len());
    let ulen = 32 * p.du as usize;
    for i in 0..k {
        e.basemul_acc(&mut u, &at[i][..k], &y[..k]);
        e.invntt(&mut u);
        poly::add_assign(&mut u, &e1[i]);
        e.reduce(&mut u);
        poly::compress_encode(&u, p.du, &mut c1[ulen * i..ulen * (i + 1)]);
    }

    let mut v = Poly::ZERO;
    let mut mu = Poly::ZERO;
    e.basemul_acc(&mut v, &t_hat[..k], &y[..k]);
    e.invntt(&mut v);
    poly::add_assign(&mut v, &e2[0]);
    poly::from_msg(m, &mut mu);
    poly::add_assign(&mut v, &mu);
    e.reduce(&mut v);
    poly::compress_encode(&v, p.dv, c2);

    poly::zeroize_vec(&mut y);
    poly::zeroize_vec(&mut e1);
    e2[0].zeroize();
    u.zeroize();
    v.zeroize();
    mu.zeroize();
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15). `ct` must be `p.ct_len()` bytes.
pub(crate) fn decrypt(e: Engine, p: Params, s_hat: &PolyVec, ct: &[u8], m: &mut [u8; 32]) {
    let k = p.k;
    let (c1, c2) = ct.split_at(p.c1_len());
    let ulen = 32 * p.du as usize;
    let mut u = [Poly::ZERO; 4];
    for (i, ui) in u[..k].iter_mut().enumerate() {
        poly::decode_decompress(&c1[ulen * i..ulen * (i + 1)], p.du, ui);
        e.ntt(ui);
    }
    let mut v = Poly::ZERO;
    poly::decode_decompress(c2, p.dv, &mut v);

    let mut w = Poly::ZERO;
    e.basemul_acc(&mut w, &s_hat[..k], &u[..k]);
    e.invntt(&mut w);
    poly::rsub_assign(&mut w, &v);
    e.reduce(&mut w);
    poly::to_msg(&w, m);

    poly::zeroize_vec(&mut u);
    v.zeroize();
    w.zeroize();
}
