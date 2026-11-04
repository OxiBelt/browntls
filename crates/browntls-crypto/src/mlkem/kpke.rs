//! K-PKE (FIPS 203 §5) and the SHAKE-based samplers.
//!
//! Matrix expansion and noise sampling run up to four XOF/PRF instances in
//! lock step with the batched [`Shake128x4`] / [`Shake256x4`]
//! ([`sample_ntt_lanes`], [`sample_cbd_lanes`]). A batch with a single
//! instance uses the single-lane SHAKE; batches of two or three fill the
//! unused lanes with copies of the first input and discard their output.

use super::backend::Engine;
use super::poly::{self, N, Poly, PolyVec};
use crate::hash::{HashFunction, Sha3_512, Shake128, Shake128x4, Shake256, Shake256x4};
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
/// Initial squeeze: three blocks yield 336 candidates; 256 are needed
/// (acceptance ~81%), so more blocks are rarely required.
const SAMPLE_NTT_INITIAL: usize = 3 * SHAKE128_RATE;

/// Expands `Â` (`transposed == false`) or `Âᵀ` from `rho` (FIPS 203
/// Algorithm 13 lines 3-7 / Algorithm 14 lines 4-8), four entries at a time.
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

/// XOF input `rho || j || i` for `Â[i][j]`; the transpose swaps the two
/// index bytes.
fn xof_seed(rho: &[u8; 32], (i, j): (usize, usize), transposed: bool) -> [u8; 34] {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    let (x, y) = if transposed { (i, j) } else { (j, i) };
    seed[32] = x as u8;
    seed[33] = y as u8;
    seed
}

/// Runs one to four SampleNTT instances (FIPS 203 Algorithm 7) for the
/// matrix entries `lanes`. Public data.
fn sample_ntt_lanes(
    e: Engine,
    rho: &[u8; 32],
    lanes: &[(usize, usize)],
    transposed: bool,
    a: &mut Matrix,
) {
    if let [(i, j)] = *lanes {
        let mut xof = Shake128::new();
        xof.update(&xof_seed(rho, (i, j), transposed));
        let mut rd = xof.finalize_xof();
        let out = &mut a[i][j].0;
        let mut buf = [0u8; SAMPLE_NTT_INITIAL];
        rd.read_blocks(&mut buf);
        let mut ctr = e.rej_uniform(out, 0, &buf);
        while ctr < N {
            let blk = &mut buf[..SHAKE128_RATE];
            rd.read_blocks(blk);
            ctr = e.rej_uniform(out, ctr, blk);
        }
        return;
    }
    let Some(&first) = lanes.first() else {
        return;
    };
    let lane = |l: usize| lanes.get(l).copied().unwrap_or(first);
    let seeds: [[u8; 34]; 4] = core::array::from_fn(|l| xof_seed(rho, lane(l), transposed));
    let mut xof = Shake128x4::new([&seeds[0], &seeds[1], &seeds[2], &seeds[3]]);
    let mut buf = [[0u8; SAMPLE_NTT_INITIAL]; 4];
    xof.squeeze(&mut buf);
    let mut ctr = [0usize; 4];
    for (l, &(i, j)) in lanes.iter().enumerate() {
        ctr[l] = e.rej_uniform(&mut a[i][j].0, 0, &buf[l]);
    }
    let mut blk = [[0u8; SHAKE128_RATE]; 4];
    while ctr[..lanes.len()].iter().any(|&c| c < N) {
        xof.squeeze_blocks(&mut blk);
        for (l, &(i, j)) in lanes.iter().enumerate() {
            if ctr[l] < N {
                ctr[l] = e.rej_uniform(&mut a[i][j].0, ctr[l], &blk[l]);
            }
        }
    }
}

/// Noise parameter per nonce: `eta_lo` for nonces below `split`, `eta_hi`
/// from there on.
#[derive(Clone, Copy)]
struct EtaSchedule {
    split: usize,
    eta_lo: usize,
    eta_hi: usize,
}

impl EtaSchedule {
    fn eta(self, nonce: usize) -> usize {
        if nonce < self.split {
            self.eta_lo
        } else {
            self.eta_hi
        }
    }
}

/// `out[i] = SamplePolyCBD_eta(i)(PRF_eta(i)(seed, i))` for every `i`
/// (FIPS 203 Algorithm 8 with PRF = SHAKE256), four nonces at a time.
fn sample_cbd(seed: &[u8; 32], etas: EtaSchedule, out: &mut [Poly]) {
    for (c, chunk) in out.chunks_mut(4).enumerate() {
        sample_cbd_lanes(seed, etas, 4 * c, chunk);
    }
}

/// One to four PRF + CBD instances with consecutive nonces from `nonce0`.
fn sample_cbd_lanes(seed: &[u8; 32], etas: EtaSchedule, nonce0: usize, out: &mut [Poly]) {
    if let [p] = out {
        let eta = etas.eta(nonce0);
        let mut buf = [0u8; 192];
        let mut prf = Shake256::new();
        prf.update(seed);
        prf.update(&[nonce0 as u8]);
        prf.finalize_xof().read(&mut buf[..64 * eta]);
        poly::cbd(p, eta, &buf);
        buf.zeroize();
        return;
    }
    let n = out.len();
    let mut inputs = [[0u8; 33]; 4];
    for (l, input) in inputs.iter_mut().enumerate() {
        input[..32].copy_from_slice(seed);
        input[32] = (nonce0 + l.min(n.saturating_sub(1))) as u8;
    }
    let mut prf = Shake256x4::new([&inputs[0], &inputs[1], &inputs[2], &inputs[3]]);
    inputs.as_flattened_mut().zeroize();
    if (0..n).all(|l| etas.eta(nonce0 + l) == 2) {
        // One permutation per batch: 128 bytes fit in the 136-byte rate.
        let mut buf = [[0u8; 128]; 4];
        prf.squeeze(&mut buf);
        for (p, b) in out.iter_mut().zip(&buf) {
            poly::cbd(p, 2, b);
        }
        buf.as_flattened_mut().zeroize();
    } else {
        let mut buf = [[0u8; 192]; 4];
        prf.squeeze(&mut buf);
        for (l, (p, b)) in out.iter_mut().zip(&buf).enumerate() {
            poly::cbd(p, etas.eta(nonce0 + l), b);
        }
        buf.as_flattened_mut().zeroize();
    }
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

    // s (nonces 0..k) and e (nonces k..2k), all with eta_1.
    let mut noise = [Poly::ZERO; 8];
    let all_eta1 = EtaSchedule {
        split: 2 * k,
        eta_lo: p.eta1,
        eta_hi: p.eta1,
    };
    sample_cbd(&sigma, all_eta1, &mut noise[..2 * k]);
    sigma.zeroize();
    s_hat[..k].copy_from_slice(&noise[..k]);
    let mut err = [Poly::ZERO; 4];
    err[..k].copy_from_slice(&noise[k..2 * k]);
    for x in noise.iter_mut() {
        x.zeroize();
    }
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

    // y (nonces 0..k, eta_1), e1 (k..2k, eta_2) and e2 (2k, eta_2).
    let mut noise = [Poly::ZERO; 9];
    let etas = EtaSchedule {
        split: k,
        eta_lo: p.eta1,
        eta_hi: p.eta2,
    };
    sample_cbd(r, etas, &mut noise[..2 * k + 1]);
    let (y, rest) = noise.split_at_mut(k);
    let (e1, rest) = rest.split_at_mut(k);
    let e2 = &rest[0];
    for yi in y.iter_mut() {
        e.ntt(yi);
    }

    let mut u = Poly::ZERO;
    let (c1, c2) = ct.split_at_mut(p.c1_len());
    let ulen = 32 * p.du as usize;
    for i in 0..k {
        e.basemul_acc(&mut u, &at[i][..k], y);
        e.invntt(&mut u);
        poly::add_assign(&mut u, &e1[i]);
        e.reduce(&mut u);
        poly::compress_encode(&u, p.du, &mut c1[ulen * i..ulen * (i + 1)]);
    }

    let mut v = Poly::ZERO;
    let mut mu = Poly::ZERO;
    e.basemul_acc(&mut v, &t_hat[..k], y);
    e.invntt(&mut v);
    poly::add_assign(&mut v, e2);
    poly::from_msg(m, &mut mu);
    poly::add_assign(&mut v, &mu);
    e.reduce(&mut v);
    poly::compress_encode(&v, p.dv, c2);

    for x in noise.iter_mut() {
        x.zeroize();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::backend::Backend;

    /// Batched sampling (partial and full batches) equals one lane at a time.
    #[test]
    fn batched_sampling_matches_single_lane() {
        let rho: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        for b in Backend::available() {
            let e = Engine::new(b).unwrap();
            for transposed in [false, true] {
                let mut single = [[Poly::ZERO; 4]; 4];
                for i in 0..4 {
                    for j in 0..4 {
                        sample_ntt_lanes(e, &rho, &[(i, j)], transposed, &mut single);
                    }
                }
                for width in 2..=4 {
                    let mut batched = [[Poly::ZERO; 4]; 4];
                    let jobs: std::vec::Vec<_> = (0..16).map(|n| (n / 4, n % 4)).collect();
                    for group in jobs.chunks(width) {
                        sample_ntt_lanes(e, &rho, group, transposed, &mut batched);
                    }
                    assert_eq!(batched, single, "{b:?} width {width}");
                }
            }
        }
        for (eta_lo, eta_hi, split) in [(2, 2, 9), (3, 2, 2), (3, 3, 9), (2, 3, 1)] {
            let etas = EtaSchedule {
                split,
                eta_lo,
                eta_hi,
            };
            let mut single = [Poly::ZERO; 9];
            for (n, p) in single.iter_mut().enumerate() {
                sample_cbd_lanes(&rho, etas, n, core::slice::from_mut(p));
            }
            for width in 2..=4 {
                let mut batched = [Poly::ZERO; 9];
                for (c, chunk) in batched.chunks_mut(width).enumerate() {
                    sample_cbd_lanes(&rho, etas, c * width, chunk);
                }
                assert_eq!(batched, single, "width {width}");
            }
            let mut via = [Poly::ZERO; 9];
            sample_cbd(&rho, etas, &mut via);
            assert_eq!(via, single);
        }
    }
}
