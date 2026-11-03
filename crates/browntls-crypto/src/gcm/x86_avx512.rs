//! x86-64 GHASH, and fused AES-GCM, with VPCLMULQDQ and VAES on ZMM
//! registers.
//!
//! GHASH runs in the POLYVAL representation of [`super::x86`] with four
//! blocks per register. Thirty-two blocks are multiplied by `H^32 .. H^1`
//! (schoolbook, four carry-less multiplications per register) and the
//! 256-bit products are summed across registers and lanes before a single
//! reduction. Shorter runs use the matching lower powers in exactly as many
//! registers as needed; their data is loaded with byte masks, which also
//! supplies the zero padding of a final partial block.
//!
//! [`seal`] and [`open`] fuse CTR mode and GHASH. Each iteration encrypts
//! 32 counter blocks in eight registers and, interleaved with the AES
//! rounds, multiplies 32 ciphertext blocks whose values are already
//! available: the previous group when sealing, the current input group when
//! opening. The carry-less multiplications therefore never wait on the AES
//! pipeline and both units run in parallel. Decryption writes plaintext as
//! it goes and the caller zeroes the buffer if the tag turns out to be
//! wrong.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::x86;
use crate::Error;
use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::aes::RoundKeys;
use crate::aes::x86_vaes512::{self as aes512, dispatch_regs};
use crate::cpu::{Features, features};
use crate::zeroize::zeroize_bytes;

/// Blocks per register.
const LANES: usize = 4;
/// Registers per group.
const REGS: usize = 8;
/// Blocks absorbed per reduction and encrypted per iteration.
const GROUP: usize = REGS * LANES;
const GROUP_BYTES: usize = GROUP * 16;

/// Returns whether the CPU can run this backend: AVX-512 F/BW/VL with OS
/// support for ZMM state, VPCLMULQDQ (which then covers the ZMM encoding)
/// and the XMM baseline the shared helpers rely on.
pub(crate) fn supported(f: Features) -> bool {
    f.x86_avx512() && f.x86_vpclmulqdq() && f.x86_avx2() && f.x86_pclmulqdq() && f.x86_sse41()
}

/// Precomputed powers of the hash key.
///
/// `h[i]` holds `H^(32 - i)` in POLYVAL form for `i < 32`; the last four
/// entries are zero so that any four consecutive entries starting below 32
/// can be loaded as one register (zero powers meet the zero padding of
/// short tails). A value can only be constructed by [`Key::new`], which
/// checks [`supported`]; this invariant makes the `#[target_feature]` calls
/// sound.
#[repr(C, align(64))]
pub(crate) struct Key {
    h: [[u8; 16]; GROUP + LANES],
}

impl Drop for Key {
    fn drop(&mut self) {
        for b in &mut self.h {
            zeroize_bytes(b);
        }
    }
}

impl Key {
    /// Precomputes the key powers from the GCM hash subkey `h`.
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        assert!(
            supported(features()),
            "AVX-512 VPCLMULQDQ backend selected without CPU support"
        );
        let h1 = super::polyval_key(h);
        // SAFETY: PCLMULQDQ and SSE4.1 support was just verified.
        unsafe { powers_impl(&h1) }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        // SAFETY: `Key::new` verified AVX-512 F/BW/VL, VPCLMULQDQ, AVX2,
        // PCLMULQDQ and SSE4.1 support.
        unsafe { update_impl(self, y, blocks) }
    }

    /// The powers `H^n .. H^1` (then zeros) for a run of `n <= 32` blocks,
    /// as whole registers.
    #[inline]
    fn powers(&self, n: usize) -> &[[[u8; 16]; LANES]] {
        self.h[GROUP - n..].as_chunks::<LANES>().0
    }
}

#[target_feature(enable = "pclmulqdq,sse4.1")]
fn powers_impl(h1: &[u8; 16]) -> Key {
    let h1v = x86::load(h1);
    let mut key = Key {
        h: [[0; 16]; GROUP + LANES],
    };
    let mut p = h1v;
    x86::store(&mut key.h[GROUP - 1], p);
    for i in (0..GROUP - 1).rev() {
        p = x86::mul(p, h1v);
        x86::store(&mut key.h[i], p);
    }
    key
}

/// Adds the four 256-bit products `x[lane] * h[lane]` to the schoolbook
/// accumulators `(lo, mid, hi)`.
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f")]
fn mul_acc(x: __m512i, h: __m512i, sum: &mut [__m512i; 3]) {
    sum[0] = _mm512_xor_si512(sum[0], _mm512_clmulepi64_epi128(x, h, 0x00));
    // Three-way XOR in one instruction (truth table 0x96).
    sum[1] = _mm512_ternarylogic_epi64(
        sum[1],
        _mm512_clmulepi64_epi128(x, h, 0x01),
        _mm512_clmulepi64_epi128(x, h, 0x10),
        0x96,
    );
    sum[2] = _mm512_xor_si512(sum[2], _mm512_clmulepi64_epi128(x, h, 0x11));
}

/// Multiplies register `j` of `x` (blocks byte-reversed, accumulator added
/// to the first) by the powers `h[j]` and returns the summed unreduced
/// products.
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f")]
fn mul_regs<const N: usize>(h: &[[[u8; 16]; LANES]], x: &[__m512i; N]) -> [__m512i; 3] {
    let mut sum = [_mm512_setzero_si512(); 3];
    for (x, h) in x.iter().zip(h) {
        mul_acc(*x, aes512::load(h), &mut sum);
    }
    sum
}

/// XORs the four lanes together.
#[inline]
#[target_feature(enable = "avx512f,avx2")]
fn fold(v: __m512i) -> __m128i {
    let y = _mm256_xor_si256(_mm512_castsi512_si256(v), _mm512_extracti64x4_epi64(v, 1));
    _mm_xor_si128(_mm256_castsi256_si128(y), _mm256_extracti128_si256(y, 1))
}

/// Folds the middle products into the outer ones and the lanes together,
/// then reduces the 256-bit sum.
#[inline]
#[target_feature(enable = "avx512f,avx512bw,avx2,pclmulqdq")]
fn reduce(sum: [__m512i; 3]) -> __m128i {
    let [lo, mid, hi] = sum;
    let lo = _mm512_xor_si512(lo, _mm512_bslli_epi128(mid, 8));
    let hi = _mm512_xor_si512(hi, _mm512_bsrli_epi128(mid, 8));
    x86::reduce_product(fold(lo), _mm_setzero_si128(), fold(hi))
}

/// Byte-reverses every block of `v`.
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
fn reverse(v: __m512i, swap: __m512i) -> __m512i {
    _mm512_shuffle_epi8(v, swap)
}

/// Absorbs `data` (1 to 511 bytes, a final partial block zero padded) into
/// `acc` using exactly `N` registers (`64 * (N - 1) < data.len() <= 64 * N`).
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq")]
fn absorb_tail<const N: usize>(key: &Key, swap: __m512i, acc: __m128i, data: &[u8]) -> __m128i {
    debug_assert_eq!(data.len().div_ceil(64), N);
    let mut x = [_mm512_setzero_si512(); N];
    for (x, chunk) in x.iter_mut().zip(data.chunks(64)) {
        *x = reverse(aes512::load_partial(chunk), swap);
    }
    x[0] = _mm512_xor_si512(x[0], _mm512_zextsi128_si512(acc));
    reduce(mul_regs(key.powers(data.len().div_ceil(16)), &x))
}

/// Absorbs one whole group of 32 blocks into `acc`.
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq")]
fn absorb_group(key: &Key, swap: __m512i, acc: __m128i, g: &[u8; GROUP_BYTES]) -> __m128i {
    let quads = g.as_chunks::<16>().0.as_chunks::<LANES>().0;
    let mut x: [__m512i; REGS] = core::array::from_fn(|i| reverse(aes512::load(&quads[i]), swap));
    x[0] = _mm512_xor_si512(x[0], _mm512_zextsi128_si512(acc));
    reduce(mul_regs(key.powers(GROUP), &x))
}

/// Absorbs `data` of any length (a final partial block is zero padded) into
/// `acc`.
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq")]
fn absorb(key: &Key, swap: __m512i, mut acc: __m128i, data: &[u8]) -> __m128i {
    let (groups, tail) = data.as_chunks::<GROUP_BYTES>();
    for g in groups {
        acc = absorb_group(key, swap, acc, g);
    }
    let regs = tail.len().div_ceil(64);
    if regs > 0 {
        acc = dispatch_regs!(regs, absorb_tail(key, swap, acc, tail));
    }
    acc
}

#[target_feature(enable = "vpclmulqdq,avx512f,avx512bw,avx512vl,avx2,pclmulqdq,sse4.1")]
fn update_impl(key: &Key, y: &mut [u8; 16], blocks: &[u8]) {
    let swap128 = x86::bswap_mask();
    let swap = _mm512_broadcast_i32x4(swap128);
    let acc = _mm_shuffle_epi8(x86::load(y), swap128);
    let acc = absorb(key, swap, acc, blocks);
    x86::store(y, _mm_shuffle_epi8(acc, swap128));
}

/// Encrypts `in_out` in place under `nonce`, authenticating `aad` and the
/// ciphertext, and returns the tag.
pub(crate) fn seal(
    aes: &aes512::Key,
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
) -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    // SAFETY: `aes512::Key::new` verified AVX-512 F/BW/VL, VAES, AVX2, AES-NI
    // and SSE4.1; `Key::new` verified VPCLMULQDQ and PCLMULQDQ.
    unsafe { gcm_impl::<false>(aes.round_keys(), key, nonce, aad, in_out, &mut tag) }
    tag
}

/// Decrypts `in_out` in place under `nonce` and verifies `tag` over `aad`
/// and the ciphertext. The buffer is zeroed on failure.
pub(crate) fn open(
    aes: &aes512::Key,
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    let mut expected = [0u8; TAG_LEN];
    // SAFETY: `aes512::Key::new` verified AVX-512 F/BW/VL, VAES, AVX2, AES-NI
    // and SSE4.1; `Key::new` verified VPCLMULQDQ and PCLMULQDQ.
    unsafe { gcm_impl::<true>(aes.round_keys(), key, nonce, aad, in_out, &mut expected) }
    let ok = crate::ct::eq(&expected, tag);
    zeroize_bytes(&mut expected);
    if !ok {
        zeroize_bytes(in_out);
        return Err(Error::DecryptFailed);
    }
    Ok(())
}

/// Per-call state of the fused loop: the broadcast round keys, the counter
/// generator and the byte-swap controls.
struct Fused<'a> {
    keys: [__m512i; 15],
    nr: usize,
    ctr: aes512::Counter,
    key: &'a Key,
    swap: __m512i,
    swap128: __m128i,
}

impl Fused<'_> {
    /// One fused iteration: encrypts the 32 counter blocks for `cur`,
    /// applies them, and meanwhile multiplies 32 blocks of ciphertext into
    /// `acc`: the input of `cur` when decrypting, otherwise `prev` (the
    /// previous group's output) when there is one.
    #[inline]
    #[target_feature(enable = "vaes,vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq")]
    fn group<const DECRYPT: bool>(
        &mut self,
        acc: __m128i,
        cur: &mut [u8; GROUP_BYTES],
        prev: Option<&[u8; GROUP_BYTES]>,
    ) -> __m128i {
        let quads = cur.as_chunks_mut::<16>().0.as_chunks_mut::<LANES>().0;
        let prev = prev.map(|p| p.as_chunks::<16>().0.as_chunks::<LANES>().0);
        let hashing = DECRYPT || prev.is_some();
        let powers = self.key.powers(GROUP);
        let nr = self.nr;

        let input: [__m512i; REGS] = core::array::from_fn(|j| aes512::load(&quads[j]));
        let mut b: [__m512i; REGS] = core::array::from_fn(|_| self.ctr.next());
        let mut sum = [_mm512_setzero_si512(); 3];
        let mut carry = _mm512_zextsi128_si512(acc);
        // AES-128 has nine middle rounds and AES-256 thirteen, so the eight
        // register multiplications fit in the first eight of them.
        for (r, k) in self.keys[1..nr].iter().enumerate() {
            for x in b.iter_mut() {
                *x = _mm512_aesenc_epi128(*x, *k);
            }
            if hashing && r < REGS {
                let src = if DECRYPT {
                    input[r]
                } else {
                    match prev {
                        Some(p) => aes512::load(&p[r]),
                        None => _mm512_setzero_si512(),
                    }
                };
                let x = _mm512_xor_si512(reverse(src, self.swap), carry);
                carry = _mm512_setzero_si512();
                mul_acc(x, aes512::load(&powers[r]), &mut sum);
            }
        }
        for ((quad, x), input) in quads.iter_mut().zip(b).zip(input) {
            let output = _mm512_xor_si512(input, _mm512_aesenclast_epi128(x, self.keys[nr]));
            aes512::store(quad, output);
        }
        if hashing { reduce(sum) } else { acc }
    }

    /// CTR over a tail of 1 to 511 bytes in exactly `N` registers
    /// (`64 * (N - 1) < data.len() <= 64 * N`), returning the unreduced
    /// products of its ciphertext blocks (register `j` by `powers[j]`), with
    /// `carry` added to the first block.
    #[inline]
    #[target_feature(enable = "vaes,vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq")]
    fn tail<const N: usize, const DECRYPT: bool>(
        &mut self,
        powers: &[[[u8; 16]; LANES]],
        carry: __m512i,
        data: &mut [u8],
    ) -> [__m512i; 3] {
        debug_assert_eq!(data.len().div_ceil(64), N);
        let ks = self.ctr.keystream::<N>(&self.keys, self.nr);
        let mut x = [_mm512_setzero_si512(); N];
        for ((chunk, k), x) in data.chunks_mut(64).zip(ks).zip(x.iter_mut()) {
            let input = aes512::load_partial(chunk);
            let output = _mm512_xor_si512(input, k);
            aes512::store_partial(chunk, output);
            let ct = if DECRYPT {
                input
            } else {
                // Drop the keystream beyond the end of the data.
                _mm512_maskz_mov_epi8(aes512::byte_mask(chunk.len()), output)
            };
            *x = reverse(ct, self.swap);
        }
        x[0] = _mm512_xor_si512(x[0], carry);
        mul_regs(powers, &x)
    }

    /// The GHASH lengths block, byte-reversed, in lane 0.
    #[inline]
    #[target_feature(enable = "avx512f,ssse3")]
    fn lengths_block(&self, aad: &[u8], ct: &[u8]) -> __m512i {
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
        lengths[8..].copy_from_slice(&((ct.len() as u64) << 3).to_be_bytes());
        _mm512_zextsi128_si512(_mm_shuffle_epi8(x86::load(&lengths), self.swap128))
    }

    /// Short messages: the padded AAD (at most one register), the padded
    /// ciphertext and the lengths block form one run of at most 32 blocks,
    /// so a single aggregated multiplication and reduction yields the hash.
    #[inline]
    #[target_feature(enable = "vaes,vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq,ssse3")]
    fn short<const DECRYPT: bool>(&mut self, aad: &[u8], in_out: &mut [u8]) -> __m128i {
        let a = aad.len().div_ceil(16);
        let c = in_out.len().div_ceil(16);
        let n = a + c + 1;
        debug_assert!(a <= LANES && n <= GROUP);
        let key = self.key;
        let mut sum = [_mm512_setzero_si512(); 3];
        if a > 0 {
            // AAD blocks at positions 0..a: powers H^n .. H^(n - a + 1).
            let x = reverse(aes512::load_partial(aad), self.swap);
            mul_acc(x, aes512::load(&key.powers(n)[0]), &mut sum);
        }
        if c > 0 {
            // Ciphertext blocks at positions a..a+c: powers from H^(c + 1).
            let regs = c.div_ceil(LANES);
            let zero = _mm512_setzero_si512();
            let powers = key.powers(c + 1);
            let s = dispatch_regs!(regs, Self::tail::<DECRYPT>(self, powers, zero, in_out));
            for (sum, s) in sum.iter_mut().zip(s) {
                *sum = _mm512_xor_si512(*sum, s);
            }
        }
        // The lengths block at position n - 1: power H^1.
        mul_acc(
            self.lengths_block(aad, in_out),
            aes512::load(&key.powers(1)[0]),
            &mut sum,
        );
        reduce(sum)
    }

    /// General messages: the AAD, then the groups (software pipelined),
    /// then the tail together with the lengths block.
    #[inline]
    #[target_feature(enable = "vaes,vpclmulqdq,avx512f,avx512bw,avx2,pclmulqdq,ssse3")]
    fn long<const DECRYPT: bool>(&mut self, aad: &[u8], in_out: &mut [u8]) -> __m128i {
        let key = self.key;
        let mut acc = absorb(key, self.swap, _mm_setzero_si128(), aad);
        let lengths = self.lengths_block(aad, in_out);
        let (groups, tail) = in_out.as_chunks_mut::<GROUP_BYTES>();
        for i in 0..groups.len() {
            let (before, rest) = groups.split_at_mut(i);
            let prev = if DECRYPT { None } else { before.last() };
            acc = self.group::<DECRYPT>(acc, &mut rest[0], prev);
        }
        if !DECRYPT && let Some(last) = groups.last() {
            acc = absorb_group(key, self.swap, acc, last);
        }
        // A tail holds up to 32 blocks (31 whole ones and a partial one).
        let t = tail.len().div_ceil(16);
        let regs = t.div_ceil(LANES);
        let carry = _mm512_zextsi128_si512(acc);
        if t > 0 && t < GROUP {
            // The tail blocks and the lengths block form one run of t + 1
            // blocks, reduced together.
            let powers = key.powers(t + 1);
            let mut sum = dispatch_regs!(regs, Self::tail::<DECRYPT>(self, powers, carry, tail));
            mul_acc(lengths, aes512::load(&key.powers(1)[0]), &mut sum);
            reduce(sum)
        } else {
            if t > 0 {
                let powers = key.powers(t);
                acc = reduce(dispatch_regs!(
                    regs,
                    Self::tail::<DECRYPT>(self, powers, carry, tail)
                ));
            }
            x86::mul(
                _mm_xor_si128(acc, _mm512_castsi512_si128(lengths)),
                x86::load(&key.h[GROUP - 1]),
            )
        }
    }
}

#[target_feature(enable = "vaes,vpclmulqdq,avx512f,avx512bw,avx512vl,avx2,aes,pclmulqdq,sse4.1")]
fn gcm_impl<const DECRYPT: bool>(
    rk: &RoundKeys,
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) {
    let keys = aes512::load_keys(rk);
    let nr = rk.rounds;
    let swap128 = x86::bswap_mask();

    // E(J0) in lane 0 (the other lanes encrypt round key 0 and are dropped);
    // issued first so that it overlaps with the work below.
    let j0 = super::j0(nonce);
    let mut e = [_mm512_xor_si512(
        _mm512_zextsi128_si512(x86::load(&j0)),
        keys[0],
    )];
    aes512::rounds(&keys, nr, &mut e);
    let ej0 = _mm512_castsi512_si128(e[0]);

    let mut first = j0;
    super::inc32(&mut first);
    let mut fused = Fused {
        ctr: aes512::Counter::new(&first, keys[0]),
        keys,
        nr,
        key,
        swap: _mm512_broadcast_i32x4(swap128),
        swap128,
    };
    let short = aad.len() <= 64 && aad.len().div_ceil(16) + in_out.len().div_ceil(16) < GROUP;
    let acc = if short {
        fused.short::<DECRYPT>(aad, in_out)
    } else {
        fused.long::<DECRYPT>(aad, in_out)
    };
    x86::store(tag, _mm_xor_si128(ej0, _mm_shuffle_epi8(acc, swap128)));
}
