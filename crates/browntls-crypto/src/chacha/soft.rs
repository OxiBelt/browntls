//! Portable ChaCha20 (RFC 8439, IETF variant: 32-bit counter, 96-bit nonce).
//!
//! Only additions, XORs and fixed rotations are used, so the code is constant
//! time on every target.

use crate::zeroize::Zeroize;

/// "expand 32-byte k".
pub(super) const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Block size in bytes.
pub(super) const BLOCK: usize = 64;

#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Builds the initial state for block `counter`.
#[inline(always)]
pub(super) fn initial_state(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    [
        SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3], key[0], key[1], key[2], key[3], key[4], key[5],
        key[6], key[7], counter, nonce[0], nonce[1], nonce[2],
    ]
}

/// Computes one 64-byte keystream block.
#[inline]
pub(super) fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3], out: &mut [u8; BLOCK]) {
    let init = initial_state(key, counter, nonce);
    let mut x = init;
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    for ((o, w), i) in out.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(init) {
        *o = w.wrapping_add(i).to_le_bytes();
    }
    x.zeroize();
}

/// XORs `data` in place with the first `data.len()` bytes of `keystream`.
#[inline(always)]
pub(super) fn xor_in_place(data: &mut [u8], keystream: &[u8]) {
    debug_assert!(data.len() <= keystream.len());
    let (chunks, tail) = data.as_chunks_mut::<8>();
    let full = chunks.len() * 8;
    for (d, k) in chunks.iter_mut().zip(keystream.as_chunks::<8>().0) {
        *d = (u64::from_ne_bytes(*d) ^ u64::from_ne_bytes(*k)).to_ne_bytes();
    }
    for (d, k) in tail.iter_mut().zip(&keystream[full..]) {
        *d ^= k;
    }
}

/// XORs `data` with the keystream starting at block `counter`.
///
/// The block counter wraps modulo 2^32, consistently across all backends.
pub(super) fn xor(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let mut ks = [0u8; BLOCK];
    let mut ctr = counter;
    for chunk in data.chunks_mut(BLOCK) {
        block(key, ctr, nonce, &mut ks);
        xor_in_place(chunk, &ks);
        ctr = ctr.wrapping_add(1);
    }
    ks.zeroize();
}
