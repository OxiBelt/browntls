//! Portable constant-time AES encryption and decryption.
//!
//! A 64-bit bitsliced implementation that processes four blocks in parallel,
//! following the construction of BearSSL's `aes_ct64` (Thomas Pornin). The
//! S-box is the Boyar–Peralta 113-gate circuit, ShiftRows and MixColumns are
//! fixed bit permutations and XORs, and the key schedule uses the same S-box.
//! The inverse S-box wraps the forward circuit in the inverse affine map, and
//! decryption uses the standard (not the equivalent) inverse cipher, so both
//! directions share one bitsliced key schedule.
//! There are no table lookups and no secret-dependent branches; every
//! operation is a 64-bit logical or constant-shift instruction.
//!
//! Internal layout (from BearSSL): a 32-bit word `w[i]` of a block is the
//! little-endian decoding of bytes `4i..4i+4`. `interleave_in` spreads the
//! four words of a block over two 64-bit words, `ortho` then transposes the
//! eight words holding four blocks so that `q[k]` contains bit `k` of every
//! byte of every block.

use crate::zeroize::zeroize_u64;

const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

const M1: u64 = 0x1111_1111_1111_1111;
const M2: u64 = 0x2222_2222_2222_2222;
const M4: u64 = 0x4444_4444_4444_4444;
const M8: u64 = 0x8888_8888_8888_8888;

/// Bitsliced expanded key: eight 64-bit words per round key.
pub(crate) struct Key {
    skey: [u64; 8 * 15],
    rounds: usize,
}

impl Drop for Key {
    fn drop(&mut self) {
        zeroize_u64(&mut self.skey);
    }
}

impl Key {
    /// Builds the bitsliced key from the standard word schedule.
    pub(crate) fn new(words: &[u32; 60], rounds: usize) -> Self {
        let mut skey = [0u64; 8 * 15];
        for (i, rk) in words[..(rounds + 1) * 4]
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
        {
            let (a, b) = interleave_in(rk);
            let mut q = [a, a, a, a, b, b, b, b];
            ortho(&mut q);
            // Each nibble of `q[k]` is now 0000 or 1111 (the four "blocks" are
            // identical), so four words compress into one and re-expand by
            // multiplying every nibble by 15.
            let comp = [
                (q[0] & M1) | (q[1] & M2) | (q[2] & M4) | (q[3] & M8),
                (q[4] & M1) | (q[5] & M2) | (q[6] & M4) | (q[7] & M8),
            ];
            for (j, c) in comp.iter().enumerate() {
                let x = [c & M1, (c & M2) >> 1, (c & M4) >> 2, (c & M8) >> 3];
                for (k, xk) in x.iter().enumerate() {
                    // Every nibble of `xk` is 0 or 1; 15 * nibble is 0x0 or 0xF.
                    skey[8 * i + 4 * j + k] = (xk << 4).wrapping_sub(*xk);
                }
            }
        }
        Self { skey, rounds }
    }

    /// Encrypts up to four blocks in parallel.
    fn encrypt4(&self, blocks: &mut [[u8; 16]; 4]) {
        let mut q = load4(blocks);
        bitslice_encrypt(self.rounds, &self.skey, &mut q);
        store4(&mut q, blocks);
    }

    /// Encrypts every block in place.
    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        self.for_each4(blocks, Self::encrypt4);
    }

    /// Decrypts up to four blocks in parallel.
    fn decrypt4(&self, blocks: &mut [[u8; 16]; 4]) {
        let mut q = load4(blocks);
        bitslice_decrypt(self.rounds, &self.skey, &mut q);
        store4(&mut q, blocks);
    }

    /// Decrypts every block in place.
    pub(crate) fn decrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        self.for_each4(blocks, Self::decrypt4);
    }

    /// Applies `f` to groups of four blocks, padding the last group.
    fn for_each4(&self, blocks: &mut [[u8; 16]], f: fn(&Self, &mut [[u8; 16]; 4])) {
        let (chunks, rest) = blocks.as_chunks_mut::<4>();
        for chunk in chunks {
            f(self, chunk);
        }
        if !rest.is_empty() {
            let mut tmp = [[0u8; 16]; 4];
            tmp[..rest.len()].copy_from_slice(rest);
            f(self, &mut tmp);
            rest.copy_from_slice(&tmp[..rest.len()]);
            crate::zeroize::zeroize_bytes(tmp.as_flattened_mut());
        }
    }
}

/// Loads four blocks into bitsliced form.
#[inline]
fn load4(blocks: &[[u8; 16]; 4]) -> [u64; 8] {
    let mut q = [0u64; 8];
    for (i, block) in blocks.iter().enumerate() {
        let (a, b) = interleave_in(&words(block));
        q[i] = a;
        q[i + 4] = b;
    }
    ortho(&mut q);
    q
}

/// Stores the bitsliced state into four blocks and wipes it (it holds
/// keystream, CBC-MAC chaining values or plaintext).
#[inline]
fn store4(q: &mut [u64; 8], blocks: &mut [[u8; 16]; 4]) {
    ortho(q);
    for (i, block) in blocks.iter_mut().enumerate() {
        let w = interleave_out(q[i], q[i + 4]);
        for (chunk, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(w) {
            *chunk = word.to_le_bytes();
        }
    }
    zeroize_u64(q);
}

/// Standard AES key expansion (FIPS 197 §5.2) producing `4 * (rounds + 1)`
/// little-endian words; `SubWord` uses the bitsliced S-box so no table is
/// indexed by key material.
///
/// `key` must be 16 or 32 bytes long.
pub(crate) fn key_schedule(key: &[u8]) -> ([u32; 60], usize) {
    let nk = key.len() / 4;
    let rounds = nk + 6;
    let nkf = (rounds + 1) * 4;
    let mut skey = [0u32; 60];
    for (w, bytes) in skey.iter_mut().zip(key.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*bytes);
    }
    let mut tmp = skey[nk - 1];
    let (mut j, mut k) = (0, 0);
    for i in nk..nkf {
        if j == 0 {
            tmp = sub_word(tmp.rotate_right(8)) ^ RCON[k];
        } else if nk > 6 && j == 4 {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[i - nk];
        skey[i] = tmp;
        j += 1;
        if j == nk {
            j = 0;
            k += 1;
        }
    }
    (skey, rounds)
}

fn sub_word(x: u32) -> u32 {
    let mut q = [0u64; 8];
    q[0] = u64::from(x);
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    // The S-box output of the single word is in the low 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let out = q[0] as u32;
    out
}

#[inline]
fn words(block: &[u8; 16]) -> [u32; 4] {
    let c = block.as_chunks::<4>().0;
    [
        u32::from_le_bytes(c[0]),
        u32::from_le_bytes(c[1]),
        u32::from_le_bytes(c[2]),
        u32::from_le_bytes(c[3]),
    ]
}

#[inline]
fn interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let mut x = [
        u64::from(w[0]),
        u64::from(w[1]),
        u64::from(w[2]),
        u64::from(w[3]),
    ];
    for v in &mut x {
        *v |= *v << 16;
        *v &= 0x0000_FFFF_0000_FFFF;
        *v |= *v << 8;
        *v &= 0x00FF_00FF_00FF_00FF;
    }
    (x[0] | (x[2] << 8), x[1] | (x[3] << 8))
}

#[inline]
fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let mut x = [
        q0 & 0x00FF_00FF_00FF_00FF,
        q1 & 0x00FF_00FF_00FF_00FF,
        (q0 >> 8) & 0x00FF_00FF_00FF_00FF,
        (q1 >> 8) & 0x00FF_00FF_00FF_00FF,
    ];
    let mut w = [0u32; 4];
    for (v, out) in x.iter_mut().zip(&mut w) {
        *v |= *v >> 8;
        *v &= 0x0000_FFFF_0000_FFFF;
        // Both halves fit in 32 bits after masking.
        #[allow(clippy::cast_possible_truncation)]
        let r = (*v as u32) | ((*v >> 16) as u32);
        *out = r;
    }
    w
}

/// Bit-transposes four blocks into (or out of) bitsliced form.
#[inline]
fn ortho(q: &mut [u64; 8]) {
    macro_rules! swapn {
        ($cl:expr, $ch:expr, $s:expr, $x:expr, $y:expr) => {{
            let a = $x;
            let b = $y;
            $x = (a & $cl) | ((b & $cl) << $s);
            $y = ((a & $ch) >> $s) | (b & $ch);
        }};
    }
    macro_rules! swap2 {
        ($x:expr, $y:expr) => {
            swapn!(
                0x5555_5555_5555_5555u64,
                0xAAAA_AAAA_AAAA_AAAAu64,
                1,
                $x,
                $y
            )
        };
    }
    macro_rules! swap4 {
        ($x:expr, $y:expr) => {
            swapn!(
                0x3333_3333_3333_3333u64,
                0xCCCC_CCCC_CCCC_CCCCu64,
                2,
                $x,
                $y
            )
        };
    }
    macro_rules! swap8 {
        ($x:expr, $y:expr) => {
            swapn!(
                0x0F0F_0F0F_0F0F_0F0Fu64,
                0xF0F0_F0F0_F0F0_F0F0u64,
                4,
                $x,
                $y
            )
        };
    }
    swap2!(q[0], q[1]);
    swap2!(q[2], q[3]);
    swap2!(q[4], q[5]);
    swap2!(q[6], q[7]);

    swap4!(q[0], q[2]);
    swap4!(q[1], q[3]);
    swap4!(q[4], q[6]);
    swap4!(q[5], q[7]);

    swap8!(q[0], q[4]);
    swap8!(q[1], q[5]);
    swap8!(q[2], q[6]);
    swap8!(q[3], q[7]);
}

/// Bitsliced AES S-box (Boyar–Peralta circuit; `x0` is the most significant
/// input bit and lives in `q[7]`).
#[inline]
fn sbox(q: &mut [u64; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

#[inline]
fn add_round_key(q: &mut [u64; 8], sk: &[u64]) {
    for (x, k) in q.iter_mut().zip(sk) {
        *x ^= k;
    }
}

#[inline]
fn shift_rows(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_FFF0_0000) >> 4)
            | ((v & 0x0000_0000_000F_0000) << 12)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0xF000_0000_0000_0000) >> 12)
            | ((v & 0x0FFF_0000_0000_0000) << 4);
    }
}

#[inline]
fn mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let r0 = q0.rotate_right(16);
    let r1 = q1.rotate_right(16);
    let r2 = q2.rotate_right(16);
    let r3 = q3.rotate_right(16);
    let r4 = q4.rotate_right(16);
    let r5 = q5.rotate_right(16);
    let r6 = q6.rotate_right(16);
    let r7 = q7.rotate_right(16);

    q[0] = q7 ^ r7 ^ r0 ^ (q0 ^ r0).rotate_right(32);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ (q1 ^ r1).rotate_right(32);
    q[2] = q1 ^ r1 ^ r2 ^ (q2 ^ r2).rotate_right(32);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ (q3 ^ r3).rotate_right(32);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ (q4 ^ r4).rotate_right(32);
    q[5] = q4 ^ r4 ^ r5 ^ (q5 ^ r5).rotate_right(32);
    q[6] = q5 ^ r5 ^ r6 ^ (q6 ^ r6).rotate_right(32);
    q[7] = q6 ^ r6 ^ r7 ^ (q7 ^ r7).rotate_right(32);
}

fn bitslice_encrypt(rounds: usize, skey: &[u64], q: &mut [u64; 8]) {
    add_round_key(q, &skey[..8]);
    for u in 1..rounds {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, &skey[8 * u..8 * u + 8]);
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, &skey[8 * rounds..8 * rounds + 8]);
}

/// Bitsliced inverse S-box: the inverse affine map `T(y) = A^-1(y ^ 0x63)`,
/// the forward S-box, then `T` again, since
/// `T(S(T(y))) = T(A(inv(T(y))) ^ 0x63) = inv(A^-1(y ^ 0x63)) = S^-1(y)`.
#[inline]
fn inv_sbox(q: &mut [u64; 8]) {
    inv_affine(q);
    sbox(q);
    inv_affine(q);
}

/// `T(y) = A^-1(y ^ 0x63)`: complement bits 0, 1, 5 and 6, then output bit
/// `i` is the XOR of input bits `i + 2`, `i + 5` and `i + 7` (mod 8).
#[inline]
fn inv_affine(q: &mut [u64; 8]) {
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

#[inline]
fn inv_shift_rows(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_0FFF_0000) << 4)
            | ((v & 0x0000_0000_F000_0000) >> 12)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x000F_0000_0000_0000) << 12)
            | ((v & 0xFFF0_0000_0000_0000) >> 4);
    }
}

/// InvMixColumns: multiplication of every column by
/// `{0e, 0b, 0d, 09}` in bitsliced form (rows are 16-bit lanes, so
/// `rotate_right(16)` and `rotate_right(32)` move to the next and the
/// opposite row).
#[inline]
fn inv_mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let r0 = q0.rotate_right(16);
    let r1 = q1.rotate_right(16);
    let r2 = q2.rotate_right(16);
    let r3 = q3.rotate_right(16);
    let r4 = q4.rotate_right(16);
    let r5 = q5.rotate_right(16);
    let r6 = q6.rotate_right(16);
    let r7 = q7.rotate_right(16);

    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ (q0 ^ q5 ^ q6 ^ r0 ^ r5).rotate_right(32);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ (q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6).rotate_right(32);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ (q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7).rotate_right(32);
    q[3] = q0
        ^ q1
        ^ q2
        ^ q5
        ^ q6
        ^ r0
        ^ r2
        ^ r3
        ^ r5
        ^ (q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7).rotate_right(32);
    q[4] = q1
        ^ q2
        ^ q3
        ^ q5
        ^ r1
        ^ r3
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ (q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6).rotate_right(32);
    q[5] = q2
        ^ q3
        ^ q4
        ^ q6
        ^ r2
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ (q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7).rotate_right(32);
    q[6] =
        q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7 ^ (q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7).rotate_right(32);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ (q4 ^ q5 ^ q7 ^ r4 ^ r7).rotate_right(32);
}

/// The inverse cipher (FIPS 197 §5.3) on the encryption key schedule.
fn bitslice_decrypt(rounds: usize, skey: &[u64], q: &mut [u64; 8]) {
    add_round_key(q, &skey[8 * rounds..8 * rounds + 8]);
    for u in (1..rounds).rev() {
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, &skey[8 * u..8 * u + 8]);
        inv_mix_columns(q);
    }
    inv_shift_rows(q);
    inv_sbox(q);
    add_round_key(q, &skey[..8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_matches_fips197_table() {
        // Spot-check the bitsliced S-box against FIPS 197 Figure 7.
        for (input, expected) in [(0x00u32, 0x63u32), (0x01, 0x7c), (0x53, 0xed), (0xff, 0x16)] {
            assert_eq!(sub_word(input) & 0xff, expected);
        }
        // SubWord acts byte-wise.
        assert_eq!(sub_word(0x0053_ff01), 0x63ed_167c);
    }

    #[test]
    fn inv_sbox_inverts_sbox() {
        // All 256 byte values, four per word, eight words per state.
        let mut q = [0u64; 8];
        for (i, w) in q.iter_mut().enumerate() {
            for j in 0..8u64 {
                *w |= ((8 * i as u64 + j) * 4) << (8 * j);
            }
        }
        for offset in 0..4u64 {
            let mut x: [u64; 8] = core::array::from_fn(|i| q[i] + offset * 0x0101_0101_0101_0101);
            let orig = x;
            ortho(&mut x);
            sbox(&mut x);
            inv_sbox(&mut x);
            ortho(&mut x);
            assert_eq!(x, orig);
        }
    }

    #[test]
    fn inv_round_functions_invert_forward_ones() {
        let orig: [u64; 8] =
            core::array::from_fn(|i| (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut q = orig;
        shift_rows(&mut q);
        inv_shift_rows(&mut q);
        assert_eq!(q, orig);
        mix_columns(&mut q);
        inv_mix_columns(&mut q);
        assert_eq!(q, orig);
    }

    #[test]
    fn ortho_is_involution() {
        let mut q = [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
            0xdddd_eeee_ffff_0000,
            0x0f0f_0f0f_f0f0_f0f0,
            0xaaaa_5555_aaaa_5555,
        ];
        let orig = q;
        ortho(&mut q);
        ortho(&mut q);
        assert_eq!(q, orig);
    }
}
