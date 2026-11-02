//! Poly1305 one-time authenticator (RFC 8439, section 2.5).
//!
//! The portable backend keeps the accumulator in two 64-bit limbs plus a small
//! third limb and multiplies with 64x64->128-bit products, which compile to
//! `MUL`/`MULX` on x86-64, `MUL`+`UMULH` on aarch64 and `MUL`+`MULHU` on
//! riscv64. All of these run in data-independent time on the supported
//! cores; there are no secret-dependent branches or memory accesses.

use crate::Error;
use crate::zeroize::Zeroize;

/// Poly1305 block size in bytes.
pub(super) const BLOCK: usize = 16;
/// Poly1305 key length in bytes (`r || s`).
pub const KEY_LEN: usize = 32;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Accumulator and clamped key in radix 2^64.
#[derive(Clone)]
pub(super) struct State {
    pub(super) r: [u64; 2],
    pub(super) h: [u64; 3],
}

impl State {
    pub(super) fn new(r_bytes: &[u8; 16]) -> Self {
        let r0 = u64::from_le_bytes(*r_bytes.first_chunk::<8>().unwrap_or(&[0; 8]))
            & 0x0fff_fffc_0fff_ffff;
        let r1 = u64::from_le_bytes(*r_bytes.last_chunk::<8>().unwrap_or(&[0; 8]))
            & 0x0fff_fffc_0fff_fffc;
        Self {
            r: [r0, r1],
            h: [0; 3],
        }
    }

    /// Absorbs whole 16-byte blocks. `hibit` is 1 for full message blocks
    /// (the appended `0x01` byte lands at bit 128) and 0 for the final,
    /// already padded partial block.
    #[inline(always)]
    pub(super) fn blocks(&mut self, data: &[u8], hibit: u64) {
        let [r0, r1] = self.r;
        // r1 is a multiple of 4 after clamping, so s1 = 5 * r1 / 4 is exact.
        let s1 = r1 + (r1 >> 2);
        let [mut h0, mut h1, mut h2] = self.h;
        for m in data.as_chunks::<BLOCK>().0 {
            let (lo, hi) = m.split_at(8);
            let m0 = u64::from_le_bytes(lo.try_into().unwrap_or([0; 8]));
            let m1 = u64::from_le_bytes(hi.try_into().unwrap_or([0; 8]));
            // h += m
            let t = u128::from(h0) + u128::from(m0);
            h0 = t as u64;
            let t = u128::from(h1) + u128::from(m1) + (t >> 64);
            h1 = t as u64;
            h2 = h2 + hibit + (t >> 64) as u64;
            // h *= r (mod 2^130 - 5), partially reduced.
            // Bounds: h2 <= 6, r0, r1 < 2^60, s1 < 2^61.
            let d0 = u128::from(h0) * u128::from(r0) + u128::from(h1) * u128::from(s1);
            let d1 = u128::from(h0) * u128::from(r1)
                + u128::from(h1) * u128::from(r0)
                + u128::from(h2) * u128::from(s1);
            let d2 = h2 * r0;
            let d1 = d1 + (d0 >> 64);
            let d2 = d2 + (d1 >> 64) as u64;
            h0 = d0 as u64;
            h1 = d1 as u64;
            // Fold bits >= 130 back in multiplied by 5: c = (d2 >> 2) * 5.
            let c = (d2 & !3) + (d2 >> 2);
            h2 = d2 & 3;
            let t = u128::from(h0) + u128::from(c);
            h0 = t as u64;
            let t = u128::from(h1) + (t >> 64);
            h1 = t as u64;
            h2 += (t >> 64) as u64;
        }
        self.h = [h0, h1, h2];
    }

    /// Fully reduces the accumulator and adds `s`, returning the tag.
    pub(super) fn finish(&self, s: &[u64; 2]) -> [u8; TAG_LEN] {
        let [h0, h1, h2] = self.h;
        // h < 2p here (h2 <= 4), so a single conditional subtraction of p
        // suffices: compute g = h + 5 and keep it iff g >= 2^130.
        let t = u128::from(h0) + 5;
        let g0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let g1 = t as u64;
        let g2 = h2 + (t >> 64) as u64;
        let mask = ((g2 >> 2) & 1).wrapping_neg();
        let h0 = h0 ^ (mask & (h0 ^ g0));
        let h1 = h1 ^ (mask & (h1 ^ g1));
        let t = u128::from(h0) + u128::from(s[0]);
        let t0 = t as u64;
        let t1 = h1.wrapping_add(s[1]).wrapping_add((t >> 64) as u64);
        let mut tag = [0u8; TAG_LEN];
        tag[..8].copy_from_slice(&t0.to_le_bytes());
        tag[8..].copy_from_slice(&t1.to_le_bytes());
        tag
    }

    pub(super) fn zeroize(&mut self) {
        self.r.zeroize();
        self.h.zeroize();
    }
}

/// Absorbs whole blocks with the best available Poly1305 backend.
#[inline]
pub(super) fn blocks(state: &mut State, data: &[u8], backend: PolyBackend) {
    match backend {
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        PolyBackend::Bmi2 => super::x86::poly1305_blocks_bmi2(state, data),
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        PolyBackend::Avx2 => super::poly1305_avx2::blocks(state, data),
        _ => state.blocks(data, 1),
    }
}

/// Poly1305 implementation tiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolyBackend {
    /// Portable radix-2^64 code.
    Soft,
    /// x86-64 radix-2^64 code compiled with BMI2 (`MULX`) and ADX.
    Bmi2,
    /// x86-64 AVX2, four blocks in parallel in radix 2^26 (inputs of at
    /// least 1 KiB; shorter ones use the BMI2 scalar code).
    Avx2,
}

impl PolyBackend {
    /// Every tier in increasing order of preference.
    pub const ALL: [Self; 3] = [Self::Soft, Self::Bmi2, Self::Avx2];

    /// Returns whether this tier can run on the current CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        let f = crate::cpu::features();
        match self {
            Self::Soft => true,
            Self::Bmi2 => f.x86_bmi2() && f.x86_adx(),
            Self::Avx2 => f.x86_v3(),
        }
    }

    /// The preferred available tier.
    #[must_use]
    pub fn best() -> Self {
        if Self::Avx2.is_available() {
            Self::Avx2
        } else if Self::Bmi2.is_available() {
            Self::Bmi2
        } else {
            Self::Soft
        }
    }
}

/// Poly1305 one-time authenticator.
///
/// A key must authenticate at most one message. Key material and the
/// accumulator are zeroised on drop.
pub struct Poly1305 {
    state: State,
    s: [u64; 2],
    buf: [u8; BLOCK],
    buf_len: usize,
    backend: PolyBackend,
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly1305 { .. }")
    }
}

impl Poly1305 {
    /// Creates an authenticator from a one-time key `r || s`.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self::with_backend(key, PolyBackend::best())
    }

    /// Like [`Poly1305::new`] with an explicit backend (for tests and
    /// diagnostics); falls back to [`PolyBackend::Soft`] if `backend` is not
    /// available on this CPU.
    #[must_use]
    pub fn with_backend(key: &[u8; KEY_LEN], backend: PolyBackend) -> Self {
        let (r, s) = key.split_at(16);
        let r: &[u8; 16] = r.try_into().unwrap_or(&[0; 16]);
        let s0 = u64::from_le_bytes(s[..8].try_into().unwrap_or([0; 8]));
        let s1 = u64::from_le_bytes(s[8..].try_into().unwrap_or([0; 8]));
        Self {
            state: State::new(r),
            s: [s0, s1],
            buf: [0; BLOCK],
            buf_len: 0,
            backend: if backend.is_available() {
                backend
            } else {
                PolyBackend::Soft
            },
        }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK {
                return;
            }
            self.state.blocks(&self.buf, 1);
            self.buf_len = 0;
        }
        let full = data.len() - data.len() % BLOCK;
        if full > 0 {
            blocks(&mut self.state, &data[..full], self.backend);
        }
        let rest = &data[full..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// Absorbs `data` followed by zero padding to a 16-byte boundary (the
    /// AEAD construction's `pad16`). The internal buffer must be empty.
    pub(super) fn update_padded(&mut self, data: &[u8]) {
        debug_assert_eq!(self.buf_len, 0);
        let full = data.len() - data.len() % BLOCK;
        if full > 0 {
            blocks(&mut self.state, &data[..full], self.backend);
        }
        let rest = &data[full..];
        if !rest.is_empty() {
            let mut b = [0u8; BLOCK];
            b[..rest.len()].copy_from_slice(rest);
            self.state.blocks(&b, 1);
            b.zeroize();
        }
    }

    /// Returns the authentication tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.buf_len > 0 {
            let mut b = [0u8; BLOCK];
            b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            b[self.buf_len] = 1;
            self.state.blocks(&b, 0);
            b.zeroize();
            self.buf_len = 0;
        }
        self.state.finish(&self.s)
    }

    /// Computes the tag and compares it with `expected` in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the tags differ.
    pub fn verify(self, expected: &[u8; TAG_LEN]) -> Result<(), Error> {
        let mut tag = self.finalize();
        let ok = crate::ct::eq(&tag, expected);
        tag.zeroize();
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.s.zeroize();
        self.buf.zeroize();
    }
}
