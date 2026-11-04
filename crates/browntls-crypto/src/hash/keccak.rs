//! Keccak-f\[1600\] permutation: single-state and four-way batched variants.
//!
//! The round function is written once, generically over a [`Lanes`] type that
//! holds one 64-bit Keccak lane of one or more independent states (a `u64`, or
//! one SIMD register holding the same lane of 2 or 4 states). Each backend
//! supplies the lane operations — plain shifts and `AND-NOT`, or fused
//! instructions such as AVX-512 `VPTERNLOGQ`/`VPROLQ` and Armv8.2 `EOR3`,
//! `RAX1`, `XAR` and `BCAX` — and the generic code is monomorphised inside a
//! `#[target_feature]` function so the fused forms are actually emitted.
//!
//! Batched states use the lane-major layout [`StateX4`] (`[lane][instance]`),
//! which lets SIMD backends load lane `i` of all instances with one vector
//! load. The public [`keccak_f1600_x4`] accepts four ordinary states and
//! transposes.
//!
//! All backends are constant time: the permutation has no data-dependent
//! branches or memory accesses.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;

use crate::cpu::Features;

/// Keccak-f\[1600\] round constants.
pub(crate) const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Four Keccak states in lane-major order: `s[i][j]` is lane `i` of instance
/// `j`.
pub(crate) type StateX4 = [[u64; 4]; 25];

/// One Keccak lane of one or more independent states.
///
/// Implementations must be `#[inline(always)]` so that the generic round is
/// compiled with the caller's target features.
pub(crate) trait Lanes: Copy {
    /// `a ^ b`.
    fn xor(self, b: Self) -> Self;
    /// XOR of five lanes (θ column parity).
    #[inline(always)]
    fn xor5(a: Self, b: Self, c: Self, d: Self, e: Self) -> Self {
        a.xor(b).xor(c).xor(d).xor(e)
    }
    /// Rotate left by `L` bits; `R` is always `64 - L` (`1 <= L <= 63`).
    fn rol<const L: i32, const R: i32>(self) -> Self;
    /// `c_prev ^ rol(c_next, 1)` (θ effect, Armv8.2 `RAX1`).
    #[inline(always)]
    fn theta_d(c_prev: Self, c_next: Self) -> Self {
        c_prev.xor(c_next.rol::<1, 63>())
    }
    /// `rol(a ^ d, L)` (θ application fused with ρ, Armv8.2 `XAR`).
    #[inline(always)]
    fn xor_rol<const L: i32, const R: i32>(a: Self, d: Self) -> Self {
        a.xor(d).rol::<L, R>()
    }
    /// `a ^ (!b & c)` (χ, Armv8.2 `BCAX`).
    fn chi(a: Self, b: Self, c: Self) -> Self;
    /// `self ^ rc` with `rc` broadcast to every instance (ι).
    fn xor_rc(self, rc: u64) -> Self;
}

impl Lanes for u64 {
    #[inline(always)]
    fn xor(self, b: Self) -> Self {
        self ^ b
    }
    #[inline(always)]
    #[allow(clippy::cast_sign_loss)]
    fn rol<const L: i32, const R: i32>(self) -> Self {
        self.rotate_left(L as u32)
    }
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        a ^ (!b & c)
    }
    #[inline(always)]
    fn xor_rc(self, rc: u64) -> Self {
        self ^ rc
    }
}

/// One round (θ, ρ, π, χ, ι) from `a` into a fresh state.
///
/// Output lane `X + 5Y` takes input lane `x + 5y` with `X = y` and
/// `Y = 2x + 3y (mod 5)`, rotated by the ρ offset of `(x, y)`; the five
/// rotated lanes of an output row are then combined by χ.
#[inline(always)]
pub(crate) fn round<L: Lanes>(a: &[L; 25], rc: u64) -> [L; 25] {
    let c0 = L::xor5(a[0], a[5], a[10], a[15], a[20]);
    let c1 = L::xor5(a[1], a[6], a[11], a[16], a[21]);
    let c2 = L::xor5(a[2], a[7], a[12], a[17], a[22]);
    let c3 = L::xor5(a[3], a[8], a[13], a[18], a[23]);
    let c4 = L::xor5(a[4], a[9], a[14], a[19], a[24]);
    let d0 = L::theta_d(c4, c1);
    let d1 = L::theta_d(c0, c2);
    let d2 = L::theta_d(c1, c3);
    let d3 = L::theta_d(c2, c4);
    let d4 = L::theta_d(c3, c0);

    // Row 0: lanes 0, 6, 12, 18, 24.
    let b0 = a[0].xor(d0);
    let b1 = L::xor_rol::<44, 20>(a[6], d1);
    let b2 = L::xor_rol::<43, 21>(a[12], d2);
    let b3 = L::xor_rol::<21, 43>(a[18], d3);
    let b4 = L::xor_rol::<14, 50>(a[24], d4);
    let e0 = L::chi(b0, b1, b2).xor_rc(rc);
    let e1 = L::chi(b1, b2, b3);
    let e2 = L::chi(b2, b3, b4);
    let e3 = L::chi(b3, b4, b0);
    let e4 = L::chi(b4, b0, b1);

    // Row 1: lanes 3, 9, 10, 16, 22.
    let b0 = L::xor_rol::<28, 36>(a[3], d3);
    let b1 = L::xor_rol::<20, 44>(a[9], d4);
    let b2 = L::xor_rol::<3, 61>(a[10], d0);
    let b3 = L::xor_rol::<45, 19>(a[16], d1);
    let b4 = L::xor_rol::<61, 3>(a[22], d2);
    let e5 = L::chi(b0, b1, b2);
    let e6 = L::chi(b1, b2, b3);
    let e7 = L::chi(b2, b3, b4);
    let e8 = L::chi(b3, b4, b0);
    let e9 = L::chi(b4, b0, b1);

    // Row 2: lanes 1, 7, 13, 19, 20.
    let b0 = L::xor_rol::<1, 63>(a[1], d1);
    let b1 = L::xor_rol::<6, 58>(a[7], d2);
    let b2 = L::xor_rol::<25, 39>(a[13], d3);
    let b3 = L::xor_rol::<8, 56>(a[19], d4);
    let b4 = L::xor_rol::<18, 46>(a[20], d0);
    let e10 = L::chi(b0, b1, b2);
    let e11 = L::chi(b1, b2, b3);
    let e12 = L::chi(b2, b3, b4);
    let e13 = L::chi(b3, b4, b0);
    let e14 = L::chi(b4, b0, b1);

    // Row 3: lanes 4, 5, 11, 17, 23.
    let b0 = L::xor_rol::<27, 37>(a[4], d4);
    let b1 = L::xor_rol::<36, 28>(a[5], d0);
    let b2 = L::xor_rol::<10, 54>(a[11], d1);
    let b3 = L::xor_rol::<15, 49>(a[17], d2);
    let b4 = L::xor_rol::<56, 8>(a[23], d3);
    let e15 = L::chi(b0, b1, b2);
    let e16 = L::chi(b1, b2, b3);
    let e17 = L::chi(b2, b3, b4);
    let e18 = L::chi(b3, b4, b0);
    let e19 = L::chi(b4, b0, b1);

    // Row 4: lanes 2, 8, 14, 15, 21.
    let b0 = L::xor_rol::<62, 2>(a[2], d2);
    let b1 = L::xor_rol::<55, 9>(a[8], d3);
    let b2 = L::xor_rol::<39, 25>(a[14], d4);
    let b3 = L::xor_rol::<41, 23>(a[15], d0);
    let b4 = L::xor_rol::<2, 62>(a[21], d1);
    let e20 = L::chi(b0, b1, b2);
    let e21 = L::chi(b1, b2, b3);
    let e22 = L::chi(b2, b3, b4);
    let e23 = L::chi(b3, b4, b0);
    let e24 = L::chi(b4, b0, b1);

    [
        e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18, e19,
        e20, e21, e22, e23, e24,
    ]
}

/// The full 24-round permutation, two rounds per iteration so that the state
/// ping-pongs between two register sets without copies.
#[inline(always)]
pub(crate) fn permute<L: Lanes>(a: &mut [L; 25]) {
    let mut s = *a;
    for rc in RC.as_chunks::<2>().0 {
        let e = round(&s, rc[0]);
        s = round(&e, rc[1]);
    }
    *a = s;
}

pub(crate) mod soft {
    use super::StateX4;

    /// Portable Keccak-f\[1600\] (unrolled rounds).
    pub(crate) fn keccak_f1600(a: &mut [u64; 25]) {
        super::permute(a);
    }

    /// Portable four-way permutation: four single-state permutations using
    /// the best available single-state backend.
    pub(crate) fn keccak_f1600_x4(s: &mut StateX4) {
        for j in 0..4 {
            let mut one: [u64; 25] = core::array::from_fn(|i| s[i][j]);
            super::keccak_f1600(&mut one);
            for (lane, v) in s.iter_mut().zip(one) {
                lane[j] = v;
            }
        }
    }
}

/// A single-state Keccak-f\[1600\] backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable unrolled code.
    Soft,
    /// x86-64 scalar code compiled with BMI1/BMI2 (`ANDN`, `RORX`).
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    X86Bmi,
    /// riscv64 scalar code compiled with Zbb (`ANDN`, `RORI`).
    #[cfg(target_arch = "riscv64")]
    RvZbb,
}

impl Backend {
    /// Every backend in order of preference.
    pub(crate) const ALL: &'static [Self] = &[
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::X86Bmi,
        #[cfg(target_arch = "riscv64")]
        Self::RvZbb,
        Self::Soft,
    ];

    /// Whether this backend can run with features `f`.
    // aarch64 has no single-state backend besides `Soft`.
    #[cfg_attr(
        not(any(
            all(target_arch = "x86_64", target_feature = "sse2"),
            target_arch = "riscv64"
        )),
        allow(unused_variables)
    )]
    pub(crate) fn is_available(self, f: Features) -> bool {
        // `f` is unused when every accelerated backend is compiled out.
        let _ = f;
        match self {
            Self::Soft => true,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86Bmi => x86::bmi_available(f),
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => riscv64::zbb_available(f),
        }
    }

    /// The preferred available backend.
    /// A display name for acceleration status reports.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86Bmi => "BMI1/BMI2",
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => "Zbb",
        }
    }

    /// Runs the permutation. Falls back to [`soft`] if the backend is not
    /// available on this CPU.
    pub(crate) fn permute(self, state: &mut [u64; 25]) {
        match self {
            Self::Soft => soft::keccak_f1600(state),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86Bmi => x86::keccak_f1600_bmi(state),
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => riscv64::keccak_f1600_zbb(state),
        }
    }
}

/// A four-way batched Keccak-f\[1600\] backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendX4 {
    /// Four sequential single-state permutations.
    Soft,
    /// AVX-512VL: four instances in one YMM register per lane, `VPROLQ` and
    /// `VPTERNLOGQ`.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Avx512,
    /// AVX2: four instances in one YMM register per lane.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Avx2,
    /// Armv8.2 SHA3 (`EOR3`, `RAX1`, `XAR`, `BCAX`): two instances per Q
    /// register, two passes.
    #[cfg(target_arch = "aarch64")]
    ArmSha3,
    /// Advanced SIMD: two instances per Q register, two passes.
    #[cfg(target_arch = "aarch64")]
    Neon,
    /// RVV 1.0 with Zvkb (`vror`, `vandn`), VLEN-agnostic (e64, `vl <= 4`).
    #[cfg(target_arch = "riscv64")]
    RvvZvkb,
    /// RVV 1.0 base instructions, VLEN-agnostic (e64, `vl <= 4`).
    #[cfg(target_arch = "riscv64")]
    Rvv,
}

impl BackendX4 {
    /// Every backend in order of preference.
    pub(crate) const ALL: &'static [Self] = &[
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::Avx512,
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::Avx2,
        #[cfg(target_arch = "aarch64")]
        Self::ArmSha3,
        #[cfg(target_arch = "aarch64")]
        Self::Neon,
        #[cfg(target_arch = "riscv64")]
        Self::RvvZvkb,
        #[cfg(target_arch = "riscv64")]
        Self::Rvv,
        Self::Soft,
    ];

    /// Whether this backend can run with features `f`.
    pub(crate) fn is_available(self, f: Features) -> bool {
        // `f` is unused when every accelerated backend is compiled out.
        let _ = f;
        match self {
            Self::Soft => true,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx512 => x86::avx512_available(f),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx2 => x86::avx2_available(f),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha3 => aarch64::sha3_available(f),
            #[cfg(target_arch = "aarch64")]
            Self::Neon => aarch64::neon_available(f),
            #[cfg(target_arch = "riscv64")]
            Self::RvvZvkb => riscv64::rvv_zvkb_available(f),
            #[cfg(target_arch = "riscv64")]
            Self::Rvv => riscv64::rvv_available(f),
        }
    }

    /// The preferred available backend.
    /// A display name for acceleration status reports.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx512 => "AVX-512VL",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx2 => "AVX2",
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha3 => "FEAT_SHA3",
            #[cfg(target_arch = "aarch64")]
            Self::Neon => "NEON",
            #[cfg(target_arch = "riscv64")]
            Self::RvvZvkb => "RVV+Zvkb",
            #[cfg(target_arch = "riscv64")]
            Self::Rvv => "RVV",
        }
    }

    /// Runs the permutation on four lane-major states. Falls back to
    /// [`soft`] if the backend is not available on this CPU.
    pub(crate) fn permute(self, s: &mut StateX4) {
        match self {
            Self::Soft => soft::keccak_f1600_x4(s),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx512 => x86::keccak_f1600_x4_avx512(s),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx2 => x86::keccak_f1600_x4_avx2(s),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha3 => aarch64::keccak_f1600_x4_sha3(s),
            #[cfg(target_arch = "aarch64")]
            Self::Neon => aarch64::keccak_f1600_x4_neon(s),
            #[cfg(target_arch = "riscv64")]
            Self::RvvZvkb => riscv64::keccak_f1600_x4_rvv_zvkb(s),
            #[cfg(target_arch = "riscv64")]
            Self::Rvv => riscv64::keccak_f1600_x4_rvv(s),
        }
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Keccak;
    const PREFERENCE: &'static [Self] = Self::ALL;

    fn available(self) -> bool {
        self.is_available(crate::cpu::features())
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86Bmi => Uses::DEDICATED,
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        Backend::name(self)
    }
}

impl crate::accel::Backends for BackendX4 {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::KeccakX4;
    const PREFERENCE: &'static [Self] = Self::ALL;

    fn available(self) -> bool {
        self.is_available(crate::cpu::features())
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx512 => Uses::SIMD,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Avx2 => Uses::SIMD,
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha3 => Uses::BOTH,
            #[cfg(target_arch = "aarch64")]
            Self::Neon => Uses::SIMD,
            #[cfg(target_arch = "riscv64")]
            Self::RvvZvkb => Uses::BOTH,
            #[cfg(target_arch = "riscv64")]
            Self::Rvv => Uses::SIMD,
        }
    }

    fn name(self) -> &'static str {
        BackendX4::name(self)
    }
}

/// Applies Keccak-f\[1600\] to `state` (lane `x + 5y` at index `x + 5*y`),
/// selecting the best available backend.
#[inline]
pub fn keccak_f1600(state: &mut [u64; 25]) {
    crate::accel::select::<Backend>().permute(state);
}

/// Applies Keccak-f\[1600\] to four lane-major states at once.
#[inline]
pub(crate) fn keccak_f1600_x4_lanes(s: &mut StateX4) {
    crate::accel::select::<BackendX4>().permute(s);
}

/// Applies Keccak-f\[1600\] independently to each of four states, using a
/// SIMD backend that processes the four states in parallel where available
/// (AVX2/AVX-512VL, Advanced SIMD/SHA3, RVV).
///
/// Equivalent to calling [`keccak_f1600`] on each state.
pub fn keccak_f1600_x4(states: &mut [[u64; 25]; 4]) {
    let mut s: StateX4 = core::array::from_fn(|i| core::array::from_fn(|j| states[j][i]));
    keccak_f1600_x4_lanes(&mut s);
    for (j, st) in states.iter_mut().enumerate() {
        for (i, lane) in st.iter_mut().enumerate() {
            *lane = s[i][j];
        }
    }
    crate::zeroize::zeroize_u64(s.as_flattened_mut());
}
