//! Run-time selection of the polynomial-arithmetic backend.

use super::poly::{self, N, Poly};
use crate::Error;

/// A polynomial-arithmetic backend for ML-KEM.
///
/// [`Backend::detect`] picks the best backend for the running CPU; keys use
/// it by default. Selecting a specific backend is intended for testing and
/// benchmarking; every backend computes bit-identical results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// Portable Rust (16-bit Montgomery/Barrett arithmetic).
    Portable,
    /// x86-64 AVX2 (16 x i16 lanes).
    Avx2,
    /// aarch64 Advanced SIMD (8 x i16 lanes).
    Neon,
    /// riscv64 RVV 1.0, vector-length agnostic (e16).
    Rvv,
}

impl Backend {
    /// All backends, best first.
    pub const ALL: [Self; 4] = [Self::Avx2, Self::Neon, Self::Rvv, Self::Portable];

    /// Returns the best backend available on this CPU.
    #[must_use]
    pub fn detect() -> Self {
        if !crate::accel::allowed(crate::accel::Algorithm::MlKem) {
            return Self::Portable;
        }
        Self::ALL
            .into_iter()
            .find(|b| b.is_available())
            .unwrap_or(Self::Portable)
    }

    /// Returns whether this backend can run on this CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        let f = crate::cpu::features();
        match self {
            Self::Portable => true,
            Self::Avx2 => {
                cfg!(all(target_arch = "x86_64", target_feature = "sse2")) && f.x86_avx2()
            }
            Self::Neon => {
                cfg!(all(target_arch = "aarch64", target_feature = "neon")) && f.arm_neon()
            }
            Self::Rvv => cfg!(target_arch = "riscv64") && f.rv_v(),
        }
    }

    /// Returns every backend available on this CPU (best first).
    pub fn available() -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(|b| b.is_available())
    }
}

/// A backend that has been verified to be available on this CPU.
///
/// Invariant: an `Engine` holding a SIMD backend is only constructed by
/// [`Engine::new`] / [`Engine::detect`] after the corresponding CPU feature was
/// detected. The architecture modules rely on this for the safety of calling
/// their `#[target_feature]` functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Engine(Backend);

impl Engine {
    pub(crate) fn detect() -> Self {
        Self(Backend::detect())
    }

    pub(crate) fn new(b: Backend) -> Result<Self, Error> {
        if b.is_available() {
            Ok(Self(b))
        } else {
            Err(Error::Unsupported)
        }
    }

    pub(crate) fn backend(self) -> Backend {
        self.0
    }

    /// Forward NTT followed by Barrett reduction (`|a| < q` in).
    pub(crate) fn ntt(self, p: &mut Poly) {
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::ntt(p),
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Backend::Neon => super::aarch64::ntt(p),
            #[cfg(target_arch = "riscv64")]
            Backend::Rvv => super::riscv64::ntt(p),
            _ => poly::ntt(p),
        }
    }

    /// Inverse NTT including the `2^16 / 128` scaling.
    pub(crate) fn invntt(self, p: &mut Poly) {
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::invntt(p),
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Backend::Neon => super::aarch64::invntt(p),
            #[cfg(target_arch = "riscv64")]
            Backend::Rvv => super::riscv64::invntt(p),
            _ => poly::invntt(p),
        }
    }

    /// `r = reduce(sum a[i] o b[i])`.
    pub(crate) fn basemul_acc(self, r: &mut Poly, a: &[Poly], b: &[Poly]) {
        debug_assert!(a.len() == b.len() && a.len() <= 4);
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::basemul_acc(r, a, b),
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Backend::Neon => super::aarch64::basemul_acc(r, a, b),
            #[cfg(target_arch = "riscv64")]
            Backend::Rvv => super::riscv64::basemul_acc(r, a, b),
            _ => poly::basemul_acc(r, a, b),
        }
    }

    /// Barrett-reduces every coefficient.
    pub(crate) fn reduce(self, p: &mut Poly) {
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::reduce(p),
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Backend::Neon => super::aarch64::reduce(p),
            #[cfg(target_arch = "riscv64")]
            Backend::Rvv => super::riscv64::reduce(p),
            _ => poly::reduce(p),
        }
    }

    /// Multiplies every coefficient by `2^16` (Montgomery form).
    pub(crate) fn tomont(self, p: &mut Poly) {
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::tomont(p),
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Backend::Neon => super::aarch64::tomont(p),
            #[cfg(target_arch = "riscv64")]
            Backend::Rvv => super::riscv64::tomont(p),
            _ => poly::tomont(p),
        }
    }

    /// Uniform rejection sampling (public data).
    pub(crate) fn rej_uniform(self, out: &mut [i16; N], ctr: usize, buf: &[u8]) -> usize {
        match self.0 {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Avx2 => super::x86::rej_uniform(out, ctr, buf),
            _ => poly::rej_uniform(out, ctr, buf),
        }
    }
}
