//! The pair of secret-exponent exponentiations of a CRT signature.
//!
//! [`CrtExp`] is created with a key and keeps the backend chosen then: the
//! AVX-512 IFMA dual exponentiation ([`super::ifma`]) when the RSA
//! acceleration policy selects it, otherwise two
//! [`Mont::exp_ct`] calls with the key's Montgomery kernel. Both compute the
//! same values with the same constant-time structure.

use super::HALF_LIMBS;
use super::mont::Mont;

/// Backend for the two CRT exponentiations of a private key.
#[derive(Clone)]
pub(crate) struct CrtExp {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    ifma: Option<super::ifma::CrtIfma>,
}

impl core::fmt::Debug for CrtExp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CrtExp {{ backend: {} }}", self.name())
    }
}

impl CrtExp {
    /// Chooses the backend for primes `p` and `q` under the current policy.
    pub(crate) fn new(p: &Mont<HALF_LIMBS>, q: &Mont<HALF_LIMBS>) -> Self {
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        {
            let ifma = if crate::accel::select::<crate::rsa::RsaBackend>()
                == crate::rsa::RsaBackend::Ifma
            {
                super::ifma::Ifma::detect().and_then(|t| super::ifma::CrtIfma::new(t, p, q))
            } else {
                None
            };
            Self { ifma }
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
        {
            let _ = (p, q);
            Self {}
        }
    }

    /// The portable/scalar backend (two [`Mont::exp_ct`] calls), whatever
    /// the policy (for differential tests).
    #[cfg(test)]
    pub(crate) fn scalar() -> Self {
        Self {
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            ifma: None,
        }
    }

    /// Short backend name for diagnostics.
    pub(crate) fn name(&self) -> &'static str {
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        if self.ifma.is_some() {
            return "avx512-ifma";
        }
        "montgomery"
    }

    /// `out_p = base_p^dp mod p` and `out_q = base_q^dq mod q`, bases and
    /// results in Montgomery form (`p.len() == q.len()` limbs, exponents of
    /// the same length). Constant time.
    #[allow(clippy::too_many_arguments, reason = "two parallel problems")]
    pub(crate) fn exp(
        &self,
        p: &Mont<HALF_LIMBS>,
        q: &Mont<HALF_LIMBS>,
        out_p: &mut [u64],
        out_q: &mut [u64],
        base_p: &[u64],
        base_q: &[u64],
        dp: &[u64],
        dq: &[u64],
    ) {
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        if let Some(ifma) = &self.ifma {
            ifma.exp([out_p, out_q], [base_p, base_q], [dp, dq]);
            return;
        }
        p.exp_ct(out_p, base_p, dp);
        q.exp_ct(out_q, base_q, dq);
    }
}
