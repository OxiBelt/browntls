//! TLS 1.3 cipher suites and key schedule.

pub(crate) mod key_schedule;

use core::fmt;

use crate::crypto::cipher::Tls13AeadAlgorithm;
use crate::crypto::tls13::Hkdf;
use crate::suites::CipherSuiteCommon;

/// A TLS 1.3 cipher suite.
pub struct Tls13CipherSuite {
    /// The parts shared with TLS 1.2 suites.
    pub common: CipherSuiteCommon,

    /// HKDF with the suite's hash.
    pub hkdf_provider: &'static dyn Hkdf,

    /// The record protection algorithm.
    pub aead_alg: &'static dyn Tls13AeadAlgorithm,
}

impl Tls13CipherSuite {
    /// Whether a session created under `prev` can be resumed with this suite:
    /// the hashes must match (RFC 8446 §4.2.11).
    pub fn can_resume_from(&self, prev: &'static Self) -> Option<&'static Self> {
        (prev.common.hash_provider.algorithm() == self.common.hash_provider.algorithm()).then_some(prev)
    }

    /// Whether every component claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.common.fips() && self.hkdf_provider.fips() && self.aead_alg.fips()
    }
}

impl From<&'static Tls13CipherSuite> for crate::suites::SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        Self::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls13CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13CipherSuite")
            .field("suite", &self.common.suite)
            .finish_non_exhaustive()
    }
}
