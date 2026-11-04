//! Cipher suite descriptions shared by both protocol versions.

use core::fmt;

use crate::crypto::cipher::{AeadKey, Iv};
use crate::crypto::{self, KeyExchangeAlgorithm};
use crate::enums::{CipherSuite, SignatureAlgorithm};
use crate::msgs::handshake::ALL_KEY_EXCHANGE_ALGORITHMS;
#[cfg(feature = "tls12")]
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
#[cfg(feature = "tls12")]
use crate::versions::TLS12;
use crate::versions::{SupportedProtocolVersion, TLS13};

/// The parts of a cipher suite common to TLS 1.2 and TLS 1.3.
pub struct CipherSuiteCommon {
    /// The suite's code point.
    pub suite: CipherSuite,

    /// The hash used for the transcript and key derivation.
    pub hash_provider: &'static dyn crypto::hash::Hash,

    /// How many records may be protected under one key before it must be
    /// refreshed (TLS 1.3) or the connection closed (TLS 1.2).
    pub confidentiality_limit: u64,
}

impl CipherSuiteCommon {
    /// Whether the hash claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.hash_provider.fips()
    }
}

impl fmt::Debug for CipherSuiteCommon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherSuiteCommon")
            .field("suite", &self.suite)
            .field("confidentiality_limit", &self.confidentiality_limit)
            .finish_non_exhaustive()
    }
}

/// A cipher suite supported by a provider.
#[derive(Clone, Copy, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 suite.
    #[cfg(feature = "tls12")]
    Tls12(&'static Tls12CipherSuite),
    /// A TLS 1.3 suite.
    Tls13(&'static Tls13CipherSuite),
}

impl SupportedCipherSuite {
    /// The suite's code point.
    pub fn suite(&self) -> CipherSuite {
        self.common().suite
    }

    pub(crate) fn hash_provider(&self) -> &'static dyn crypto::hash::Hash {
        self.common().hash_provider
    }

    pub(crate) fn common(&self) -> &CipherSuiteCommon {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => &inner.common,
            Self::Tls13(inner) => &inner.common,
        }
    }

    /// The TLS 1.3 suite, if this is one.
    pub const fn tls13(&self) -> Option<&'static Tls13CipherSuite> {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => None,
            Self::Tls13(inner) => Some(inner),
        }
    }

    /// The protocol version this suite belongs to.
    pub fn version(&self) -> &'static SupportedProtocolVersion {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => &TLS12,
            Self::Tls13(_) => &TLS13,
        }
    }

    /// Whether this suite can be used with certificates of `sig_alg`.
    #[cfg_attr(not(feature = "tls12"), allow(unused_variables))]
    pub fn usable_for_signature_algorithm(&self, sig_alg: SignatureAlgorithm) -> bool {
        match self {
            Self::Tls13(_) => true,
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => inner
                .sign
                .iter()
                .any(|scheme| scheme.algorithm() == Some(sig_alg)),
        }
    }

    /// Whether every component claims FIPS validation.
    pub fn fips(&self) -> bool {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(cs) => cs.fips(),
            Self::Tls13(cs) => cs.fips(),
        }
    }

    pub(crate) fn key_exchange_algorithms(&self) -> &[KeyExchangeAlgorithm] {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(tls12) => core::slice::from_ref(&tls12.kx),
            Self::Tls13(_) => ALL_KEY_EXCHANGE_ALGORITHMS,
        }
    }

    pub(crate) fn usable_for_kx_algorithm(&self, kxa: KeyExchangeAlgorithm) -> bool {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(tls12) => tls12.kx == kxa,
            Self::Tls13(_) => {
                let _ = kxa;
                true
            }
        }
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite().fmt(f)
    }
}

/// Traffic secrets extracted from a connection, with their next sequence numbers.
pub struct ExtractedSecrets {
    /// The transmit direction: `(sequence number, secrets)`.
    pub tx: (u64, ConnectionTrafficSecrets),
    /// The receive direction: `(sequence number, secrets)`.
    pub rx: (u64, ConnectionTrafficSecrets),
}

impl fmt::Debug for ExtractedSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedSecrets")
            .field("tx_seq", &self.tx.0)
            .field("rx_seq", &self.rx.0)
            .finish_non_exhaustive()
    }
}

pub(crate) struct PartiallyExtractedSecrets {
    pub(crate) tx: ConnectionTrafficSecrets,
    pub(crate) rx: ConnectionTrafficSecrets,
}

/// The key material for one direction of traffic.
#[non_exhaustive]
pub enum ConnectionTrafficSecrets {
    /// AES-128-GCM.
    Aes128Gcm {
        /// The key.
        key: AeadKey,
        /// The IV.
        iv: Iv,
    },
    /// AES-256-GCM.
    Aes256Gcm {
        /// The key.
        key: AeadKey,
        /// The IV.
        iv: Iv,
    },
    /// ChaCha20-Poly1305.
    Chacha20Poly1305 {
        /// The key.
        key: AeadKey,
        /// The IV.
        iv: Iv,
    },
    /// AES-128-CCM with a 16-byte tag (Linux `TLS_CIPHER_AES_CCM_128`).
    /// AES-128-CCM-8 has no kernel TLS cipher, so its keys are never
    /// extracted.
    Aes128Ccm {
        /// The key.
        key: AeadKey,
        /// The IV.
        iv: Iv,
    },
}

impl fmt::Debug for ConnectionTrafficSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Aes128Gcm { .. } => "Aes128Gcm(..)",
            Self::Aes256Gcm { .. } => "Aes256Gcm(..)",
            Self::Chacha20Poly1305 { .. } => "Chacha20Poly1305(..)",
            Self::Aes128Ccm { .. } => "Aes128Ccm(..)",
        })
    }
}
