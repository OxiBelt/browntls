//! AEAD record protection algorithms, as trait objects for building custom
//! cipher suites (for example a suite that mixes native AEADs with another
//! provider's hash and key derivation).
//!
//! Every algorithm here uses a 96-bit nonce and a 128-bit tag and encrypts
//! in place with `browntls_crypto::gcm` / `browntls_crypto::chacha`.

#[cfg(feature = "tls12")]
use crate::crypto::cipher::Tls12AeadAlgorithm;
use crate::crypto::cipher::{AeadKey, Iv, Tls13AeadAlgorithm};
use crate::suites::ConnectionTrafficSecrets;

/// AES-128-GCM for TLS 1.3 records (RFC 8446 §5.2).
pub static TLS13_AES_128_GCM: &dyn Tls13AeadAlgorithm = &super::tls13::AES_128_GCM;
/// AES-256-GCM for TLS 1.3 records (RFC 8446 §5.2).
pub static TLS13_AES_256_GCM: &dyn Tls13AeadAlgorithm = &super::tls13::AES_256_GCM;
/// ChaCha20-Poly1305 for TLS 1.3 records (RFC 8446 §5.2).
pub static TLS13_CHACHA20_POLY1305: &dyn Tls13AeadAlgorithm = &super::tls13::CHACHA20_POLY1305;

/// AES-128-GCM for TLS 1.2 records (RFC 5288).
#[cfg(feature = "tls12")]
pub static TLS12_AES_128_GCM: &dyn Tls12AeadAlgorithm = &super::tls12::AES_128_GCM;
/// AES-256-GCM for TLS 1.2 records (RFC 5288).
#[cfg(feature = "tls12")]
pub static TLS12_AES_256_GCM: &dyn Tls12AeadAlgorithm = &super::tls12::AES_256_GCM;
/// ChaCha20-Poly1305 for TLS 1.2 records (RFC 7905).
#[cfg(feature = "tls12")]
pub static TLS12_CHACHA20_POLY1305: &dyn Tls12AeadAlgorithm = &super::tls12::CHACHA20_POLY1305;

/// The tag length of every supported AEAD.
pub(crate) const TAG_LEN: usize = browntls_crypto::aead::TAG_LEN;

/// Which [`ConnectionTrafficSecrets`] variant an algorithm's keys map to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Kind {
    /// The key material in the form kernel TLS offload expects.
    pub(crate) fn secrets(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::Chacha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

/// Splits `payload` into the ciphertext and the trailing tag.
///
/// The caller has checked `payload.len() >= TAG_LEN`.
pub(crate) fn split_tag(payload: &mut [u8]) -> Option<(&mut [u8], [u8; TAG_LEN])> {
    let body_len = payload.len().checked_sub(TAG_LEN)?;
    let (body, tag) = payload.split_at_mut(body_len);
    let tag: [u8; TAG_LEN] = (&*tag).try_into().ok()?;
    Some((body, tag))
}
