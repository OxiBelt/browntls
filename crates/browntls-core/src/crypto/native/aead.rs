//! AEAD record protection algorithms, as trait objects for building custom
//! cipher suites (for example a suite that mixes native AEADs with another
//! provider's hash and key derivation).
//!
//! Every algorithm here uses a 96-bit nonce and encrypts in place with
//! `browntls_crypto::gcm`, `browntls_crypto::chacha` or
//! `browntls_crypto::ccm`. The tag is 128 bits except for AES-128-CCM-8,
//! whose 64-bit tag its record protection (`ccm`) accounts for.

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
/// AES-128-CCM (AEAD_AES_128_CCM, 16-byte tag) for TLS 1.3 records
/// (RFC 9846 Appendix B.4, RFC 5116 §5.3).
pub static TLS13_AES_128_CCM: &dyn Tls13AeadAlgorithm = &super::ccm::AES_128_CCM;
/// AES-128-CCM-8 (AEAD_AES_128_CCM_8, 8-byte tag) for TLS 1.3 records
/// (RFC 9846 Appendix B.4, RFC 6655 §6.1). Its keys cannot be extracted for
/// kernel TLS offload.
pub static TLS13_AES_128_CCM_8: &dyn Tls13AeadAlgorithm = &super::ccm::AES_128_CCM_8;

/// AES-128-GCM for TLS 1.2 records (RFC 5288).
#[cfg(feature = "tls12")]
pub static TLS12_AES_128_GCM: &dyn Tls12AeadAlgorithm = &super::tls12::AES_128_GCM;
/// AES-256-GCM for TLS 1.2 records (RFC 5288).
#[cfg(feature = "tls12")]
pub static TLS12_AES_256_GCM: &dyn Tls12AeadAlgorithm = &super::tls12::AES_256_GCM;
/// ChaCha20-Poly1305 for TLS 1.2 records (RFC 7905).
#[cfg(feature = "tls12")]
pub static TLS12_CHACHA20_POLY1305: &dyn Tls12AeadAlgorithm = &super::tls12::CHACHA20_POLY1305;

/// The tag length of the AEADs behind [`browntls_crypto::aead::Aead`]
/// (AES-GCM, ChaCha20-Poly1305); the CCM record protection uses its own.
pub(crate) const TAG_LEN: usize = browntls_crypto::aead::TAG_LEN;

/// Which [`ConnectionTrafficSecrets`] variant an algorithm's keys map to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Aes128Ccm,
}

impl Kind {
    /// The key material in the form kernel TLS offload expects.
    pub(crate) fn secrets(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::Chacha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
            Self::Aes128Ccm => ConnectionTrafficSecrets::Aes128Ccm { key, iv },
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
