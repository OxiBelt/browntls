//! Session ticket encryption with AES-256-GCM under a random key.

use alloc::vec::Vec;
use core::fmt;

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{self, AeadInOut, KeyInit};

use crate::crypto::TicketProducer;
use crate::crypto::cipher::AeadKey;
use crate::rand::GetRandomFailed;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypts tickets with AES-256-GCM. Each ticket carries a fresh random
/// nonce: `nonce || ciphertext || tag`.
pub struct AeadTicketProducer {
    cipher: aes_gcm::Aes256Gcm,
}

impl AeadTicketProducer {
    /// Generates a fresh random key.
    pub fn new() -> Result<Self, GetRandomFailed> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| GetRandomFailed)?;
        let key = AeadKey::from(key);
        let cipher =
            aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| GetRandomFailed)?;
        Ok(Self { cipher })
    }
}

impl TicketProducer for AeadTicketProducer {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).ok()?;
        let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(&mut out[NONCE_LEN..]))
            .ok()?;
        out.extend_from_slice(&tag);
        Some(out)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let nonce: aead::Nonce<aes_gcm::Aes256Gcm> = cipher[..NONCE_LEN].try_into().ok()?;
        let body_len = cipher.len() - NONCE_LEN - TAG_LEN;
        let mut body = cipher[NONCE_LEN..NONCE_LEN + body_len].to_vec();
        let tag: aead::Tag<aes_gcm::Aes256Gcm> = cipher[NONCE_LEN + body_len..].try_into().ok()?;
        self.cipher
            .decrypt_inout_detached(&nonce, &[], InOutBuf::from(body.as_mut_slice()), &tag)
            .ok()?;
        Some(body)
    }
}

impl fmt::Debug for AeadTicketProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadTicketProducer(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let t = AeadTicketProducer::new().unwrap();
        let ct = t.encrypt(b"session state").unwrap();
        assert_eq!(ct.len(), NONCE_LEN + 13 + TAG_LEN);
        assert_eq!(t.decrypt(&ct).unwrap(), b"session state");
        let mut bad = ct.clone();
        bad[NONCE_LEN] ^= 1;
        assert!(t.decrypt(&bad).is_none());
        assert!(t.decrypt(&ct[..10]).is_none());
        let other = AeadTicketProducer::new().unwrap();
        assert!(other.decrypt(&ct).is_none());
    }
}
