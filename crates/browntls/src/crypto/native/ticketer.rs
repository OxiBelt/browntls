//! Session ticket encryption with AES-256-GCM under a random key.

use alloc::vec::Vec;
use core::fmt;

use browntls_crypto::aead::{Aead, NONCE_LEN, TAG_LEN};
use browntls_crypto::gcm::Aes256Gcm;
use browntls_crypto::rand::{OsRng, SecureRandom as _};
use browntls_crypto::zeroize::zeroize_bytes;

use crate::crypto::TicketProducer;
use crate::rand::GetRandomFailed;

/// Encrypts tickets with AES-256-GCM. Each ticket carries a fresh random
/// nonce: `nonce || ciphertext || tag`.
///
/// With 96-bit random nonces a key must not seal more than about 2^32
/// tickets (NIST SP 800-38D §8.3), so callers must replace the producer
/// (rotate the key) well before that. The expanded key is zeroised on drop.
pub struct AeadTicketProducer {
    cipher: Aes256Gcm,
}

impl AeadTicketProducer {
    /// Generates a producer with a fresh random key.
    pub fn new() -> Result<Self, GetRandomFailed> {
        let mut key = [0u8; 32];
        let cipher = OsRng
            .fill(&mut key)
            .map_err(|_| GetRandomFailed)
            .and_then(|()| Aes256Gcm::new(&key).map_err(|_| GetRandomFailed));
        zeroize_bytes(&mut key);
        Ok(Self { cipher: cipher? })
    }
}

impl TicketProducer for AeadTicketProducer {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill(&mut nonce).ok()?;
        let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let tag = self
            .cipher
            .seal_in_place(&nonce, &[], &mut out[NONCE_LEN..])
            .ok()?;
        out.extend_from_slice(&tag);
        Some(out)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let body_len = cipher.len().checked_sub(NONCE_LEN + TAG_LEN)?;
        let (nonce, rest) = cipher.split_at(NONCE_LEN);
        let (body, tag) = rest.split_at(body_len);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().ok()?;
        let tag: &[u8; TAG_LEN] = tag.try_into().ok()?;
        let mut plain = body.to_vec();
        // On failure the buffer is zeroed; it is dropped either way.
        self.cipher
            .open_in_place(nonce, &[], &mut plain, tag)
            .ok()?;
        Some(plain)
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
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert!(t.decrypt(&bad).is_none());
        }
        for len in 0..NONCE_LEN + TAG_LEN {
            assert!(t.decrypt(&ct[..len]).is_none());
        }
        let other = AeadTicketProducer::new().unwrap();
        assert!(other.decrypt(&ct).is_none());
        // Nonces are fresh per ticket.
        assert_ne!(t.encrypt(b"x").unwrap(), t.encrypt(b"x").unwrap());
        let empty = t.encrypt(b"").unwrap();
        assert_eq!(t.decrypt(&empty).unwrap(), b"");
    }
}
