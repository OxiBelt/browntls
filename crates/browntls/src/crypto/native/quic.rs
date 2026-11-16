//! QUIC packet and header protection (RFC 9001 §5.3, §5.4) over
//! `browntls-crypto`: AES-GCM, ChaCha20-Poly1305 and AES-CCM packet
//! protection with AES or ChaCha20 header protection.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::aead::{Aead, TAG_LEN};
use browntls_crypto::aes::{Aes128, Aes256};
use browntls_crypto::ccm::Aes128Ccm;
use browntls_crypto::chacha::{ChaCha20Poly1305, chacha20_xor};
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm};

use crate::crypto::cipher::{AeadKey, Iv};
use crate::error::Error;
use crate::quic::{self, HeaderProtectionKey, PacketKey, SAMPLE_LEN, Tag};

/// AEAD_AES_128_GCM packet protection with AES-128 header protection.
pub static AES_128_GCM: &dyn quic::Algorithm = &QuicAead::<Aes128Gcm> {
    hp: Hp::Aes128,
    limits: Limits::GCM,
    _alg: PhantomData,
};

/// AEAD_AES_256_GCM packet protection with AES-256 header protection.
pub static AES_256_GCM: &dyn quic::Algorithm = &QuicAead::<Aes256Gcm> {
    hp: Hp::Aes256,
    limits: Limits::GCM,
    _alg: PhantomData,
};

/// AEAD_CHACHA20_POLY1305 packet protection with ChaCha20 header protection.
pub static CHACHA20_POLY1305: &dyn quic::Algorithm = &QuicAead::<ChaCha20Poly1305> {
    hp: Hp::ChaCha20,
    limits: Limits::CHACHA20_POLY1305,
    _alg: PhantomData,
};

/// AEAD_AES_128_CCM packet protection with AES-128 header protection.
pub static AES_128_CCM: &dyn quic::Algorithm = &QuicAead::<Aes128Ccm> {
    hp: Hp::Aes128,
    limits: Limits::CCM,
    _alg: PhantomData,
};

/// RFC 9001 §6.6 and Appendix B.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) confidentiality: u64,
    pub(crate) integrity: u64,
}

impl Limits {
    /// AEAD_AES_128_GCM and AEAD_AES_256_GCM: 2^23 packets encrypted, 2^52
    /// forgery attempts.
    pub(crate) const GCM: Self = Self {
        confidentiality: 1 << 23,
        integrity: 1 << 52,
    };
    /// AEAD_CHACHA20_POLY1305: no confidentiality limit below the 2^62
    /// packet numbers; 2^36 forgery attempts.
    pub(crate) const CHACHA20_POLY1305: Self = Self {
        confidentiality: u64::MAX,
        integrity: 1 << 36,
    };
    /// AEAD_AES_128_CCM: 2^21.5 for both, rounded down.
    pub(crate) const CCM: Self = Self {
        confidentiality: 2_965_820,
        integrity: 2_965_820,
    };
}

/// Which block or stream cipher derives the header protection mask.
#[derive(Clone, Copy, Debug)]
enum Hp {
    Aes128,
    Aes256,
    ChaCha20,
}

struct QuicAead<A> {
    hp: Hp,
    limits: Limits,
    _alg: PhantomData<A>,
}

impl<A: Aead + 'static> quic::Algorithm for QuicAead<A> {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        match A::new(key.as_ref()) {
            Ok(cipher) => Box::new(NativePacketKey {
                cipher,
                iv,
                limits: self.limits,
            }),
            Err(_) => Box::new(InvalidKey),
        }
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        let key = key.as_ref();
        let hp = match self.hp {
            Hp::Aes128 => <[u8; 16]>::try_from(key)
                .ok()
                .map(|k| HpKey::Aes128(Aes128::new(&k))),
            Hp::Aes256 => <[u8; 32]>::try_from(key)
                .ok()
                .map(|k| HpKey::Aes256(Aes256::new(&k))),
            Hp::ChaCha20 => <[u8; 32]>::try_from(key).ok().map(HpKey::ChaCha20),
        };
        match hp {
            Some(hp) => Box::new(hp),
            None => Box::new(InvalidKey),
        }
    }

    fn aead_key_len(&self) -> usize {
        A::KEY_LEN
    }
}

impl<A> fmt::Debug for QuicAead<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicAead")
            .field("hp", &self.hp)
            .finish_non_exhaustive()
    }
}

/// One direction's packet protection. The expanded key is zeroised on drop
/// by `browntls-crypto`, the IV by [`Iv`].
struct NativePacketKey<A> {
    cipher: A,
    iv: Iv,
    limits: Limits,
}

impl<A: Aead> PacketKey for NativePacketKey<A> {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = quic::nonce_for(&self.iv, packet_number);
        self.cipher
            .seal_in_place(&nonce, header, payload)
            .map(Tag::from)
            .map_err(|_| Error::EncryptError)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain_len = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let (body, tag) = payload.split_at_mut(plain_len);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().map_err(|_| Error::DecryptError)?;
        let nonce = quic::nonce_for(&self.iv, packet_number);
        // On failure `browntls-crypto` zeroes `body`.
        self.cipher
            .open_in_place(&nonce, header, body, &tag)
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.limits.confidentiality
    }

    fn integrity_limit(&self) -> u64 {
        self.limits.integrity
    }
}

/// Header protection keys (RFC 9001 §5.4.3, §5.4.4).
enum HpKey {
    Aes128(Aes128),
    Aes256(Aes256),
    ChaCha20([u8; 32]),
}

impl Drop for HpKey {
    fn drop(&mut self) {
        // The AES round keys are zeroised by `browntls-crypto`.
        if let Self::ChaCha20(key) = self {
            crate::crypto::zeroize_slice(key);
        }
    }
}

impl HeaderProtectionKey for HpKey {
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let sample: &[u8; SAMPLE_LEN] = sample
            .try_into()
            .map_err(|_| Error::General("QUIC header protection sample must be 16 bytes".into()))?;
        let mut mask = [0u8; 5];
        match self {
            // mask = AES-ECB(hp_key, sample)
            Self::Aes128(aes) => {
                let mut block = *sample;
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            Self::Aes256(aes) => {
                let mut block = *sample;
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            // counter = sample[0..4] (little endian), nonce = sample[4..16],
            // mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
            Self::ChaCha20(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..]);
                chacha20_xor(key, counter, &nonce, &mut mask);
            }
        }
        Ok(mask)
    }
}

/// Stands in for a key that could not be created (a key of the wrong length
/// from a misconfigured suite); every operation fails.
struct InvalidKey;

impl PacketKey for InvalidKey {
    fn encrypt_in_place(&self, _: u64, _: &[u8], _: &mut [u8]) -> Result<Tag, Error> {
        Err(Error::EncryptError)
    }

    fn decrypt_in_place<'a>(&self, _: u64, _: &[u8], _: &'a mut [u8]) -> Result<&'a [u8], Error> {
        Err(Error::DecryptError)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        0
    }

    fn integrity_limit(&self) -> u64 {
        0
    }
}

impl HeaderProtectionKey for InvalidKey {
    fn mask(&self, _: &[u8]) -> Result<[u8; 5], Error> {
        Err(Error::General("invalid QUIC header protection key".into()))
    }
}
