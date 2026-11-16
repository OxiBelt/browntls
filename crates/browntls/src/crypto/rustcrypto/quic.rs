//! QUIC packet and header protection (RFC 9001 §5.3, §5.4) over the
//! RustCrypto `aes-gcm`, `chacha20poly1305` and `aes` crates.
//!
//! ChaCha20 header protection computes the one keystream block it needs
//! here: the `chacha20` crate refuses block counter 0xffffffff (the end of
//! its keystream), which a peer can put in a header protection sample.

use alloc::boxed::Box;
use core::marker::PhantomData;

use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
use aes_gcm::aead::inout::InOutBuf;

use super::tls13::TlsAead;
use crate::crypto::cipher::{AeadKey, Iv};
use crate::error::Error;
use crate::quic::{self, HeaderProtectionKey, PacketKey, SAMPLE_LEN, Tag};

const TAG_LEN: usize = 16;

/// AEAD_AES_128_GCM packet protection with AES-128 header protection.
pub(crate) static AES_128_GCM: &dyn quic::Algorithm = &QuicAead::<aes_gcm::Aes128Gcm> {
    hp: Hp::Aes128,
    limits: (1 << 23, 1 << 52),
    _alg: PhantomData,
};

/// AEAD_AES_256_GCM packet protection with AES-256 header protection.
pub(crate) static AES_256_GCM: &dyn quic::Algorithm = &QuicAead::<aes_gcm::Aes256Gcm> {
    hp: Hp::Aes256,
    limits: (1 << 23, 1 << 52),
    _alg: PhantomData,
};

/// AEAD_CHACHA20_POLY1305 packet protection with ChaCha20 header protection.
pub(crate) static CHACHA20_POLY1305: &dyn quic::Algorithm =
    &QuicAead::<chacha20poly1305::ChaCha20Poly1305> {
        hp: Hp::ChaCha20,
        limits: (u64::MAX, 1 << 36),
        _alg: PhantomData,
    };

#[derive(Clone, Copy)]
enum Hp {
    Aes128,
    Aes256,
    ChaCha20,
}

struct QuicAead<A> {
    hp: Hp,
    /// (confidentiality, integrity), RFC 9001 §6.6.
    limits: (u64, u64),
    _alg: PhantomData<A>,
}

impl<A: TlsAead> quic::Algorithm for QuicAead<A> {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        match A::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(RcPacketKey {
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
            Hp::Aes128 => aes::Aes128::new_from_slice(key).ok().map(HpKey::Aes128),
            Hp::Aes256 => aes::Aes256::new_from_slice(key).ok().map(HpKey::Aes256),
            Hp::ChaCha20 => <[u8; 32]>::try_from(key).ok().map(HpKey::ChaCha20),
        };
        match hp {
            Some(hp) => Box::new(hp),
            None => Box::new(InvalidKey),
        }
    }

    fn aead_key_len(&self) -> usize {
        A::key_size()
    }
}

struct RcPacketKey<A> {
    cipher: A,
    iv: Iv,
    limits: (u64, u64),
}

impl<A: TlsAead> PacketKey for RcPacketKey<A> {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = quic::nonce_for(&self.iv, packet_number);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.into(), header, InOutBuf::from(payload))
            .map_err(|_| Error::EncryptError)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(Tag::from(out))
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
        if self
            .cipher
            .decrypt_inout_detached(
                &nonce.into(),
                header,
                InOutBuf::from(&mut *body),
                &tag.into(),
            )
            .is_err()
        {
            body.fill(0);
            return Err(Error::DecryptError);
        }
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.limits.0
    }

    fn integrity_limit(&self) -> u64 {
        self.limits.1
    }
}

/// Header protection keys (RFC 9001 §5.4.3, §5.4.4). The AES key schedules
/// are zeroised on drop by the `aes` crate's `zeroize` feature.
enum HpKey {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
    ChaCha20([u8; 32]),
}

impl Drop for HpKey {
    fn drop(&mut self) {
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
            Self::Aes128(aes) => {
                let mut block = (*sample).into();
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            Self::Aes256(aes) => {
                let mut block = (*sample).into();
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            // counter = sample[0..4] (little endian), nonce = sample[4..16],
            // mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
            Self::ChaCha20(key) => {
                let mut block = chacha20_block(key, sample);
                mask.copy_from_slice(&block[..5]);
                crate::crypto::zeroize_slice(&mut block);
            }
        }
        Ok(mask)
    }
}

/// The ChaCha20 block function (RFC 8439 §2.3) for `key`, with the block
/// counter and nonce taken from a header protection sample (RFC 9001
/// §5.4.4). Any counter value, 0xffffffff included, is valid.
fn chacha20_block(key: &[u8; 32], sample: &[u8; SAMPLE_LEN]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
        state[4 + i] = u32::from_le_bytes(*chunk);
    }
    for (i, chunk) in sample.as_chunks::<4>().0.iter().enumerate() {
        state[12 + i] = u32::from_le_bytes(*chunk);
    }

    let mut x = state;
    let quarter = |x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(7);
    };
    for _ in 0..10 {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 1, 5, 9, 13);
        quarter(&mut x, 2, 6, 10, 14);
        quarter(&mut x, 3, 7, 11, 15);
        quarter(&mut x, 0, 5, 10, 15);
        quarter(&mut x, 1, 6, 11, 12);
        quarter(&mut x, 2, 7, 8, 13);
        quarter(&mut x, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, chunk) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *chunk = x[i].wrapping_add(state[i]).to_le_bytes();
    }
    // The state holds the header protection key.
    for word in state.iter_mut().chain(x.iter_mut()) {
        *word = 0;
    }
    core::hint::black_box((&state, &x));
    out
}

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
