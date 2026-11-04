//! TLS 1.2 cipher suites: AES-GCM (RFC 5288) and ChaCha20-Poly1305 (RFC 7905).

use alloc::boxed::Box;
use core::marker::PhantomData;

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadInOut, KeyInit};

use super::hash;
use super::hmac;
use super::tls13::{Kind, TlsAead};
use crate::crypto::KeyExchangeAlgorithm;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use crate::crypto::tls12::PrfUsingHmac;
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls12::{TLS12_ECDSA_SCHEMES, TLS12_RSA_SCHEMES, Tls12CipherSuite};

const TAG_LEN: usize = 16;
/// The explicit nonce carried in each AES-GCM record (RFC 5288 §3).
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_FIXED_IV_LEN: usize = 4;

/// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &CHACHA20_POLY1305,
    });

/// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &CHACHA20_POLY1305,
    });

/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &AES_128_GCM,
    });

/// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA384),
        aead_alg: &AES_256_GCM,
    });

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &AES_128_GCM,
    });

/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        prf_provider: &PrfUsingHmac(&hmac::HMAC_SHA384),
        aead_alg: &AES_256_GCM,
    });

/// AES-GCM in TLS 1.2: a 4-byte fixed IV plus an 8-byte explicit per-record nonce.
pub(crate) struct Gcm<A> {
    kind: Kind,
    _alg: PhantomData<A>,
}

pub(crate) static AES_128_GCM: Gcm<aes_gcm::Aes128Gcm> = Gcm {
    kind: Kind::Aes128Gcm,
    _alg: PhantomData,
};
pub(crate) static AES_256_GCM: Gcm<aes_gcm::Aes256Gcm> = Gcm {
    kind: Kind::Aes256Gcm,
    _alg: PhantomData,
};

impl<A: TlsAead> Tls12AeadAlgorithm for Gcm<A> {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        // The full 12-byte IV is the fixed part followed by the explicit seed;
        // the per-record explicit nonce is then `Nonce(iv, seq)[4..]`.
        let mut iv = [0u8; NONCE_LEN];
        iv[..GCM_FIXED_IV_LEN].copy_from_slice(&write_iv[..GCM_FIXED_IV_LEN.min(write_iv.len())]);
        let n = explicit.len().min(GCM_EXPLICIT_NONCE_LEN);
        iv[GCM_FIXED_IV_LEN..GCM_FIXED_IV_LEN + n].copy_from_slice(&explicit[..n]);
        match A::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(GcmEncrypter {
                cipher,
                iv: Iv::new(iv),
            }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, read_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut fixed = [0u8; GCM_FIXED_IV_LEN];
        let n = read_iv.len().min(GCM_FIXED_IV_LEN);
        fixed[..n].copy_from_slice(&read_iv[..n]);
        match A::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(GcmDecrypter { cipher, fixed }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: A::key_size(),
            fixed_iv_len: GCM_FIXED_IV_LEN,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut full = [0u8; NONCE_LEN];
        let n = iv.len().min(GCM_FIXED_IV_LEN);
        full[..n].copy_from_slice(&iv[..n]);
        let m = explicit.len().min(GCM_EXPLICIT_NONCE_LEN);
        full[GCM_FIXED_IV_LEN..GCM_FIXED_IV_LEN + m].copy_from_slice(&explicit[..m]);
        Ok(self.kind.secrets(key, Iv::new(full)))
    }
}

struct GcmEncrypter<A> {
    cipher: A,
    iv: Iv,
}

impl<A: TlsAead> MessageEncrypter for GcmEncrypter<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let nonce = Nonce::new(&self.iv, seq);
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&nonce.0[GCM_FIXED_IV_LEN..]);
        payload.extend_from_chunks(&msg.payload);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let body = &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..];
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.0.into(), &aad, InOutBuf::from(body))
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + TAG_LEN
    }
}

struct GcmDecrypter<A> {
    cipher: A,
    fixed: [u8; GCM_FIXED_IV_LEN],
}

impl<A: TlsAead> MessageDecrypter for GcmDecrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < GCM_EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }
        let plain_len = payload.len() - GCM_EXPLICIT_NONCE_LEN - TAG_LEN;
        if plain_len > MAX_PLAINTEXT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..GCM_FIXED_IV_LEN].copy_from_slice(&self.fixed);
        nonce[GCM_FIXED_IV_LEN..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);

        let (_, rest) = payload.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let (ciphertext, tag) = rest.split_at_mut(plain_len);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptError)?;
        self.cipher
            .decrypt_inout_detached(&nonce.into(), &aad, InOutBuf::from(ciphertext), &tag.into())
            .map_err(|_| Error::DecryptError)?;
        payload.consume_prefix(GCM_EXPLICIT_NONCE_LEN);
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// ChaCha20-Poly1305 in TLS 1.2 (RFC 7905): a 12-byte IV XORed with the sequence number.
pub(crate) struct ChaCha {
    kind: Kind,
}

pub(crate) static CHACHA20_POLY1305: ChaCha = ChaCha {
    kind: Kind::Chacha20Poly1305,
};

impl Tls12AeadAlgorithm for ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        match chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(ChaChaEncrypter {
                cipher,
                iv: Iv::copy(iv),
            }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        match chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(ChaChaDecrypter {
                cipher,
                iv: Iv::copy(iv),
            }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: NONCE_LEN,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.kind.secrets(key, Iv::copy(iv)))
    }
}

struct ChaChaEncrypter {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for ChaChaEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let nonce = Nonce::new(&self.iv, seq);
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.0.into(), &aad, InOutBuf::from(payload.as_mut()))
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

struct ChaChaDecrypter {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let plain_len = payload.len() - TAG_LEN;
        if plain_len > MAX_PLAINTEXT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (ciphertext, tag) = payload.split_at_mut(plain_len);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptError)?;
        self.cipher
            .decrypt_inout_detached(
                &nonce.0.into(),
                &aad,
                InOutBuf::from(ciphertext),
                &tag.into(),
            )
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::message::OutboundChunks;

    #[test]
    fn roundtrip_tls12_aeads() {
        for alg in [
            &AES_128_GCM as &dyn Tls12AeadAlgorithm,
            &AES_256_GCM,
            &CHACHA20_POLY1305,
        ] {
            let shape = alg.key_block_shape();
            let key = AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
            let iv = alloc::vec![1u8; shape.fixed_iv_len];
            let extra = alloc::vec![2u8; shape.explicit_nonce_len];
            let mut enc = alg.encrypter(key, &iv, &extra);
            let key = AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
            let mut dec = alg.decrypter(key, &iv);

            let plain = OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::Single(b"tls 1.2 payload"),
            };
            let opaque = enc.encrypt(plain, 7).unwrap();
            assert_eq!(opaque.typ, ContentType::ApplicationData);
            assert_eq!(
                opaque.payload.len(),
                15 + shape.explicit_nonce_len + TAG_LEN
            );
            let mut wire = opaque.encode();

            let mut tampered = wire.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x80;
            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut tampered[5..],
            );
            assert_eq!(dec.decrypt(msg, 7).unwrap_err(), Error::DecryptError);

            // wrong content type in AAD fails
            let mut copy = wire.clone();
            let msg = InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut copy[5..],
            );
            assert_eq!(dec.decrypt(msg, 7).unwrap_err(), Error::DecryptError);

            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut wire[5..],
            );
            let plain = dec.decrypt(msg, 7).unwrap();
            assert_eq!(plain.payload, b"tls 1.2 payload");
            assert_eq!(plain.typ, ContentType::ApplicationData);
        }
    }
}
