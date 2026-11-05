//! TLS 1.2 cipher suites and record protection: AES-GCM (RFC 5288) and
//! ChaCha20-Poly1305 (RFC 7905).

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::aead::Aead;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm};

use super::aead::{Kind, TAG_LEN, split_tag};
use super::{hash, prf};
use crate::crypto::KeyExchangeAlgorithm;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, Tls12RecordProtection, UnsupportedOperationError,
    make_tls12_aad,
};
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls12::{TLS12_ECDSA_SCHEMES, TLS12_RSA_SCHEMES, Tls12CipherSuite};

/// The explicit nonce carried in each AES-GCM record (RFC 5288 §3).
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
/// The implicit (key block) part of the AES-GCM nonce (RFC 5288 §3).
const GCM_FIXED_IV_LEN: usize = 4;

macro_rules! tls12_suite {
    ($(#[$m:meta])* $name:ident, $suite:ident, $hash:ident, $prf:ident, $sign:ident, $aead:ident, $limit:expr) => {
        $(#[$m])*
        pub static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$suite,
                hash_provider: &hash::$hash,
                confidentiality_limit: $limit,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            prf_provider: &prf::$prf,
            record: Tls12RecordProtection::Aead(&$aead),
        });
    };
}

tls12_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_128_GCM,
    1 << 24
);
tls12_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384_IMPL,
    PRF_SHA384_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_256_GCM,
    1 << 24
);
tls12_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_ECDSA_SCHEMES,
    CHACHA20_POLY1305,
    u64::MAX
);
tls12_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_RSA_SCHEMES,
    AES_128_GCM,
    1 << 24
);
tls12_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384_IMPL,
    PRF_SHA384_IMPL,
    TLS12_RSA_SCHEMES,
    AES_256_GCM,
    1 << 24
);
tls12_suite!(
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_RSA_SCHEMES,
    CHACHA20_POLY1305,
    u64::MAX
);

/// Copies up to `N` bytes of `src` into a zero-padded array.
fn padded<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = src.len().min(N);
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// The 12-byte GCM IV: the 4-byte fixed part followed by the 8-byte seed
/// from which explicit nonces are derived.
fn gcm_iv(fixed: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; NONCE_LEN];
    iv[..GCM_FIXED_IV_LEN].copy_from_slice(&padded::<GCM_FIXED_IV_LEN>(fixed));
    iv[GCM_FIXED_IV_LEN..].copy_from_slice(&padded::<GCM_EXPLICIT_NONCE_LEN>(explicit));
    Iv::new(iv)
}

/// AES-GCM in TLS 1.2: a 4-byte fixed IV plus an 8-byte explicit per-record
/// nonce sent in the clear (RFC 5288 §3).
pub(crate) struct Gcm<A> {
    kind: Kind,
    _alg: PhantomData<A>,
}

pub(crate) static AES_128_GCM: Gcm<Aes128Gcm> = Gcm {
    kind: Kind::Aes128Gcm,
    _alg: PhantomData,
};
pub(crate) static AES_256_GCM: Gcm<Aes256Gcm> = Gcm {
    kind: Kind::Aes256Gcm,
    _alg: PhantomData,
};

impl<A: Aead + 'static> Tls12AeadAlgorithm for Gcm<A> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        // The explicit nonce of record `seq` is `(extra XOR seq)`: unique per
        // record under one key, and not a counter an observer can predict
        // across connections (as rustls and BoringSSL do).
        match A::new(key.as_ref()) {
            Ok(cipher) => Box::new(GcmEncrypter {
                cipher,
                iv: gcm_iv(iv, extra),
            }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        match A::new(key.as_ref()) {
            Ok(cipher) => Box::new(GcmDecrypter {
                cipher,
                fixed: padded(iv),
            }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            mac_key_len: 0,
            enc_key_len: A::KEY_LEN,
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
        // Kernel TLS takes the 4-byte salt and an 8-byte IV; together they are
        // the same 12 bytes as the encrypter's IV.
        Ok(self.kind.secrets(key, gcm_iv(iv, explicit)))
    }
}

impl<A> fmt::Debug for Gcm<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tls12Gcm({:?})", self.kind)
    }
}

struct GcmEncrypter<A> {
    cipher: A,
    iv: Iv,
}

impl<A: Aead> MessageEncrypter for GcmEncrypter<A> {
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
            .seal_in_place(&nonce.0, &aad, body)
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

impl<A: Aead> MessageDecrypter for GcmDecrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let plain_len = payload
            .len()
            .checked_sub(GCM_EXPLICIT_NONCE_LEN + TAG_LEN)
            .ok_or(Error::DecryptError)?;
        if plain_len > MAX_PLAINTEXT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        // nonce = fixed IV || explicit nonce from the record.
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..GCM_FIXED_IV_LEN].copy_from_slice(&self.fixed);
        nonce[GCM_FIXED_IV_LEN..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);

        let (ciphertext, tag) =
            split_tag(&mut payload[GCM_EXPLICIT_NONCE_LEN..]).ok_or(Error::DecryptError)?;
        self.cipher
            .open_in_place(&nonce, &aad, ciphertext, &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.consume_prefix(GCM_EXPLICIT_NONCE_LEN);
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// ChaCha20-Poly1305 in TLS 1.2 (RFC 7905 §2): a 12-byte IV XORed with the
/// sequence number; no explicit nonce.
pub(crate) struct ChaCha;

pub(crate) static CHACHA20_POLY1305: ChaCha = ChaCha;

impl Tls12AeadAlgorithm for ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        match ChaCha20Poly1305::new(key.as_ref()) {
            Ok(cipher) => Box::new(ChaChaEncrypter {
                cipher,
                iv: Iv::copy(iv),
            }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        match ChaCha20Poly1305::new(key.as_ref()) {
            Ok(cipher) => Box::new(ChaChaDecrypter {
                cipher,
                iv: Iv::copy(iv),
            }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            mac_key_len: 0,
            enc_key_len: ChaCha20Poly1305::KEY_LEN,
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
        Ok(Kind::Chacha20Poly1305.secrets(key, Iv::copy(iv)))
    }
}

impl fmt::Debug for ChaCha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tls12ChaCha20Poly1305")
    }
}

struct ChaChaEncrypter {
    cipher: ChaCha20Poly1305,
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
            .seal_in_place(&nonce.0, &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

struct ChaChaDecrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let plain_len = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        if plain_len > MAX_PLAINTEXT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (ciphertext, tag) = split_tag(payload).ok_or(Error::DecryptError)?;
        self.cipher
            .open_in_place(&nonce.0, &aad, ciphertext, &tag)
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

    fn inbound(typ: ContentType, wire: &mut [u8]) -> InboundOpaqueMessage<'_> {
        InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, &mut wire[5..])
    }

    #[test]
    fn roundtrip_and_rejections() {
        for alg in [
            &AES_128_GCM as &dyn Tls12AeadAlgorithm,
            &AES_256_GCM,
            &CHACHA20_POLY1305,
        ] {
            let shape = alg.key_block_shape();
            let key = || AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
            let iv = alloc::vec![1u8; shape.fixed_iv_len];
            let extra = alloc::vec![2u8; shape.explicit_nonce_len];
            let mut enc = alg.encrypter(key(), &iv, &extra);
            let mut dec = alg.decrypter(key(), &iv);

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
            let wire = opaque.encode();
            if shape.explicit_nonce_len == 8 {
                // explicit nonce = extra XOR seq
                assert_eq!(&wire[5..13], &[2, 2, 2, 2, 2, 2, 2, 5]);
            }

            for i in 5..wire.len() {
                let mut t = wire.clone();
                t[i] ^= 0x80;
                assert_eq!(
                    dec.decrypt(inbound(ContentType::ApplicationData, &mut t), 7)
                        .unwrap_err(),
                    Error::DecryptError
                );
            }
            // wrong content type or sequence number in the AAD fails
            let mut copy = wire.clone();
            assert_eq!(
                dec.decrypt(inbound(ContentType::Handshake, &mut copy), 7)
                    .unwrap_err(),
                Error::DecryptError
            );
            let mut copy = wire.clone();
            assert_eq!(
                dec.decrypt(inbound(ContentType::ApplicationData, &mut copy), 8)
                    .unwrap_err(),
                Error::DecryptError
            );

            let mut copy = wire.clone();
            let plain = dec
                .decrypt(inbound(ContentType::ApplicationData, &mut copy), 7)
                .unwrap();
            assert_eq!(plain.payload, b"tls 1.2 payload");
            assert_eq!(plain.typ, ContentType::ApplicationData);

            let mut short = alloc::vec![0u8; 5 + shape.explicit_nonce_len + TAG_LEN - 1];
            assert_eq!(
                dec.decrypt(inbound(ContentType::ApplicationData, &mut short), 0)
                    .unwrap_err(),
                Error::DecryptError
            );
            let mut huge =
                alloc::vec![0u8; 5 + shape.explicit_nonce_len + MAX_PLAINTEXT_LEN + 1 + TAG_LEN];
            assert_eq!(
                dec.decrypt(inbound(ContentType::ApplicationData, &mut huge), 0)
                    .unwrap_err(),
                Error::PeerSentOversizedRecord
            );
        }
    }

    #[test]
    fn short_ivs_do_not_panic() {
        let _ = AES_128_GCM.encrypter(AeadKey::new(&[0u8; 16]), &[], &[]);
        let _ = AES_128_GCM.decrypter(AeadKey::new(&[0u8; 16]), &[1]);
        let _ = CHACHA20_POLY1305.encrypter(AeadKey::new(&[0u8; 32]), &[], &[]);
        let secrets = AES_128_GCM
            .extract_keys(AeadKey::new(&[5u8; 16]), &[1, 2, 3, 4], &[9; 8])
            .unwrap();
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                assert_eq!(key.as_ref(), [5u8; 16]);
                assert_eq!(iv.as_ref(), [1, 2, 3, 4, 9, 9, 9, 9, 9, 9, 9, 9]);
            }
            _ => panic!("wrong variant"),
        }
    }
}
