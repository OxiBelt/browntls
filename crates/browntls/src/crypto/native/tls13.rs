//! TLS 1.3 cipher suites and record protection (RFC 8446 §5.2, §5.3).

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::aead::Aead;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm};

use super::aead::{Kind, TAG_LEN, split_tag};
use super::{hash, hkdf};
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls13::Tls13CipherSuite;

/// `TLS13_AES_128_GCM_SHA256`.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256_IMPL,
            // RFC 8446 §5.5 and the AEAD limits analysis: 2^24.5 full-size
            // records; rounded down.
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &hkdf::HKDF_SHA256_IMPL,
        aead_alg: &AES_128_GCM,
    });

/// `TLS13_AES_256_GCM_SHA384`.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384_IMPL,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &hkdf::HKDF_SHA384_IMPL,
        aead_alg: &AES_256_GCM,
    });

/// `TLS13_CHACHA20_POLY1305_SHA256`.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256_IMPL,
            // RFC 8446 §5.5: the ChaCha20-Poly1305 limit exceeds 2^64 records.
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &hkdf::HKDF_SHA256_IMPL,
        aead_alg: &CHACHA20_POLY1305,
    });

/// A TLS 1.3 AEAD over a `browntls-crypto` [`Aead`].
pub(crate) struct Tls13Aead<A> {
    kind: Kind,
    _alg: PhantomData<A>,
}

pub(crate) static AES_128_GCM: Tls13Aead<Aes128Gcm> = Tls13Aead {
    kind: Kind::Aes128Gcm,
    _alg: PhantomData,
};
pub(crate) static AES_256_GCM: Tls13Aead<Aes256Gcm> = Tls13Aead {
    kind: Kind::Aes256Gcm,
    _alg: PhantomData,
};
pub(crate) static CHACHA20_POLY1305: Tls13Aead<ChaCha20Poly1305> = Tls13Aead {
    kind: Kind::Chacha20Poly1305,
    _alg: PhantomData,
};

impl<A: Aead + 'static> Tls13AeadAlgorithm for Tls13Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match A::new(key.as_ref()) {
            Ok(cipher) => Box::new(Tls13Encrypter { cipher, iv }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match A::new(key.as_ref()) {
            Ok(cipher) => Box::new(Tls13Decrypter { cipher, iv }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_len(&self) -> usize {
        A::KEY_LEN
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.kind.secrets(key, iv))
    }
}

impl<A> fmt::Debug for Tls13Aead<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tls13Aead({:?})", self.kind)
    }
}

/// Seals records under one traffic key. The expanded key is zeroised on drop
/// by `browntls-crypto`; the IV by [`Iv`].
struct Tls13Encrypter<A> {
    cipher: A,
    iv: Iv,
}

impl<A: Aead> MessageEncrypter for Tls13Encrypter<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // TLSInnerPlaintext = content || ContentType (no padding).
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let tag = self
            .cipher
            .seal_in_place(&nonce.0, &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

struct Tls13Decrypter<A> {
    cipher: A,
    iv: Iv,
}

impl<A: Aead> MessageDecrypter for Tls13Decrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        // RFC 8446 §5.2: TLSInnerPlaintext is at most 2^14 + 1 bytes.
        if payload.len() > MAX_PLAINTEXT_LEN + 1 + TAG_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain_len = payload.len() - TAG_LEN;
        let (ciphertext, tag) = split_tag(payload).ok_or(Error::DecryptError)?;
        // On failure `browntls-crypto` zeroes the buffer: no unauthenticated
        // plaintext is released.
        self.cipher
            .open_in_place(&nonce.0, &aad, ciphertext, &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::message::OutboundChunks;

    fn inbound(wire: &mut [u8]) -> InboundOpaqueMessage<'_> {
        InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut wire[5..],
        )
    }

    #[test]
    fn roundtrip_and_rejections() {
        for alg in [
            &AES_128_GCM as &dyn Tls13AeadAlgorithm,
            &AES_256_GCM,
            &CHACHA20_POLY1305,
        ] {
            let key = || AeadKey::from([0x42u8; 32]).with_length(alg.key_len());
            let mut enc = alg.encrypter(key(), Iv::new([7u8; 12]));
            let mut dec = alg.decrypter(key(), Iv::new([7u8; 12]));

            let plain = OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: OutboundChunks::Single(b"hello world"),
            };
            assert_eq!(enc.encrypted_payload_len(11), 11 + 1 + 16);
            let opaque = enc.encrypt(plain, 3).unwrap();
            assert_eq!(opaque.typ, ContentType::ApplicationData);
            assert_eq!(opaque.version, ProtocolVersion::TLSv1_2);
            let wire = opaque.encode();
            assert_eq!(wire.len(), 5 + 11 + 1 + 16);

            // A wrong sequence number, a flipped bit anywhere in the body, or
            // a truncated body (which changes the AAD length) must all fail.
            let mut copy = wire.clone();
            assert_eq!(
                dec.decrypt(inbound(&mut copy), 4).unwrap_err(),
                Error::DecryptError
            );
            for i in 5..wire.len() {
                let mut t = wire.clone();
                t[i] ^= 1;
                assert_eq!(
                    dec.decrypt(inbound(&mut t), 3).unwrap_err(),
                    Error::DecryptError
                );
            }
            let mut copy = wire.clone();
            let mut msg = inbound(&mut copy);
            msg.payload.truncate(msg.payload.len() - 1);
            assert_eq!(dec.decrypt(msg, 3).unwrap_err(), Error::DecryptError);

            let mut copy = wire.clone();
            let plain = dec.decrypt(inbound(&mut copy), 3).unwrap();
            assert_eq!(plain.typ, ContentType::Handshake);
            assert_eq!(plain.version, ProtocolVersion::TLSv1_3);
            assert_eq!(plain.payload, b"hello world");

            let mut short = [0u8; 5 + 15];
            assert_eq!(
                dec.decrypt(inbound(&mut short), 5).unwrap_err(),
                Error::DecryptError
            );
            let mut huge = alloc::vec![0u8; 5 + MAX_PLAINTEXT_LEN + 2 + TAG_LEN];
            assert_eq!(
                dec.decrypt(inbound(&mut huge), 5).unwrap_err(),
                Error::PeerSentOversizedRecord
            );
        }
    }

    #[test]
    fn wrong_key_length_yields_inert_cipher() {
        let mut enc = AES_128_GCM.encrypter(AeadKey::from([0u8; 32]), Iv::default());
        let plain = OutboundPlainMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(&[1, 0]),
        };
        assert_eq!(enc.encrypt(plain, 0).unwrap_err(), Error::EncryptError);
        let mut dec = CHACHA20_POLY1305.decrypter(AeadKey::new(&[0u8; 16]), Iv::default());
        let mut buf = [0u8; 5 + 32];
        assert_eq!(
            dec.decrypt(inbound(&mut buf), 0).unwrap_err(),
            Error::DecryptError
        );
    }

    #[test]
    fn extract_keys_preserves_material() {
        let secrets = AES_256_GCM
            .extract_keys(AeadKey::from([3u8; 32]), Iv::new([4u8; 12]))
            .unwrap();
        match secrets {
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                assert_eq!(key.as_ref(), [3u8; 32]);
                assert_eq!(iv.as_ref(), [4u8; 12]);
            }
            _ => panic!("wrong variant"),
        }
    }
}
