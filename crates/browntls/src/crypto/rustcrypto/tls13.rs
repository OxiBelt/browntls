//! TLS 1.3 cipher suites: AES-GCM and ChaCha20-Poly1305 record protection.

use alloc::boxed::Box;
use core::marker::PhantomData;

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};

use super::hash;
use super::hmac;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use crate::crypto::tls13::HkdfUsingHmac;
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls13::Tls13CipherSuite;

/// The AEAD tag length of every supported algorithm.
const TAG_LEN: usize = 16;

/// `TLS13_CHACHA20_POLY1305_SHA256`.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
    aead_alg: &CHACHA20_POLY1305,
};

/// `TLS13_AES_256_GCM_SHA384`.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA384),
        aead_alg: &AES_256_GCM,
    });

/// `TLS13_AES_128_GCM_SHA256`.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
    aead_alg: &AES_128_GCM,
};

/// Which [`ConnectionTrafficSecrets`] variant an algorithm's keys map to.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Kind {
    pub(crate) fn secrets(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::Chacha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

/// A TLS 1.3 AEAD built on any 96-bit-nonce, 128-bit-tag `aead` implementation.
pub(crate) struct Aead<A> {
    kind: Kind,
    _alg: PhantomData<A>,
}

pub(crate) static AES_128_GCM: Aead<aes_gcm::Aes128Gcm> = Aead {
    kind: Kind::Aes128Gcm,
    _alg: PhantomData,
};
pub(crate) static AES_256_GCM: Aead<aes_gcm::Aes256Gcm> = Aead {
    kind: Kind::Aes256Gcm,
    _alg: PhantomData,
};
pub(crate) static CHACHA20_POLY1305: Aead<chacha20poly1305::ChaCha20Poly1305> = Aead {
    kind: Kind::Chacha20Poly1305,
    _alg: PhantomData,
};

/// The bounds an AEAD implementation must satisfy to protect TLS records.
pub(crate) trait TlsAead:
    AeadInOut + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
}

impl<A> TlsAead for A where
    A: AeadInOut + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
}

impl<A: TlsAead> Tls13AeadAlgorithm for Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match A::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(Tls13Encrypter { cipher, iv }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match A::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(Tls13Decrypter { cipher, iv }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_len(&self) -> usize {
        A::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.kind.secrets(key, iv))
    }
}

struct Tls13Encrypter<A> {
    cipher: A,
    iv: Iv,
}

impl<A: TlsAead> MessageEncrypter for Tls13Encrypter<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.0.into(), &aad, InOutBuf::from(payload.as_mut()))
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

impl<A: TlsAead> MessageDecrypter for Tls13Decrypter<A> {
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
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::message::OutboundChunks;

    #[test]
    fn roundtrip_all_aeads() {
        for alg in [
            &AES_128_GCM as &dyn Tls13AeadAlgorithm,
            &AES_256_GCM,
            &CHACHA20_POLY1305,
        ] {
            let key = AeadKey::from([0x42u8; 32]).with_length(alg.key_len());
            let iv = Iv::new([7u8; 12]);
            let mut enc = alg.encrypter(key, iv);
            let key = AeadKey::from([0x42u8; 32]).with_length(alg.key_len());
            let mut dec = alg.decrypter(key, Iv::new([7u8; 12]));

            let plain = OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: OutboundChunks::Single(b"hello world"),
            };
            let opaque = enc.encrypt(plain, 3).unwrap();
            assert_eq!(opaque.typ, ContentType::ApplicationData);
            assert_eq!(opaque.payload.len(), 11 + 1 + 16);
            let mut wire = opaque.encode();

            // wrong sequence number fails
            let mut copy = wire.clone();
            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut copy[5..],
            );
            assert_eq!(dec.decrypt(msg, 4).unwrap_err(), Error::DecryptError);

            // tampering fails
            let mut tampered = wire.clone();
            tampered[7] ^= 1;
            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut tampered[5..],
            );
            assert_eq!(dec.decrypt(msg, 3).unwrap_err(), Error::DecryptError);

            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut wire[5..],
            );
            let plain = dec.decrypt(msg, 3).unwrap();
            assert_eq!(plain.typ, ContentType::Handshake);
            assert_eq!(plain.version, ProtocolVersion::TLSv1_3);
            assert_eq!(plain.payload, b"hello world");

            let mut short = [0u8; 15];
            let msg = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut short,
            );
            assert_eq!(dec.decrypt(msg, 5).unwrap_err(), Error::DecryptError);
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
    }
}
