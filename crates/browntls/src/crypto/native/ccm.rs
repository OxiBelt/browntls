//! AES-CCM record protection for TLS 1.3 (RFC 9846 §5.2, Appendix B.4).
//!
//! | Suite | AEAD | Tag | Confidentiality limit | Integrity limit |
//! |---|---|---|---|---|
//! | `TLS_AES_128_CCM_SHA256` | AEAD_AES_128_CCM (RFC 5116 §5.3) | 16 bytes | 2^23 records | 2^23.5 failed decryptions |
//! | `TLS_AES_128_CCM_8_SHA256` | AEAD_AES_128_CCM_8 (RFC 6655 §6.1) | 8 bytes | 2^23 records | 2^7 failed decryptions |
//!
//! RFC 9846 §5.5 gives key usage limits only for AES-GCM and
//! ChaCha20-Poly1305. The CCM limits are those of RFC 9147 Appendix B,
//! derived for the same targets as TLS 1.3 (an advantage of 2^-60 for
//! confidentiality and 2^-57 for integrity) with 2^14-byte records: the
//! confidentiality limit q <= 2^23 (§B.1) holds for both tag lengths, and the
//! integrity limit is v <= 2^23.5 for 128-bit tags (§B.2) but v <= 2^7 for
//! 64-bit tags (§B.3), which RFC 9147 considers unsuitable for general use.
//!
//! The record layer enforces the confidentiality limit through
//! [`CipherSuiteCommon::confidentiality_limit`](crate::CipherSuiteCommon):
//! the key is updated or the connection closed before it is reached. The
//! integrity limit is enforced here. TLS closes the connection on the first
//! record that fails authentication (RFC 9846 §5.2), but a server that
//! rejects 0-RTT data skips records that fail to decrypt under the handshake
//! key, up to `max_early_data_size` bytes (RFC 9846 §4.2.10; 16384 bytes even
//! when early data is disabled), which alone would allow over 1800 CCM_8
//! forgery attempts. Each decrypter therefore counts the records that fail
//! authentication under its key; once the count reaches the limit it rejects
//! every further record without attempting authentication.
//!
//! The Linux kernel TLS interface offers AES-128-CCM
//! (`TLS_CIPHER_AES_CCM_128`), to which [`ConnectionTrafficSecrets::Aes128Ccm`]
//! maps, but no cipher with an 8-byte tag: extracting CCM_8 keys fails with
//! [`UnsupportedOperationError`].

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::aead::Aead as _;
use browntls_crypto::ccm::{Aes128Ccm, Aes128Ccm8};

use super::aead::Kind;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::ConnectionTrafficSecrets;

/// Records under one key before it must be replaced (RFC 9147 Appendix B.1),
/// for both tag lengths.
pub(crate) const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

/// A CCM parameter set for TLS 1.3 records.
pub(crate) trait Variant: Send + Sync + Sized + 'static {
    /// The AEAD's tag length in bytes.
    const TAG_LEN: usize;
    /// Records that may fail authentication under one key (RFC 9147
    /// Appendix B).
    const INTEGRITY_LIMIT: u64;
    /// The kernel TLS mapping, if any.
    const KIND: Option<Kind>;

    fn new(key: &[u8]) -> Result<Self, browntls_crypto::Error>;

    /// Encrypts `body` in place and writes the tag into `tag`
    /// (`Self::TAG_LEN` bytes).
    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), browntls_crypto::Error>;

    /// Verifies `tag` and decrypts `body` in place; `browntls-crypto` zeroes
    /// `body` on failure and writes no plaintext before verification.
    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), browntls_crypto::Error>;
}

impl Variant for Aes128Ccm {
    const TAG_LEN: usize = 16;
    /// ⌊2^23.5⌋ (RFC 9147 Appendix B.2).
    const INTEGRITY_LIMIT: u64 = 11_863_283;
    const KIND: Option<Kind> = Some(Kind::Aes128Ccm);

    fn new(key: &[u8]) -> Result<Self, browntls_crypto::Error> {
        <Self as browntls_crypto::aead::Aead>::new(key)
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), browntls_crypto::Error> {
        let t = self.seal_in_place(nonce, aad, body)?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), browntls_crypto::Error> {
        let tag = tag
            .try_into()
            .map_err(|_| browntls_crypto::Error::InvalidLength)?;
        self.open_in_place(nonce, aad, body, tag)
    }
}

impl Variant for Aes128Ccm8 {
    const TAG_LEN: usize = Aes128Ccm8::TAG_LEN;
    /// 2^7 (RFC 9147 Appendix B.3).
    const INTEGRITY_LIMIT: u64 = 1 << 7;
    const KIND: Option<Kind> = None;

    fn new(key: &[u8]) -> Result<Self, browntls_crypto::Error> {
        Aes128Ccm8::new(key)
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), browntls_crypto::Error> {
        let t = self.seal_in_place(nonce, aad, body)?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), browntls_crypto::Error> {
        let tag = tag
            .try_into()
            .map_err(|_| browntls_crypto::Error::InvalidLength)?;
        self.open_in_place(nonce, aad, body, tag)
    }
}

/// A TLS 1.3 AEAD over a CCM [`Variant`].
pub(crate) struct Tls13Ccm<V>(PhantomData<V>);

pub(crate) static AES_128_CCM: Tls13Ccm<Aes128Ccm> = Tls13Ccm(PhantomData);
pub(crate) static AES_128_CCM_8: Tls13Ccm<Aes128Ccm8> = Tls13Ccm(PhantomData);

impl<V: Variant> Tls13AeadAlgorithm for Tls13Ccm<V> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match V::new(key.as_ref()) {
            Ok(cipher) => Box::new(Encrypter { cipher, iv }),
            Err(_) => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match V::new(key.as_ref()) {
            Ok(cipher) => Box::new(Decrypter {
                cipher,
                iv,
                failures: 0,
            }),
            Err(_) => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        V::KIND
            .map(|kind| kind.secrets(key, iv))
            .ok_or(UnsupportedOperationError)
    }
}

impl<V: Variant> fmt::Debug for Tls13Ccm<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tls13Ccm(tag_len: {})", V::TAG_LEN)
    }
}

/// Seals records under one traffic key. The expanded key is zeroised on drop
/// by `browntls-crypto`; the IV by [`Iv`].
struct Encrypter<V> {
    cipher: V,
    iv: Iv,
}

impl<V: Variant> MessageEncrypter for Encrypter<V> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // TLSInnerPlaintext = content || ContentType (no padding), then the
        // tag (RFC 9846 §5.2).
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let body_len = payload.len();
        payload.extend_from_slice(&[0u8; 16][..V::TAG_LEN]);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let (body, tag) = payload.as_mut().split_at_mut(body_len);
        self.cipher
            .seal(&nonce.0, &aad, body, tag)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + V::TAG_LEN
    }
}

/// Opens records under one traffic key, counting authentication failures
/// against the integrity limit.
struct Decrypter<V> {
    cipher: V,
    iv: Iv,
    failures: u64,
}

impl<V: Variant> MessageDecrypter for Decrypter<V> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < V::TAG_LEN {
            return Err(Error::DecryptError);
        }
        // RFC 9846 §5.2: TLSInnerPlaintext is at most 2^14 + 1 bytes, so the
        // record expansion is one byte plus this AEAD's tag.
        if payload.len() > MAX_PLAINTEXT_LEN + 1 + V::TAG_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        // RFC 9147 Appendix B: once the integrity limit is reached, no
        // further forgery attempt under this key is evaluated.
        if self.failures >= V::INTEGRITY_LIMIT {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain_len = payload.len() - V::TAG_LEN;
        let (body, tag) = payload.split_at_mut(plain_len);
        if self.cipher.open(&nonce.0, &aad, body, tag).is_err() {
            self.failures += 1;
            return Err(Error::DecryptError);
        }
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

    fn seal(
        enc: &mut dyn MessageEncrypter,
        typ: ContentType,
        payload: &[u8],
        seq: u64,
    ) -> alloc::vec::Vec<u8> {
        let plain = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(payload),
        };
        enc.encrypt(plain, seq).unwrap().encode()
    }

    fn roundtrip_and_rejections<V: Variant>(alg: &Tls13Ccm<V>, tag_len: usize) {
        let key = || AeadKey::new(&[0x42u8; 16]);
        let mut enc = alg.encrypter(key(), Iv::new([7u8; 12]));
        let mut dec = alg.decrypter(key(), Iv::new([7u8; 12]));
        assert_eq!(alg.key_len(), 16);
        assert_eq!(enc.encrypted_payload_len(11), 11 + 1 + tag_len);
        let wire = seal(&mut *enc, ContentType::Handshake, b"hello world", 3);
        assert_eq!(wire[..3], [0x17, 0x03, 0x03]);
        assert_eq!(wire.len(), 5 + 11 + 1 + tag_len);
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            11 + 1 + tag_len
        );

        // A wrong sequence number, a flipped bit anywhere in the record or
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
                Error::DecryptError,
                "byte {i}"
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

        // Shorter than a tag: rejected before any cryptography.
        let mut short = alloc::vec![0u8; 5 + tag_len - 1];
        assert_eq!(
            dec.decrypt(inbound(&mut short), 5).unwrap_err(),
            Error::DecryptError
        );
        // The largest record is 2^14 + 1 + tag bytes; one more is oversized.
        let max = alloc::vec![0x61u8; MAX_PLAINTEXT_LEN];
        let wire = seal(&mut *enc, ContentType::ApplicationData, &max, 9);
        assert_eq!(wire.len(), 5 + MAX_PLAINTEXT_LEN + 1 + tag_len);
        let mut copy = wire.clone();
        assert_eq!(dec.decrypt(inbound(&mut copy), 9).unwrap().payload, max);
        let mut huge = alloc::vec![0u8; 5 + MAX_PLAINTEXT_LEN + 2 + tag_len];
        assert_eq!(
            dec.decrypt(inbound(&mut huge), 5).unwrap_err(),
            Error::PeerSentOversizedRecord
        );
    }

    #[test]
    fn ccm_roundtrip_and_rejections() {
        roundtrip_and_rejections(&AES_128_CCM, 16);
    }

    #[test]
    fn ccm_8_roundtrip_and_rejections() {
        roundtrip_and_rejections(&AES_128_CCM_8, 8);
    }

    /// RFC 5116 / RFC 6655: the record body is the CCM ciphertext followed
    /// by the tag, under the nonce of RFC 9846 §5.3 and the record header
    /// as additional data; the two variants share the keystream.
    #[test]
    fn records_are_ciphertext_then_tag() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let seq = 0x0102_0304_0506_0708;
        let payload = b"0123456789abcdefghij";
        let mut enc = AES_128_CCM.encrypter(AeadKey::new(&key), Iv::new(iv));
        let mut enc8 = AES_128_CCM_8.encrypter(AeadKey::new(&key), Iv::new(iv));
        let wire = seal(&mut *enc, ContentType::ApplicationData, payload, seq);
        let wire8 = seal(&mut *enc8, ContentType::ApplicationData, payload, seq);

        let nonce = Nonce::new(&Iv::new(iv), seq).0;
        let mut inner = payload.to_vec();
        inner.push(ContentType::ApplicationData.into());
        let mut body = inner.clone();
        let tag = <Aes128Ccm as browntls_crypto::aead::Aead>::new(&key)
            .unwrap()
            .seal_in_place(&nonce, &make_tls13_aad(inner.len() + 16), &mut body)
            .unwrap();
        assert_eq!(wire[5..5 + body.len()], body);
        assert_eq!(wire[5 + body.len()..], tag);
        let mut body8 = inner.clone();
        let tag8 = Aes128Ccm8::new(&key)
            .unwrap()
            .seal_in_place(&nonce, &make_tls13_aad(inner.len() + 8), &mut body8)
            .unwrap();
        assert_eq!(body8, body);
        assert_eq!(wire8[5..5 + body.len()], body);
        assert_eq!(wire8[5 + body.len()..], tag8);
    }

    #[test]
    fn integrity_limit_retires_the_key() {
        fn check<V: Variant>(alg: &Tls13Ccm<V>) {
            let key = || AeadKey::new(&[9u8; 16]);
            let mut enc = alg.encrypter(key(), Iv::new([3u8; 12]));
            let mut dec = alg.decrypter(key(), Iv::new([3u8; 12]));
            let wire = seal(&mut *enc, ContentType::ApplicationData, b"data", 0);
            let forged = |wire: &[u8]| {
                let mut t = wire.to_vec();
                let last = t.len() - 1;
                t[last] ^= 0x80;
                t
            };
            for _ in 0..V::INTEGRITY_LIMIT.min(200) {
                let mut f = forged(&wire);
                assert_eq!(
                    dec.decrypt(inbound(&mut f), 0).unwrap_err(),
                    Error::DecryptError
                );
            }
            let mut copy = wire.clone();
            let result = dec
                .decrypt(inbound(&mut copy), 0)
                .map(|m| m.payload.to_vec());
            if V::INTEGRITY_LIMIT <= 200 {
                // Even the genuine record is refused once the limit is hit.
                assert_eq!(result.unwrap_err(), Error::DecryptError);
            } else {
                assert_eq!(result.unwrap(), b"data");
            }
            // A fresh key starts a fresh count.
            let mut dec = alg.decrypter(key(), Iv::new([3u8; 12]));
            let mut copy = wire.clone();
            assert_eq!(dec.decrypt(inbound(&mut copy), 0).unwrap().payload, b"data");
        }
        assert_eq!(<Aes128Ccm8 as Variant>::INTEGRITY_LIMIT, 128);
        check(&AES_128_CCM_8);
        check(&AES_128_CCM);
    }

    #[test]
    fn limits_follow_rfc9147_appendix_b() {
        assert_eq!(CONFIDENTIALITY_LIMIT, 1 << 23);
        // 2^23.5 = 2^23 * sqrt(2); the limit is its integer part.
        let limit = <Aes128Ccm as Variant>::INTEGRITY_LIMIT;
        assert!(limit * limit <= 1 << 47 && (limit + 1) * (limit + 1) > 1 << 47);
    }

    #[test]
    fn key_extraction_maps_ccm_and_refuses_ccm_8() {
        match AES_128_CCM
            .extract_keys(AeadKey::new(&[3u8; 16]), Iv::new([4u8; 12]))
            .unwrap()
        {
            ConnectionTrafficSecrets::Aes128Ccm { key, iv } => {
                assert_eq!(key.as_ref(), [3u8; 16]);
                assert_eq!(iv.as_ref(), [4u8; 12]);
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(
            AES_128_CCM_8
                .extract_keys(AeadKey::new(&[3u8; 16]), Iv::new([4u8; 12]))
                .unwrap_err(),
            UnsupportedOperationError
        );
    }

    #[test]
    fn wrong_key_length_yields_inert_cipher() {
        let mut enc = AES_128_CCM_8.encrypter(AeadKey::new(&[0u8; 32]), Iv::default());
        let plain = OutboundPlainMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(&[1, 0]),
        };
        assert_eq!(enc.encrypt(plain, 0).unwrap_err(), Error::EncryptError);
        let mut dec = AES_128_CCM.decrypter(AeadKey::new(&[0u8; 32]), Iv::default());
        let mut buf = [0u8; 5 + 32];
        assert_eq!(
            dec.decrypt(inbound(&mut buf), 0).unwrap_err(),
            Error::DecryptError
        );
    }
}
