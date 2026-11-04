//! TLS 1.2 CBC cipher suites (RFC 5246 §6.2.3.2, RFC 5289, RFC 8422) with
//! HMAC-SHA1, HMAC-SHA256 or HMAC-SHA384, in MAC-then-encrypt or
//! Encrypt-then-MAC (RFC 7366) order.
//!
//! The record transform lives in `browntls_crypto::tls_cbc`, which processes
//! MAC-then-encrypt records in time independent of the padding (Lucky
//! Thirteen); this module adapts it to the record layer and draws the
//! explicit per-record IV from the operating system (RFC 5246 §6.2.3.2
//! requires an unpredictable IV).
//!
//! These suites form the non-preferred tier of the TLS 1.2 list (see the
//! crate documentation): a browntls peer uses one only when nothing better is
//! shared, and by default only with Encrypt-then-MAC.

use alloc::boxed::Box;
use core::fmt;

use browntls_crypto::cbc::AesCbcKey;
use browntls_crypto::rand::{OsRng, SecureRandom as _};
use browntls_crypto::tls_cbc::{MacAlgorithm, MacOrder, RecordKey};

use super::{hash, prf};
use crate::crypto::KeyExchangeAlgorithm;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12BlockCipherAlgorithm, Tls12MacOrder, Tls12RecordProtection,
};
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};
use crate::tls12::{TLS12_ECDSA_SCHEMES, TLS12_RSA_SCHEMES, Tls12CipherSuite};

/// The CBC block and IV length.
const BLOCK_LEN: usize = 16;

/// Records under one AES-CBC key before the connection must end: with
/// 2^14-byte records this stays well below the 2^34.5-block birthday bound
/// at which 128-bit block collisions leak plaintext (2^-32 probability).
const CBC_CONFIDENTIALITY_LIMIT: u64 = 1 << 24;

macro_rules! cbc_suite {
    ($(#[$m:meta])* $name:ident, $hash:ident, $prf:ident, $sign:ident, $alg:ident) => {
        $(#[$m])*
        pub static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$name,
                hash_provider: &hash::$hash,
                confidentiality_limit: CBC_CONFIDENTIALITY_LIMIT,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            prf_provider: &prf::$prf,
            record: Tls12RecordProtection::BlockCipher(&$alg),
        });
    };
}

// RFC 5246 §5: suites that name no PRF hash use the SHA-256 PRF.
cbc_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (RFC 8422 §6).
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_128_CBC_SHA1
);
cbc_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` (RFC 8422 §6).
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_256_CBC_SHA1
);
cbc_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` (RFC 8422 §6).
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_RSA_SCHEMES,
    AES_128_CBC_SHA1
);
cbc_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` (RFC 8422 §6).
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_RSA_SCHEMES,
    AES_256_CBC_SHA1
);
cbc_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` (RFC 5289 §3.1).
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_128_CBC_SHA256
);
cbc_suite!(
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384` (RFC 5289 §3.1).
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    SHA384_IMPL,
    PRF_SHA384_IMPL,
    TLS12_ECDSA_SCHEMES,
    AES_256_CBC_SHA384
);
cbc_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` (RFC 5289 §3.1).
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    SHA256_IMPL,
    PRF_SHA256_IMPL,
    TLS12_RSA_SCHEMES,
    AES_128_CBC_SHA256
);
cbc_suite!(
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` (RFC 5289 §3.1).
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    SHA384_IMPL,
    PRF_SHA384_IMPL,
    TLS12_RSA_SCHEMES,
    AES_256_CBC_SHA384
);

/// AES-CBC with an HMAC: the `GenericBlockCipher` record protection.
pub(crate) struct AesCbcHmac {
    key_len: usize,
    mac: MacAlgorithm,
}

pub(crate) static AES_128_CBC_SHA1: AesCbcHmac = AesCbcHmac {
    key_len: 16,
    mac: MacAlgorithm::HmacSha1,
};
pub(crate) static AES_256_CBC_SHA1: AesCbcHmac = AesCbcHmac {
    key_len: 32,
    mac: MacAlgorithm::HmacSha1,
};
pub(crate) static AES_128_CBC_SHA256: AesCbcHmac = AesCbcHmac {
    key_len: 16,
    mac: MacAlgorithm::HmacSha256,
};
pub(crate) static AES_256_CBC_SHA384: AesCbcHmac = AesCbcHmac {
    key_len: 32,
    mac: MacAlgorithm::HmacSha384,
};

impl AesCbcHmac {
    fn record_key(
        &self,
        mac_key: &[u8],
        key: &AeadKey,
        order: Tls12MacOrder,
    ) -> Option<RecordKey<AesCbcKey>> {
        let order = match order {
            Tls12MacOrder::MacThenEncrypt => MacOrder::MacThenEncrypt,
            Tls12MacOrder::EncryptThenMac => MacOrder::EncryptThenMac,
        };
        let cipher = AesCbcKey::new(key.as_ref()).ok()?;
        RecordKey::new(cipher, self.mac, mac_key, order).ok()
    }
}

impl Tls12BlockCipherAlgorithm for AesCbcHmac {
    fn encrypter(
        &self,
        mac_key: &[u8],
        key: AeadKey,
        order: Tls12MacOrder,
    ) -> Box<dyn MessageEncrypter> {
        match self.record_key(mac_key, &key, order) {
            Some(key) => Box::new(CbcEncrypter { key }),
            None => <dyn MessageEncrypter>::invalid(),
        }
    }

    fn decrypter(
        &self,
        mac_key: &[u8],
        key: AeadKey,
        order: Tls12MacOrder,
    ) -> Box<dyn MessageDecrypter> {
        match self.record_key(mac_key, &key, order) {
            Some(key) => Box::new(CbcDecrypter { key }),
            None => <dyn MessageDecrypter>::invalid(),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            mac_key_len: self.mac.mac_len(),
            enc_key_len: self.key_len,
            // RFC 5246 §6.3: block ciphers carry an explicit IV in every
            // record; no IV comes from the key block.
            fixed_iv_len: 0,
            explicit_nonce_len: 0,
        }
    }
}

impl fmt::Debug for AesCbcHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tls12AesCbc({}, {:?})", self.key_len * 8, self.mac)
    }
}

struct CbcEncrypter {
    key: RecordKey<AesCbcKey>,
}

impl MessageEncrypter for CbcEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let plaintext_len = msg.payload.len();
        let total_len = self.encrypted_payload_len(plaintext_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&[0u8; BLOCK_LEN]);
        payload.extend_from_chunks(&msg.payload);
        payload.resize(total_len);

        // RFC 5246 §6.2.3.2: the IV must be unpredictable; a fresh random
        // value per record.
        let mut iv = [0u8; BLOCK_LEN];
        OsRng.fill(&mut iv).map_err(|_| Error::EncryptError)?;

        let written = self
            .key
            .seal(
                seq,
                msg.typ.into(),
                msg.version.to_array(),
                &iv,
                payload.as_mut(),
                plaintext_len,
            )
            .map_err(|_| Error::EncryptError)?;
        debug_assert_eq!(written, total_len);
        payload.truncate(written);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        self.key.sealed_len(payload_len)
    }
}

struct CbcDecrypter {
    key: RecordKey<AesCbcKey>,
}

impl MessageDecrypter for CbcDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        // Every failure, including a bad length or padding, is `bad_record_mac`
        // (RFC 5246 §6.2.3.2); the transform itself takes the same time for
        // each of them.
        let range = self
            .key
            .open(
                seq,
                msg.typ.into(),
                msg.version.to_array(),
                payload.as_mut(),
            )
            .map_err(|_| Error::DecryptError)?;
        if range.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.consume_prefix(range.start);
        payload.truncate(range.len());
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

    fn algs() -> [&'static AesCbcHmac; 4] {
        [
            &AES_128_CBC_SHA1,
            &AES_256_CBC_SHA1,
            &AES_128_CBC_SHA256,
            &AES_256_CBC_SHA384,
        ]
    }

    #[test]
    fn roundtrip_both_orders() {
        for alg in algs() {
            for order in [Tls12MacOrder::MacThenEncrypt, Tls12MacOrder::EncryptThenMac] {
                let shape = alg.key_block_shape();
                assert_eq!((shape.fixed_iv_len, shape.explicit_nonce_len), (0, 0));
                let mac_key = alloc::vec![3u8; shape.mac_key_len];
                let key = || AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
                let mut enc = alg.encrypter(&mac_key, key(), order);
                let mut dec = alg.decrypter(&mac_key, key(), order);

                for len in [0usize, 1, 15, 16, 17, 255, 256, 1000, MAX_PLAINTEXT_LEN] {
                    let data = alloc::vec![0x5au8; len];
                    let plain = OutboundPlainMessage {
                        typ: ContentType::ApplicationData,
                        version: ProtocolVersion::TLSv1_2,
                        payload: OutboundChunks::Single(&data),
                    };
                    let opaque = enc.encrypt(plain, 7).unwrap();
                    assert_eq!(opaque.payload.len(), enc.encrypted_payload_len(len));
                    assert!(opaque.payload.len() <= MAX_PLAINTEXT_LEN + 2048);
                    let mut wire = opaque.encode();
                    let got = dec
                        .decrypt(inbound(ContentType::ApplicationData, &mut wire), 7)
                        .unwrap();
                    assert_eq!(got.payload, &data[..]);
                }

                // Two records with equal plaintext differ (fresh IVs).
                let plain = || OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: OutboundChunks::Single(b"same"),
                };
                let a = enc.encrypt(plain(), 1).unwrap().encode();
                let b = enc.encrypt(plain(), 1).unwrap().encode();
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn rejections() {
        for alg in algs() {
            for order in [Tls12MacOrder::MacThenEncrypt, Tls12MacOrder::EncryptThenMac] {
                let shape = alg.key_block_shape();
                let mac_key = alloc::vec![3u8; shape.mac_key_len];
                let key = || AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
                let mut enc = alg.encrypter(&mac_key, key(), order);
                let mut dec = alg.decrypter(&mac_key, key(), order);
                let plain = OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: OutboundChunks::Single(b"tls 1.2 cbc payload"),
                };
                let wire = enc.encrypt(plain, 7).unwrap().encode();

                for i in 5..wire.len() {
                    let mut t = wire.clone();
                    t[i] ^= 0x80;
                    assert_eq!(
                        dec.decrypt(inbound(ContentType::ApplicationData, &mut t), 7)
                            .unwrap_err(),
                        Error::DecryptError,
                        "byte {i}"
                    );
                }
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
                // truncated and non-block-multiple lengths
                for cut in 1..=BLOCK_LEN {
                    let mut short = wire[..wire.len() - cut].to_vec();
                    assert_eq!(
                        dec.decrypt(inbound(ContentType::ApplicationData, &mut short), 7)
                            .unwrap_err(),
                        Error::DecryptError
                    );
                }
                let mut tiny = alloc::vec![0u8; 5 + BLOCK_LEN];
                assert_eq!(
                    dec.decrypt(inbound(ContentType::ApplicationData, &mut tiny), 7)
                        .unwrap_err(),
                    Error::DecryptError
                );
                // Oversized ciphertext (RFC 5246 §6.2.3: at most 2^14 + 2048).
                let mut huge = alloc::vec![0u8; 5 + MAX_PLAINTEXT_LEN + 2048 + BLOCK_LEN];
                assert!(
                    dec.decrypt(inbound(ContentType::ApplicationData, &mut huge), 7)
                        .is_err()
                );
                let mut copy = wire.clone();
                assert_eq!(
                    dec.decrypt(inbound(ContentType::ApplicationData, &mut copy), 7)
                        .unwrap()
                        .payload,
                    b"tls 1.2 cbc payload"
                );
            }
        }
    }

    #[test]
    fn orders_are_incompatible() {
        let alg = &AES_128_CBC_SHA256;
        let shape = alg.key_block_shape();
        let mac_key = alloc::vec![3u8; shape.mac_key_len];
        let key = || AeadKey::from([9u8; 32]).with_length(shape.enc_key_len);
        let mut enc = alg.encrypter(&mac_key, key(), Tls12MacOrder::EncryptThenMac);
        let mut dec = alg.decrypter(&mac_key, key(), Tls12MacOrder::MacThenEncrypt);
        let plain = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(b"x"),
        };
        let mut wire = enc.encrypt(plain, 0).unwrap().encode();
        assert!(
            dec.decrypt(inbound(ContentType::ApplicationData, &mut wire), 0)
                .is_err()
        );
    }

    #[test]
    fn bad_keys_do_not_panic() {
        let _ =
            AES_128_CBC_SHA1.encrypter(&[], AeadKey::new(&[0u8; 7]), Tls12MacOrder::EncryptThenMac);
        let _ = AES_256_CBC_SHA384.decrypter(
            &[1],
            AeadKey::new(&[0u8; 32]),
            Tls12MacOrder::MacThenEncrypt,
        );
    }
}
