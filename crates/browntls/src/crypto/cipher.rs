//! Record protection: AEAD algorithms and the message encrypter/decrypter traits.

use alloc::boxed::Box;
use core::fmt;

use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::codec::{put_u16, put_u64};
pub use crate::msgs::message::{
    BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, OutboundChunks,
    OutboundOpaqueMessage, OutboundPlainMessage, PlainMessage, PrefixedPayload,
};
use crate::suites::ConnectionTrafficSecrets;

/// An AEAD usable with TLS 1.3 (RFC 8446 §5.2).
pub trait Tls13AeadAlgorithm: Send + Sync {
    /// Creates a record encrypter from the traffic key and IV.
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;

    /// Creates a record decrypter from the traffic key and IV.
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;

    /// The key length in bytes.
    fn key_len(&self) -> usize;

    /// Converts the traffic key and IV into a form usable outside the library
    /// (kernel TLS offload).
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// An AEAD usable with TLS 1.2 (RFC 5246 §6.2.3.3).
pub trait Tls12AeadAlgorithm: Send + Sync + 'static {
    /// Creates a record encrypter from the write key, the fixed IV and the
    /// `extra` bytes that seed the explicit nonce.
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Creates a record decrypter from the read key and the fixed IV.
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;

    /// How the key block is split for this algorithm.
    fn key_block_shape(&self) -> KeyBlockShape;

    /// Converts the key material into a form usable outside the library.
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// The operation is not supported by this algorithm.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct UnsupportedOperationError;

impl From<UnsupportedOperationError> for Error {
    fn from(_: UnsupportedOperationError) -> Self {
        Self::general("operation not supported")
    }
}

impl fmt::Display for UnsupportedOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation not supported")
    }
}

impl core::error::Error for UnsupportedOperationError {}

/// How a TLS 1.2 key block is split (RFC 5246 §6.3).
///
/// The key block is `client_write_MAC_key || server_write_MAC_key ||
/// client_write_key || server_write_key || client_write_IV ||
/// server_write_IV`, followed (for AEADs with an explicit nonce) by the
/// per-connection seeds of the explicit nonces.
#[derive(Debug, Clone, Copy)]
pub struct KeyBlockShape {
    /// The length of each MAC key (0 for AEADs).
    pub mac_key_len: usize,
    /// The length of each write key.
    pub enc_key_len: usize,
    /// The length of each fixed IV (0 for block ciphers, whose IV is
    /// explicit in every record).
    pub fixed_iv_len: usize,
    /// The length of the explicit per-record nonce (0 for ChaCha20-Poly1305
    /// and block ciphers).
    pub explicit_nonce_len: usize,
}

impl KeyBlockShape {
    /// The total key block length.
    pub fn total_len(&self) -> usize {
        (self.mac_key_len + self.enc_key_len + self.fixed_iv_len + self.explicit_nonce_len) * 2
    }
}

/// The order of encryption and MAC for a TLS 1.2 block cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12MacOrder {
    /// `encrypt(data || MAC || padding)` (RFC 5246 §6.2.3.2). Its padding
    /// check is a known timing side channel (Lucky Thirteen); the receiver
    /// has to process every record in time independent of the padding.
    MacThenEncrypt,
    /// `encrypt(data || padding) || MAC` (RFC 7366), negotiated with the
    /// `encrypt_then_mac` extension. RFC 9325 §4.2 says a CBC suite should
    /// not be used without it.
    EncryptThenMac,
}

/// A block cipher with an HMAC usable with TLS 1.2 (`GenericBlockCipher`,
/// RFC 5246 §6.2.3.2), in either MAC order.
///
/// The explicit per-record IV is the implementation's responsibility: it
/// must be unpredictable (RFC 5246 §6.2.3.2).
pub trait Tls12BlockCipherAlgorithm: Send + Sync + 'static {
    /// Creates a record encrypter from the write MAC key and write key.
    fn encrypter(
        &self,
        mac_key: &[u8],
        key: AeadKey,
        order: Tls12MacOrder,
    ) -> Box<dyn MessageEncrypter>;

    /// Creates a record decrypter from the read MAC key and read key.
    fn decrypter(
        &self,
        mac_key: &[u8],
        key: AeadKey,
        order: Tls12MacOrder,
    ) -> Box<dyn MessageDecrypter>;

    /// How the key block is split for this algorithm (`fixed_iv_len` and
    /// `explicit_nonce_len` are zero).
    fn key_block_shape(&self) -> KeyBlockShape;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// The record protection of a TLS 1.2 cipher suite (RFC 5246 §6.2.3).
#[derive(Clone, Copy)]
pub enum Tls12RecordProtection {
    /// `GenericAEADCipher` (RFC 5246 §6.2.3.3).
    Aead(&'static dyn Tls12AeadAlgorithm),
    /// `GenericBlockCipher` (RFC 5246 §6.2.3.2), with or without
    /// Encrypt-then-MAC (RFC 7366). `GenericStreamCipher` suites are not
    /// supported (RC4 is prohibited by RFC 7465).
    BlockCipher(&'static dyn Tls12BlockCipherAlgorithm),
}

impl Tls12RecordProtection {
    /// How the key block is split.
    pub fn key_block_shape(&self) -> KeyBlockShape {
        match self {
            Self::Aead(alg) => alg.key_block_shape(),
            Self::BlockCipher(alg) => alg.key_block_shape(),
        }
    }

    /// Whether this is a block cipher, to which `encrypt_then_mac` applies.
    pub fn is_block_cipher(&self) -> bool {
        matches!(self, Self::BlockCipher(_))
    }

    /// Whether the implementation is FIPS validated.
    pub fn fips(&self) -> bool {
        match self {
            Self::Aead(alg) => alg.fips(),
            Self::BlockCipher(alg) => alg.fips(),
        }
    }
}

impl fmt::Debug for Tls12RecordProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Aead(_) => "Tls12RecordProtection::Aead",
            Self::BlockCipher(_) => "Tls12RecordProtection::BlockCipher",
        })
    }
}

/// Decrypts records.
pub trait MessageDecrypter: Send + Sync {
    /// Decrypts `msg` in place; `seq` is the record sequence number.
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error>;

    /// Whether too many records have failed authentication under this key
    /// for it to be used again (an AEAD integrity limit, for example
    /// RFC 9147 Appendix B for AES-CCM-8).
    ///
    /// Once this returns `true`, a decryption failure is fatal even where the
    /// record layer would otherwise skip undecryptable records (rejected
    /// 0-RTT data), so the connection fails with `bad_record_mac` instead of
    /// waiting for records the key can no longer accept.
    fn integrity_limit_reached(&self) -> bool {
        false
    }
}

/// Encrypts records.
pub trait MessageEncrypter: Send + Sync {
    /// Encrypts `msg`; `seq` is the record sequence number.
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error>;

    /// The ciphertext length (excluding the record header) for a plaintext of `payload_len`.
    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter)
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter)
    }
}

/// The nonce length of every supported AEAD.
pub const NONCE_LEN: usize = 12;

/// A per-connection IV from which per-record nonces are derived.
#[derive(Default)]
pub struct Iv([u8; NONCE_LEN]);

impl Iv {
    /// Wraps a 12-byte IV.
    pub fn new(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }

    /// Copies up to 12 bytes from `value` (zero-padded on the right).
    pub fn copy(value: &[u8]) -> Self {
        let mut iv = [0u8; NONCE_LEN];
        let n = value.len().min(NONCE_LEN);
        iv[..n].copy_from_slice(&value[..n]);
        Self(iv)
    }
}

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Iv {
    fn drop(&mut self) {
        super::zeroize_slice(&mut self.0);
    }
}

impl fmt::Debug for Iv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Iv(..)")
    }
}

/// A per-record nonce: the IV XORed with the big-endian sequence number
/// (RFC 8446 §5.3, RFC 7905 §2).
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Derives the nonce for record `seq`.
    #[inline]
    pub fn new(iv: &Iv, seq: u64) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        put_u64(seq, &mut nonce[4..]);
        for (n, i) in nonce.iter_mut().zip(iv.0.iter()) {
            *n ^= *i;
        }
        Self(nonce)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(..)")
    }
}

/// The TLS 1.3 additional data: the record header (RFC 8446 §5.2).
#[inline]
pub fn make_tls13_aad(payload_len: usize) -> [u8; 5] {
    let version = ProtocolVersion::TLSv1_2.to_array();
    // `payload_len` is bounded by the record size limit, so this fits in a u16.
    let len = (payload_len as u16).to_be_bytes();
    [
        ContentType::ApplicationData.into(),
        version[0],
        version[1],
        len[0],
        len[1],
    ]
}

/// The TLS 1.2 additional data (RFC 5246 §6.2.3.3).
#[inline]
pub fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0u8; TLS12_AAD_SIZE];
    put_u64(seq, &mut out[..8]);
    out[8] = typ.into();
    put_u16(vers.into(), &mut out[9..]);
    // `len` is bounded by the record size limit, so this fits in a u16.
    put_u16(len as u16, &mut out[11..]);
    out
}

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// An AEAD key of at most 32 bytes; zeroised on drop.
pub struct AeadKey {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl AeadKey {
    /// Wraps `buf`, which must be at most [`Self::MAX_LEN`] long.
    pub fn new(buf: &[u8]) -> Self {
        let mut key = Self {
            buf: [0u8; Self::MAX_LEN],
            used: buf.len().min(Self::MAX_LEN),
        };
        key.buf[..key.used].copy_from_slice(&buf[..key.used]);
        key
    }

    /// Truncates the key to `len` bytes (or leaves it unchanged if `len` is
    /// larger).
    pub fn with_length(self, len: usize) -> Self {
        let mut key = Self {
            buf: self.buf,
            used: len.min(self.used),
        };
        key.buf[key.used..].fill(0);
        key
    }

    /// The largest key supported.
    pub const MAX_LEN: usize = 32;
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        super::zeroize_slice(&mut self.buf);
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl From<[u8; Self::MAX_LEN]> for AeadKey {
    fn from(bytes: [u8; Self::MAX_LEN]) -> Self {
        Self {
            buf: bytes,
            used: Self::MAX_LEN,
        }
    }
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey(..)")
    }
}

struct InvalidMessageEncrypter;

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(
        &mut self,
        _m: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

struct InvalidMessageDecrypter;

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        _m: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_xors_sequence() {
        let iv = Iv::new([0xff; 12]);
        let n = Nonce::new(&iv, 1);
        assert_eq!(
            n.0,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe
            ]
        );
    }

    #[test]
    fn aads() {
        assert_eq!(make_tls13_aad(0x1234), [0x17, 3, 3, 0x12, 0x34]);
        assert_eq!(
            make_tls12_aad(1, ContentType::Handshake, ProtocolVersion::TLSv1_2, 5),
            [0, 0, 0, 0, 0, 0, 0, 1, 0x16, 3, 3, 0, 5]
        );
    }

    #[test]
    fn key_truncation() {
        let key = AeadKey::from([7u8; 32]).with_length(16);
        assert_eq!(key.as_ref(), [7u8; 16]);
        assert_eq!(
            Iv::copy(&[1, 2]).as_ref(),
            [1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
