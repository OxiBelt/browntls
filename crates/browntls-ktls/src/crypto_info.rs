//! The `TLS_TX`/`TLS_RX` socket option values (`struct tls12_crypto_info_*`
//! of `include/uapi/linux/tls.h`), built from extracted secrets.

use core::fmt;

use browntls::{ConnectionTrafficSecrets, ProtocolVersion};

/// `TLS_CIPHER_AES_GCM_128`.
const CIPHER_AES_GCM_128: u16 = 51;
/// `TLS_CIPHER_AES_GCM_256`.
const CIPHER_AES_GCM_256: u16 = 52;
/// `TLS_CIPHER_AES_CCM_128`.
const CIPHER_AES_CCM_128: u16 = 53;
/// `TLS_CIPHER_CHACHA20_POLY1305`.
const CIPHER_CHACHA20_POLY1305: u16 = 54;

/// The largest `tls12_crypto_info_*` structure (AES-256-GCM and
/// ChaCha20-Poly1305: 56 bytes).
const MAX_LEN: usize = 56;

/// The value of the `TLS_TX` or `TLS_RX` socket option for one direction:
/// a `struct tls12_crypto_info_*` in its exact byte layout.
///
/// Every field of these structures is a byte array after the two
/// native-endian `u16`s of `struct tls_crypto_info`, so the layout has no
/// padding: version, cipher type, IV, key, salt, record sequence number.
/// The key material is wiped when the value is dropped.
pub struct CryptoInfo {
    bytes: [u8; MAX_LEN],
    len: usize,
}

/// A cipher whose keys Linux kernel TLS cannot take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedCipher;

impl fmt::Display for UnsupportedCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the cipher has no Linux kernel TLS form")
    }
}

impl std::error::Error for UnsupportedCipher {}

impl CryptoInfo {
    /// The option value for `secrets` under `version`, the next record
    /// having sequence number `seq`.
    ///
    /// AES-GCM and AES-CCM split the 12-byte IV into the 4-byte salt and an
    /// 8-byte IV; for TLS 1.2 AES-GCM that IV is the explicit nonce of the
    /// next record, as [`browntls::ExtractedSecrets`] provides it.
    /// ChaCha20-Poly1305 takes the whole IV and no salt.
    pub fn new(
        version: ProtocolVersion,
        secrets: &ConnectionTrafficSecrets,
        seq: u64,
    ) -> Result<Self, UnsupportedCipher> {
        let version = match version {
            ProtocolVersion::TLSv1_2 => 0x0303u16,
            ProtocolVersion::TLSv1_3 => 0x0304,
            _ => return Err(UnsupportedCipher),
        };
        let (cipher, key, iv, salt_len) = match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (CIPHER_AES_GCM_128, key, iv, 4),
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (CIPHER_AES_GCM_256, key, iv, 4),
            ConnectionTrafficSecrets::Aes128Ccm { key, iv } => (CIPHER_AES_CCM_128, key, iv, 4),
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                (CIPHER_CHACHA20_POLY1305, key, iv, 0)
            }
            _ => return Err(UnsupportedCipher),
        };
        let (key, iv) = (key.as_ref(), iv.as_ref());
        let expected_key = match cipher {
            CIPHER_AES_GCM_128 | CIPHER_AES_CCM_128 => 16,
            _ => 32,
        };
        if key.len() != expected_key || iv.len() != 12 {
            return Err(UnsupportedCipher);
        }
        let (salt, iv) = iv.split_at(salt_len);

        let mut info = Self {
            bytes: [0; MAX_LEN],
            len: 0,
        };
        for part in [
            &version.to_ne_bytes()[..],
            &cipher.to_ne_bytes(),
            iv,
            key,
            salt,
            &seq.to_be_bytes(),
        ] {
            info.bytes[info.len..info.len + part.len()].copy_from_slice(part);
            info.len += part.len();
        }
        Ok(info)
    }

    /// The option value, ready for `setsockopt`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The `cipher_type` field.
    pub fn cipher_type(&self) -> u16 {
        u16::from_ne_bytes([self.bytes[2], self.bytes[3]])
    }
}

impl Drop for CryptoInfo {
    fn drop(&mut self) {
        self.bytes.fill(0);
        // Keeps the wipe from being removed as a dead store.
        core::hint::black_box(&mut self.bytes);
    }
}

impl fmt::Debug for CryptoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoInfo")
            .field("cipher_type", &self.cipher_type())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use browntls::crypto::cipher::{AeadKey, Iv};

    use super::*;

    fn iv() -> Iv {
        Iv::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    }

    #[test]
    fn layouts_match_the_kernel_structures() {
        let seq = 0x0102_0304_0506_0708;
        let cases = [
            (
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: AeadKey::new(&[0xaa; 16]),
                    iv: iv(),
                },
                51u16,
                40usize,
            ),
            (
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: AeadKey::new(&[0xaa; 32]),
                    iv: iv(),
                },
                52,
                56,
            ),
            (
                ConnectionTrafficSecrets::Aes128Ccm {
                    key: AeadKey::new(&[0xaa; 16]),
                    iv: iv(),
                },
                53,
                40,
            ),
            (
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: AeadKey::new(&[0xaa; 32]),
                    iv: iv(),
                },
                54,
                56,
            ),
        ];
        for (secrets, cipher, len) in cases {
            let info = CryptoInfo::new(ProtocolVersion::TLSv1_3, &secrets, seq).unwrap();
            let b = info.as_bytes();
            assert_eq!(b.len(), len, "{cipher}");
            assert_eq!(b[..2], 0x0304u16.to_ne_bytes());
            assert_eq!(info.cipher_type(), cipher);
            let key_len = if len == 40 { 16 } else { 32 };
            if cipher == 54 {
                // iv[12], key[32], salt[0], rec_seq[8]
                assert_eq!(b[4..16], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
                assert!(b[16..48].iter().all(|&x| x == 0xaa));
            } else {
                // iv[8], key, salt[4], rec_seq[8]
                assert_eq!(b[4..12], [5, 6, 7, 8, 9, 10, 11, 12]);
                assert!(b[12..12 + key_len].iter().all(|&x| x == 0xaa));
                assert_eq!(b[12 + key_len..16 + key_len], [1, 2, 3, 4]);
            }
            assert_eq!(b[len - 8..], seq.to_be_bytes());

            let tls12 = CryptoInfo::new(ProtocolVersion::TLSv1_2, &secrets, 0).unwrap();
            assert_eq!(tls12.as_bytes()[..2], 0x0303u16.to_ne_bytes());
            assert!(format!("{tls12:?}").contains("cipher_type"));
            assert!(!format!("{tls12:?}").contains("170"), "no key bytes");
        }
    }

    #[test]
    fn other_versions_and_lengths_are_refused() {
        let secrets = ConnectionTrafficSecrets::Aes128Gcm {
            key: AeadKey::new(&[0; 16]),
            iv: iv(),
        };
        assert_eq!(
            CryptoInfo::new(ProtocolVersion::TLSv1_1, &secrets, 0).unwrap_err(),
            UnsupportedCipher
        );
        let short = ConnectionTrafficSecrets::Aes256Gcm {
            key: AeadKey::new(&[0; 16]),
            iv: iv(),
        };
        assert!(CryptoInfo::new(ProtocolVersion::TLSv1_3, &short, 0).is_err());
        assert!(!UnsupportedCipher.to_string().is_empty());
    }
}
