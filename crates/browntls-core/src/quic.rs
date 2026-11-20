//! QUIC-TLS: TLS 1.3 as the cryptographic handshake of QUIC (RFC 9001).
//!
//! This module is the TLS side of the RFC 9001 interface and nothing more.
//! It does not parse or build QUIC packets, frames or transport parameters
//! (RFC 9000); a QUIC implementation supplies those and drives a connection
//! through this API:
//!
//! * Handshake bytes. [`ConnectionCommon::read_hs`] takes the in-order
//!   contents of CRYPTO frames; [`ConnectionCommon::write_hs`] returns the
//!   bytes to send in CRYPTO frames at the current sending encryption level,
//!   and a [`KeyChange`] when the next level's keys become available. TLS
//!   records are not used: no record protection, no ChangeCipherSpec (RFC 9001
//!   §8.4) and no EndOfEarlyData (§8.3).
//! * Packet protection. [`Keys::initial`] derives the Initial keys from the
//!   client's Destination Connection ID (§5.2); handshake, 0-RTT and 1-RTT
//!   keys come from the TLS key schedule (§5.1). Each direction has a
//!   [`PacketKey`] (AEAD, §5.3) and a [`HeaderProtectionKey`] (§5.4).
//! * Key update. [`Secrets::next_packet_keys`] derives the next 1-RTT packet
//!   keys with the "quic ku" label (§6); TLS KeyUpdate messages are refused.
//! * Errors. A TLS alert is reported by [`ConnectionCommon::alert`] and maps
//!   to a QUIC CRYPTO_ERROR code with [`crypto_error_code`] (§4.8).
//! * The `quic_transport_parameters` extension (§8.2) carries opaque bytes
//!   supplied by, and returned to, the QUIC implementation.
//!
//! The QUIC implementation remains responsible for everything RFC 9001
//! assigns to QUIC: which packets carry which encryption level, discarding
//! keys (§4.9), buffering out-of-order CRYPTO data, counting packets against
//! the AEAD limits (§6.6), handshake confirmation and the key-phase bit.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

pub use crate::common_state::Side;
use crate::crypto::cipher::{AeadKey, Iv, NONCE_LEN};
use crate::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock};
use crate::enums::{AlertDescription, CipherSuite};
use crate::error::Error;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{hkdf_expand_label, hkdf_expand_label_block};

mod connection;
mod state;
pub(crate) mod tls;

pub use connection::{ClientConnection, Connection, ConnectionCommon, ServerConnection};
pub(crate) use state::Quic;

/// The QUIC versions whose use of TLS this module implements.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Version {
    /// QUIC version 1 (RFC 9000, RFC 9001).
    #[default]
    V1,
}

impl Version {
    /// RFC 9001 §5.2: the salt for the Initial secret.
    fn initial_salt(self) -> &'static [u8] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
        }
    }

    /// RFC 9001 §5.1 and §6.1: the HKDF-Expand-Label labels.
    fn labels(self) -> Labels {
        match self {
            Self::V1 => Labels {
                key: b"quic key",
                iv: b"quic iv",
                hp: b"quic hp",
                ku: b"quic ku",
            },
        }
    }

    /// RFC 9001 §5.8: the fixed AEAD_AES_128_GCM key and nonce of the Retry
    /// Integrity Tag.
    fn retry_key_and_nonce(self) -> ([u8; 16], [u8; NONCE_LEN]) {
        match self {
            Self::V1 => (
                [
                    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3,
                    0x68, 0xc8, 0x4e,
                ],
                [
                    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
                ],
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct Labels {
    key: &'static [u8],
    iv: &'static [u8],
    hp: &'static [u8],
    ku: &'static [u8],
}

/// An AEAD and its header protection cipher, as QUIC packet protection uses
/// them (RFC 9001 §5.3, §5.4).
///
/// A [`Tls13CipherSuite`] usable with QUIC names one in its `quic` field;
/// TLS_AES_128_CCM_8_SHA256 has none (RFC 9001 §5.3).
pub trait Algorithm: Send + Sync {
    /// A packet protection key from the "quic key" and "quic iv" outputs.
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey>;

    /// A header protection key from the "quic hp" output.
    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey>;

    /// The AEAD key length, which is also the header protection key length.
    fn aead_key_len(&self) -> usize;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// The length of the header protection sample and of every QUIC AEAD tag
/// defined so far (RFC 9001 §5.3, §5.4.2).
pub const SAMPLE_LEN: usize = 16;

/// A header protection key (RFC 9001 §5.4).
///
/// Implementations provide the mask computation; the masking of the first
/// byte and of the Packet Number field is common to every algorithm and
/// provided here.
pub trait HeaderProtectionKey: Send + Sync {
    /// The five-byte mask for `sample` (RFC 9001 §5.4.1: `mask[0..5]`).
    ///
    /// Fails if `sample` is not [`Self::sample_len`] bytes long.
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error>;

    /// The number of ciphertext bytes sampled (16 for every algorithm
    /// defined in RFC 9001).
    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }

    /// Applies header protection to an unprotected header.
    ///
    /// `first` is the packet's first byte; `packet_number` starts at the
    /// Packet Number field and holds at least the encoded packet number,
    /// whose length the (unprotected) first byte gives. Only that many bytes
    /// are masked.
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let mask = self.mask(sample)?;
        apply_header_mask(&mask, first, packet_number, false)
    }

    /// Removes header protection.
    ///
    /// `packet_number` should be the four bytes starting at the Packet
    /// Number field (RFC 9001 §5.4.2 guarantees they exist when the sample
    /// does). Only the encoded packet number, whose length is read from the
    /// unmasked first byte, is unmasked, without branching on that length.
    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let mask = self.mask(sample)?;
        apply_header_mask(&mask, first, packet_number, true)
    }
}

/// RFC 9001 §5.4.1: masks (or unmasks, when `protected`) the low bits of the
/// first byte and the packet number bytes.
fn apply_header_mask(
    mask: &[u8; 5],
    first: &mut u8,
    packet_number: &mut [u8],
    protected: bool,
) -> Result<(), Error> {
    // Long headers protect four bits of the first byte, short headers five.
    // The header form bit itself is never protected.
    let bits = if *first & 0x80 == 0x80 { 0x0f } else { 0x1f };
    let first_mask = mask[0] & bits;
    let unprotected_first = if protected {
        *first ^ first_mask
    } else {
        *first
    };
    let pn_len = usize::from(unprotected_first & 0x03) + 1;
    if packet_number.len() < pn_len {
        return Err(Error::General(
            "QUIC packet number field shorter than its encoded length".into(),
        ));
    }
    // RFC 9001 §9.5: no branch or memory access depends on the packet
    // number length; every byte up to four is visited and masked or not.
    for (i, (byte, m)) in packet_number
        .iter_mut()
        .take(4)
        .zip(mask[1..].iter())
        .enumerate()
    {
        let active = u8::from(i < pn_len).wrapping_neg();
        *byte ^= m & active;
    }
    *first ^= first_mask;
    Ok(())
}

/// A QUIC packet protection key (RFC 9001 §5.3).
pub trait PacketKey: Send + Sync {
    /// Encrypts `payload` in place for packet `packet_number`, with `header`
    /// (the unprotected header up to and including the packet number) as
    /// associated data, and returns the tag to append.
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error>;

    /// Decrypts `payload` (ciphertext followed by the tag) in place and
    /// returns the plaintext part.
    ///
    /// On failure nothing of `payload` is to be trusted.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error>;

    /// The tag length in bytes.
    fn tag_len(&self) -> usize;

    /// How many packets may be encrypted with this key (RFC 9001 §6.6).
    fn confidentiality_limit(&self) -> u64;

    /// How many packets may fail authentication across the connection for
    /// this AEAD before the connection must close (RFC 9001 §6.6).
    fn integrity_limit(&self) -> u64;
}

/// An AEAD authentication tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tag([u8; SAMPLE_LEN]);

impl From<[u8; SAMPLE_LEN]> for Tag {
    fn from(bytes: [u8; SAMPLE_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(..)")
    }
}

/// The AEAD nonce for `packet_number`: the IV XORed with the left-padded
/// packet number (RFC 9001 §5.3).
pub fn nonce_for(iv: &Iv, packet_number: u64) -> [u8; NONCE_LEN] {
    crate::crypto::cipher::Nonce::new(iv, packet_number).0
}

/// A cipher suite with the QUIC algorithm that goes with it.
#[derive(Clone, Copy)]
pub struct Suite {
    /// The TLS 1.3 cipher suite.
    pub suite: &'static Tls13CipherSuite,
    /// Its QUIC packet and header protection.
    pub quic: &'static dyn Algorithm,
}

impl Suite {
    /// The Initial keys for `client_dst_connection_id` (RFC 9001 §5.2).
    ///
    /// RFC 9001 uses TLS_AES_128_GCM_SHA256 for Initial packets.
    pub fn keys(&self, client_dst_connection_id: &[u8], side: Side, version: Version) -> Keys {
        Keys::initial(
            version,
            self.suite,
            self.quic,
            client_dst_connection_id,
            side,
        )
    }
}

impl fmt::Debug for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Suite")
            .field("suite", &self.suite.common.suite)
            .finish_non_exhaustive()
    }
}

/// Packet and header protection keys for one direction.
pub struct DirectionalKeys {
    /// Header protection.
    pub header: Box<dyn HeaderProtectionKey>,
    /// Packet protection.
    pub packet: Box<dyn PacketKey>,
}

impl DirectionalKeys {
    /// Derives both keys from a traffic secret (RFC 9001 §5.1).
    pub fn new(
        suite: &'static Tls13CipherSuite,
        quic: &'static dyn Algorithm,
        secret: &OkmBlock,
        version: Version,
    ) -> Self {
        let builder = KeyBuilder::new(secret, version, suite.hkdf_provider, quic);
        Self {
            header: builder.header_protection_key(),
            packet: builder.packet_key(),
        }
    }
}

impl fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectionalKeys(..)")
    }
}

/// Keys for both directions at one encryption level.
pub struct Keys {
    /// Protects packets we send.
    pub local: DirectionalKeys,
    /// Protects packets we receive.
    pub remote: DirectionalKeys,
}

impl Keys {
    /// The Initial keys (RFC 9001 §5.2): derived from the Destination
    /// Connection ID of the client's first Initial packet with the version's
    /// salt.
    ///
    /// RFC 9001 specifies TLS_AES_128_GCM_SHA256 for Initial packets; pass
    /// that suite and its QUIC algorithm.
    pub fn initial(
        version: Version,
        suite: &'static Tls13CipherSuite,
        quic: &'static dyn Algorithm,
        client_dst_connection_id: &[u8],
        side: Side,
    ) -> Self {
        let initial_secret = suite
            .hkdf_provider
            .extract_from_secret(Some(version.initial_salt()), client_dst_connection_id);
        let secrets = Secrets {
            client: hkdf_expand_label_block(&*initial_secret, b"client in", &[]),
            server: hkdf_expand_label_block(&*initial_secret, b"server in", &[]),
            suite,
            quic,
            side,
            version,
        };
        Self::new(&secrets)
    }

    fn new(secrets: &Secrets) -> Self {
        let (local, remote) = secrets.local_remote();
        Self {
            local: DirectionalKeys::new(secrets.suite, secrets.quic, local, secrets.version),
            remote: DirectionalKeys::new(secrets.suite, secrets.quic, remote, secrets.version),
        }
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(..)")
    }
}

/// Packet protection keys for both directions, without header protection
/// (which a key update leaves unchanged, RFC 9001 §6).
pub struct PacketKeySet {
    /// Protects packets we send.
    pub local: Box<dyn PacketKey>,
    /// Protects packets we receive.
    pub remote: Box<dyn PacketKey>,
}

impl PacketKeySet {
    fn new(secrets: &Secrets) -> Self {
        let (local, remote) = secrets.local_remote();
        let hkdf = secrets.suite.hkdf_provider;
        Self {
            local: KeyBuilder::new(local, secrets.version, hkdf, secrets.quic).packet_key(),
            remote: KeyBuilder::new(remote, secrets.version, hkdf, secrets.quic).packet_key(),
        }
    }
}

impl fmt::Debug for PacketKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketKeySet(..)")
    }
}

/// The 1-RTT secrets, from which the packet keys of later key phases derive
/// (RFC 9001 §6).
pub struct Secrets {
    client: OkmBlock,
    server: OkmBlock,
    suite: &'static Tls13CipherSuite,
    quic: &'static dyn Algorithm,
    side: Side,
    version: Version,
}

impl Secrets {
    /// Secrets of the current key phase, from the client and server
    /// application traffic secrets of `suite` (or of a later key phase).
    pub fn new(
        client: OkmBlock,
        server: OkmBlock,
        suite: &'static Tls13CipherSuite,
        quic: &'static dyn Algorithm,
        side: Side,
        version: Version,
    ) -> Self {
        Self {
            client,
            server,
            suite,
            quic,
            side,
            version,
        }
    }

    /// The packet keys of the next key phase, advancing these secrets
    /// (`secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "",
    /// Hash.length)`, RFC 9001 §6.1).
    ///
    /// The `next` secrets of [`KeyChange::OneRtt`] are already one phase
    /// ahead of the keys returned with it, so the first call yields the keys
    /// for key phase 1.
    pub fn next_packet_keys(&mut self) -> PacketKeySet {
        let keys = PacketKeySet::new(self);
        self.update();
        keys
    }

    fn update(&mut self) {
        let ku = self.version.labels().ku;
        let next = |secret: &OkmBlock| {
            let expander = self.suite.hkdf_provider.expander_for_okm(secret);
            hkdf_expand_label_block(&*expander, ku, &[])
        };
        let client = next(&self.client);
        let server = next(&self.server);
        self.client = client;
        self.server = server;
    }

    fn local_remote(&self) -> (&OkmBlock, &OkmBlock) {
        match self.side {
            Side::Client => (&self.client, &self.server),
            Side::Server => (&self.server, &self.client),
        }
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets")
            .field("suite", &self.suite.common.suite)
            .field("side", &self.side)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// New keys from [`ConnectionCommon::write_hs`]: the bytes written by that
/// call belong to the previous encryption level, everything after to this one.
#[allow(clippy::large_enum_variant)]
pub enum KeyChange {
    /// The Handshake keys.
    Handshake {
        /// Keys for both directions.
        keys: Keys,
    },
    /// The 1-RTT keys, and the secrets for later key updates.
    OneRtt {
        /// Keys for both directions, key phase 0.
        keys: Keys,
        /// The secrets of key phase 1 onwards.
        next: Secrets,
    },
}

impl fmt::Debug for KeyChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake { .. } => f.write_str("KeyChange::Handshake"),
            Self::OneRtt { .. } => f.write_str("KeyChange::OneRtt"),
        }
    }
}

/// Derives packet and header protection keys from one secret.
struct KeyBuilder {
    expander: Box<dyn HkdfExpander>,
    labels: Labels,
    quic: &'static dyn Algorithm,
}

impl KeyBuilder {
    fn new(
        secret: &OkmBlock,
        version: Version,
        hkdf: &'static dyn Hkdf,
        quic: &'static dyn Algorithm,
    ) -> Self {
        Self {
            expander: hkdf.expander_for_okm(secret),
            labels: version.labels(),
            quic,
        }
    }

    fn aead_key(&self, label: &[u8]) -> AeadKey {
        let len = self.quic.aead_key_len().min(AeadKey::MAX_LEN);
        let mut buf = [0u8; AeadKey::MAX_LEN];
        hkdf_expand_label(&*self.expander, label, &[], &mut buf[..len]);
        let key = AeadKey::new(&buf[..len]);
        crate::crypto::zeroize_slice(&mut buf);
        key
    }

    fn packet_key(&self) -> Box<dyn PacketKey> {
        let key = self.aead_key(self.labels.key);
        let mut iv = [0u8; NONCE_LEN];
        hkdf_expand_label(&*self.expander, self.labels.iv, &[], &mut iv);
        self.quic.packet_key(key, Iv::new(iv))
    }

    fn header_protection_key(&self) -> Box<dyn HeaderProtectionKey> {
        self.quic
            .header_protection_key(self.aead_key(self.labels.hp))
    }
}

/// The QUIC CRYPTO_ERROR code for a TLS alert: `0x0100 + AlertDescription`
/// (RFC 9001 §4.8).
pub fn crypto_error_code(alert: AlertDescription) -> u64 {
    0x0100 + u64::from(u8::from(alert))
}

/// The TLS alert a QUIC CRYPTO_ERROR code (0x0100-0x01ff) stands for, or
/// `None` for codes outside that range.
pub fn alert_from_crypto_error(code: u64) -> Option<AlertDescription> {
    match code {
        0x0100..=0x01ff => Some(AlertDescription::from((code - 0x0100) as u8)),
        _ => None,
    }
}

/// The Retry Integrity Tag of a Retry packet (RFC 9001 §5.8).
///
/// `aes_128_gcm` is a provider's TLS_AES_128_GCM_SHA256 suite, whose AEAD
/// the tag uses; any other suite is an error. `retry_without_tag` is the Retry
/// packet up to, not including, the tag; `original_dst_connection_id` is the
/// Destination Connection ID of the client's Initial packet that the Retry
/// answers (at most 20 bytes).
pub fn retry_integrity_tag(
    version: Version,
    aes_128_gcm: &Suite,
    original_dst_connection_id: &[u8],
    retry_without_tag: &[u8],
) -> Result<Tag, Error> {
    if aes_128_gcm.suite.common.suite != CipherSuite::TLS13_AES_128_GCM_SHA256 {
        return Err(Error::General(
            "the Retry Integrity Tag needs AEAD_AES_128_GCM".into(),
        ));
    }
    let odcid_len = u8::try_from(original_dst_connection_id.len())
        .ok()
        .filter(|len| *len <= 20)
        .ok_or_else(|| Error::General("connection ID longer than 20 bytes".into()))?;
    let (key, nonce) = version.retry_key_and_nonce();
    let mut pseudo_packet =
        Vec::with_capacity(1 + original_dst_connection_id.len() + retry_without_tag.len());
    pseudo_packet.push(odcid_len);
    pseudo_packet.extend_from_slice(original_dst_connection_id);
    pseudo_packet.extend_from_slice(retry_without_tag);
    // Packet number zero leaves the fixed nonce as it is.
    aes_128_gcm
        .quic
        .packet_key(AeadKey::new(&key), Iv::new(nonce))
        .encrypt_in_place(0, &pseudo_packet, &mut [])
}

/// Whether `retry_packet` (with its trailing 16-byte tag) carries a valid
/// Retry Integrity Tag for `original_dst_connection_id` (RFC 9001 §5.8).
pub fn verify_retry_integrity(
    version: Version,
    aes_128_gcm: &Suite,
    original_dst_connection_id: &[u8],
    retry_packet: &[u8],
) -> bool {
    let Some(body_len) = retry_packet.len().checked_sub(SAMPLE_LEN) else {
        return false;
    };
    let (body, tag) = retry_packet.split_at(body_len);
    match retry_integrity_tag(version, aes_128_gcm, original_dst_connection_id, body) {
        Ok(expected) => crate::ct::constant_time_eq(expected.as_ref(), tag),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorMask([u8; 5]);

    impl HeaderProtectionKey for XorMask {
        fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
            if sample.len() != SAMPLE_LEN {
                return Err(Error::General("bad sample".into()));
            }
            Ok(self.0)
        }
    }

    #[test]
    fn header_mask_long_and_short() {
        let key = XorMask([0xff, 1, 2, 3, 4]);
        let sample = [0u8; SAMPLE_LEN];

        // Long header, 2-byte packet number: four first-byte bits.
        let (mut first, mut pn) = (0xc1u8, [0xaa, 0xbb, 0xcc, 0xdd]);
        key.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0xce);
        assert_eq!(pn, [0xab, 0xb9, 0xcc, 0xdd]);
        key.decrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!((first, pn), (0xc1, [0xaa, 0xbb, 0xcc, 0xdd]));

        // Short header, 4-byte packet number: five first-byte bits.
        let (mut first, mut pn) = (0x43u8, [0u8; 4]);
        key.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0x5c);
        assert_eq!(pn, [1, 2, 3, 4]);
        key.decrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!((first, pn), (0x43, [0; 4]));

        // A packet number slice shorter than the encoded length.
        let mut first = 0x43u8;
        assert!(
            key.encrypt_in_place(&sample, &mut first, &mut [0u8; 3])
                .is_err()
        );
        assert!(key.mask(&[0u8; 15]).is_err());
    }

    #[test]
    fn crypto_error_codes() {
        // RFC 9001 §4.8 and §8: the codes the RFC names.
        assert_eq!(
            crypto_error_code(AlertDescription::NoApplicationProtocol),
            0x0178
        );
        assert_eq!(
            crypto_error_code(AlertDescription::MissingExtension),
            0x016d
        );
        assert_eq!(
            crypto_error_code(AlertDescription::HandshakeFailure),
            0x0128
        );
        assert_eq!(
            crypto_error_code(AlertDescription::UnexpectedMessage),
            0x010a
        );
        assert_eq!(
            alert_from_crypto_error(0x0178),
            Some(AlertDescription::NoApplicationProtocol)
        );
        assert_eq!(alert_from_crypto_error(0x00ff), None);
        assert_eq!(alert_from_crypto_error(0x0200), None);
    }
}
