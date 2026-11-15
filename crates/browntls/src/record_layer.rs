//! The record layer: sequence numbers and the active record ciphers.

use alloc::boxed::Box;
use core::fmt;

use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::message::{
    InboundPlainMessage, MAX_PLAINTEXT_LEN, OutboundOpaqueMessage, OutboundPlainMessage,
};

/// Sequence numbers are 64 bits; we stop a little short of the limit so that a
/// close_notify can still be sent (RFC 8446 §5.5).
const SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000;
const SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffe;

/// The largest expansion a TLS 1.3 record may have over its plaintext
/// (RFC 9846 §5.2: `TLSCiphertext.length` is at most 2^14 + 256).
const MAX_TLS13_EXPANSION: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionState {
    /// No cipher is set up; records pass through unprotected.
    Invalid,
    /// A cipher is set up but not yet active (TLS 1.2 before ChangeCipherSpec).
    Prepared,
    /// The cipher protects every record.
    Active,
}

/// What to do before encrypting the next record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreEncryptAction {
    /// Carry on.
    Nothing,
    /// The confidentiality limit is reached: refresh keys (TLS 1.3) or close.
    RefreshOrClose,
    /// The sequence space is exhausted; the record must not be sent.
    Refuse,
}

/// A record that passed decryption.
pub(crate) struct Decrypted<'a> {
    /// The read sequence number is about to run out; close after this record.
    pub(crate) want_close_before_decrypt: bool,
    pub(crate) plaintext: InboundPlainMessage<'a>,
}

/// Record protection state for both directions.
pub(crate) struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,
    write_seq: u64,
    read_seq: u64,
    has_decrypted: bool,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    confidentiality_limit: u64,
    /// Remaining plaintext bytes of records that may fail decryption
    /// silently (rejected 0-RTT data on the server, RFC 9846 §4.2.10).
    trial_decryption_len: Option<usize>,
    /// The record size limit we announced (RFC 8449), once negotiated.
    inbound_size_limit: Option<InboundSizeLimit>,
    /// The current decrypter reads 0-RTT data, which the client sent before
    /// it could learn our record size limit; the limit does not apply.
    reading_early_data: bool,
}

/// The largest protected record we accept, from the record size limit we
/// announced (RFC 8449 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboundSizeLimit {
    /// The announced value, clamped to the protocol maximum: for TLS 1.3
    /// the whole `TLSInnerPlaintext` (content, type and padding), for TLS
    /// 1.2 the plaintext.
    limit: usize,
    tls13: bool,
}

impl RecordLayer {
    pub(crate) fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            write_seq: 0,
            read_seq: 0,
            has_decrypted: false,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            confidentiality_limit: u64::MAX,
            trial_decryption_len: None,
            inbound_size_limit: None,
            reading_early_data: false,
        }
    }

    /// Enforces the record size limit we announced (RFC 8449 §4) on every
    /// protected record from now on, except 0-RTT data. `limit` must
    /// already be clamped to the protocol maximum.
    pub(crate) fn set_inbound_record_size_limit(&mut self, limit: u16, tls13: bool) {
        self.inbound_size_limit = Some(InboundSizeLimit {
            limit: usize::from(limit),
            tls13,
        });
    }

    /// Whether a decrypted record breaks the record size limit we announced:
    /// "A TLS endpoint that receives a record larger than its advertised
    /// limit MUST generate a fatal record_overflow alert" (RFC 8449 §4).
    fn exceeds_inbound_size_limit(&self, encrypted_len: usize, content_len: usize) -> bool {
        let Some(InboundSizeLimit { limit, tls13 }) = self.inbound_size_limit else {
            return false;
        };
        if self.reading_early_data {
            return false;
        }
        if !tls13 {
            return content_len > limit;
        }
        // TLS 1.3 counts the content type and the padding too. The
        // decrypter strips both, so the length of the TLSInnerPlaintext
        // comes from the ciphertext: it is the ciphertext less the AEAD
        // expansion, which the (same suite's) encrypter reports as
        // `encrypted_payload_len(0) - 1`. Without an encrypter, the largest
        // expansion RFC 9846 §5.2 allows (255) bounds it.
        let expansion = match self.encrypt_state {
            DirectionState::Invalid => 255,
            _ => self
                .message_encrypter
                .encrypted_payload_len(0)
                .saturating_sub(1),
        };
        content_len >= limit || encrypted_len.saturating_sub(expansion) > limit
    }

    /// Decrypts `encr` in place. Returns `Ok(None)` when a record was dropped
    /// as part of trial decryption.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            // RFC 5246 §6.2.1 / RFC 8446 §5.1: an unprotected record carries
            // at most 2^14 bytes; the ciphertext allowance does not apply.
            if encr.payload.len() > MAX_PLAINTEXT_LEN {
                return Err(Error::PeerSentOversizedRecord);
            }
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;
        let encrypted_len = encr.payload.len();
        match self.message_decrypter.decrypt(encr, self.read_seq) {
            Ok(plaintext) => {
                if self.exceeds_inbound_size_limit(encrypted_len, plaintext.payload.len()) {
                    return Err(Error::PeerSentOversizedRecord);
                }
                self.read_seq += 1;
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                // The first record under the new key ends any skipped early
                // data: later failures are genuine.
                self.finish_trial_decryption();
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError)
                if !self.message_decrypter.integrity_limit_reached()
                    && self.doing_trial_decryption(encrypted_len) =>
            {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Encrypts `plain` with the current write key and sequence number.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<OutboundOpaqueMessage, Error> {
        if self.encrypt_state != DirectionState::Active {
            return Err(Error::EncryptError);
        }
        if self.write_seq >= SEQ_HARD_LIMIT {
            return Err(Error::EncryptError);
        }
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter.encrypt(plain, seq)
    }

    /// Installs a new encrypter and resets the write sequence number.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        confidentiality_limit: u64,
    ) {
        self.prepare_message_encrypter(cipher, confidentiality_limit);
        self.start_encrypting();
    }

    /// Installs a new decrypter and resets the read sequence number.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    /// Like `set_message_decrypter`, for the server's 0-RTT key: the
    /// record size limit (RFC 8449) does not apply to early data, which
    /// the client sent before it saw the limit.
    pub(crate) fn set_early_data_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.set_message_decrypter(cipher);
        self.reading_early_data = true;
    }

    /// Like `set_message_decrypter`, but records that fail to decrypt are
    /// dropped silently while they carry at most `max_length` bytes of
    /// plaintext in total (see `doing_trial_decryption`).
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    /// Stores an encrypter for later activation by `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        confidentiality_limit: u64,
    ) {
        self.message_encrypter = cipher;
        self.write_seq = 0;
        self.encrypt_state = DirectionState::Prepared;
        self.confidentiality_limit = confidentiality_limit;
    }

    /// Stores a decrypter for later activation by `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
        self.read_seq = 0;
        self.decrypt_state = DirectionState::Prepared;
        self.reading_early_data = false;
    }

    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        self.encrypt_state = DirectionState::Active;
    }

    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        self.decrypt_state = DirectionState::Active;
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.decrypt_state == DirectionState::Active
    }

    /// Whether at least one record has been decrypted under the current key.
    #[cfg(test)]
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_seq
    }

    /// Decides whether sending `add` more records is allowed under the limits.
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> PreEncryptAction {
        match self.write_seq.saturating_add(add) {
            v if v >= SEQ_SOFT_LIMIT => PreEncryptAction::Refuse,
            // This write reaches or crosses the limit: refresh (TLS 1.3) or
            // close (TLS 1.2) now, also when it spans several records.
            v if v >= self.confidentiality_limit && self.write_seq < self.confidentiality_limit => {
                PreEncryptAction::RefreshOrClose
            }
            // The limit was reached by an earlier write whose refresh has
            // not happened yet.
            v if v > self.confidentiality_limit => PreEncryptAction::Refuse,
            _ => PreEncryptAction::Nothing,
        }
    }

    /// Charges a skipped record of `requested` ciphertext bytes against the
    /// trial decryption budget; `false` once the budget would be exceeded.
    ///
    /// RFC 9846 §4.2.10 counts `max_early_data_size` in plaintext bytes
    /// (excluding the inner content type and padding), so each record is
    /// charged the most plaintext it can carry: its length minus the
    /// AEAD expansion. TLS 1.3 uses one suite in both directions, so that
    /// expansion (tag plus content type byte) is what our own write key
    /// adds, which is active by the time the client's records arrive. It is
    /// capped at the 256 bytes RFC 9846 §5.2 allows; without a write key
    /// nothing is subtracted (the stricter, ciphertext-based budget).
    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        let overhead = if self.encrypt_state == DirectionState::Active {
            self.message_encrypter
                .encrypted_payload_len(0)
                .min(MAX_TLS13_EXPANSION)
        } else {
            0
        };
        let plaintext_bound = requested.saturating_sub(overhead);
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(plaintext_bound))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            None => false,
        }
    }
}

impl fmt::Debug for RecordLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordLayer")
            .field("write_seq", &self.write_seq)
            .field("read_seq", &self.read_seq)
            .field("encrypt_state", &self.encrypt_state)
            .field("decrypt_state", &self.decrypt_state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::message::OutboundChunks;

    #[test]
    fn plaintext_passes_through_when_inactive() {
        let mut rl = RecordLayer::new();
        let mut payload = [1u8, 2, 3];
        let msg = InboundOpaqueMessage::new(
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &mut payload,
        );
        let out = rl.decrypt_incoming(msg).unwrap().unwrap();
        assert_eq!(out.plaintext.payload, [1, 2, 3]);
        assert!(!rl.is_decrypting());
        assert!(!rl.has_decrypted());
        assert_eq!(rl.read_seq(), 0);
    }

    #[test]
    fn encrypting_without_cipher_fails() {
        let mut rl = RecordLayer::new();
        let plain = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(&[1]),
        };
        assert_eq!(rl.encrypt_outgoing(plain).err(), Some(Error::EncryptError));
        assert_eq!(rl.pre_encrypt_action(1), PreEncryptAction::Nothing);
    }

    #[test]
    fn limits() {
        let mut rl = RecordLayer::new();
        rl.prepare_message_encrypter(<dyn MessageEncrypter>::invalid(), 10);
        rl.start_encrypting();
        rl.write_seq = 9;
        assert_eq!(rl.pre_encrypt_action(1), PreEncryptAction::RefreshOrClose);
        // A multi-record write crossing the limit also refreshes.
        assert_eq!(rl.pre_encrypt_action(3), PreEncryptAction::RefreshOrClose);
        // Once at the limit, nothing more until the refresh.
        rl.write_seq = 10;
        assert_eq!(rl.pre_encrypt_action(1), PreEncryptAction::Refuse);
        rl.write_seq = 0;
        assert_eq!(rl.pre_encrypt_action(1), PreEncryptAction::Nothing);
        rl.confidentiality_limit = u64::MAX;
        rl.write_seq = SEQ_SOFT_LIMIT;
        assert_eq!(rl.pre_encrypt_action(0), PreEncryptAction::Refuse);
    }

    /// Decrypts as the identity: TLS 1.3 unpadding, or TLS 1.2 as is.
    struct Identity {
        tls13: bool,
    }

    impl MessageDecrypter for Identity {
        fn decrypt<'a>(
            &mut self,
            msg: InboundOpaqueMessage<'a>,
            _seq: u64,
        ) -> Result<InboundPlainMessage<'a>, Error> {
            if self.tls13 {
                msg.into_tls13_unpadded_message()
            } else {
                Ok(msg.into_plain_message())
            }
        }
    }

    /// An encrypter with a TLS 1.3 expansion of one byte (no tag).
    struct NoTag;

    impl MessageEncrypter for NoTag {
        fn encrypt(
            &mut self,
            _msg: OutboundPlainMessage<'_>,
            _seq: u64,
        ) -> Result<OutboundOpaqueMessage, Error> {
            Err(Error::EncryptError)
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len + 1
        }
    }

    fn decrypt(rl: &mut RecordLayer, mut payload: alloc::vec::Vec<u8>) -> Result<usize, Error> {
        let msg = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut payload,
        );
        rl.decrypt_incoming(msg)
            .map(|d| d.map_or(0, |d| d.plaintext.payload.len()))
    }

    fn inner(content: usize, padding: usize) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0x61; content];
        v.push(0x17);
        v.resize(content + 1 + padding, 0);
        v
    }

    #[test]
    fn tls13_inbound_record_size_limit_counts_type_and_padding() {
        let mut rl = RecordLayer::new();
        rl.set_message_encrypter(Box::new(NoTag), u64::MAX);
        rl.set_message_decrypter(Box::new(Identity { tls13: true }));
        // Not negotiated: anything up to the protocol limit.
        assert_eq!(decrypt(&mut rl, inner(1000, 0)), Ok(1000));

        rl.set_inbound_record_size_limit(64, true);
        assert_eq!(decrypt(&mut rl, inner(63, 0)), Ok(63));
        assert_eq!(decrypt(&mut rl, inner(10, 53)), Ok(10));
        assert_eq!(
            decrypt(&mut rl, inner(64, 0)),
            Err(Error::PeerSentOversizedRecord)
        );
        assert_eq!(
            decrypt(&mut rl, inner(10, 54)),
            Err(Error::PeerSentOversizedRecord)
        );

        // 0-RTT data is exempt; the next key is not.
        rl.set_early_data_decrypter(Box::new(Identity { tls13: true }));
        assert_eq!(decrypt(&mut rl, inner(1000, 0)), Ok(1000));
        rl.set_message_decrypter(Box::new(Identity { tls13: true }));
        assert_eq!(
            decrypt(&mut rl, inner(64, 0)),
            Err(Error::PeerSentOversizedRecord)
        );
    }

    #[test]
    fn tls12_inbound_record_size_limit_counts_plaintext() {
        let mut rl = RecordLayer::new();
        rl.set_message_decrypter(Box::new(Identity { tls13: false }));
        rl.set_inbound_record_size_limit(64, false);
        assert_eq!(decrypt(&mut rl, alloc::vec![0; 64]), Ok(64));
        assert_eq!(
            decrypt(&mut rl, alloc::vec![0; 65]),
            Err(Error::PeerSentOversizedRecord)
        );
        // Unprotected records are not subject to the limit (RFC 8449 §4).
        let mut rl = RecordLayer::new();
        rl.set_inbound_record_size_limit(64, false);
        assert_eq!(decrypt(&mut rl, alloc::vec![0; 1000]), Ok(1000));
    }
}
