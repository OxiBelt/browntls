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
    /// Remaining bytes of records that may fail decryption silently (rejected
    /// 0-RTT data on the server, RFC 8446 §4.2.10).
    trial_decryption_len: Option<usize>,
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
        }
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

    /// Like `set_message_decrypter`, but up to `max_length` bytes of records
    /// that fail to decrypt are dropped silently.
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

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
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
}
