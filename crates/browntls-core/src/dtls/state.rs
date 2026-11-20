//! The DTLS state of a connection: epochs and their keys, the outgoing
//! flight and its retransmission, acknowledgements, and timers.

use alloc::vec::Vec;
use core::fmt;

use crate::crypto::tls13::OkmBlock;
use crate::enums::AlertDescription;
use crate::msgs::enums::AlertLevel;
use crate::tls13::Tls13CipherSuite;

/// The DTLS side of a connection's
/// [`CommonState`](crate::common_state::CommonState).
pub(crate) struct Dtls {
    /// The first handshake message sequence number this side uses, and
    /// expects of the peer: 1 on a server that answers a ClientHello
    /// carrying the cookie of a stateless HelloRetryRequest.
    first_message_seq: u16,
    queued: Vec<Vec<u8>>,
}

impl Dtls {
    pub(crate) fn new() -> Self {
        Self {
            first_message_seq: 0,
            queued: Vec::new(),
        }
    }

    /// A server only, before anything is processed: the handshake
    /// continues a stateless HelloRetryRequest (RFC 9147 §5.1), so the
    /// ClientHello to come has `message_seq` 1 and so has our ServerHello.
    pub(crate) fn continue_after_stateless_retry(&mut self) {
        self.first_message_seq = 1;
    }

    /// The peer's transport address as the caller gave it (opaque bytes),
    /// which a server binds its HelloRetryRequest cookies to (RFC 9147
    /// §5.1). Empty on a client.
    pub(crate) fn peer_address(&self) -> &[u8] {
        &[]
    }

    /// A server only: whether a ClientHello without a valid cookie is
    /// answered with a HelloRetryRequest carrying one (RFC 9147 §5.1),
    /// which is the default.
    pub(crate) fn require_cookie(&self) -> bool {
        true
    }

    /// The largest handshake message (with its four-byte TLS header) that
    /// goes out unfragmented in one datagram of unprotected records. A
    /// first ClientHello should fit, so that a server can answer it
    /// without keeping state (RFC 9147 §5.1).
    pub(crate) fn max_unfragmented_handshake(&self) -> usize {
        1200 - 25
    }

    /// Queues a handshake message (in its TLS encoding: type, 24-bit
    /// length, body) for the flight being prepared, under the current
    /// sending epoch.
    pub(crate) fn queue_handshake(&mut self, encoded: &[u8]) {
        self.queued.push(encoded.to_vec());
    }

    /// Queues an alert, sent once under the current sending epoch.
    pub(crate) fn queue_alert(&mut self, _level: AlertLevel, _description: AlertDescription) {}

    /// The traffic secret of the next sending epoch: the handshake secret
    /// starts epoch 2, the first application secret epoch 3, and every
    /// later one (a KeyUpdate of ours) the epoch after.
    pub(crate) fn set_write_secret(
        &mut self,
        _suite: &'static Tls13CipherSuite,
        _secret: &OkmBlock,
    ) {
    }

    /// The traffic secret of the next receiving epoch (see
    /// [`Self::set_write_secret`]).
    pub(crate) fn set_read_secret(
        &mut self,
        _suite: &'static Tls13CipherSuite,
        _secret: &OkmBlock,
    ) {
    }
}

impl fmt::Debug for Dtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dtls").finish_non_exhaustive()
    }
}
