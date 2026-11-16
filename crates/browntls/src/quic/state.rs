//! The QUIC state of a connection: handshake messages queued per
//! encryption level, and the secrets each level's keys come from.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use super::{DirectionalKeys, KeyChange, Keys, Secrets, Side, Version};
use crate::crypto::tls13::OkmBlock;
use crate::enums::AlertDescription;
use crate::tls13::Tls13CipherSuite;

/// The encryption levels that carry TLS handshake messages (RFC 9001 §4.1.4;
/// 0-RTT carries none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Initial,
    Handshake,
    OneRtt,
}

/// A pair of traffic secrets and the suite they belong to.
struct SecretPair {
    client: OkmBlock,
    server: OkmBlock,
    suite: &'static Tls13CipherSuite,
}

/// The QUIC side of a connection's [`CommonState`].
pub(crate) struct Quic {
    version: Version,
    /// Our transport parameters, sent in ClientHello or EncryptedExtensions.
    pub(crate) local_params: Vec<u8>,
    /// The peer's transport parameters (on a client offering 0-RTT, those
    /// remembered with the ticket until EncryptedExtensions replaces them).
    pub(crate) peer_params: Option<Vec<u8>>,
    /// The first fatal alert this side raised.
    pub(super) alert: Option<AlertDescription>,
    /// Handshake messages to send, with the level that protects each.
    queue: VecDeque<(Level, Vec<u8>)>,
    /// The level that protects handshake messages we produce now.
    write_level: Level,
    /// The sending level the QUIC implementation has keys for.
    emitted_level: Level,
    /// The level the peer's handshake messages arrive at now.
    pub(crate) read_level: Level,
    early: Option<(OkmBlock, &'static Tls13CipherSuite)>,
    handshake: Option<SecretPair>,
    traffic: Option<SecretPair>,
}

impl Quic {
    pub(crate) fn new(version: Version, local_params: Vec<u8>) -> Self {
        Self {
            version,
            local_params,
            peer_params: None,
            alert: None,
            queue: VecDeque::new(),
            write_level: Level::Initial,
            emitted_level: Level::Initial,
            read_level: Level::Initial,
            early: None,
            handshake: None,
            traffic: None,
        }
    }

    /// Queues an encoded handshake message at the current sending level.
    pub(crate) fn queue_handshake(&mut self, encoded: Vec<u8>) {
        self.queue.push_back((self.write_level, encoded));
    }

    pub(crate) fn record_alert(&mut self, alert: AlertDescription) {
        if self.alert.is_none() {
            self.alert = Some(alert);
        }
    }

    /// `client_early_traffic_secret` (0-RTT keys).
    pub(crate) fn set_early_secret(&mut self, secret: OkmBlock, suite: &'static Tls13CipherSuite) {
        self.early = Some((secret, suite));
    }

    /// Forgets the 0-RTT secret: a server that refused early data.
    pub(crate) fn clear_early_secret(&mut self) {
        self.early = None;
    }

    /// The handshake traffic secrets: from now on both sides send and
    /// receive handshake messages at the Handshake level.
    pub(crate) fn set_handshake_secrets(
        &mut self,
        client: OkmBlock,
        server: OkmBlock,
        suite: &'static Tls13CipherSuite,
    ) {
        self.handshake = Some(SecretPair {
            client,
            server,
            suite,
        });
        self.write_level = Level::Handshake;
        self.read_level = Level::Handshake;
    }

    /// The application traffic secrets. The server's sending level moves to
    /// 1-RTT at once (its Finished is already queued); the client's moves
    /// once it has queued its own Finished.
    pub(crate) fn set_traffic_secrets(
        &mut self,
        client: OkmBlock,
        server: OkmBlock,
        suite: &'static Tls13CipherSuite,
        side: Side,
    ) {
        self.traffic = Some(SecretPair {
            client,
            server,
            suite,
        });
        if side == Side::Server {
            self.write_level = Level::OneRtt;
        }
    }

    /// Our handshake flight is complete; later messages (none on a client,
    /// tickets on a server) go at 1-RTT.
    pub(crate) fn start_local_traffic(&mut self) {
        self.write_level = Level::OneRtt;
    }

    /// The peer's handshake flight is complete; later messages from it
    /// arrive at 1-RTT.
    pub(crate) fn start_remote_traffic(&mut self) {
        self.read_level = Level::OneRtt;
    }

    pub(super) fn write_hs(&mut self, buf: &mut Vec<u8>, side: Side) -> Option<KeyChange> {
        while self
            .queue
            .front()
            .is_some_and(|(level, _)| *level == self.emitted_level)
        {
            if let Some((_, bytes)) = self.queue.pop_front() {
                buf.extend_from_slice(&bytes);
            }
        }

        match self.emitted_level {
            Level::Initial => {
                let pair = self.handshake.take()?;
                let secrets = self.secrets(pair, side)?;
                self.emitted_level = Level::Handshake;
                Some(KeyChange::Handshake {
                    keys: Keys::new(&secrets),
                })
            }
            // The 1-RTT keys come once no further handshake message of ours
            // can be produced at the Handshake level.
            Level::Handshake if self.write_level == Level::OneRtt => {
                let pair = self.traffic.take()?;
                let mut secrets = self.secrets(pair, side)?;
                self.emitted_level = Level::OneRtt;
                let keys = Keys::new(&secrets);
                secrets.update();
                Some(KeyChange::OneRtt {
                    keys,
                    next: secrets,
                })
            }
            _ => None,
        }
    }

    fn secrets(&self, pair: SecretPair, side: Side) -> Option<Secrets> {
        Some(Secrets {
            quic: pair.suite.quic?,
            client: pair.client,
            server: pair.server,
            suite: pair.suite,
            side,
            version: self.version,
        })
    }

    pub(super) fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        let (secret, suite) = self.early.as_ref()?;
        Some(DirectionalKeys::new(
            suite,
            suite.quic?,
            secret,
            self.version,
        ))
    }
}

impl fmt::Debug for Quic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quic")
            .field("version", &self.version)
            .field("write_level", &self.write_level)
            .field("read_level", &self.read_level)
            .field("alert", &self.alert)
            .finish_non_exhaustive()
    }
}
