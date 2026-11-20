//! A fuzz-driven datagram network between one DTLS client and server, with
//! a virtual clock: each datagram is delivered, dropped, duplicated, held
//! back behind the next one, damaged, or preceded by a forged datagram;
//! quiet periods advance the clock by fuzz-chosen amounts.

use std::collections::VecDeque;
use std::time::Duration;

use browntls_core::revocation::RevocationResponse;
use browntls_core::{Error, SideData, dtls};

use super::shape;
use crate::input::Input;

/// Iterations of the network loop per run.
const MAX_STEPS: usize = 2000;

/// Virtual time a run may take: long enough for an unanswered peer to
/// give up (nine retransmissions with a doubling timer capped at 60 s).
const MAX_VIRTUAL: Duration = Duration::from_secs(900);

/// Delivered datagrams kept for replays.
const MAX_LOG: usize = 32;

/// Losses that an undamaged handshake survives for certain.
pub(super) const MAX_LOSS: usize = 3;

/// Why a run stopped short (the errors are for failure messages).
#[derive(Debug)]
#[allow(dead_code)]
pub(super) enum Failure {
    Client(Error),
    Server(Error),
    /// No timer armed and nothing to send, before the goal.
    Stalled,
    /// The step or virtual time budget ran out.
    Budget,
}

/// One direction.
#[derive(Default)]
struct Link {
    held: Option<Vec<u8>>,
    inbox: VecDeque<Vec<u8>>,
}

impl Link {
    fn release(&mut self) {
        if let Some(held) = self.held.take() {
            self.inbox.push_back(held);
        }
    }
}

/// The network and the clock.
pub(super) struct Net<'a> {
    fates: Input<'a>,
    clock: Input<'a>,
    /// OCSP answers for a client that defers its revocation check.
    revocation: Input<'a>,
    pub(super) now: Duration,
    to_server: Link,
    to_client: Link,
    /// Datagrams damaged on the way.
    pub(super) corrupted: usize,
    /// A forged datagram was delivered.
    pub(super) forged: bool,
    /// A revocation answer failed the check.
    pub(super) refused: bool,
    pub(super) dropped: usize,
    pub(super) client_received: Vec<Vec<u8>>,
    pub(super) server_received: Vec<Vec<u8>>,
    /// Delivered datagrams as they arrived, and whether to the server.
    pub(super) log: VecDeque<(bool, Vec<u8>)>,
}

impl<'a> Net<'a> {
    pub(super) fn new(now: Duration) -> Self {
        Self {
            fates: Input::new(&[]),
            clock: Input::new(&[]),
            revocation: Input::new(&[]),
            now,
            to_server: Link::default(),
            to_client: Link::default(),
            corrupted: 0,
            forged: false,
            refused: false,
            dropped: 0,
            client_received: Vec::new(),
            server_received: Vec::new(),
            log: VecDeque::new(),
        }
    }

    /// Takes the fates, clock and revocation answers of the next run.
    pub(super) fn script(&mut self, fates: &'a [u8], clock: &'a [u8], revocation: &'a [u8]) {
        self.fates = Input::new(fates);
        self.clock = Input::new(clock);
        self.revocation = Input::new(revocation);
        self.corrupted = 0;
        self.forged = false;
        self.refused = false;
        self.dropped = 0;
    }

    /// Whether the last run's network was gentle enough that a handshake
    /// must succeed: nothing damaged or forged (an unprotected hello or
    /// alert cannot be told from a forgery), at most [`MAX_LOSS`] losses,
    /// and no refused revocation answer.
    pub(super) fn undamaged(&self) -> bool {
        self.corrupted == 0 && !self.forged && !self.refused && self.dropped <= MAX_LOSS
    }

    /// Whether the last run lost at most [`MAX_LOSS`] datagrams, counting
    /// damaged ones as lost: established connections must then settle,
    /// whatever was forged.
    pub(super) fn lossless(&self) -> bool {
        self.dropped + self.corrupted <= MAX_LOSS
    }

    /// Logs a datagram delivered to the server (or the client) for later
    /// replays, as it was before decryption in place.
    pub(super) fn remember(&mut self, to_server: bool, datagram: &[u8]) {
        self.log.push_back((to_server, datagram.to_vec()));
        if self.log.len() > MAX_LOG {
            self.log.pop_front();
        }
    }

    /// Puts `datagram` on the wire towards the server or the client.
    pub(super) fn send(&mut self, to_server: bool, mut datagram: Vec<u8>) {
        let link = if to_server {
            &mut self.to_server
        } else {
            &mut self.to_client
        };
        match self.fates.choose(9) {
            4 => self.dropped += 1,
            5 => {
                link.inbox.push_back(datagram.clone());
                link.inbox.push_back(datagram);
                link.release();
            }
            6 => {
                if let Some(held) = link.held.replace(datagram) {
                    link.inbox.push_back(held);
                }
            }
            7 if !datagram.is_empty() => {
                let at = usize::from(self.fates.u16()) % datagram.len();
                datagram[at] ^= self.fates.byte().max(1);
                self.corrupted += 1;
                link.inbox.push_back(datagram);
                link.release();
            }
            8 => {
                link.inbox.push_back(shape::datagram(&mut self.fates));
                link.inbox.push_back(datagram);
                link.release();
                self.forged = true;
            }
            _ => {
                link.inbox.push_back(datagram);
                link.release();
            }
        }
    }

    /// Sends what `conn` has, checking every datagram against its MTU.
    fn flush<D: SideData>(
        &mut self,
        conn: &mut dtls::ConnectionCommon<D>,
        to_server: bool,
    ) -> Result<bool, Error> {
        let mut moved = false;
        let mut out = Vec::new();
        while conn.write_datagram(&mut out, self.now)? {
            assert!(!out.is_empty(), "an empty datagram");
            assert!(
                out.len() <= conn.mtu(),
                "{} byte datagram over the MTU of {}",
                out.len(),
                conn.mtu()
            );
            self.send(to_server, std::mem::take(&mut out));
            moved = true;
        }
        assert!(
            out.is_empty(),
            "write_datagram returned false after writing"
        );
        Ok(moved)
    }

    /// Delivers what waits for `conn`.
    fn deliver<D: SideData>(
        &mut self,
        conn: &mut dtls::ConnectionCommon<D>,
        to_server: bool,
    ) -> Result<bool, Error> {
        let mut moved = false;
        loop {
            let link = if to_server {
                &mut self.to_server
            } else {
                &mut self.to_client
            };
            let Some(mut datagram) = link.inbox.pop_front() else {
                return Ok(moved);
            };
            moved = true;
            self.remember(to_server, &datagram);
            let received = conn.read_datagram(&mut datagram, self.now)?;
            let data = received
                .app_data()
                .iter()
                .map(|range| datagram[range.clone()].to_vec());
            if to_server {
                self.server_received.extend(data);
            } else {
                self.client_received.extend(data);
            }
        }
    }

    /// Answers a deferred revocation check of the client.
    fn revocation(&mut self, client: &mut dtls::ClientConnection) -> Result<bool, Error> {
        let Some(id) = client.pending_revocation().map(|query| query.id()) else {
            return Ok(false);
        };
        let answer = self.revocation.byte();
        if answer & 8 != 0 {
            // Another query's identifier is refused and changes nothing.
            let wrong = id.wrapping_add(1 + u64::from(answer >> 4));
            assert!(
                client
                    .resolve_peer_revocation(wrong, RevocationResponse::Unavailable, self.now)
                    .is_err()
            );
            assert_eq!(client.pending_revocation().map(|q| q.id()), Some(id));
        }
        let response = match answer & 3 {
            0 => RevocationResponse::Unavailable,
            n => RevocationResponse::Der(vec![n]),
        };
        if answer & 3 != 1 && answer & 3 != 2 {
            self.refused = true;
        }
        client.resolve_peer_revocation(id, response, self.now)?;
        Ok(true)
    }

    /// Runs the two endpoints until `goal` holds once the network is
    /// quiet, advancing the clock to (or towards) the next timer whenever
    /// nothing moves.
    pub(super) fn run(
        &mut self,
        client: &mut dtls::ClientConnection,
        server: &mut dtls::ServerConnection,
        goal: fn(&dtls::ClientConnection, &dtls::ServerConnection) -> bool,
    ) -> Result<(), Failure> {
        let start = self.now;
        for _ in 0..MAX_STEPS {
            let mut moved = self.flush(client, true).map_err(Failure::Client)?;
            moved |= self.flush(server, false).map_err(Failure::Server)?;
            moved |= self.deliver(server, true).map_err(Failure::Server)?;
            moved |= self.deliver(client, false).map_err(Failure::Client)?;
            moved |= self.revocation(client).map_err(Failure::Client)?;
            if moved {
                continue;
            }
            if self.to_server.held.is_some() || self.to_client.held.is_some() {
                self.to_server.release();
                self.to_client.release();
                continue;
            }
            if goal(client, server) {
                return Ok(());
            }
            let next = match (client.next_timeout(), server.next_timeout()) {
                (Some(a), Some(b)) => a.min(b),
                (a, b) => a.or(b).ok_or(Failure::Stalled)?,
            };
            // Early, on time or late, as the clock bytes say.
            self.now = match self.clock.byte() {
                0 => self.now.max(next),
                n @ 1..=127 => self.now + Duration::from_millis(8 * u64::from(n)),
                n => self.now.max(next) + Duration::from_millis(64 * u64::from(n - 128)),
            };
            if self.now - start > MAX_VIRTUAL {
                return Err(Failure::Budget);
            }
            client.handle_timeout(self.now).map_err(Failure::Client)?;
            server.handle_timeout(self.now).map_err(Failure::Server)?;
        }
        Err(Failure::Budget)
    }

    /// After a failure: lets both sides send what they still have (the
    /// alert) and the other read it, without checking the outcome.
    pub(super) fn wind_down(
        &mut self,
        client: &mut dtls::ClientConnection,
        server: &mut dtls::ServerConnection,
    ) {
        let _ = self.flush(client, true);
        let _ = self.flush(server, false);
        self.to_server.release();
        self.to_client.release();
        let _ = self.deliver(server, true);
        let _ = self.deliver(client, false);
        self.to_server.inbox.clear();
        self.to_client.inbox.clear();
    }
}

/// Both handshakes are complete and nothing waits on a timer: every
/// flight and post-handshake message is acknowledged.
pub(super) fn settled(client: &dtls::ClientConnection, server: &dtls::ServerConnection) -> bool {
    !client.is_handshaking()
        && !server.is_handshaking()
        && client.next_timeout().is_none()
        && server.next_timeout().is_none()
}
