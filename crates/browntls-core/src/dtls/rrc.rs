//! RFC 9853 wire codec and bounded, transport-independent path validation.
//!
//! The caller must gate use on negotiated RRC and CID, authenticate and
//! replay-check records before declaring them fresh, and bind opaque path
//! identities to the complete transport address. Time is monotonic elapsed
//! time from one caller-chosen origin, never wall time.
//!
//! Feed each accepted record exactly once to [`Validation::receive`], then
//! drive [`Validation::poll`] at paced intervals and deadlines. Execute each
//! [`Action::Send`] once as an encrypted, authenticated RRC record on its
//! specified path. The supplied send size must include the entire protected
//! DTLS record, including headers, tag and padding. Every returned send has
//! already consumed its allowance; failed sends do not refund it. All other
//! outgoing traffic to the candidate must use [`Validation::reserve_send`].
//! Do not clone this state or outstanding actions to duplicate send credit.
//!
//! There is one pending candidate, three cookies per validation stage, no
//! allocation, and no I/O. A nested path cannot replace the candidate or
//! inherit its credit. Challenges on a third path can receive an immediate
//! reply using only that record's credit; unused credit is discarded.

#![forbid(unsafe_code)]

use core::fmt;
use core::time::Duration;

use crate::crypto::SecureRandom;
use crate::ct::constant_time_eq;

/// RFC 9853 extension type; its extension data is empty.
pub const EXTENSION_TYPE: u16 = 61;
/// The protected RRC record content type.
pub const CONTENT_TYPE: u8 = 27;
/// One message type byte and an eight-byte opaque cookie.
pub const WIRE_LEN: usize = 9;
/// Maximum paced challenges in each of the old and new path stages.
pub const MAX_PROBES: usize = 3;
/// Recommended validation timeout when no RTT estimate is available.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Codec, configuration, clock, or randomness failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A known message has an incorrect length, or extension data is nonempty.
    InvalidEncoding,
    /// A timeout must permit three nonzero probe intervals.
    InvalidTimeout,
    /// The caller's elapsed clock moved backwards.
    TimeWentBackwards,
    /// The caller's clock cannot represent a future timer.
    TimeOverflow,
    /// The configured provider could not generate a fresh cookie.
    RandomFailed,
    /// A supplied record size cannot contain the specified plaintext.
    InvalidRecordSize,
}

/// Recognized RRC message types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Ask the peer to prove that this path works.
    Challenge = 0,
    /// This path works and remains preferred.
    Response = 1,
    /// This path works but is no longer preferred.
    Drop = 2,
}

/// One RRC message. Debug output intentionally omits the cookie.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// The message's purpose.
    pub kind: MessageType,
    /// Uninterpreted wire bytes, freshly random for locally created probes.
    pub cookie: [u8; 8],
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Message {
    /// Decode exactly one record payload, ignoring unknown message types.
    /// Unknown types impose no assumptions about future payload lengths.
    pub fn decode(payload: &[u8]) -> Result<Option<Self>, Error> {
        let kind = match payload.first() {
            Some(0) => MessageType::Challenge,
            Some(1) => MessageType::Response,
            Some(2) => MessageType::Drop,
            Some(_) => return Ok(None),
            None => return Err(Error::InvalidEncoding),
        };
        let cookie = payload[1..]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?;
        Ok(Some(Self { kind, cookie }))
    }

    /// Encode the type and cookie without DTLS record framing or protection.
    pub fn encode(&self) -> [u8; WIRE_LEN] {
        let mut output = [0; WIRE_LEN];
        output[0] = self.kind as u8;
        output[1..].copy_from_slice(&self.cookie);
        output
    }
}

/// Validate the empty RRC extension data, without negotiating its use.
pub fn decode_extension(data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// Path selection policy. Enhanced selection probes the bound path first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Validate the newly observed path directly.
    Basic,
    /// Keep the old path if it answers; otherwise validate the new path.
    Enhanced,
}

/// The caller's record-layer authentication and replay decision.
pub enum Record<'a> {
    /// Unauthenticated, replayed, or otherwise discarded input: no effects.
    Discarded,
    /// A cryptographically authenticated record accepted by replay protection.
    AuthenticatedFresh {
        /// Full accepted DTLS record size, excluding unrelated datagram bytes.
        dtls_bytes: usize,
        /// RRC plaintext, or `None` for an accepted non-RRC record.
        rrc: Option<&'a [u8]>,
    },
}

/// A synchronous caller hook; no action is queued inside the state machine.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Action<P> {
    /// No record or binding change is required.
    None,
    /// Protect and send this message exactly once on this actual path.
    Send {
        /// Actual destination; never substitute the current bound address.
        path: P,
        /// Plaintext to protect under the active DTLS security context.
        message: Message,
    },
    /// Enhanced selection verified the old path and retained its binding.
    Keep {
        /// The still-bound old path.
        path: P,
    },
    /// A timely matching response validated the candidate; update the binding.
    Adopt {
        /// The newly bound path.
        path: P,
    },
    /// New-path validation expired; the old binding is unchanged.
    Failed {
        /// The candidate whose validation failed.
        path: P,
    },
}

struct Phase {
    old: bool,
    deadline: Option<Duration>,
    next_probe: Duration,
    cookies: [[u8; 8]; MAX_PROBES],
    sent: usize,
}

impl Phase {
    fn new(old: bool, now: Duration) -> Self {
        Self {
            old,
            deadline: None,
            next_probe: now,
            cookies: [[0; 8]; MAX_PROBES],
            sent: 0,
        }
    }

    fn matches(&self, cookie: &[u8; 8], now: Duration) -> bool {
        self.deadline.is_some_and(|deadline| now < deadline)
            && self.cookies[..self.sent]
                .iter()
                .any(|sent| constant_time_eq(sent, cookie))
    }
}

struct Candidate<P> {
    path: P,
    allowance: u64,
    phase: Phase,
}

/// One bound address and at most one pending candidate. `P` must compare the
/// complete caller-supplied path identity, including relevant local routing.
/// The provider reference must come from this connection's configuration.
pub struct Validation<P> {
    bound: P,
    candidate: Option<Candidate<P>>,
    selection: Selection,
    timeout: Duration,
    interval: Duration,
    last_time: Duration,
    random: &'static dyn SecureRandom,
}

impl<P: Clone + Eq> Validation<P> {
    /// Start with an already validated path. Use `DEFAULT_TIMEOUT` without
    /// an RTT estimate, or normally three times the old path's RTT.
    pub fn new(
        bound: P,
        selection: Selection,
        timeout: Duration,
        random: &'static dyn SecureRandom,
    ) -> Result<Self, Error> {
        if timeout < Duration::from_nanos(MAX_PROBES as u64) {
            return Err(Error::InvalidTimeout);
        }
        Ok(Self {
            bound,
            candidate: None,
            selection,
            timeout,
            interval: timeout / MAX_PROBES as u32,
            last_time: Duration::ZERO,
            random,
        })
    }

    /// The current validated path, unchanged until an `Adopt` action.
    pub fn bound_path(&self) -> &P {
        &self.bound
    }

    /// The sole candidate, if a validation is pending.
    pub fn pending_path(&self) -> Option<&P> {
        self.candidate.as_ref().map(|candidate| &candidate.path)
    }

    /// Current stage's expiry, set when its first probe is emitted. The
    /// caller must also poll for backup probes every `timeout / MAX_PROBES`.
    /// A stage waiting for send allowance has no running timer yet.
    pub fn deadline(&self) -> Option<Duration> {
        self.candidate.as_ref().and_then(|c| c.phase.deadline)
    }

    /// Reserve complete outgoing DTLS bytes before sending any other traffic.
    /// Validated-path sends are unrestricted. Unknown paths have no credit.
    /// Reservations are deliberately not refunded after local send failure.
    pub fn reserve_send(&mut self, path: &P, dtls_bytes: usize) -> bool {
        if *path == self.bound {
            return true;
        }
        let Some(candidate) = self.candidate.as_mut().filter(|c| c.path == *path) else {
            return false;
        };
        let Ok(bytes) = u64::try_from(dtls_bytes) else {
            return false;
        };
        let Some(remaining) = candidate.allowance.checked_sub(bytes) else {
            return false;
        };
        candidate.allowance = remaining;
        true
    }

    fn clock(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.last_time {
            return Err(Error::TimeWentBackwards);
        }
        self.last_time = now;
        Ok(())
    }

    /// Accept one record. Discarded inputs cannot grant credit, echo cookies,
    /// start validation, or satisfy a probe. Invalid known encodings return an
    /// error before granting credit. Unknown types are silently ignored.
    ///
    /// `preferred` states whether the incoming path remains locally preferred;
    /// it selects response versus drop only for a challenge. `reply_bytes`
    /// is the full protected reply size; a blocked reply is not queued. The
    /// caller must provision record sizes that let one reply fit in 3x credit.
    /// Drive `poll` separately to advance expired stages and send probes.
    pub fn receive(
        &mut self,
        path: P,
        now: Duration,
        record: Record<'_>,
        preferred: bool,
        reply_bytes: usize,
    ) -> Result<Action<P>, Error> {
        let Record::AuthenticatedFresh { dtls_bytes, rrc } = record else {
            return Ok(Action::None);
        };
        self.clock(now)?;
        if dtls_bytes == 0 || rrc.is_some_and(|payload| payload.len() > dtls_bytes) {
            return Err(Error::InvalidRecordSize);
        }
        let message = rrc.map(Message::decode).transpose()?.flatten();
        if message.is_some_and(|message| message.kind == MessageType::Challenge)
            && reply_bytes < WIRE_LEN
        {
            return Err(Error::InvalidRecordSize);
        }
        let credit = u64::try_from(dtls_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(3);
        let is_reply = message.is_some_and(|m| m.kind != MessageType::Challenge);
        if path != self.bound && self.candidate.is_none() && !is_reply {
            self.candidate = Some(Candidate {
                path: path.clone(),
                allowance: 0,
                phase: Phase::new(self.selection == Selection::Enhanced, now),
            });
        }
        if let Some(candidate) = self.candidate.as_mut().filter(|c| c.path == path) {
            candidate.allowance = candidate.allowance.saturating_add(credit);
        }
        let Some(mut message) = message else {
            return Ok(Action::None);
        };
        if message.kind == MessageType::Challenge {
            // Third-path replies use only this record's ephemeral credit.
            let tracked = path == self.bound || self.pending_path() == Some(&path);
            let allowed = if tracked {
                self.reserve_send(&path, reply_bytes)
            } else {
                u64::try_from(reply_bytes).is_ok_and(|bytes| bytes <= credit)
            };
            if !allowed {
                return Ok(Action::None);
            }
            message.kind = if preferred {
                MessageType::Response
            } else {
                MessageType::Drop
            };
            return Ok(Action::Send { path, message });
        }
        let Some(candidate) = self.candidate.as_mut() else {
            return Ok(Action::None);
        };
        let expected = if candidate.phase.old {
            &self.bound
        } else {
            &candidate.path
        };
        if &path != expected || !candidate.phase.matches(&message.cookie, now) {
            return Ok(Action::None);
        }
        if candidate.phase.old {
            if message.kind == MessageType::Drop {
                candidate.phase = Phase::new(false, now);
                return Ok(Action::None);
            }
            self.candidate = None;
            return Ok(Action::Keep {
                path: self.bound.clone(),
            });
        }
        if message.kind == MessageType::Response {
            self.bound = candidate.path.clone();
            self.candidate = None;
            return Ok(Action::Adopt {
                path: self.bound.clone(),
            });
        }
        Ok(Action::None)
    }

    /// Advance timeouts and emit at most one paced probe. Each emitted probe
    /// gets a fresh provider-generated cookie. The timer starts with the
    /// first emitted probe of each stage. Lost probes are never retransmitted
    /// with the same cookie. All emitted cookies remain valid until timeout.
    /// Old-stage timeout starts a new basic stage; new-stage timeout fails.
    pub fn poll(&mut self, now: Duration, probe_bytes: usize) -> Result<Action<P>, Error> {
        self.clock(now)?;
        if probe_bytes < WIRE_LEN {
            return Err(Error::InvalidRecordSize);
        }
        let Some(candidate) = self.candidate.as_mut() else {
            return Ok(Action::None);
        };
        if candidate
            .phase
            .deadline
            .is_some_and(|deadline| now >= deadline)
        {
            if candidate.phase.old {
                candidate.phase = Phase::new(false, now);
            } else {
                let path = candidate.path.clone();
                self.candidate = None;
                return Ok(Action::Failed { path });
            }
        }
        let phase = &candidate.phase;
        if phase.sent == MAX_PROBES || now < phase.next_probe {
            return Ok(Action::None);
        }
        let path = if phase.old {
            self.bound.clone()
        } else {
            let bytes = u64::try_from(probe_bytes).map_err(|_| Error::InvalidRecordSize)?;
            if bytes > candidate.allowance {
                return Ok(Action::None);
            }
            candidate.path.clone()
        };
        let deadline = match phase.deadline {
            Some(deadline) => deadline,
            None => now.checked_add(self.timeout).ok_or(Error::TimeOverflow)?,
        };
        let next_probe = now.checked_add(self.interval).ok_or(Error::TimeOverflow)?;
        let mut cookie = [0; 8];
        self.random
            .fill(&mut cookie)
            .map_err(|_| Error::RandomFailed)?;
        // All fallible work precedes reservation and recording this probe.
        if !self.reserve_send(&path, probe_bytes) {
            return Ok(Action::None);
        }
        if let Some(candidate) = self.candidate.as_mut() {
            let phase = &mut candidate.phase;
            phase.cookies[phase.sent] = cookie;
            phase.sent += 1;
            phase.deadline = Some(deadline);
            phase.next_probe = next_probe;
        }
        Ok(Action::Send {
            path,
            message: Message {
                kind: MessageType::Challenge,
                cookie,
            },
        })
    }
}

#[cfg(test)]
mod tests;
