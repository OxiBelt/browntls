//! Socket path policy around the transport-independent RRC validator.

use alloc::vec::Vec;
use core::ops::Range;
use core::time::Duration;
use std::net::SocketAddr;

use crate::conn::SideData;
use crate::dtls::rrc::{self, Action, Validation};
use crate::dtls::{ConnectionCommon, Received};
use crate::error::Error;

/// The wrapper owns one validated destination and at most one candidate.
/// Application output and ordinary protocol output use only the bound path.
/// Socket-address validation shared by the blocking and Tokio adapters.
#[derive(Debug)]
pub struct UdpPathValidation {
    validation: Validation<SocketAddr>,
    selection: rrc::Selection,
    next_poll: Option<Duration>,
    pending_since: Option<Duration>,
}

impl UdpPathValidation {
    /// Starts validation from an established, already validated address.
    pub fn new<D: SideData>(
        conn: &ConnectionCommon<D>,
        active: SocketAddr,
        selection: rrc::Selection,
    ) -> Result<Self, Error> {
        Ok(Self {
            validation: conn.new_path_validation(active, selection, rrc::DEFAULT_TIMEOUT)?,
            selection,
            next_poll: None,
            pending_since: None,
        })
    }

    /// The active validated transport address.
    pub fn active(&self) -> SocketAddr {
        *self.validation.bound_path()
    }

    /// The candidate being validated, when one is pending.
    pub fn pending(&self) -> Option<SocketAddr> {
        self.validation.pending_path().copied()
    }

    /// The next probe or expiry time on the connection clock.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.next_poll
    }

    /// Only checked records grant credit. Foreign paths must carry a CID;
    /// a third path cannot satisfy a probe or replace a pending candidate.
    /// Application data is released per record, only on the validated path
    /// at that point in the datagram. Pre-validation data is discarded.
    pub fn input<D: SideData>(
        &mut self,
        conn: &mut ConnectionCommon<D>,
        received: &Received,
        datagram: &[u8],
        source: SocketAddr,
        now: Duration,
        send: &mut impl FnMut(&[u8], SocketAddr),
    ) -> Result<Vec<Range<usize>>, Error> {
        let mut app = Vec::new();
        let mut ranges = received.app_data().iter().peekable();
        for record in received.authenticated_records() {
            let active = source == self.active();
            if !active
                && (record.connection_id().is_none()
                    || self.pending().is_some_and(|pending| pending != source))
            {
                continue;
            }
            if !conn.peer_has_closed() && !conn.has_sent_close_notify() {
                // RFC 9853 §5.2 uses the responder's local preference.
                // This socket remains preferred when the peer changes address.
                let action = conn.handle_path_record(
                    &mut self.validation,
                    record,
                    datagram,
                    source,
                    true,
                    now,
                )?;
                Self::execute(conn, action, send)?;
            }
            let authenticated = record.range();
            while let Some(range) = ranges.peek().copied() {
                if range.end > authenticated.end {
                    break;
                }
                if source == self.active() && range.start >= authenticated.start {
                    app.push(range.clone());
                }
                ranges.next();
            }
        }
        self.schedule(now);
        Ok(app)
    }

    /// Drives due probes through the caller's send operation.
    pub fn poll<D: SideData>(
        &mut self,
        conn: &mut ConnectionCommon<D>,
        now: Duration,
        send: &mut impl FnMut(&[u8], SocketAddr),
    ) -> Result<(), Error> {
        if conn.peer_has_closed() || conn.has_sent_close_notify() {
            self.next_poll = None;
            return Ok(());
        }
        // A validator waiting for amplification credit has no deadline.
        // Bound that wait too, without allocating or retaining app data.
        // Three stage lengths leave time for both enhanced/basic stages.
        if self
            .pending_since
            .is_some_and(|since| now.saturating_sub(since) >= rrc::DEFAULT_TIMEOUT * 3)
        {
            *self = Self::new(conn, self.active(), self.selection)?;
            return Ok(());
        }
        if self.next_poll.is_some_and(|due| due <= now) {
            let action = conn.poll_path_validation(&mut self.validation, now)?;
            Self::execute(conn, action, send)?;
            let next = now.saturating_add(rrc::DEFAULT_TIMEOUT / rrc::MAX_PROBES as u32);
            self.next_poll = Some(self.validation.deadline().map_or(next, |due| due.min(next)));
        }
        self.schedule(now);
        Ok(())
    }

    fn schedule(&mut self, now: Duration) {
        if self.pending().is_none() {
            self.pending_since = None;
            self.next_poll = None;
        } else {
            self.pending_since.get_or_insert(now);
            // Poll on a fixed cadence, independently of input.
            // The first probe is immediate; further probes are paced.
            self.next_poll.get_or_insert(now);
        }
    }

    fn execute<D: SideData>(
        conn: &mut ConnectionCommon<D>,
        action: Action<SocketAddr>,
        send: &mut impl FnMut(&[u8], SocketAddr),
    ) -> Result<(), Error> {
        if let Action::Send { path, message } = action {
            // The validator has already reserved this exact protected size.
            // Never reserve twice or refund credit after a socket failure.
            let reserved = conn.rrc_record_len()?;
            let mut out = Vec::new();
            conn.send_rrc(&message, &mut out)?;
            if out.len() > reserved {
                return Err(Error::EncryptError);
            }
            send(&out, path);
        }
        Ok(())
    }
}
