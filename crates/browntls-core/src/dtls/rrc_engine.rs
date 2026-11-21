//! Negotiation and record protection around the caller-owned RRC validator.

use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use super::cid::{AuthenticatedRecord, ConnectionIdPolicy};
use super::connection::ConnectionCommon;
use super::rrc::{self, Action, Validation};
use super::state::{APPLICATION_EPOCH, Dtls, Settings};
use crate::common_state::CommonState;
use crate::conn::SideData;
use crate::enums::{AlertDescription, ContentType};
use crate::error::Error;

// Public validator types keep diagnostic output independent of cookies and
// caller path identities. These impls leave the pure validator unchanged.
impl<P> fmt::Debug for Validation<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validation").finish_non_exhaustive()
    }
}

impl fmt::Debug for rrc::Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discarded => f.write_str("Discarded"),
            Self::AuthenticatedFresh { dtls_bytes, rrc } => f
                .debug_struct("AuthenticatedFresh")
                .field("dtls_bytes", dtls_bytes)
                .field("is_rrc", &rrc.is_some())
                .finish_non_exhaustive(),
        }
    }
}

impl Settings {
    /// Offers RFC 9853 RRC and CID together. Both are disabled by default.
    /// An empty receiving CID is allowed, independently in each direction.
    ///
    /// The caller must keep routing pinned until validation succeeds, drive
    /// the validator's timers, execute each action once on its specified
    /// path, and reserve allowance for all other candidate-path traffic.
    /// This setting alone does not enforce transport send limits.
    pub fn with_return_routability_checks(mut self, policy: ConnectionIdPolicy) -> Self {
        self.connection_ids = Some(policy);
        self.return_routability_check = true;
        self
    }
}

impl Dtls {
    pub(crate) fn rrc_offer(&self) -> Option<()> {
        (self.settings.return_routability_check && self.cid.offer().is_some()).then_some(())
    }

    pub(crate) fn select_rrc(&mut self, peer_offered: bool) {
        // A CID response exists even when both receiving IDs are empty.
        self.rrc_negotiated =
            peer_offered && self.settings.return_routability_check && self.cid.response().is_some();
    }
}

/// The codec parses empty RRC extensions independently of the DTLS version.
/// Only a DTLS association with a selected CID may accept the server's echo.
pub(crate) fn select_server_hello(common: &mut CommonState, present: bool) -> Result<(), Error> {
    let accepted = match common.dtls.as_deref_mut() {
        Some(dtls) => {
            dtls.select_rrc(present);
            !present || dtls.rrc_negotiated
        }
        None => !present,
    };
    if !accepted {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            Error::General("unoffered DTLS RRC or missing CID selection".into()),
        ));
    }
    Ok(())
}

impl AuthenticatedRecord {
    /// Adapt this checked metadata to the version-independent validator.
    /// Supply the same decrypted datagram returned by `read_datagram`, and
    /// feed each accepted record exactly once. Metadata is not a routing
    /// authorization, and reusing it would duplicate amplification credit.
    pub fn path_validation_record<'a>(
        &self,
        datagram: &'a [u8],
    ) -> Result<rrc::Record<'a>, rrc::Error> {
        let range = self.range();
        let record = datagram
            .get(range.clone())
            .ok_or(rrc::Error::InvalidRecordSize)?;
        let rrc = match self.rrc_payload_range() {
            Some(payload) if payload.start >= range.start && payload.end <= range.end => {
                Some(datagram.get(payload).ok_or(rrc::Error::InvalidRecordSize)?)
            }
            Some(_) => return Err(rrc::Error::InvalidRecordSize),
            None => None,
        };
        Ok(rrc::Record::AuthenticatedFresh {
            dtls_bytes: record.len(),
            rrc,
        })
    }
}

impl<Data: SideData> ConnectionCommon<Data> {
    /// Whether the completed association negotiated both RRC and CID.
    pub fn return_routability_checks_negotiated(&self) -> bool {
        !self.is_handshaking() && self.dtls().rrc_negotiated
    }

    fn check_rrc_ready(&self) -> Result<(), Error> {
        self.check_cid_ready()?;
        if !self.dtls().rrc_negotiated {
            return Err(Error::General("DTLS RRC was not negotiated".into()));
        }
        Ok(())
    }

    /// Create caller-owned validation for an already validated path, using
    /// this connection's configured random source. Paths are opaque here.
    pub fn new_path_validation<P: Clone + Eq>(
        &self,
        bound: P,
        selection: rrc::Selection,
        timeout: Duration,
    ) -> Result<Validation<P>, Error> {
        self.check_rrc_ready()?;
        let random = self
            .dtls()
            .cid
            .random()
            .ok_or_else(|| Error::General("DTLS random source unavailable".into()))?;
        Validation::new(bound, selection, timeout, random).map_err(validation_error)
    }

    /// Size of one protected RRC datagram under the current keys and CID.
    /// Recompute after a key or CID change before reserving send allowance.
    pub fn rrc_record_len(&self) -> Result<usize, Error> {
        self.check_rrc_ready()?;
        self.dtls()
            .record_len(self.dtls().write_epoch(), rrc::WIRE_LEN)
            .filter(|len| *len <= self.mtu())
            .ok_or(Error::EncryptError)
    }

    /// Append one protected control datagram, sharing application traffic's
    /// sequence numbers, MTU and confidentiality limits, including its
    /// request to refresh keys near exhaustion. Nothing is queued or routed.
    /// For an `Action::Send`, use its exact path and execute it only once.
    pub fn send_rrc(&mut self, message: &rrc::Message, out: &mut Vec<u8>) -> Result<(), Error> {
        self.check_rrc_ready()?;
        if !self.core.common_state.may_send_application_data {
            return Err(Error::HandshakeNotComplete);
        }
        if self.dtls_mut().seal_application_record(
            out,
            ContentType::ReturnRoutabilityCheck,
            &message.encode(),
        )? {
            self.core.common_state.refresh_traffic_keys_pending = true;
        }
        Ok(())
    }

    /// Feed one record from this connection's latest decrypted datagram to
    /// caller-owned validation, exactly once. The caller supplies the actual
    /// source path and its preference; only application epochs grant credit.
    /// The returned action has no transport effect until the caller acts.
    /// All other sends to a candidate need `Validation::reserve_send` too.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_path_record<P: Clone + Eq>(
        &self,
        validation: &mut Validation<P>,
        record: &AuthenticatedRecord,
        datagram: &[u8],
        path: P,
        preferred: bool,
        now: Duration,
    ) -> Result<Action<P>, Error> {
        self.check_rrc_ready()?;
        let application_epoch = if self.dtls().is_v12() {
            1
        } else {
            APPLICATION_EPOCH
        };
        if record.epoch() < application_epoch
            || (&path != validation.bound_path() && record.connection_id().is_none())
        {
            return Ok(Action::None);
        }
        validation
            .receive(
                path,
                now,
                record
                    .path_validation_record(datagram)
                    .map_err(validation_error)?,
                preferred,
                self.rrc_record_len()?,
            )
            .map_err(validation_error)
    }

    /// Drive paced probes and timeouts using the current protected size.
    /// Call independently of input, at validator deadlines and probe times;
    /// execute each returned send once on its specified path. Failed sends
    /// retain their consumed allowance. This never changes engine routing.
    pub fn poll_path_validation<P: Clone + Eq>(
        &self,
        validation: &mut Validation<P>,
        now: Duration,
    ) -> Result<Action<P>, Error> {
        validation
            .poll(now, self.rrc_record_len()?)
            .map_err(validation_error)
    }
}

fn validation_error(error: rrc::Error) -> Error {
    Error::General(alloc::format!("DTLS RRC validation: {error:?}"))
}

#[cfg(test)]
mod tests;
