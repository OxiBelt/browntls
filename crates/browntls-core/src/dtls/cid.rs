//! CID negotiation, association lookup and updates (RFC 9146, RFC 9147 §9).
//!
//! Local identifiers have one fixed length. They remain valid until this
//! association ends, including while an update awaits ACK; none is reused.
//! This stage does not validate a new path or change a destination address.

use alloc::vec::Vec;
use core::ops::Range;

use super::state::{APPLICATION_EPOCH, Dtls, Settings};
use super::wire::{self, RecordNumber};
use crate::common_state::CommonState;
use crate::crypto::SecureRandom;
use crate::enums::{AlertDescription, HandshakeType};
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::{Codec, Reader};

/// Maximum local identifiers issued over one association's entire life,
/// including the handshake identifier. Peer spare storage has the same cap.
pub const MAX_CONNECTION_IDS: usize = 16;

/// Opt-in policy for DTLS connection IDs, independent in each direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionIdPolicy {
    receive_len: u8,
    allow_sending: bool,
}

impl ConnectionIdPolicy {
    /// Chooses the fixed length of locally generated receiving IDs (8 to
    /// 32 bytes), or zero to negotiate an empty receiving CID. Sending
    /// peer-selected IDs of any wire length (0 to 255) requires
    /// `allow_sending`, except that an empty peer CID is always permitted.
    pub fn new(receive_len: u8, allow_sending: bool) -> Result<Self, Error> {
        if receive_len != 0 && !(8..=32).contains(&receive_len) {
            return Err(local_error("DTLS receiving CID length must be 0 or 8..=32"));
        }
        Ok(Self {
            receive_len,
            allow_sending,
        })
    }
}

impl Settings {
    /// Chooses which DTLS versions this endpoint can negotiate.
    pub fn with_versions(mut self, versions: super::Versions) -> Self {
        self.versions = versions;
        self
    }

    /// Enables connection IDs for this DTLS connection. The default
    /// settings do not offer or select the extension. Stream TLS and QUIC
    /// configuration are unaffected.
    pub fn with_connection_ids(mut self, policy: ConnectionIdPolicy) -> Self {
        self.connection_ids = Some(policy);
        self
    }
}

/// How a newly issued set of connection IDs should be used (RFC 9147 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionIdUsage {
    /// The peer must use one of the new IDs immediately for future records.
    Immediate,
    /// The peer may retain its current ID and keep these as spares.
    Spare,
}

/// A record whose header names this association and whose traffic-key
/// authentication and replay checks succeeded. This proves neither peer
/// address reachability nor permission to migrate to another path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedRecord {
    range: Range<usize>,
    number: RecordNumber,
    cid: Vec<u8>,
}

impl AuthenticatedRecord {
    /// The complete record within the input datagram.
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// The authenticated receiving CID, or `None` for the empty direction.
    pub fn connection_id(&self) -> Option<&[u8]> {
        (!self.cid.is_empty()).then_some(self.cid.as_slice())
    }

    /// The receiving epoch.
    pub fn epoch(&self) -> u64 {
        self.number.epoch
    }

    /// The reconstructed record sequence number in that epoch.
    pub fn sequence_number(&self) -> u64 {
        self.number.seq
    }

    pub(super) fn new(range: Range<usize>, number: RecordNumber, cid: Vec<u8>) -> Self {
        Self { range, number, cid }
    }

    pub(super) fn set_connection_id(&mut self, cid: &[u8]) {
        self.cid.extend_from_slice(cid);
    }
}

#[derive(Default)]
pub(crate) struct Cids {
    policy: Option<ConnectionIdPolicy>,
    random: Option<&'static dyn SecureRandom>,
    local: Vec<Vec<u8>>,
    peer: Vec<Vec<u8>>,
    negotiated: bool,
    /// The initial selection fixes whether the peer may issue updates,
    /// even when a later immediate update selects an empty CID.
    peer_can_issue: bool,
    request_unfulfilled: bool,
    /// Coalesce a request while our previous NewConnectionId awaits ACK.
    requested: Option<u8>,
}

impl Cids {
    pub(super) fn initialize(
        &mut self,
        policy: Option<ConnectionIdPolicy>,
        random: &'static dyn SecureRandom,
    ) -> Result<(), Error> {
        self.policy = policy;
        self.random = Some(random);
        if let Some(policy) = policy {
            let id = if policy.receive_len == 0 {
                Vec::new()
            } else {
                crate::rand::random_vec(random, usize::from(policy.receive_len))?
            };
            self.local.push(id);
        }
        Ok(())
    }

    pub(crate) fn offer(&self) -> Option<PayloadU8> {
        self.policy.map(|_| PayloadU8::new(self.local[0].clone()))
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn supports_v12_selection(
        &self,
        peer: Option<&PayloadU8>,
        cipher: crate::crypto::cipher::Tls12RecordProtection,
    ) -> bool {
        use crate::crypto::cipher::Tls12RecordProtection;

        let Some((policy, peer)) = self.policy.zip(peer) else {
            return true;
        };
        let (send, receive) = match cipher {
            Tls12RecordProtection::Aead(algorithm) => algorithm.dtls12_cid_support(),
            Tls12RecordProtection::BlockCipher(_) => (false, false),
        };
        (peer.0.is_empty() || send) && (policy.receive_len == 0 || receive)
    }

    pub(crate) fn select(&mut self, peer: Option<&PayloadU8>, server: bool) -> Result<(), Error> {
        let Some(peer) = peer else { return Ok(()) };
        let permitted = self
            .policy
            .is_some_and(|p| p.allow_sending || peer.0.is_empty());
        if !permitted {
            // A server can decline the offer; an unsolicited or forbidden
            // server selection must fail the client's handshake.
            return if server {
                Ok(())
            } else {
                Err(local_error("unoffered DTLS CID selection"))
            };
        }
        self.peer_can_issue = !peer.0.is_empty();
        self.peer = alloc::vec![peer.0.clone()];
        self.negotiated = true;
        Ok(())
    }

    pub(crate) fn response(&self) -> Option<PayloadU8> {
        self.negotiated
            .then(|| PayloadU8::new(self.local[0].clone()))
    }

    pub(super) fn receive_len(&self) -> usize {
        if self.negotiated {
            self.local[0].len()
        } else {
            0
        }
    }

    pub(super) fn matches(&self, cid: Option<&[u8]>) -> bool {
        if self.receive_len() == 0 {
            return cid.is_none();
        }
        cid.is_some_and(|id| self.local.iter().any(|local| local == id))
    }

    pub(super) fn outbound(&self) -> &[u8] {
        self.peer.first().map_or(&[], Vec::as_slice)
    }

    pub(super) fn local_ids(&self) -> impl Iterator<Item = &[u8]> {
        self.local
            .iter()
            .filter(move |id| self.negotiated && !id.is_empty())
            .map(Vec::as_slice)
    }

    fn can_issue(&self) -> bool {
        self.negotiated && self.receive_len() != 0
    }

    fn new_ids(&mut self, count: u8, usage: ConnectionIdUsage) -> Result<(usize, Vec<u8>), Error> {
        if !self.can_issue() {
            return Err(local_error("DTLS receiving CID was not negotiated"));
        }
        let count = usize::from(count).min(MAX_CONNECTION_IDS - self.local.len());
        if count == 0 && usage == ConnectionIdUsage::Immediate {
            return Err(local_error("immediate CID update requires a fresh ID"));
        }
        let random = self.random.ok_or(Error::FailedToGetRandomBytes)?;
        let mut fresh = Vec::new();
        for _ in 0..count {
            let mut unique = None;
            for _ in 0..4 {
                let id = crate::rand::random_vec(random, self.receive_len())?;
                if !self.local.contains(&id) && !fresh.contains(&id) {
                    unique = Some(id);
                    break;
                }
            }
            fresh.push(unique.ok_or(Error::FailedToGetRandomBytes)?);
        }
        let mut list = Vec::new();
        for id in &fresh {
            PayloadU8::new(id.clone()).encode(&mut list);
        }
        let mut body = Vec::new();
        (list.len() as u16).encode(&mut body);
        body.extend_from_slice(&list);
        body.push(match usage {
            ConnectionIdUsage::Immediate => 0,
            ConnectionIdUsage::Spare => 1,
        });
        self.local.extend(fresh);
        Ok((count, body))
    }

    fn receive_new(&mut self, body: &[u8]) -> Result<(), CidError> {
        if !self.negotiated || !self.peer_can_issue {
            return Err(unexpected());
        }
        let mut r = Reader::init(body);
        let len = usize::from(u16::read(&mut r).map_err(decode)?);
        let mut list = r.sub(len).map_err(decode)?;
        let usage = u8::read(&mut r).map_err(decode)?;
        r.expect_empty("NewConnectionId").map_err(decode)?;
        if usage > 1 || (usage == 0 && !list.any_left()) {
            return Err(illegal());
        }
        // Parse every item, but retain only a bounded set. Different peer
        // lengths, including empty IDs, are permitted by the wire grammar.
        let mut ids = Vec::new();
        while list.any_left() {
            let id = PayloadU8::read(&mut list).map_err(decode)?.0;
            if !id.is_empty() && !self.policy.is_some_and(|p| p.allow_sending) {
                return Err(illegal());
            }
            if ids.len() < MAX_CONNECTION_IDS && !ids.contains(&id) {
                ids.push(id);
            }
        }
        if usage == 0 {
            self.peer = ids;
        } else {
            for id in ids {
                if self.peer.len() < MAX_CONNECTION_IDS && !self.peer.contains(&id) {
                    self.peer.push(id);
                }
            }
        }
        self.request_unfulfilled = false;
        Ok(())
    }
}

type CidError = (AlertDescription, Error);
fn local_error(message: &str) -> Error {
    Error::General(message.into())
}
fn unexpected() -> CidError {
    (
        AlertDescription::UnexpectedMessage,
        local_error("unexpected DTLS CID message"),
    )
}
fn illegal() -> CidError {
    (
        AlertDescription::IllegalParameter,
        local_error("invalid DTLS CID update"),
    )
}
fn decode(err: InvalidMessage) -> CidError {
    (AlertDescription::DecodeError, err.into())
}

/// Select only in the DTLS ServerHello, after unsolicited-extension checks.
pub(crate) fn select_server_hello(
    common: &mut CommonState,
    peer: Option<&PayloadU8>,
) -> Result<(), Error> {
    let Some(dtls) = common.dtls.as_deref_mut() else {
        return Ok(());
    };
    if let Err(err) = dtls.cid.select(peer, false) {
        return Err(common.send_fatal_alert(AlertDescription::IllegalParameter, err));
    }
    Ok(())
}

impl Dtls {
    /// A peer may select longer IDs than ours, including after the MTU
    /// was set. A handshake fragment and a one-record ACK must each fit.
    pub(super) fn check_cid_mtu(&self, mtu: usize) -> Result<(), Error> {
        let minimum = (wire::HANDSHAKE_HEADER_LEN + 1).max(2 + wire::RECORD_NUMBER_LEN);
        if !self.cid.outbound().is_empty()
            && self.write_epoch() != 0
            && self
                .record_room(self.write_epoch(), mtu)
                .is_none_or(|room| room < minimum)
        {
            return Err(local_error(
                "DTLS MTU is too small for the selected peer CID",
            ));
        }
        Ok(())
    }

    pub(crate) fn initialize_cids(
        &mut self,
        random: &'static dyn SecureRandom,
    ) -> Result<(), Error> {
        self.cid.initialize(self.settings.connection_ids, random)
    }

    pub(super) fn issue_cids(
        &mut self,
        count: u8,
        usage: ConnectionIdUsage,
    ) -> Result<usize, Error> {
        if self.out.stopped() || self.out.has_type(HandshakeType::NewConnectionId) {
            return Err(local_error(
                "DTLS NewConnectionId is already pending or connection closed",
            ));
        }
        let (count, body) = self.cid.new_ids(count, usage)?;
        self.queue_cid(HandshakeType::NewConnectionId, &body);
        Ok(count)
    }

    pub(super) fn request_cids(&mut self, count: u8) -> Result<(), Error> {
        if !self.cid.negotiated || self.cid.outbound().is_empty() {
            return Err(local_error("DTLS sending CID was not negotiated"));
        }
        if usize::from(count) > MAX_CONNECTION_IDS
            || self.cid.request_unfulfilled
            || self.out.has_type(HandshakeType::RequestConnectionId)
            || self.out.stopped()
        {
            return Err(local_error(
                "DTLS CID request exceeds bounds or is already pending",
            ));
        }
        self.cid.request_unfulfilled = true;
        self.queue_cid(HandshakeType::RequestConnectionId, &[count]);
        Ok(())
    }

    fn queue_cid(&mut self, typ: HandshakeType, body: &[u8]) {
        let mut encoded = alloc::vec![u8::from(typ)];
        encoded.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        encoded.extend_from_slice(body);
        self.queue_handshake(&encoded);
    }

    /// Intercept only DTLS CID messages; the shared TLS/QUIC handshake
    /// parser continues to reject them as unknown handshake messages.
    pub(super) fn handle_cid_message(
        &mut self,
        epoch: u64,
        bytes: &[u8],
        handshaking: bool,
    ) -> Result<bool, CidError> {
        let Some(&typ) = bytes.first() else {
            return Ok(false);
        };
        let typ = HandshakeType::from(typ);
        if !matches!(
            typ,
            HandshakeType::NewConnectionId | HandshakeType::RequestConnectionId
        ) {
            return Ok(false);
        }
        if handshaking || epoch < APPLICATION_EPOCH || !self.cid.negotiated {
            return Err(unexpected());
        }
        let body = bytes
            .get(4..)
            .ok_or_else(|| decode(InvalidMessage::MessageTooShort))?;
        match typ {
            HandshakeType::NewConnectionId => self.cid.receive_new(body)?,
            HandshakeType::RequestConnectionId => {
                if !self.cid.can_issue() {
                    return Err(unexpected());
                }
                let [count] = body else {
                    return Err(decode(InvalidMessage::MessageTooShort));
                };
                // One queued response and one coalesced request at most;
                // authenticated floods cannot grow the outgoing flight.
                if self.cid.requested.is_some() {
                    return Err((
                        AlertDescription::TooManyCidsRequested,
                        local_error("too many DTLS CID requests"),
                    ));
                }
                self.cid.requested = Some(*count);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub(super) fn answer_cid_request(&mut self) -> Result<(), Error> {
        if self.out.has_type(HandshakeType::NewConnectionId) || self.out.stopped() {
            return Ok(());
        }
        if let Some(count) = self.cid.requested.take() {
            self.issue_cids(count, ConnectionIdUsage::Spare)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
