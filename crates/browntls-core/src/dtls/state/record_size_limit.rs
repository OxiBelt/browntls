//! Negotiated DTLS record size limits (RFC 8449).

use super::{Dtls, MAX_PLAINTEXT_LEN};
use crate::error::Error;

#[derive(Clone, Copy)]
pub(super) struct RecordSizeLimits {
    inbound: u16,
    outbound: u16,
    tls13: bool,
}

impl Dtls {
    /// The unmodified value configured for the ClientHello or server
    /// acknowledgement. The handshake layer clamps it for the negotiated
    /// protocol version.
    pub(crate) fn record_size_limit_offer(&self) -> Option<u16> {
        self.settings.record_size_limit
    }

    /// Starts tracking authenticated records before the client learns
    /// whether the server acknowledged its DTLS 1.3 offer.
    pub(crate) fn start_record_size_limit_observation(&mut self) {
        self.observe_record_size_limit = true;
        self.observed_record_size_limit_overflow = false;
    }

    /// Installs already validated and version-clamped record limits.
    pub(crate) fn set_record_size_limits(
        &mut self,
        ours: u16,
        peer: u16,
        tls13: bool,
    ) -> Result<(), Error> {
        self.observe_record_size_limit = false;
        if self.observed_record_size_limit_overflow {
            self.observed_record_size_limit_overflow = false;
            return Err(Error::PeerSentOversizedRecord);
        }
        self.record_size_limits = Some(RecordSizeLimits {
            inbound: ours,
            outbound: peer,
            tls13,
        });
        Ok(())
    }

    /// The peer omitted the acknowledgement, so discard tentative
    /// observations and leave record sizes unrestricted by RFC 8449.
    pub(crate) fn clear_record_size_limit_observation(&mut self) {
        self.observe_record_size_limit = false;
        self.observed_record_size_limit_overflow = false;
        self.record_size_limits = None;
    }

    /// Checks an authenticated record before replay marking or dispatch.
    pub(in crate::dtls) fn check_inbound_record_size_limit(
        &mut self,
        plaintext_len: usize,
    ) -> Result<(), Error> {
        let limit = self
            .record_size_limits
            .map(|limits| limits.inbound)
            .or_else(|| {
                if self.observe_record_size_limit {
                    self.settings
                        .record_size_limit
                        .map(|limit| limit.min(crate::common_state::max_record_size_limit(true)))
                } else {
                    None
                }
            });
        let Some(limit) = limit else {
            return Ok(());
        };
        if plaintext_len <= usize::from(limit) {
            return Ok(());
        }
        if self.observe_record_size_limit {
            self.observed_record_size_limit_overflow = true;
            Ok(())
        } else {
            Err(Error::PeerSentOversizedRecord)
        }
    }

    pub(super) fn outbound_content_limit(&self, epoch: u64) -> usize {
        if epoch == 0 {
            return MAX_PLAINTEXT_LEN;
        }
        let v12_cid = self.is_v12() && !self.cid.outbound().is_empty();
        self.record_size_limits
            .map_or(MAX_PLAINTEXT_LEN - usize::from(v12_cid), |limits| {
                usize::from(limits.outbound) - usize::from(limits.tls13 || v12_cid)
            })
    }

    pub(in crate::dtls) fn has_negotiated_record_size_limits(&self) -> bool {
        self.record_size_limits.is_some()
    }
}
