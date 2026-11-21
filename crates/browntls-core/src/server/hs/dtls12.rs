//! Address validation for DTLS 1.2, before committing a full server flight.

use alloc::vec::Vec;

use super::{ExpectClientHello, ServerContext};
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::ClientHelloPayload;

const LABEL: &[u8] = b"browntls dtls12 verify 1";

/// Separate domain and bounded lifetime, using the configured cookie sealer.
pub(crate) fn valid(config: &crate::ServerConfig, cookie: &[u8], address: &[u8]) -> bool {
    let (Some(sealer), Ok(now)) = (&config.hello_retry_cookies, config.current_time()) else {
        return false;
    };
    let Some(plain) = sealer.decrypt(cookie) else {
        return false;
    };
    let Some(rest) = plain.strip_prefix(LABEL) else {
        return false;
    };
    let Some((time, peer)) = rest.split_first_chunk::<8>() else {
        return false;
    };
    now.as_secs().abs_diff(u64::from_be_bytes(*time)) <= 60 && peer == address
}

impl ExpectClientHello {
    /// A retry consumes no transcript bytes. Its ClientHello is retransmitted
    /// by the client, so a stateless server needs no retry timer.
    pub(super) fn dtls12_retry(
        &mut self,
        hello: &ClientHelloPayload,
        cx: &mut ServerContext<'_>,
    ) -> Result<bool, Error> {
        let Some(dtls) = cx.common.dtls.as_mut() else {
            return Ok(false);
        };
        if !dtls.require_cookie() {
            return Ok(false);
        }
        if hello
            .legacy_cookie
            .as_ref()
            .is_some_and(|c| valid(&self.config, &c.0, dtls.peer_address()))
        {
            return Ok(false);
        }
        let mut plain = Vec::from(LABEL);
        plain.extend_from_slice(&self.config.current_time()?.as_secs().to_be_bytes());
        plain.extend_from_slice(dtls.peer_address());
        let cookie = self
            .config
            .hello_retry_cookies
            .as_ref()
            .and_then(|sealer| sealer.encrypt(&plain))
            .filter(|c| !c.is_empty() && c.len() <= 255)
            .ok_or_else(|| Error::General("DTLS 1.2 cookie sealing failed".into()))?;
        let mut encoded = Vec::new();
        encoded.push(u8::from(HandshakeType::HelloVerifyRequest));
        crate::msgs::codec::u24((3 + cookie.len()) as u32).encode(&mut encoded);
        // RFC 6347 section 4.2.1: DTLS 1.0 here avoids version intolerance;
        // this field never commits the client to a negotiated version.
        ProtocolVersion::DTLSv1_0.encode(&mut encoded);
        encoded.push(cookie.len() as u8);
        encoded.extend_from_slice(&cookie);
        dtls.queue_handshake(&encoded);
        Ok(true)
    }
}
