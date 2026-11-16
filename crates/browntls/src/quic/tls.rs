//! RFC 9001 rules on the TLS handshake that the shared state machines
//! apply on QUIC connections.

use crate::common_state::CommonState;
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::msgs::handshake::ClientHelloPayload;

/// RFC 9001 §4.2: QUIC MUST NOT negotiate a version older than TLS 1.3.
pub(crate) fn require_tls13(
    common: &mut CommonState,
    version: ProtocolVersion,
) -> Result<(), Error> {
    if common.is_quic() && version != ProtocolVersion::TLSv1_3 {
        return Err(common.send_fatal_alert(
            AlertDescription::ProtocolVersion,
            PeerIncompatible::Tls13RequiredForQuic,
        ));
    }
    Ok(())
}

/// RFC 9001 §8.1: on QUIC, ALPN in use on either side (`configured` by the
/// server, `offered` by the client) must end in a negotiated protocol, or
/// the connection fails with no_application_protocol.
pub(crate) fn require_alpn(
    common: &mut CommonState,
    configured: bool,
    offered: bool,
) -> Result<(), Error> {
    if common.is_quic() && common.alpn_protocol.is_none() && (configured || offered) {
        return Err(common.send_fatal_alert(
            AlertDescription::NoApplicationProtocol,
            Error::NoApplicationProtocol,
        ));
    }
    Ok(())
}

/// The QUIC checks of a server on a ClientHello, which take the client's
/// transport parameters.
pub(crate) fn read_client_hello(
    common: &mut CommonState,
    hello: &ClientHelloPayload,
) -> Result<(), Error> {
    match &mut common.quic {
        // RFC 9001 §8.2: the extension belongs to QUIC only; a TLS
        // implementation that supports it MUST refuse it elsewhere.
        None if hello.extensions.transport_parameters.is_some() => Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::QuicTransportParametersWithoutQuic,
        )),
        None => Ok(()),
        Some(quic) => {
            // RFC 9001 §8.2: the client MUST send its transport parameters.
            let Some(params) = &hello.extensions.transport_parameters else {
                return Err(
                    common.missing_extension(PeerMisbehaved::MissingQuicTransportParameters)
                );
            };
            quic.peer_params = Some(params.bytes().to_vec());
            // RFC 9001 §8.4: QUIC clients MUST NOT use the middlebox
            // compatibility mode; servers SHOULD refuse a non-empty
            // legacy_session_id as a QUIC PROTOCOL_VIOLATION, which is not
            // a TLS alert.
            if !hello.session_id.is_empty() {
                return Err(PeerMisbehaved::NonEmptySessionIdInQuicClientHello.into());
            }
            Ok(())
        }
    }
}
