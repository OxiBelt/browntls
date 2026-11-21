//! Checks of the TLS 1.3 handshake that apply on DTLS 1.3 connections
//! only (RFC 9147 §5).

use crate::common_state::CommonState;
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::msgs::handshake::ClientHelloPayload;

/// A DTLS connection uses DTLS 1.3, which the handshake knows as TLS 1.3;
/// DTLS 1.2 is not implemented.
pub(crate) fn require_tls13(
    common: &mut CommonState,
    version: ProtocolVersion,
) -> Result<(), Error> {
    if common.is_dtls() && version != ProtocolVersion::TLSv1_3 {
        return Err(common.send_fatal_alert(
            AlertDescription::ProtocolVersion,
            PeerIncompatible::Tls13RequiredForDtls,
        ));
    }
    Ok(())
}

/// The DTLS checks of a server on a ClientHello. RFC 9147 §5.3: a DTLS 1.3
/// ClientHello whose `legacy_cookie` is not empty is illegal_parameter.
pub(crate) fn read_client_hello(
    common: &mut CommonState,
    hello: &ClientHelloPayload,
) -> Result<(), Error> {
    if common.is_dtls()
        && hello
            .legacy_cookie
            .as_ref()
            .is_none_or(|cookie| !cookie.0.is_empty())
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::IllegalDtlsLegacyCookie,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;
    use crate::common_state::Side;
    use crate::enums::CipherSuite;
    use crate::msgs::base::PayloadU8;
    use crate::msgs::enums::Compression;
    use crate::msgs::handshake::{ClientExtensions, Random, SessionId};

    fn common(dtls: bool) -> CommonState {
        let mut common = CommonState::new(Side::Server);
        if dtls {
            common.dtls = Some(Box::new(crate::dtls::Dtls::new(
                Side::Server,
                crate::dtls::Settings::default(),
            )));
        }
        common
    }

    fn hello(legacy_cookie: Option<PayloadU8>) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from([0; 32]),
            session_id: SessionId::empty(),
            legacy_cookie,
            cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            compression_methods: vec![Compression::Null],
            extensions: ClientExtensions::default(),
        }
    }

    /// RFC 9147 §5.3: a non-empty legacy_cookie is illegal_parameter.
    #[test]
    fn legacy_cookie_must_be_empty() {
        let refused = Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalDtlsLegacyCookie,
        ));
        assert_eq!(
            read_client_hello(&mut common(true), &hello(Some(PayloadU8::empty()))),
            Ok(())
        );
        let cookie = PayloadU8::new(vec![0]);
        assert_eq!(
            read_client_hello(&mut common(true), &hello(Some(cookie))),
            refused
        );
        assert_eq!(read_client_hello(&mut common(true), &hello(None)), refused);
        assert_eq!(read_client_hello(&mut common(false), &hello(None)), Ok(()));
    }

    #[test]
    fn only_tls13_over_dtls() {
        assert_eq!(
            require_tls13(&mut common(true), ProtocolVersion::TLSv1_3),
            Ok(())
        );
        assert_eq!(
            require_tls13(&mut common(true), ProtocolVersion::TLSv1_2),
            Err(Error::PeerIncompatible(
                PeerIncompatible::Tls13RequiredForDtls
            ))
        );
        assert_eq!(
            require_tls13(&mut common(false), ProtocolVersion::TLSv1_2),
            Ok(())
        );
    }
}
