//! Common TLS, DTLS and QUIC client construction.

use alloc::vec::Vec;

use browntls_pki::{ServerName, ServiceIdentity};

use super::{ClientConfig, ClientConnectionData};
use crate::client::hs;
use crate::common_state::{CommonState, Side};
use crate::conn::ConnectionCore;
use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::sync::Arc;

impl ConnectionCore<ClientConnectionData> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        identity: Option<ServiceIdentity>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        Self::for_client_with(config, name, identity, alpn_protocols, None, None)
    }

    /// A QUIC client (RFC 9001): TLS 1.3 only, with a QUIC-capable suite.
    pub(crate) fn for_quic_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        identity: Option<ServiceIdentity>,
        alpn_protocols: Vec<Vec<u8>>,
        quic: crate::quic::Quic,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for QUIC".into(),
            ));
        }
        if !config
            .provider
            .cipher_suites
            .iter()
            .any(|cs| cs.usable_for_quic())
        {
            return Err(Error::General(
                "no cipher suite of the configuration is usable with QUIC".into(),
            ));
        }
        // ECH over QUIC is not supported yet: the outer ClientHello carries
        // no ALPN, so a QUIC server rejecting ECH could not complete the
        // handshake that delivers retry configurations (RFC 9001 §8.1).
        if config.ech_mode.is_some() {
            return Err(Error::General(
                "Encrypted Client Hello is not supported over QUIC".into(),
            ));
        }
        Self::for_client_with(config, name, identity, alpn_protocols, Some(quic), None)
    }

    /// A DTLS client with an explicit endpoint version policy, a matching
    /// suite, and no Encrypted Client Hello. Queue the first ClientHello.
    pub(crate) fn for_dtls_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        identity: Option<ServiceIdentity>,
        dtls: crate::dtls::Dtls,
    ) -> Result<Self, Error> {
        if ![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
            .iter()
            .any(|v| dtls.allows(*v) && config.supports_version(*v))
        {
            return Err(Error::General(
                "no configured version matches the DTLS endpoint policy".into(),
            ));
        }
        if !config.provider.cipher_suites.iter().any(|cs| {
            cs.usable_for_dtls()
                && dtls.allows(cs.version().version)
                && config.supports_version(cs.version().version)
        }) {
            return Err(Error::General(
                "no cipher suite of the configuration is usable with the DTLS endpoint policy"
                    .into(),
            ));
        }
        if config.ech_mode.is_some() {
            return Err(Error::General(
                "Encrypted Client Hello is not supported over DTLS".into(),
            ));
        }
        let alpn_protocols = config.alpn_protocols.clone();
        Self::for_client_with(config, name, identity, alpn_protocols, None, Some(dtls))
    }

    fn for_client_with(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        identity: Option<ServiceIdentity>,
        alpn_protocols: Vec<Vec<u8>>,
        quic: Option<crate::quic::Quic>,
        dtls: Option<crate::dtls::Dtls>,
    ) -> Result<Self, Error> {
        if identity.is_some() && config.verifier().requires_raw_public_keys() {
            return Err(Error::General(
                "service identities require an X.509 certificate".into(),
            ));
        }
        if config.max_tls13_tickets_per_connection > 255 {
            return Err(Error::BadTls13TicketLimit);
        }
        crate::external_binding::handshake::check_client_config(config.external_binding.as_ref())?;
        let mut common_state = CommonState::new(Side::Client);
        common_state.quic = quic.map(alloc::boxed::Box::new);
        common_state.dtls = dtls.map(alloc::boxed::Box::new);
        common_state.set_max_fragment_size(config.max_fragment_size)?;
        crate::common_state::check_record_size_limit_config(config.record_size_limit)?;
        crate::trusted_ca_keys::check_config(config.trusted_ca_keys.as_deref())?;
        common_state.enable_secret_extraction = config.enable_secret_extraction;
        common_state.fips = config.fips();
        let mut data = ClientConnectionData::new(config.clone(), name.clone(), identity);
        let mut cx = crate::conn::Context {
            common: &mut common_state,
            data: &mut data,
        };
        let state = hs::start_handshake(name, alpn_protocols, config, &mut cx)?;
        Ok(Self::new(state, data, common_state))
    }
}
