//! Routing and certificate identity for a client connection.

use browntls_pki::{ReferenceIdentifier, ServerName, ServiceIdentity};

use crate::error::Error;
use crate::verify::CertificateIdentity;

/// Routing name and certificate identity policy for a client connection.
///
/// A DNS routing name supplies SNI when enabled. Reference identifiers come
/// from trusted application inputs and do not change DNS resolution, SNI or
/// ALPN. Include a DNS-ID in the reference set explicitly if the application
/// permits that fallback.
#[derive(Clone, Debug)]
pub struct ClientServerIdentity {
    routing_name: ServerName<'static>,
    service_identity: ServiceIdentity,
}

impl ClientServerIdentity {
    /// Sets the routing name and the service identities to authenticate.
    #[must_use]
    pub fn new(routing_name: ServerName<'static>, service_identity: ServiceIdentity) -> Self {
        Self {
            routing_name,
            service_identity,
        }
    }

    pub(crate) fn into_parts(self) -> (ServerName<'static>, ServiceIdentity) {
        (self.routing_name, self.service_identity)
    }
}

impl super::ClientConnectionData {
    pub(crate) fn certificate_identity<'a>(
        &'a self,
        name: &'a ServerName<'_>,
    ) -> CertificateIdentity<'a> {
        if self.ech_status != crate::ech::EchStatus::Rejected
            && let Some(policy) = self.service_identity.as_deref()
        {
            return CertificateIdentity::Service(policy);
        }
        CertificateIdentity::Name(name)
    }
}

impl CertificateIdentity<'_> {
    pub(crate) fn matched_reference(
        self,
        index: Option<usize>,
    ) -> Result<Option<ReferenceIdentifier>, Error> {
        let invalid_match =
            || Error::General("certificate verifier returned an invalid identity match".into());
        match (self, index) {
            (Self::Name(_), None) => Ok(None),
            (Self::Name(ServerName::DnsName(dns)), Some(0)) => {
                Ok(Some(ReferenceIdentifier::Dns(dns.to_owned())))
            }
            (Self::Name(ServerName::IpAddress(ip)), Some(0)) => {
                Ok(Some(ReferenceIdentifier::Ip(*ip)))
            }
            (Self::Service(policy), Some(index)) => policy
                .references()
                .get(index)
                .cloned()
                .map(Some)
                .ok_or_else(invalid_match),
            _ => Err(invalid_match()),
        }
    }
}

impl crate::CommonState {
    /// The caller's reference identity authenticated by the server
    /// certificate, once the handshake has completed. Available after
    /// resumption of a session established under the same policy.
    ///
    /// Returns `None` before authentication, on server-side connections, or
    /// when the verifier or authentication method reports no identity.
    pub fn matched_service_identity(&self) -> Option<&ReferenceIdentifier> {
        if self.is_handshaking() {
            return None;
        }
        self.matched_service_identity.as_ref()
    }
}
