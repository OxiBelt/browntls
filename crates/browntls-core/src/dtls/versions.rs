//! Endpoint policy, independent of the TLS configuration and provider.

use crate::enums::ProtocolVersion;

/// Versions an individual DTLS endpoint may negotiate.
///
/// TLS configuration versions and suites must also permit the selection.
/// Retransmission never changes this policy. DTLS 1.2 requires `tls12`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Versions {
    /// DTLS 1.3 only (the default).
    #[default]
    V1_3,
    /// Prefer DTLS 1.3, allowing DTLS 1.2 certificate handshakes.
    V1_2And1_3,
    /// DTLS 1.2 only, including configured session resumption.
    V1_2,
}

impl Versions {
    pub(crate) fn allows(self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => self != Self::V1_2,
            ProtocolVersion::TLSv1_2 => cfg!(feature = "tls12") && self != Self::V1_3,
            _ => false,
        }
    }
}
