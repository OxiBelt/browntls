//! Client session storage contract.

use crate::msgs::enums::NamedGroup;
#[cfg(feature = "tls12")]
use crate::msgs::persist::Tls12ClientSessionValue;
use crate::msgs::persist::Tls13ClientSessionValue;
use browntls_pki::ServerName;
use core::fmt;

/// Stores session state for resumption, keyed by server name.
pub trait ClientSessionStore: fmt::Debug + Send + Sync {
    /// Remembers which key exchange group `server_name` accepted.
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup);

    /// The group `server_name` last accepted, if remembered.
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup>;

    /// Stores a TLS 1.2 session for `server_name`.
    #[cfg(feature = "tls12")]
    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue);

    /// The stored TLS 1.2 session for `server_name`, if any.
    #[cfg(feature = "tls12")]
    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue>;

    /// Forgets the TLS 1.2 session for `server_name`.
    #[cfg(feature = "tls12")]
    fn remove_tls12_session(&self, server_name: &ServerName<'static>);

    /// Stores a DTLS 1.2 session separately from stream TLS sessions.
    /// The default implementation does not support DTLS 1.2 resumption.
    #[cfg(feature = "tls12")]
    fn set_dtls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: Tls12ClientSessionValue,
    ) {
    }

    /// The stored DTLS 1.2 session, if supported by this store.
    #[cfg(feature = "tls12")]
    fn dtls12_session(&self, _server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    /// Forgets only the DTLS 1.2 session for `server_name`.
    #[cfg(feature = "tls12")]
    fn remove_dtls12_session(&self, _server_name: &ServerName<'static>) {}

    /// Stores a TLS 1.3 ticket for `server_name`.
    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue);

    /// Removes and returns a TLS 1.3 ticket for `server_name`.
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue>;
}
