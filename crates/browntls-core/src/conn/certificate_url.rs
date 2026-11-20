//! The client certificate URL pause (RFC 6066 §5) of the connection APIs: a
//! TLS 1.2 server that received a CertificateURL message waits for the
//! application to fetch what it names. The library itself opens no
//! connection to any URL.

use super::{ConnectionCommon, ConnectionCore, Context, SideData};
use crate::certificate_url::{ClientCertificateUrlQuery, ClientCertificateUrlResponse};
use crate::common_state::CommonState;
use crate::enums::AlertDescription;
use crate::error::Error;
use crate::unbuffered::UnbufferedConnectionCommon;

impl CommonState {
    /// The client certificate URL query blocking the handshake, if any: a
    /// TLS 1.2 server received a CertificateURL message (RFC 6066 §5).
    /// Client connections never have one.
    ///
    /// The URLs are chosen by the unauthenticated client. The library
    /// never fetches them: the application authorizes and performs every
    /// fetch, then answers with `resolve_client_certificate_url`. See
    /// [`certificate_url`](crate::certificate_url).
    pub fn pending_client_certificate_url(&self) -> Option<&ClientCertificateUrlQuery> {
        self.pending_certificate_url
            .as_deref()
            .map(|pending| pending.query())
    }
}

impl<Data: SideData> ConnectionCore<Data> {
    pub(crate) fn resolve_client_certificate_url(
        &mut self,
        id: u64,
        response: ClientCertificateUrlResponse,
    ) -> Result<(), Error> {
        if self
            .common_state
            .pending_client_certificate_url()
            .map(ClientCertificateUrlQuery::id)
            != Some(id)
        {
            return Err(Error::general(
                "no matching pending client certificate URL query",
            ));
        }
        let Some(pending) = self.common_state.pending_certificate_url.take() else {
            return Err(Error::general("no pending client certificate URL query"));
        };
        let result = match pending.into_chain(response) {
            Ok(chain) => {
                let state = self.take_state()?;
                state.resume_client_certificate_url(
                    &mut Context {
                        common: &mut self.common_state,
                        data: &mut self.data,
                    },
                    chain,
                )
            }
            Err(err) => Err(self
                .common_state
                .send_fatal_alert(AlertDescription::from(err), err)),
        };
        match result {
            Ok(state) => {
                self.state = Ok(state);
                Ok(())
            }
            Err(err) => {
                let err = Self::ensure_alert_sent(&mut self.common_state, err);
                Err(self.fail(err))
            }
        }
    }
}

impl<Data: SideData> ConnectionCommon<Data> {
    /// Supplies the answer to the pending client certificate URL query
    /// ([`CommonState::pending_client_certificate_url`]) and processes any
    /// buffered input.
    ///
    /// The library never fetches a URL: `response` is what the
    /// application fetched, after it authorized each destination. A wrong
    /// `id` is an error that leaves the connection as it was. An
    /// unobtainable chain fails the handshake with
    /// `certificate_unobtainable`, an object whose hash differs from the
    /// client's with `bad_certificate_hash_value`.
    pub fn resolve_client_certificate_url(
        &mut self,
        id: u64,
        response: ClientCertificateUrlResponse,
    ) -> Result<(), Error> {
        self.core.resolve_client_certificate_url(id, response)?;
        self.process_new_packets().map(|_| ())
    }
}

#[cfg(feature = "std")]
impl super::Connection {
    /// See [`ConnectionCommon::resolve_client_certificate_url`].
    pub fn resolve_client_certificate_url(
        &mut self,
        id: u64,
        response: ClientCertificateUrlResponse,
    ) -> Result<(), Error> {
        match self {
            Self::Client(conn) => conn.resolve_client_certificate_url(id, response),
            Self::Server(conn) => conn.resolve_client_certificate_url(id, response),
        }
    }
}

impl<Data: SideData> UnbufferedConnectionCommon<Data> {
    /// Supplies the answer to the pending client certificate URL query
    /// ([`CommonState::pending_client_certificate_url`]).
    ///
    /// The library never fetches a URL: `response` is what the
    /// application fetched, after it authorized each destination. Call
    /// [`Self::process_tls_records`] again, even when no new bytes arrived.
    /// A wrong `id` is an error that leaves the connection as it was.
    pub fn resolve_client_certificate_url(
        &mut self,
        id: u64,
        response: ClientCertificateUrlResponse,
    ) -> Result<(), Error> {
        self.core.resolve_client_certificate_url(id, response)
    }
}
