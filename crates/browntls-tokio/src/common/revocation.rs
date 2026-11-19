//! A stream's side of certificate status queries: where the answers come
//! from, and the answer on its way to the connection.
//!
//! Without the `ocsp` feature there is no fetcher to attach, and every
//! query is answered `Unavailable` at once.

use std::fmt;
use std::task::{Context, Poll};

use browntls::revocation::{RevocationQuery, RevocationResponse};

#[cfg(feature = "ocsp")]
use crate::revocation::{Delivered, PendingResponse, RevocationFetcher};

/// The fetcher a connector or acceptor gives to its streams, if any.
#[derive(Clone, Default)]
pub(crate) struct RevocationSource {
    #[cfg(feature = "ocsp")]
    fetcher: Option<std::sync::Arc<RevocationFetcher>>,
}

impl RevocationSource {
    #[cfg(feature = "ocsp")]
    pub(crate) fn new(fetcher: std::sync::Arc<RevocationFetcher>) -> Self {
        Self {
            fetcher: Some(fetcher),
        }
    }

    /// Whether a fetcher is attached.
    pub(crate) fn is_attached(&self) -> bool {
        #[cfg(feature = "ocsp")]
        {
            self.fetcher.is_some()
        }
        #[cfg(not(feature = "ocsp"))]
        {
            false
        }
    }

    /// The state of one stream that takes its answers from here.
    pub(crate) fn for_stream(&self) -> PeerRevocation {
        PeerRevocation {
            #[cfg(feature = "ocsp")]
            fetcher: self.fetcher.clone(),
            #[cfg(feature = "ocsp")]
            flight: None,
        }
    }
}

impl fmt::Debug for RevocationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationSource")
            .field("attached", &self.is_attached())
            .finish()
    }
}

/// One stream's certificate status queries: the answer being fetched for
/// the query its connection waits on.
pub(crate) struct PeerRevocation {
    #[cfg(feature = "ocsp")]
    fetcher: Option<std::sync::Arc<RevocationFetcher>>,
    #[cfg(feature = "ocsp")]
    flight: Option<Box<Flight>>,
}

#[cfg(feature = "ocsp")]
#[derive(Default)]
struct Flight {
    /// The query being answered, by its id, and its answer on the way.
    pending: Option<(u64, PendingResponse)>,
    /// The response the connection was given last and has not judged yet.
    delivered: Option<Delivered>,
}

impl PeerRevocation {
    /// The answer to `query`, the one the connection waits on. `Pending`
    /// while it is fetched; the fetch then wakes `cx`.
    pub(crate) fn poll_response(
        &mut self,
        cx: &mut Context<'_>,
        query: &RevocationQuery,
    ) -> Poll<RevocationResponse> {
        #[cfg(feature = "ocsp")]
        if let Some(fetcher) = &self.fetcher {
            let flight = self.flight.get_or_insert_with(Box::default);
            // A lookup begun for an earlier query is given up.
            if !matches!(&flight.pending, Some((id, _)) if *id == query.id()) {
                flight.pending = Some((query.id(), fetcher.begin(query)));
            }
            if let Some((_, pending)) = &mut flight.pending {
                let (response, delivered) = ready!(pending.poll(cx));
                flight.pending = None;
                flight.delivered = delivered;
                return Poll::Ready(response);
            }
        }
        let _ = (cx, query);
        Poll::Ready(RevocationResponse::Unavailable)
    }

    /// The connection took the last answer (`accepted`) or failed over it.
    /// A response it refused is not given to another connection.
    pub(crate) fn settled(&mut self, accepted: bool) {
        #[cfg(feature = "ocsp")]
        if let Some(delivered) = self.flight.take().and_then(|flight| flight.delivered)
            && !accepted
            && let Some(fetcher) = &self.fetcher
        {
            fetcher.refused(&delivered);
        }
        let _ = accepted;
    }
}

impl fmt::Debug for PeerRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("PeerRevocation");
        #[cfg(feature = "ocsp")]
        debug.field("attached", &self.fetcher.is_some()).field(
            "pending",
            &self
                .flight
                .as_ref()
                .and_then(|flight| flight.pending.as_ref().map(|(id, _)| id)),
        );
        debug.finish_non_exhaustive()
    }
}
