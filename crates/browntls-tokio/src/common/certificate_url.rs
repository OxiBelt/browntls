//! A server stream's side of client certificate URL queries (RFC 6066 §5):
//! the fetch of the chain its connection waits for, through the
//! application's fetcher. Nothing here opens a connection to a URL.

use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls_core::certificate_url::{ClientCertificateUrlQuery, ClientCertificateUrlResponse};
use browntls_core::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use super::Stream;
use crate::certificate_url::{FetchClientCertificateUrl, FetchFuture};

/// One stream's client certificate URL queries: the fetcher, and the fetch
/// for the query its connection waits on. Boxed, to keep streams without a
/// fetcher small.
#[derive(Default)]
pub(crate) struct CertificateUrlAnswers(Option<Box<Answers>>);

struct Answers {
    fetcher: Arc<dyn FetchClientCertificateUrl>,
    pending: Option<(u64, FetchFuture)>,
}

impl CertificateUrlAnswers {
    pub(crate) fn new(fetcher: Option<Arc<dyn FetchClientCertificateUrl>>) -> Self {
        Self(fetcher.map(|fetcher| {
            Box::new(Answers {
                fetcher,
                pending: None,
            })
        }))
    }

    /// The answer to `query`, the one the connection waits on: `Pending`
    /// while it is fetched, the fetch then waking `cx`. Without a fetcher,
    /// `Unobtainable` at once.
    pub(crate) fn poll_response(
        &mut self,
        cx: &mut Context<'_>,
        query: &ClientCertificateUrlQuery,
    ) -> Poll<ClientCertificateUrlResponse> {
        let Some(answers) = &mut self.0 else {
            return Poll::Ready(ClientCertificateUrlResponse::Unobtainable);
        };
        // A fetch begun for an earlier query is given up.
        if !matches!(&answers.pending, Some((id, _)) if *id == query.id()) {
            answers.pending = Some((query.id(), answers.fetcher.fetch(query.clone())));
        }
        let Some((_, fetch)) = &mut answers.pending else {
            return Poll::Ready(ClientCertificateUrlResponse::Unobtainable);
        };
        let result = ready!(fetch.as_mut().poll(cx));
        answers.pending = None;
        Poll::Ready(match result {
            Ok(objects) => ClientCertificateUrlResponse::Fetched(objects),
            Err(_) => ClientCertificateUrlResponse::Unobtainable,
        })
    }
}

impl fmt::Debug for CertificateUrlAnswers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let answers = self.0.as_deref();
        let pending = answers.and_then(|a| a.pending.as_ref().map(|(id, _)| id));
        f.debug_struct("CertificateUrlAnswers")
            .field("attached", &answers.is_some())
            .field("pending", &pending)
            .finish()
    }
}

impl<IO, C, SD> Stream<'_, IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    /// Answers the client certificate URL query the connection waits on,
    /// if any: `Ready(Ok(()))` once it waits on none, `Pending` while the
    /// chain is fetched, the fetch then waking `cx`. A connection that
    /// fails over the answer has its alert written if the transport takes
    /// it now.
    pub(crate) fn poll_client_certificate_url(
        &mut self,
        cx: &mut Context<'_>,
        answers: &mut CertificateUrlAnswers,
    ) -> Poll<io::Result<()>> {
        while let Some(query) = self.session.pending_client_certificate_url() {
            let id = query.id();
            let response = ready!(answers.poll_response(cx, query));
            if let Err(err) = self.session.resolve_client_certificate_url(id, response) {
                let _ = self.write_io(cx);
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
            }
        }
        Poll::Ready(Ok(()))
    }
}
