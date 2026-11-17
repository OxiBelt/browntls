//! The future that drives a handshake to completion.

use std::future::Future;
use std::io;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{Stream, StreamState};

/// A stream whose handshake [`MidHandshake`] can drive.
pub(crate) trait IoSession {
    type Io;
    type Session;

    /// Whether the stream may be returned before its handshake completes.
    fn skip_handshake(&self) -> bool;
    fn parts(&mut self) -> (&mut StreamState, &mut Self::Io, &mut Self::Session);
    fn into_io(self) -> Self::Io;
}

/// A handshake in progress, or how it ended.
pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    /// Setting up the connection failed before any I/O.
    Error {
        io: IS::Io,
        error: io::Error,
    },
    /// The future already returned.
    End,
}

impl<IS, SD> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::Error { io, error } => return Poll::Ready(Err((error, io))),
            // Like any future, this one must not be polled after it returned
            // `Ready`; by then the transport has been handed back.
            #[allow(clippy::panic)]
            Self::End => panic!("TLS handshake future polled after completion"),
        };

        if !stream.skip_handshake() {
            let (st, io, session) = stream.parts();
            let mut tls_stream = Stream::new(io, session)
                .set_eof(!st.state.readable())
                .set_need_flush(st.need_flush);

            macro_rules! try_poll {
                ($e:expr) => {
                    match $e {
                        Poll::Ready(Ok(x)) => x,
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err((err, stream.into_io())));
                        }
                        Poll::Pending => {
                            st.need_flush = tls_stream.need_flush;
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                };
            }

            while tls_stream.session.is_handshaking() {
                try_poll!(tls_stream.handshake(cx));
            }
            try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
        }

        Poll::Ready(Ok(stream))
    }
}
