//! The future that drives a handshake to completion.

use std::future::Future;
use std::io;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::server::AcceptedAlert;
use browntls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{Stream, StreamState, coop, poll_send_alert};

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
    /// Continuing a handshake failed before any I/O, with an alert to send
    /// before reporting `error`.
    SendAlert {
        io: IS::Io,
        alert: AcceptedAlert,
        error: io::Error,
    },
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
        coop::budgeted(cx, |cx| this.poll_handshake(cx))
    }
}

impl<IS, SD> MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<IS, (io::Error, IS::Io)>> {
        let this = self;

        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::SendAlert {
                mut io,
                mut alert,
                error,
            } => {
                if poll_send_alert(&mut io, &mut alert, cx).is_pending() {
                    *this = Self::SendAlert { io, alert, error };
                    return Poll::Pending;
                }
                return Poll::Ready(Err((error, io)));
            }
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
