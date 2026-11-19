//! The future that drives a handshake to completion, and how a handshake
//! that failed after its stream was handed out keeps reporting that.

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

    /// Whether the stream may be returned before its handshake starts.
    fn skip_handshake(&self) -> bool;

    /// Whether the stream may be returned while its handshake is still in
    /// progress, once [`early_phase_reached`](Self::early_phase_reached)
    /// says so and everything queued so far has been written and flushed.
    fn returns_early(&self) -> bool {
        false
    }

    /// Whether `session`, still handshaking, got to where a stream that
    /// [`returns_early`](Self::returns_early) is handed out.
    fn early_phase_reached(_session: &mut Self::Session) -> bool {
        false
    }

    fn refs(&self) -> (&Self::Io, &Self::Session);
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

impl<IS: IoSession> MidHandshake<IS> {
    /// The transport, unless the future already returned.
    pub(crate) fn io(&self) -> Option<&IS::Io> {
        match self {
            Self::Handshaking(stream) => Some(stream.refs().0),
            Self::SendAlert { io, .. } | Self::Error { io, .. } => Some(io),
            Self::End => None,
        }
    }

    /// The transport, unless the future already returned.
    pub(crate) fn io_mut(&mut self) -> Option<&mut IS::Io> {
        match self {
            Self::Handshaking(stream) => Some(stream.parts().1),
            Self::SendAlert { io, .. } | Self::Error { io, .. } => Some(io),
            Self::End => None,
        }
    }

    /// The connection, while there is one and the future has not returned.
    pub(crate) fn session(&self) -> Option<&IS::Session> {
        match self {
            Self::Handshaking(stream) => Some(stream.refs().1),
            Self::SendAlert { .. } | Self::Error { .. } | Self::End => None,
        }
    }

    /// The connection, while there is one and the future has not returned.
    pub(crate) fn session_mut(&mut self) -> Option<&mut IS::Session> {
        match self {
            Self::Handshaking(stream) => Some(stream.parts().2),
            Self::SendAlert { .. } | Self::Error { .. } | Self::End => None,
        }
    }
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
            let returns_early = stream.returns_early();
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

            let mut returned_early = false;
            while tls_stream.session.is_handshaking() {
                // Our flight is out before the stream is: nothing is left
                // for the caller's first operation to write.
                if returns_early
                    && !tls_stream.session.wants_write()
                    && !tls_stream.need_flush
                    && IS::early_phase_reached(tls_stream.session)
                {
                    returned_early = true;
                    break;
                }
                try_poll!(tls_stream.handshake(cx, &mut st.revocation));
            }
            if returned_early {
                st.need_flush = false;
            } else {
                try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
            }
        }

        Poll::Ready(Ok(stream))
    }
}

/// A handshake failure met after the stream was handed out, kept to report
/// again: every later operation on the stream fails with it.
#[derive(Debug)]
pub(crate) struct HandshakeFailure {
    kind: io::ErrorKind,
    tls: Option<browntls::Error>,
    message: String,
}

impl HandshakeFailure {
    pub(crate) fn new(err: &io::Error) -> Self {
        Self {
            kind: err.kind(),
            tls: err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<browntls::Error>())
                .cloned(),
            message: err.to_string(),
        }
    }

    pub(crate) fn error(&self) -> io::Error {
        match &self.tls {
            Some(tls) => io::Error::new(self.kind, tls.clone()),
            None => io::Error::new(self.kind, self.message.clone()),
        }
    }
}
