//! TLS 1.3 0-RTT ("early") data on the client: writes before the handshake
//! completes, and their resending when the server declines them.

use std::fmt;
use std::io::{self, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use browntls::ClientConnection;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{Stream, StreamState};

/// The server declined the 0-RTT data, and the connection may not speak the
/// application protocol it was written for, so it was not sent again (RFC
/// 9846 §4.2.10: early data is resent automatically only when the same ALPN
/// protocol is selected). The operation that ended the early phase returns
/// this as an `io::Error` of kind `Other`; the stream itself stays usable,
/// and the application decides what to send. With split halves that
/// operation may be a read: check
/// [`ClientConnection::is_early_data_accepted`] before relying on early data
/// having arrived.
///
/// Declined early data is resent automatically only when the connection
/// offered no ALPN protocol and none was selected, or offered exactly one
/// and the server selected it.
#[derive(Debug)]
pub struct EarlyDataNotResent {
    /// How many bytes of early data were declined and not resent.
    pub len: usize,
}

impl fmt::Display for EarlyDataNotResent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the server declined {} bytes of 0-RTT data, which were not sent again \
             because the ALPN protocol may differ",
            self.len
        )
    }
}

impl std::error::Error for EarlyDataNotResent {}

/// A stream returned before its handshake, while it may send early data.
///
/// `Debug` shows lengths and state only: `sent` is application plaintext.
pub(crate) struct EarlyData {
    /// The early data written so far, kept to resend if the server
    /// declines it.
    sent: Vec<u8>,
    /// How much of `sent` was resent after a refusal.
    resent: usize,
    /// The ALPN protocols the ClientHello offered.
    offered_alpn: Vec<Vec<u8>>,
    /// The handshake failed: every later operation reports it.
    failure: Option<Failure>,
    /// A read waiting for the early phase to end; woken when any operation
    /// ends it, since that operation may have taken over the read's
    /// registration in the transport.
    read_waker: Option<Waker>,
}

/// A handshake failure kept to report again.
#[derive(Debug)]
struct Failure {
    kind: io::ErrorKind,
    tls: Option<browntls::Error>,
    message: String,
}

impl Failure {
    fn new(err: &io::Error) -> Self {
        Self {
            kind: err.kind(),
            tls: err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<browntls::Error>())
                .cloned(),
            message: err.to_string(),
        }
    }

    fn error(&self) -> io::Error {
        match &self.tls {
            Some(tls) => io::Error::new(self.kind, tls.clone()),
            None => io::Error::new(self.kind, self.message.clone()),
        }
    }
}

impl fmt::Debug for EarlyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlyData")
            .field("sent_len", &self.sent.len())
            .field("resent", &self.resent)
            .field("offered_alpn", &self.offered_alpn.len())
            .field("failure", &self.failure)
            .field("read_waker", &self.read_waker.is_some())
            .finish()
    }
}

impl EarlyData {
    pub(crate) fn new(offered_alpn: Vec<Vec<u8>>) -> Self {
        Self {
            sent: Vec::new(),
            resent: 0,
            offered_alpn,
            failure: None,
            read_waker: None,
        }
    }

    /// Records the waker of a read that waits for the early phase to end.
    pub(crate) fn park_reader(&mut self, cx: &Context<'_>) {
        match &mut self.read_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
        }
    }

    /// Whether declined early data may be resent on this connection.
    fn may_resend(&self, session: &ClientConnection) -> bool {
        match (self.offered_alpn.as_slice(), session.alpn_protocol()) {
            ([], None) => true,
            ([offered], Some(selected)) => offered.as_slice() == selected,
            _ => false,
        }
    }
}

/// Writes as much of `bufs` as the early-data allowance takes. `Ok(0)` once
/// none can be sent any more (the allowance is spent or the server already
/// answered): the caller then finishes the handshake.
pub(crate) fn write(
    early: &mut EarlyData,
    session: &mut ClientConnection,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize> {
    if let Some(failure) = &early.failure {
        return Err(failure.error());
    }
    let Some(mut writer) = session.early_data() else {
        return Ok(0);
    };
    let mut written = 0;
    for buf in bufs.iter().filter(|buf| !buf.is_empty()) {
        let n = writer.write(buf)?;
        early.sent.extend_from_slice(&buf[..n]);
        written += n;
        if n < buf.len() {
            break;
        }
    }
    Ok(written)
}

/// Completes the handshake, resends the early data if the server declined
/// it and that is allowed, and ends the early-data phase (`*slot` becomes
/// `None`). A handshake failure is kept and reported by every later call.
pub(crate) fn poll_finish<IO>(
    slot: &mut Option<EarlyData>,
    io: &mut IO,
    session: &mut ClientConnection,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let Some(early) = slot else {
        return Poll::Ready(Ok(()));
    };
    if let Some(failure) = &early.failure {
        return Poll::Ready(Err(failure.error()));
    }
    let mut stream = Stream::new(io, session)
        .set_eof(!st.state.readable())
        .set_need_flush(st.need_flush)
        .set_read_before(st.read_before);
    while stream.session.is_handshaking() {
        let poll = stream.handshake(cx);
        st.need_flush = stream.need_flush;
        st.read_before = stream.read_before;
        match poll {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => {
                early.failure = Some(Failure::new(&err));
                // Never resent now: do not keep the plaintext.
                early.sent = Vec::new();
                if let Some(waker) = early.read_waker.take() {
                    waker.wake();
                }
                return Poll::Ready(Err(err));
            }
            Poll::Pending => return Poll::Pending,
        }
    }
    // The handshake ends for us before our own last flight (EndOfEarlyData,
    // Finished) is out; the peer needs it before anything else.
    ready!(Pin::new(&mut stream).poll_flush(cx))?;
    let mut result = Ok(());
    if !stream.session.is_early_data_accepted() {
        if early.may_resend(stream.session) {
            while early.resent < early.sent.len() {
                let n = ready!(Pin::new(&mut stream).poll_write(cx, &early.sent[early.resent..]))?;
                early.resent += n;
            }
        } else if !early.sent.is_empty() {
            result = Err(io::Error::other(EarlyDataNotResent {
                len: early.sent.len(),
            }));
        }
    }
    if let Some(waker) = early.read_waker.take() {
        waker.wake();
    }
    *slot = None;
    Poll::Ready(result)
}
