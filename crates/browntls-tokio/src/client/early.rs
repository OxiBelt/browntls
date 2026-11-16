//! TLS 1.3 0-RTT ("early") data on the client: writes before the handshake
//! completes, and their resending when the server declines them.

use std::io::{self, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::ClientConnection;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{Stream, StreamState};

/// A stream returned before its handshake, while it may send early data.
#[derive(Debug, Default)]
pub(crate) struct EarlyData {
    /// The early data written so far, kept to resend if the server
    /// declines it.
    sent: Vec<u8>,
    /// How much of `sent` was resent after a refusal.
    resent: usize,
}

/// Writes as much of `bufs` as the early-data allowance takes. `Ok(0)` once
/// none can be sent any more (the allowance is spent or the server already
/// answered): the caller then finishes the handshake.
pub(crate) fn write(
    early: &mut EarlyData,
    session: &mut ClientConnection,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize> {
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
/// it, and ends the early-data phase (`*slot` becomes `None`).
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
    let mut stream = Stream::new(io, session)
        .set_eof(!st.state.readable())
        .set_need_flush(st.need_flush);
    while stream.session.is_handshaking() {
        let poll = stream.handshake(cx);
        st.need_flush = stream.need_flush;
        match poll {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    // The handshake ends for us before our own last flight (EndOfEarlyData,
    // Finished) is out; the peer needs it before anything else.
    ready!(Pin::new(&mut stream).poll_flush(cx))?;
    if !stream.session.is_early_data_accepted() {
        while early.resent < early.sent.len() {
            let n = ready!(Pin::new(&mut stream).poll_write(cx, &early.sent[early.resent..]))?;
            early.resent += n;
        }
    }
    *slot = None;
    Poll::Ready(Ok(()))
}
