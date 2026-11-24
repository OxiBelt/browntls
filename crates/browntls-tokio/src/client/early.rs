//! Buffered TLS client early writes and handshake settlement.

use std::io::{self, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use browntls_core::ClientConnection;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client_early::{EarlyResult, EarlyWrite, RejectedEarlyDataPolicy};
use crate::common::{Stream, StreamState};

#[derive(Debug)]
pub(crate) struct EarlyData {
    write: EarlyWrite,
    finishing: bool,
    handshake_flushed: bool,
    /// A read may lose its transport registration to the writer.
    read_waker: Option<Waker>,
}

impl EarlyData {
    pub(crate) fn new(policy: RejectedEarlyDataPolicy) -> Self {
        Self {
            write: EarlyWrite::new(policy),
            finishing: false,
            handshake_flushed: false,
            read_waker: None,
        }
    }

    pub(crate) fn park_reader(&mut self, cx: &Context<'_>) {
        match &self.read_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            _ => self.read_waker = Some(cx.waker().clone()),
        }
    }

    pub(crate) fn read_waker(&self) -> Option<&Waker> {
        self.read_waker.as_ref()
    }
}

pub(crate) fn write(
    early: &mut EarlyData,
    session: &mut ClientConnection,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize> {
    if early.finishing {
        return Ok(0);
    }
    let Some(mut writer) = session.early_data() else {
        return Ok(0);
    };
    let mut written = 0;
    for buf in bufs.iter().filter(|buf| !buf.is_empty()) {
        let limit = early.write.limit(buf.len());
        if limit == 0 {
            break;
        }
        let n = writer.write(&buf[..limit])?;
        early.write.record(&buf[..n]);
        written += n;
        if n < buf.len() {
            break;
        }
    }
    Ok(written)
}

/// Settles the early phase and records its outcome. A write-side caller
/// checks the acknowledgement separately, after the handshake is usable.
pub(crate) fn poll_finish<IO>(
    slot: &mut Option<EarlyData>,
    result: &mut EarlyResult,
    io: &mut IO,
    session: &mut ClientConnection,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let Some(early) = slot else {
        return Poll::Ready(result.failure());
    };
    early.finishing = true;

    let finished = ready!(poll_settle(early, io, session, st, cx));
    if let Some(waker) = early.read_waker.take() {
        waker.wake();
    }
    match &finished {
        Ok(()) => result.complete(&early.write, session.is_early_data_accepted()),
        Err(error) => result.fail(&early.write, error),
    }
    *slot = None;
    Poll::Ready(finished)
}

fn poll_settle<IO>(
    early: &mut EarlyData,
    io: &mut IO,
    session: &mut ClientConnection,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = Stream::new(io, session)
        .set_eof(!st.state.readable())
        .set_need_flush(st.need_flush)
        .set_read_before(st.read_before);
    while stream.session.is_handshaking() {
        let poll = stream.handshake(cx, &mut st.revocation);
        st.need_flush = stream.need_flush;
        st.read_before = stream.read_before;
        ready!(poll)?;
    }
    if !early.handshake_flushed {
        // The peer needs our Finished before any ordinary application data.
        ready!(Pin::new(&mut stream).poll_flush(cx))?;
        early.handshake_flushed = true;
        st.need_flush = false;
    }
    if !stream.session.is_early_data_accepted()
        && early.write.may_resend(
            stream.session.early_data_alpn(),
            stream.session.alpn_protocol(),
        )
    {
        while !early.write.remaining().is_empty() {
            if stream.session.wants_write() {
                ready!(Pin::new(&mut stream).poll_flush(cx))?;
            }
            let n = stream.session.writer().write(early.write.remaining())?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            early.write.queued_resend(n);
        }
        // A previous poll may have queued the last bytes and then blocked.
        ready!(Pin::new(&mut stream).poll_flush(cx))?;
    }
    Poll::Ready(Ok(()))
}
