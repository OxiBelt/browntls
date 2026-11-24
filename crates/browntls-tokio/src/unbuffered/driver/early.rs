//! Client early writes over the unbuffered connection state machine.

use std::fmt;
use std::io::{self, IoSlice};
use std::ops::DerefMut;
use std::task::{Context, Poll};

use browntls_core::SideData;
use browntls_core::client::UnbufferedClientConnection;
use browntls_core::unbuffered::{ConnectionState, EarlyDataError, UnbufferedConnectionCommon};
use browntls_crypto::zeroize::zeroize_bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    MAX_GATHER, MAX_WRITE, Outgoing, TlsStream, encode, encrypt_with, internal, joint_waker,
    tls_error,
};
use crate::client_early::{EarlyDataOutcome, EarlyWrite, RejectedEarlyDataPolicy};

type EncryptEarly<C> = fn(&mut C, &mut Outgoing, &[u8]) -> io::Result<usize>;
type EarlyDecision<C> = fn(&C) -> (bool, Option<&[u8]>);

/// Only a client can install this state. The operations specific to the
/// client connection are supplied when it is installed.
pub(in crate::unbuffered) struct ClientEarly<C> {
    write: EarlyWrite,
    encrypt: EncryptEarly<C>,
    decision: EarlyDecision<C>,
    finishing: bool,
    handshake_flushed: bool,
}

impl ClientEarly<UnbufferedClientConnection> {
    pub(in crate::unbuffered) fn new(policy: RejectedEarlyDataPolicy) -> Self {
        Self {
            write: EarlyWrite::new(policy),
            encrypt: encrypt_early,
            decision: |conn| (conn.is_early_data_accepted(), conn.early_data_alpn()),
            finishing: false,
            handshake_flushed: false,
        }
    }
}

impl<C> fmt::Debug for ClientEarly<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientEarly")
            .field("write", &self.write)
            .field("finishing", &self.finishing)
            .finish_non_exhaustive()
    }
}

fn encrypt_early(
    conn: &mut UnbufferedClientConnection,
    outgoing: &mut Outgoing,
    data: &[u8],
) -> io::Result<usize> {
    let len = data.len().min(conn.early_data_bytes_left());
    if len == 0 {
        return Ok(0);
    }
    loop {
        match conn.process_tls_records(&mut []).state.map_err(tls_error)? {
            ConnectionState::EncodeTlsData(mut encoder) => {
                encode(&mut encoder, outgoing)?;
            }
            ConnectionState::TransmitTlsData(mut transmit) => {
                let Some(mut early) = transmit.may_encrypt_early_data() else {
                    return Ok(0);
                };
                encrypt_with(outgoing, |room| match early.encrypt(&data[..len], room) {
                    Ok(n) => Ok(n),
                    Err(EarlyDataError::Encrypt(error)) => Err(error),
                    Err(_) => Err(browntls_core::unbuffered::EncryptError::Failed),
                })?;
                // The ordinary handshake driver takes the transmit grant
                // once the stream has finished adding its early records.
                return Ok(len);
            }
            _ => {
                return Err(internal(
                    "TLS connection is missing its early-data transmit grant",
                ));
            }
        }
    }
}

impl<IO, C, D> TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    pub(in crate::unbuffered) fn poll_early_data_outcome(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<EarlyDataOutcome>> {
        self.write_side(cx, |this, cx| {
            ready!(this.poll_finish_client_early(cx))?;
            Poll::Ready(Ok(this.client_early_result.outcome))
        })
    }

    pub(super) fn poll_finish_client_early_for_read(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.client_early.is_none() {
            return Poll::Ready(self.client_early_result.failure());
        }
        let joint = joint_waker(cx.waker(), self.write_waker.as_ref());
        let poll = self.poll_finish_client_early(&mut Context::from_waker(&joint));
        self.park_reader(cx, poll.is_pending());
        poll
    }

    pub(super) fn poll_finish_client_early(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(mut early) = self.client_early.take() else {
            return Poll::Ready(self.client_early_result.failure());
        };
        early.finishing = true;
        match self.poll_settle_client_early(cx, &mut early) {
            Poll::Ready(result) => {
                self.finish_client_early(&early, &result);
                Poll::Ready(result)
            }
            Poll::Pending => {
                self.client_early = Some(early);
                Poll::Pending
            }
        }
    }

    fn poll_settle_client_early(
        &mut self,
        cx: &mut Context<'_>,
        early: &mut ClientEarly<C>,
    ) -> Poll<io::Result<()>> {
        if !early.handshake_flushed {
            ready!(self.poll_handshake(cx))?;
            early.handshake_flushed = true;
        }
        let (accepted, alpn) = (early.decision)(&self.conn);
        if !accepted && early.write.may_resend(alpn, self.conn.alpn_protocol()) {
            while !early.write.remaining().is_empty() {
                ready!(self.poll_write_out(cx))?;
                let remaining = early.write.remaining();
                let len = remaining.len().min(MAX_WRITE);
                if self.encrypt(&remaining[..len])? {
                    early.write.queued_resend(len);
                } else {
                    ready!(self.poll_revocation_for_write(cx))?;
                }
            }
            ready!(self.poll_write_out(cx))?;
            ready!(self.poll_flush_io(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn finish_client_early(&mut self, early: &ClientEarly<C>, result: &io::Result<()>) {
        match result {
            Ok(()) => self
                .client_early_result
                .complete(&early.write, (early.decision)(&self.conn).0),
            Err(error) => self.client_early_result.fail(&early.write, error),
        };
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    /// Returns 0 when the ordinary write may go ahead. The phase is
    /// settled first, including when a short transport write forces the
    /// handshake driver to read and write concurrently.
    pub(super) fn poll_write_client_early(
        &mut self,
        cx: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut early) = self.client_early.take() {
            let attempt = if early.finishing {
                Ok(0)
            } else {
                self.try_write_client_early(cx, &mut early, slices)
            };
            self.client_early = match attempt {
                Err(error) => {
                    let failure = Err(error);
                    self.finish_client_early(&early, &failure);
                    return Poll::Ready(failure.map(|()| 0));
                }
                Ok(n) if n != 0 => {
                    self.client_early = Some(early);
                    return Poll::Ready(Ok(n));
                }
                Ok(_) => Some(early),
            };
        }
        ready!(self.poll_finish_client_early(cx))?;
        Poll::Ready(self.client_early_result.check_write().map(|()| 0))
    }

    fn try_write_client_early(
        &mut self,
        cx: &mut Context<'_>,
        early: &mut ClientEarly<C>,
        slices: &[IoSlice<'_>],
    ) -> io::Result<usize> {
        let Some(first) = slices.iter().find(|slice| !slice.is_empty()) else {
            return Ok(0);
        };
        if self.poll_write_out(cx)?.is_pending() {
            return Ok(0);
        }
        if slices.len() == 1 || first.len() >= MAX_GATHER {
            let limit = early.write.limit(first.len().min(MAX_WRITE));
            let n = (early.encrypt)(&mut self.conn, &mut self.outgoing, &first[..limit])?;
            early.write.record(&first[..n]);
            return Ok(n);
        }
        let limit = early.write.limit(MAX_GATHER);
        let len = slices
            .iter()
            .fold(0usize, |total, slice| total.saturating_add(slice.len()))
            .min(limit);
        self.gather.reserve(len);
        for slice in slices {
            let room = limit - self.gather.len();
            self.gather
                .extend_from_slice(&slice[..slice.len().min(room)]);
            if self.gather.len() == limit {
                break;
            }
        }
        let result = (early.encrypt)(&mut self.conn, &mut self.outgoing, &self.gather);
        if let Ok(n) = result {
            early.write.record(&self.gather[..n]);
        }
        zeroize_bytes(&mut self.gather);
        self.gather.clear();
        result
    }
}
