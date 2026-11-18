//! A transport whose writes can be made to wait, as a socket's do when the
//! peer reads nothing and the send buffer is full. Included by the test
//! targets that need it (`#[path = "common/gate.rs"] mod gate;`).
#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Whether a [`Gate`] lets writes through, and the writer waiting for it.
#[derive(Debug, Default)]
pub struct GateState {
    closed: AtomicBool,
    waiting: Mutex<Option<Waker>>,
    /// How many bytes the transport took.
    written: AtomicUsize,
}

impl GateState {
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waiting.lock().unwrap().take() {
            waker.wake();
        }
    }

    pub fn written(&self) -> usize {
        self.written.load(Ordering::SeqCst)
    }
}

/// A transport whose writes wait (`Pending`) while its gate is closed.
#[derive(Debug)]
pub struct Gate {
    inner: DuplexStream,
    state: Arc<GateState>,
}

impl Gate {
    pub fn new(inner: DuplexStream, state: Arc<GateState>) -> Self {
        Self { inner, state }
    }
}

impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.state.closed.load(Ordering::SeqCst) {
            *self.state.waiting.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.state.written.fetch_add(*n, Ordering::SeqCst);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
