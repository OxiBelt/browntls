//! The kernel's zero-copy option and `sendfile` on an
//! [`AsyncKtlsStream`].

use std::future::poll_fn;
use std::io;
use std::os::fd::AsFd;
use std::task::{Context, Poll};

use browntls::SideData;

use super::AsyncKtlsStream;
use crate::engine::option_error;
use crate::sys;

impl<Data: SideData> AsyncKtlsStream<Data> {
    /// Lets a network device that encrypts the records itself send the
    /// pages of a file given to `sendfile` without the kernel copying them
    /// first (`TLS_TX_ZEROCOPY_RO`, Linux 5.19; off after the handover).
    /// The file must then not change until the peer has acknowledged its
    /// bytes: see
    /// [`KtlsStream::set_tx_zerocopy_sendfile`](crate::KtlsStream::set_tx_zerocopy_sendfile).
    ///
    /// The error is [`io::ErrorKind::Unsupported`] when the kernel lacks
    /// the option.
    pub fn set_tx_zerocopy_sendfile(&mut self, enable: bool) -> io::Result<()> {
        sys::set_tx_zerocopy_ro(self.socket.as_fd(), enable).map_err(option_error)
    }

    /// Whether `sendfile` may skip the kernel's copy
    /// ([`Self::set_tx_zerocopy_sendfile`]).
    pub fn tx_zerocopy_sendfile(&self) -> io::Result<bool> {
        sys::tx_zerocopy_ro(self.socket.as_fd()).map_err(option_error)
    }

    /// Sends up to `count` bytes of `file`, starting at `offset`, as
    /// application data with `sendfile(2)`: the kernel makes the records
    /// from the file's pages, and the bytes never pass through userspace.
    /// Returns how many bytes were sent, which is zero only at the end of
    /// the file (or for a `count` of zero) and may be less than `count`:
    /// call again with the offset moved on. One call sends at most 64
    /// records' worth. The file's own position is neither used nor moved.
    ///
    /// Like a write, the call waits for room on the socket, first sends
    /// what the stream holds, counts the records against the cipher
    /// suite's confidentiality limit, and keeps [`unsent`](Self::unsent)
    /// and with it `shutdown` exact, which `sendfile` on
    /// [`get_ref`](Self::get_ref) would not. A call that sent less than
    /// `count` may leave its last bytes in a record the kernel has not
    /// closed: they go out with what is sent next (more of the file, a
    /// write, `shutdown`).
    ///
    /// Only the socket is waited for. Where the kernel has to read the
    /// file from its storage first, the call blocks the thread for that
    /// long, as reading the file there would.
    ///
    /// ```no_run
    /// # async fn send<D: browntls::SideData>(
    /// #     tls: &mut browntls_ktls::AsyncKtlsStream<D>,
    /// # ) -> std::io::Result<()> {
    /// let file = std::fs::File::open("index.html")?;
    /// let len = file.metadata()?.len();
    /// let mut offset = 0;
    /// while offset < len {
    ///     let rest = usize::try_from(len - offset).unwrap_or(usize::MAX);
    ///     match tls.sendfile(&file, offset, rest).await? {
    ///         0 => break, // the file was cut short meanwhile
    ///         n => offset += n as u64,
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [`KtlsStream::sendfile`](crate::KtlsStream::sendfile) on
    /// `SIGPIPE`.
    pub async fn sendfile(
        &mut self,
        file: &impl AsFd,
        offset: u64,
        count: usize,
    ) -> io::Result<usize> {
        poll_fn(|cx| self.poll_sendfile(cx, file, offset, count)).await
    }

    /// [`Self::sendfile`] as a poll function. While it is pending the task
    /// is woken when the socket has room, like a pending write (and in
    /// place of one: the stream keeps one waiting writer).
    pub fn poll_sendfile(
        &mut self,
        cx: &mut Context<'_>,
        file: &impl AsFd,
        offset: u64,
        count: usize,
    ) -> Poll<io::Result<usize>> {
        if let Err(err) = self.engine.check() {
            return Poll::Ready(Err(err));
        }
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        let file = file.as_fd();
        self.poll_writable(cx, |engine, fd| engine.sendfile(fd, file, offset, count))
    }
}
