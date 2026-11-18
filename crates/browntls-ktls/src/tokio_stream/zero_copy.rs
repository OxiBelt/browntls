//! The kernel's zero-copy options and `sendfile` on an
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
    /// Tells the kernel whether to expect the peer's TLS 1.3 records to be
    /// unpadded, so that it decrypts them straight into the buffer of a
    /// read that has room for the whole record (`TLS_RX_EXPECT_NO_PAD`;
    /// off after the handover). The peer then decides how often a record
    /// is decrypted twice, and a read zeroes its buffer for up to a
    /// record's length behind the bytes it returns: see
    /// [`KtlsStream::set_rx_expect_no_pad`](crate::KtlsStream::set_rx_expect_no_pad).
    ///
    /// Setting it fails with [`io::ErrorKind::Unsupported`] on a kernel
    /// before Linux 7.2, which misplaces a padded record in the reader's
    /// buffer, and for TLS 1.2, whose records have no padding.
    pub fn set_rx_expect_no_pad(&mut self, expect: bool) -> io::Result<()> {
        self.engine
            .set_rx_expect_no_pad(self.socket.as_fd(), expect)
    }

    /// Whether the kernel expects unpadded records
    /// ([`Self::set_rx_expect_no_pad`]).
    pub fn rx_expect_no_pad(&self) -> io::Result<bool> {
        self.engine.rx_expect_no_pad(self.socket.as_fd())
    }

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

    /// Sends up to `count` bytes of the regular file `file`, starting at
    /// `offset`, as application data with `sendfile(2)`: the kernel makes
    /// the records from the file's pages, and the bytes never pass through
    /// userspace. Returns how many bytes were sent, which is zero only at
    /// or behind the end of the file (or for a `count` of zero) and may be
    /// less than `count`: call again with the offset moved on. One call
    /// sends at most 64 records' worth. The file's own position is neither
    /// used nor moved.
    ///
    /// Like a write, the call waits for room on the socket, first sends
    /// what the stream holds, counts the records against the cipher
    /// suite's confidentiality limit, and keeps [`unsent`](Self::unsent)
    /// and with it `shutdown` right, which `sendfile` on
    /// [`get_ref`](Self::get_ref) would not. A call that sent less than
    /// `count` may leave its last bytes in a record the kernel has not
    /// closed: they go out with what is sent next (more of the file, a
    /// write, `shutdown`) and are lost if the stream is dropped first.
    ///
    /// Only the socket is waited for. Where the kernel has to read the
    /// file from its storage first, the call blocks the thread for that
    /// long, as reading the file there would. It never asks the kernel
    /// for more than the file holds, whatever `count` is, because the
    /// kernel would then wait for TCP to take the last record; a file
    /// that holds less than the size it reports (cut short while it is
    /// sent, for one) can still cause that wait.
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
    /// The error is [`io::ErrorKind::InvalidInput`] for a `file` that is
    /// not a regular file. The call raises no `SIGPIPE`, nor does dropping
    /// the stream afterwards, within the limits (an inherited or shared
    /// descriptor) that
    /// [`KtlsStream::sendfile`](crate::KtlsStream::sendfile) names. The halves
    /// of `tokio::io::split` cannot call this; send files before
    /// splitting, or keep the stream whole.
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
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        if let Err(err) = self.engine.check() {
            return Poll::Ready(Err(err));
        }
        let file = file.as_fd();
        self.quiet_close.sent_file();
        self.poll_writable(cx, |engine, fd| engine.sendfile(fd, file, offset, count))
    }
}
