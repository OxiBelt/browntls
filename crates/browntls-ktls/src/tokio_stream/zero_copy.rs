//! The kernel's zero-copy options on an [`AsyncKtlsStream`].

use std::io;
use std::os::fd::AsFd;

use browntls::SideData;

use super::AsyncKtlsStream;
use crate::engine::option_error;
use crate::sys;

impl<Data: SideData> AsyncKtlsStream<Data> {
    /// Tells the kernel whether to expect the peer's TLS 1.3 records to be
    /// unpadded, so that it decrypts them straight into the buffer of a
    /// read that has room for the whole record (`TLS_RX_EXPECT_NO_PAD`,
    /// Linux 6.0; off after the handover). The peer then decides how often
    /// a record is decrypted twice: see
    /// [`KtlsStream::set_rx_expect_no_pad`](crate::KtlsStream::set_rx_expect_no_pad).
    ///
    /// The error is [`io::ErrorKind::Unsupported`] for TLS 1.2, whose
    /// records have no padding, and when the kernel lacks the option.
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
    /// first (`TLS_TX_ZEROCOPY_RO`, Linux 6.0; off after the handover).
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
}
