//! The kernel's zero-copy option on an [`AsyncKtlsStream`].

use std::io;
use std::os::fd::AsFd;

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
}
