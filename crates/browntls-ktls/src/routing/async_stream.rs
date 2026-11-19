//! [`AsyncRoutedStream`]: a `browntls-tokio` stream left where the routing
//! places its connection, the Tokio counterpart of
//! [`RoutedStream`](super::RoutedStream).

use std::fmt;
use std::future::Future;
use std::io::{self, IoSlice};
use std::os::fd::{AsFd, BorrowedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::client::ClientConnectionData;
use browntls::crypto::native::accel::load::kernel::{self, Place};
use browntls::server::ServerConnectionData;
use browntls::{ConnectionCommon, SideData};
use browntls_tokio::{client, server};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::meter::{Meter, records_of};
use crate::stream::unsupported;
use crate::tokio_stream::{AsyncKtlsStream, StreamHandoffError, permanent};

mod sealed {
    pub trait Sealed {}
}

/// A `browntls-tokio` stream over a Tokio TCP socket, which
/// [`AsyncRoutedStream`] can place: `client::TlsStream<TcpStream>` or
/// `server::TlsStream<TcpStream>`.
pub trait AsyncOffload: sealed::Sealed + AsyncRead + AsyncWrite + Unpin + Sized {
    /// The connection's side.
    type Data: SideData;

    /// The socket and the connection.
    #[doc(hidden)]
    fn parts(&self) -> (&TcpStream, &ConnectionCommon<Self::Data>);

    /// [`AsyncKtlsStream::from_client`] or [`AsyncKtlsStream::from_server`].
    #[doc(hidden)]
    fn into_kernel(
        self,
    ) -> impl Future<Output = Result<AsyncKtlsStream<Self::Data>, StreamHandoffError<Self>>> + Send;
}

/// A `browntls-tokio` stream over a Tokio TCP socket whose records are
/// protected where the routing placed its connection, by the kernel or in
/// userspace: the asynchronous [`RoutedStream`](super::RoutedStream).
///
/// `T` is the stream that was placed: `client::TlsStream<TcpStream>` or
/// `server::TlsStream<TcpStream>` of `browntls-tokio`.
///
/// Both variants read and write application data alike, and
/// [`shutdown`](AsyncWrite::poll_shutdown) sends `close_notify` and shuts
/// the socket's write side in both. What only one of them can do (for the
/// kernel, [`AsyncKtlsStream::sendfile`]) is reached through the variant;
/// an application that depends on the kernel hands its streams over with
/// [`AsyncKtlsStream::from_client`] or [`AsyncKtlsStream::from_server`]
/// instead of asking the routing.
///
/// ```no_run
/// # async fn run(
/// #     config: std::sync::Arc<browntls::ClientConfig>,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// use browntls_ktls::routing::AsyncRoutedStream;
/// use tokio::io::AsyncWriteExt;
///
/// // `config` has `enable_secret_extraction` set, and
/// // `browntls_ktls::routing::activate` was called.
/// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
/// let tls = browntls_tokio::TlsConnector::from(config)
///     .connect("example.com".try_into()?, tcp)
///     .await?;
/// let mut tls = AsyncRoutedStream::from_client(tls)
///     .await
///     .map_err(|e| e.into_io_error())?;
/// println!("records protected by {}", tls.place());
/// tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
/// # Ok(())
/// # }
/// ```
// One per connection, and moved rarely.
#[allow(clippy::large_enum_variant)]
pub enum AsyncRoutedStream<T: AsyncOffload> {
    /// The kernel protects the records.
    Kernel(AsyncKtlsStream<T::Data>),
    /// The stream's provider protects the records in userspace.
    Userspace(AsyncUserspaceStream<T>),
}

impl<T: AsyncOffload> AsyncRoutedStream<T> {
    /// Leaves `stream` where the routing places its connection.
    // The error hands the stream back, once per connection.
    #[allow(clippy::result_large_err)]
    async fn route(stream: T) -> Result<Self, StreamHandoffError<T>> {
        let userspace = |stream, received, early_data_len, refusal| {
            Ok(Self::Userspace(AsyncUserspaceStream {
                stream,
                received,
                taken: 0,
                early_data_len,
                meter: None,
                refusal,
            }))
        };
        let (socket, conn) = stream.parts();
        let suite = conn.negotiated_cipher_suite();
        let place = match suite.map(records_of) {
            Some(Some(records)) => kernel::place(records),
            // No stream compares the places of such records (AES-CCM), and
            // a client in its 0-RTT phase has no cipher suite yet: the
            // order alone decides.
            _ if kernel::is_active() => Place::Kernel,
            _ => Place::Userspace,
        };
        if place == Place::Userspace {
            return userspace(stream, Vec::new(), 0, None);
        }
        // What the kernel cannot take is found out before anything is
        // consumed, and is no error here: the next place takes it.
        let ready = match conn.kernel_handoff_blocker() {
            Some(blocker) if permanent(blocker, conn.is_handshaking()) => Err(unsupported(blocker)),
            // A client in its 0-RTT phase has no suite yet: the kernel
            // must take every cipher it could end up with.
            _ => super::probe::ready(suite, socket.as_fd()),
        };
        if let Err(error) = ready {
            return userspace(stream, Vec::new(), 0, Some(error));
        }
        match stream.into_kernel().await {
            Ok(stream) => Ok(Self::Kernel(stream)),
            Err(StreamHandoffError::Refused {
                stream,
                received,
                early_data_len,
                error,
            }) if error.kind() == io::ErrorKind::Unsupported => {
                userspace(stream, received, early_data_len, Some(error))
            }
            Err(other) => Err(other),
        }
    }

    /// Where the connection's records are protected.
    pub fn place(&self) -> Place {
        match self {
            Self::Kernel(_) => Place::Kernel,
            Self::Userspace(_) => Place::Userspace,
        }
    }
}

/// The placement of a `browntls-tokio` stream, for either side.
macro_rules! routed {
    ($name:ident, $stream:ty, $data:ty, $side:literal) => {
        impl sealed::Sealed for $stream {}

        impl AsyncOffload for $stream {
            type Data = $data;

            fn parts(&self) -> (&TcpStream, &ConnectionCommon<$data>) {
                let (socket, conn) = self.get_ref();
                (socket, conn)
            }

            fn into_kernel(
                self,
            ) -> impl Future<Output = Result<AsyncKtlsStream<$data>, StreamHandoffError<Self>>> + Send
            {
                AsyncKtlsStream::$name(self)
            }
        }

        impl AsyncRoutedStream<$stream> {
            #[doc = concat!("Leaves a `browntls-tokio` ", $side, " stream over a Tokio TCP socket where the routing places its connection.")]
            ///
            /// A stream placed in userspace is wrapped as it is: nothing
            /// is read or written, and the kernel is not asked. One
            /// placed with the kernel is handed over as by
            #[doc = concat!("[`AsyncKtlsStream::", stringify!($name), "`],")]
            /// for which the stream's configuration must have
            /// `enable_secret_extraction` set. A stream that the kernel
            /// cannot take (no `tls` module, a cipher suite or a
            /// configuration without a kernel form, a cipher the running
            /// kernel does not have, a peer's
            /// `record_size_limit` that needs a newer kernel) stays in
            /// userspace, and [`AsyncUserspaceStream::kernel_refusal`]
            /// tells why. If the handover had taken application data out
            /// of the stream by then, the first reads return it.
            ///
            /// The connection is placed by its cipher suite. A stream
            /// whose handshake has not chosen one yet (a client in its
            /// 0-RTT phase) follows the order alone: it goes to the
            /// kernel while kernel TLS is active, whatever the routing
            /// has measured.
            ///
            /// # Errors
            ///
            #[doc = concat!("Those of [`AsyncKtlsStream::", stringify!($name), "`]")]
            /// that do not mean that the kernel cannot take the stream:
            /// [`StreamHandoffError::Refused`] returns the stream when
            /// readying it for the handover failed (its handshake, the
            /// records to be written and read first; see there for what
            /// the stream is good for afterwards), and
            /// [`StreamHandoffError::Failed`] means the kernel took part
            /// of the connection's state and then failed. Dropping the
            /// future drops the stream with it.
            // The error hands the stream back, once per connection.
            #[allow(clippy::result_large_err)]
            pub async fn $name(stream: $stream) -> Result<Self, StreamHandoffError<$stream>> {
                Self::route(stream).await
            }
        }
    };
}

routed!(
    from_client,
    client::TlsStream<TcpStream>,
    ClientConnectionData,
    "client"
);
routed!(
    from_server,
    server::TlsStream<TcpStream>,
    ServerConnectionData,
    "server"
);

impl<T: AsyncOffload> AsyncRead for AsyncRoutedStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Userspace(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncOffload> AsyncWrite for AsyncRoutedStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Kernel(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Userspace(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Kernel(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Userspace(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Kernel(stream) => stream.is_write_vectored(),
            Self::Userspace(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => Pin::new(stream).poll_flush(cx),
            Self::Userspace(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Userspace(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl<T: AsyncOffload> AsFd for AsyncRoutedStream<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Kernel(stream) => stream.as_fd(),
            Self::Userspace(stream) => stream.as_fd(),
        }
    }
}

impl<T: AsyncOffload> fmt::Debug for AsyncRoutedStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(stream) => f.debug_tuple("Kernel").field(stream).finish(),
            Self::Userspace(stream) => f.debug_tuple("Userspace").field(stream).finish(),
        }
    }
}

/// A `browntls-tokio` stream that the routing left in userspace: the
/// stream, which reports what its writes cost, and which first returns
/// the application data a refused handover had already taken out of it.
pub struct AsyncUserspaceStream<T> {
    stream: T,
    /// Application data a refused handover took from the stream.
    received: Vec<u8>,
    /// How much of `received` was read.
    taken: usize,
    /// See [`early_data_len`](Self::early_data_len).
    early_data_len: usize,
    /// Made by the first write after the handshake: until then the
    /// connection may have no cipher suite, and its writes are not timed.
    meter: Option<Meter>,
    refusal: Option<io::Error>,
}

impl<T> AsyncUserspaceStream<T> {
    /// The `browntls-tokio` stream.
    pub fn get_ref(&self) -> &T {
        &self.stream
    }

    /// The `browntls-tokio` stream. Application data read from it
    /// directly comes before its time while [`Self::received`] is not
    /// empty, and what is written to it directly is not timed.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Why the kernel did not take the stream, when the routing had
    /// placed its connection there: the kernel did not attach the `tls`
    /// upper layer protocol, or the connection has no kernel form
    /// ([`io::ErrorKind::Unsupported`]). `None` for a stream the routing
    /// kept in userspace.
    pub fn kernel_refusal(&self) -> Option<&io::Error> {
        self.refusal.as_ref()
    }

    /// The application data that the next reads return before anything
    /// from the stream: what a refused handover had taken out of it.
    pub fn received(&self) -> &[u8] {
        &self.received[self.taken..]
    }

    /// How many of the first bytes this stream returns are 0-RTT data
    /// that a server had accepted and not read when the kernel refused
    /// its stream. An attacker can replay that data, so a server must not
    /// act on it as on the rest; a `browntls-tokio` stream returns it
    /// only through `early_data()`, this stream returns it first, in the
    /// order it was sent. The number is fixed when the stream is made and
    /// does not shrink as the data is read.
    ///
    /// Zero for a client, and for a stream out of which nothing was
    /// taken (the routing kept it in userspace, or the kernel refused it
    /// at once): 0-RTT data it holds is still read through `early_data()`
    /// of [`Self::get_mut`].
    pub fn early_data_len(&self) -> usize {
        self.early_data_len
    }

    /// The `browntls-tokio` stream and [`Self::received`], which must be
    /// read before anything the stream yields. Of the
    /// [`early_data_len`](Self::early_data_len) bytes of 0-RTT data,
    /// those not read yet are at its start.
    pub fn into_parts(mut self) -> (T, Vec<u8>) {
        self.received.drain(..self.taken);
        (self.stream, self.received)
    }
}

impl<T: AsyncOffload> AsyncUserspaceStream<T> {
    /// Runs the poll `write` of a write of `len` bytes, timed if the
    /// routing asks for it.
    fn timed(
        &mut self,
        len: usize,
        write: impl FnOnce(Pin<&mut T>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        if self.meter.is_none() {
            let (_, conn) = self.stream.parts();
            if !conn.is_handshaking() {
                let records = conn.negotiated_cipher_suite().and_then(records_of);
                self.meter = Some(Meter::userspace(records));
            }
        }
        let timing = self.meter.and_then(|meter| meter.start(len));
        let poll = write(Pin::new(&mut self.stream));
        if let (Some(timing), Poll::Ready(Ok(written))) = (timing, &poll) {
            timing.done(*written);
        }
        poll
    }
}

impl<T: AsyncOffload> AsyncRead for AsyncUserspaceStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let received = &this.received[this.taken..];
        if !received.is_empty() {
            // With no room in `buf` nothing is read, from the stream
            // neither: its data comes after this.
            let n = received.len().min(buf.remaining());
            buf.put_slice(&received[..n]);
            this.taken += n;
            if this.taken == this.received.len() {
                this.received = Vec::new();
                this.taken = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncOffload> AsyncWrite for AsyncUserspaceStream<T> {
    /// Encrypts `buf` and writes the records, as the `browntls-tokio`
    /// stream does. The routing times some writes, one poll at a time: a
    /// poll runs on one thread from start to end, so its processor time
    /// is that thread's on a runtime with several threads too, and the
    /// time between two polls is not counted. Only a poll that takes
    /// bytes is reported. One that found the socket without room has
    /// encrypted what it took without sending all of it, and is reported
    /// cheaper than it is; the write or flush that sends the rest bears
    /// that cost. Writes before the handshake is complete (on a stream
    /// returned early for 0-RTT data) are not timed.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .timed(buf.len(), |stream| stream.poll_write(cx, buf))
    }

    /// Like [`poll_write`](AsyncWrite::poll_write), for the bytes of all
    /// of `bufs`.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let len = bufs
            .iter()
            .fold(0usize, |len, buf| len.saturating_add(buf.len()));
        self.get_mut()
            .timed(len, |stream| stream.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    /// Sends `close_notify` and shuts the socket's write side, as the
    /// `browntls-tokio` stream does.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl<T: AsyncOffload> AsFd for AsyncUserspaceStream<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.parts().0.as_fd()
    }
}

/// `Debug` shows the length of the received data only: it is application
/// plaintext.
impl<T> fmt::Debug for AsyncUserspaceStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncUserspaceStream")
            .field("received", &(self.received.len() - self.taken))
            .field("early_data_len", &self.early_data_len)
            .field("kernel_refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use browntls_tokio::{TlsAcceptor, TlsConnector};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::common::{Pki, localhost, offloadable_suites, tcp_pair};

    /// What a refused handover had taken out of the stream is read first,
    /// in pieces, then what the stream yields.
    #[tokio::test]
    async fn the_data_of_a_refused_handover_is_read_first() {
        let pki = Pki::new();
        let suite = offloadable_suites()[0];
        let (client_tcp, server_tcp) = tcp_pair();
        let tokio = |tcp: std::net::TcpStream| {
            tcp.set_nonblocking(true).unwrap();
            TcpStream::from_std(tcp).unwrap()
        };
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(suite)))
                .connect(localhost(), tokio(client_tcp)),
            TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(tokio(server_tcp)),
        );
        let (mut client, server) = (client.unwrap(), server.unwrap());
        let mut tls = AsyncUserspaceStream {
            stream: server,
            received: b"early, taken".to_vec(),
            taken: 0,
            early_data_len: 5,
            meter: None,
            refusal: Some(io::ErrorKind::Unsupported.into()),
        };
        client.write_all(b" and sent").await.unwrap();
        client.flush().await.unwrap();

        // An empty read takes nothing.
        assert_eq!(tls.read(&mut []).await.unwrap(), 0);
        let mut first = [0u8; 7];
        assert_eq!(tls.read(&mut first).await.unwrap(), 7);
        assert_eq!(&first, b"early, ");
        assert_eq!(tls.received(), b"taken");
        assert_eq!(tls.early_data_len(), 5);
        // A read with room for more returns what is left of it alone.
        let mut rest = [0u8; 64];
        assert_eq!(tls.read(&mut rest).await.unwrap(), 5);
        assert_eq!(&rest[..5], b"taken");
        assert!(tls.received().is_empty());
        let mut sent = [0u8; 9];
        tls.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b" and sent");
        assert!(format!("{tls:?}").contains("received: 0"));

        // Given up part of the way, the rest comes with the stream.
        tls.received = b"0123456789".to_vec();
        tls.read_exact(&mut [0u8; 4]).await.unwrap();
        let (_, received) = tls.into_parts();
        assert_eq!(received, b"456789");
    }
}
