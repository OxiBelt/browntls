//! The buffered I/O API around the connection core.

use alloc::boxed::Box;
use core::fmt::Debug;
use core::ops::{Deref, DerefMut};

use super::{ConnectionCore, SideData, State};
use crate::common_state::{CommonState, IoState};
use crate::error::Error;
use crate::msgs::deframer::DeframerVecBuffer;
use crate::suites::ExtractedSecrets;

/// A connection whose handshake is driven by the buffered API.
pub struct ConnectionCommon<Data> {
    pub(crate) core: ConnectionCore<Data>,
    pub(crate) deframer_buffer: DeframerVecBuffer,
}

impl<Data: SideData> ConnectionCommon<Data> {
    /// Processes every complete record received so far.
    ///
    /// Call this after `read_tls`. Returns what the connection now wants to
    /// do, or the fatal error that ended it (after which an alert is usually
    /// queued for `write_tls`).
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        self.core.process_new_packets(&mut self.deframer_buffer)
    }

    /// Derives keying material bound to this session (RFC 5705, RFC 8446 §7.5).
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        self.core
            .export_keying_material(output.as_mut(), label, context)?;
        Ok(output)
    }

    /// Derives keying material from the early exporter (RFC 9846 §7.5,
    /// `early_exporter_master_secret`), the exporter for use with 0-RTT data.
    ///
    /// Available on a client from the moment it offers 0-RTT (see
    /// `ClientConnection::early_data`) and on a server once it has accepted
    /// 0-RTT; the client loses it again if the server rejects 0-RTT, since
    /// the two sides would no longer agree on the value. Like 0-RTT data the
    /// output is bound to the ClientHello and the resumption PSK only: it is
    /// not forward secret and an attacker who replays the ClientHello
    /// replays it too. Use [`Self::export_keying_material`] for anything
    /// else; the two never return the same value.
    pub fn export_early_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        let out = output.as_mut();
        if out.is_empty() {
            return Err(Error::general(
                "export_early_keying_material: output buffer is empty",
            ));
        }
        if context.is_some_and(|c| c.len() > usize::from(u16::MAX)) {
            return Err(Error::general(
                "export_early_keying_material: context too long",
            ));
        }
        match &self.core.common_state.early_exporter {
            Some(exporter) => exporter.export_keying_material(out, label, context)?,
            None => {
                return Err(Error::General(
                    "early exporter unavailable: 0-RTT was not offered, or was rejected".into(),
                ));
            }
        }
        Ok(output)
    }

    /// The `tls-exporter` channel binding of RFC 9266: 32 bytes exported
    /// with the label `EXPORTER-Channel-Binding` and an empty context.
    ///
    /// Defined only when the handshake produced a unique master secret
    /// (RFC 9266 §2): always in TLS 1.3, and in TLS 1.2 only with the
    /// extended master secret (RFC 7627), which the TLS 1.2 exporter already
    /// requires. browntls never renegotiates, so the value is fixed for the
    /// connection (RFC 9266 §4.2). Fails until the handshake is complete.
    pub fn tls_exporter_channel_binding(&self) -> Result<[u8; 32], Error> {
        self.export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
    }

    /// Extracts the traffic secrets for kernel TLS offload.
    ///
    /// Requires `enable_secret_extraction` in the configuration and a
    /// completed handshake. The connection is consumed because no further
    /// records may be protected by this library afterwards.
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        if self.deframer_buffer.has_pending() || self.core.deframer.has_buffered_handshake() {
            return Err(Error::general(
                "cannot extract secrets with unprocessed received data",
            ));
        }
        self.core.dangerous_extract_secrets()
    }

    /// Limits the buffered outgoing data (`None` removes the limit).
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.core.common_state.set_buffer_limit(limit);
    }

    /// Rotates the traffic keys (TLS 1.3 only), asking the peer to do the same.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core.refresh_traffic_keys()
    }

    pub(crate) fn replace_state(&mut self, new: Box<dyn State<Data>>) {
        self.core.state = Ok(new);
    }
}

#[cfg(feature = "std")]
impl<Data: SideData> ConnectionCommon<Data> {
    /// Reads TLS bytes from `rd` into the connection. Returns the number of
    /// bytes read; zero means the transport reached end of file.
    ///
    /// Fails if received plaintext is waiting for the application, so that a
    /// peer cannot force unbounded buffering.
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        if self.core.common_state.received_plaintext.is_full() {
            return Err(std::io::Error::other(
                "received plaintext buffer full; read it with reader() first",
            ));
        }
        let n = self.deframer_buffer.read(rd)?;
        if n == 0 {
            self.core.common_state.mark_eof();
        }
        Ok(n)
    }

    /// Writes queued TLS bytes to `wr`.
    pub fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        self.core.common_state.sendable_tls.write_to(wr)
    }

    /// Plaintext received from the peer.
    pub fn reader(&mut self) -> Reader<'_> {
        Reader {
            common: &mut self.core.common_state,
        }
    }

    /// Plaintext to send to the peer.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer {
            sink: &mut self.core,
        }
    }

    /// Drives the connection over `io` until the handshake completes, or,
    /// once it has, until some plaintext was read or all queued TLS bytes
    /// were written. Returns `(bytes read, bytes written)`.
    ///
    /// Fails with `WriteZero` if `io` accepts no bytes while TLS bytes are
    /// queued.
    pub fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), std::io::Error>
    where
        T: std::io::Read + std::io::Write,
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.wants_write() {
                match self.write_tls(io)? {
                    // A transport that accepts nothing would leave the loop
                    // spinning; report it like `Write::write_all` does.
                    0 => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "transport accepted no TLS bytes",
                        ));
                    }
                    n => wrlen += n,
                }
            }
            io.flush()?;

            if !until_handshaked && wrlen > 0 {
                return Ok((rdlen, wrlen));
            }

            while !eof && self.wants_read() {
                match self.read_tls(io) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        rdlen += n;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            if let Err(e) = self.process_new_packets() {
                // Deliver any alert before reporting the failure.
                let _ignored = self.write_tls(io);
                let _ignored = io.flush();
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }

            // After close_notify the connection stops wanting to read, so
            // the transport would never be read again: treat it like EOF.
            // Likewise, a handshake that wants neither to read nor to write
            // cannot make progress, and looping would only spin.
            if self.has_received_close_notify
                || (until_handshaked
                    && self.is_handshaking()
                    && !self.wants_read()
                    && !self.wants_write())
            {
                eof = true;
            }

            match (eof, until_handshaked, self.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection during handshake",
                    ));
                }
                (false, true, true) => {}
            }
        }
    }
}

impl<Data> Deref for ConnectionCommon<Data> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common_state
    }
}

impl<Data> DerefMut for ConnectionCommon<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common_state
    }
}

impl<Data> From<ConnectionCore<Data>> for ConnectionCommon<Data> {
    fn from(core: ConnectionCore<Data>) -> Self {
        Self {
            core,
            deframer_buffer: DeframerVecBuffer::default(),
        }
    }
}

/// Reads plaintext received from the peer.
#[cfg(feature = "std")]
pub struct Reader<'a> {
    common: &'a mut CommonState,
}

#[cfg(feature = "std")]
impl Reader<'_> {
    fn check_no_bytes_state(&self) -> std::io::Result<()> {
        if self.common.has_received_close_notify {
            // Clean EOF: the peer closed the session.
            return Ok(());
        }
        if self.common.has_seen_eof {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed connection without sending TLS close_notify: \
                 https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
            ));
        }
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

#[cfg(feature = "std")]
impl std::io::Read for Reader<'_> {
    /// Returns `Ok(0)` only after the peer's `close_notify`; before that,
    /// `WouldBlock` means no plaintext is buffered yet and `UnexpectedEof`
    /// means the transport closed without a `close_notify`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.common.received_plaintext.read(buf);
        if len == 0 && !buf.is_empty() {
            self.check_no_bytes_state()?;
        }
        Ok(len)
    }
}

#[cfg(feature = "std")]
impl std::io::BufRead for Reader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.common.received_plaintext.is_empty() {
            self.check_no_bytes_state()?;
        }
        Ok(self.common.received_plaintext.chunk().unwrap_or(&[]))
    }

    fn consume(&mut self, amt: usize) {
        self.common.received_plaintext.consume(amt);
    }
}

#[cfg(feature = "std")]
impl Debug for Reader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Reader")
    }
}

/// Writes plaintext to send to the peer.
///
/// Before the handshake completes, writes are buffered (subject to the
/// buffer limit) and sent once it does.
#[cfg(feature = "std")]
pub struct Writer<'a> {
    sink: &'a mut (dyn PlaintextSink + Send + Sync),
}

/// Where a [`Writer`] puts plaintext.
#[cfg(feature = "std")]
trait PlaintextSink {
    fn write_plain(
        &mut self,
        payload: crate::msgs::message::OutboundChunks<'_>,
    ) -> std::io::Result<usize>;
}

#[cfg(feature = "std")]
impl<Data: SideData> PlaintextSink for ConnectionCore<Data> {
    fn write_plain(
        &mut self,
        payload: crate::msgs::message::OutboundChunks<'_>,
    ) -> std::io::Result<usize> {
        if self.common_state.encrypt_failed {
            return Err(std::io::Error::other("record encryption failed"));
        }
        let mut len = self
            .common_state
            .send_plain(payload, crate::common_state::Limit::Yes);
        // A write that reached the confidentiality limit rotates the key
        // right away, so later writes go out under the next key instead of
        // being refused (RFC 9846 §5.5). A write the record layer held back
        // for the refresh is retried once under the new key. Errors are left
        // for `process_new_packets` to report: the bytes taken are queued.
        if self.common_state.refresh_traffic_keys_pending {
            let _ = self.maybe_send_key_update();
            if len == 0 && !self.common_state.refresh_traffic_keys_pending {
                len = self
                    .common_state
                    .send_plain(payload, crate::common_state::Limit::Yes);
            }
        }
        Ok(len)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.write_plain(buf.into())
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let slices: alloc::vec::Vec<&[u8]> = bufs.iter().map(|s| &**s).collect();
        let chunks = crate::msgs::message::OutboundChunks::new(&slices);
        self.sink.write_plain(chunks)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Debug for Writer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Writer")
    }
}

impl<Data> Debug for ConnectionCommon<Data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectionCommon")
            .field("common", &self.core.common_state)
            .finish_non_exhaustive()
    }
}

/// A client or server connection.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum Connection {
    /// A client connection.
    Client(crate::client::ClientConnection),
    /// A server connection.
    Server(crate::server::ServerConnection),
}

#[cfg(feature = "std")]
impl Connection {
    /// See [`ConnectionCommon::read_tls`].
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        match self {
            Self::Client(conn) => conn.read_tls(rd),
            Self::Server(conn) => conn.read_tls(rd),
        }
    }

    /// See [`ConnectionCommon::write_tls`].
    pub fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        match self {
            Self::Client(conn) => conn.write_tls(wr),
            Self::Server(conn) => conn.write_tls(wr),
        }
    }

    /// See [`ConnectionCommon::reader`].
    pub fn reader(&mut self) -> Reader<'_> {
        match self {
            Self::Client(conn) => conn.reader(),
            Self::Server(conn) => conn.reader(),
        }
    }

    /// See [`ConnectionCommon::writer`].
    pub fn writer(&mut self) -> Writer<'_> {
        match self {
            Self::Client(conn) => conn.writer(),
            Self::Server(conn) => conn.writer(),
        }
    }

    /// See [`ConnectionCommon::process_new_packets`].
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        match self {
            Self::Client(conn) => conn.process_new_packets(),
            Self::Server(conn) => conn.process_new_packets(),
        }
    }

    /// See [`ConnectionCommon::export_keying_material`].
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        match self {
            Self::Client(conn) => conn.export_keying_material(output, label, context),
            Self::Server(conn) => conn.export_keying_material(output, label, context),
        }
    }

    /// See [`ConnectionCommon::export_early_keying_material`].
    pub fn export_early_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        match self {
            Self::Client(conn) => conn.export_early_keying_material(output, label, context),
            Self::Server(conn) => conn.export_early_keying_material(output, label, context),
        }
    }

    /// See [`ConnectionCommon::tls_exporter_channel_binding`].
    pub fn tls_exporter_channel_binding(&self) -> Result<[u8; 32], Error> {
        match self {
            Self::Client(conn) => conn.tls_exporter_channel_binding(),
            Self::Server(conn) => conn.tls_exporter_channel_binding(),
        }
    }

    /// See [`ConnectionCommon::complete_io`].
    pub fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), std::io::Error>
    where
        T: std::io::Read + std::io::Write,
    {
        match self {
            Self::Client(conn) => conn.complete_io(io),
            Self::Server(conn) => conn.complete_io(io),
        }
    }

    /// See [`ConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        match self {
            Self::Client(conn) => conn.dangerous_extract_secrets(),
            Self::Server(conn) => conn.dangerous_extract_secrets(),
        }
    }

    /// See [`ConnectionCommon::set_buffer_limit`].
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        match self {
            Self::Client(conn) => conn.set_buffer_limit(limit),
            Self::Server(conn) => conn.set_buffer_limit(limit),
        }
    }

    /// See [`ConnectionCommon::refresh_traffic_keys`].
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        match self {
            Self::Client(conn) => conn.refresh_traffic_keys(),
            Self::Server(conn) => conn.refresh_traffic_keys(),
        }
    }
}

#[cfg(feature = "std")]
impl Deref for Connection {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}

#[cfg(feature = "std")]
impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}
