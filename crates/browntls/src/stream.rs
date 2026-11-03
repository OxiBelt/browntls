//! Blocking `Read`/`Write` adapters over a connection and a transport.

use core::ops::{Deref, DerefMut};
use std::io::{IoSlice, Read, Result, Write};

use crate::conn::{ConnectionCommon, SideData};

/// A TLS stream borrowing a connection and a socket.
///
/// Reads and writes block on the socket as needed to complete the handshake
/// and move records.
#[derive(Debug)]
pub struct Stream<'a, C: 'a + ?Sized, T: 'a + Read + Write + ?Sized> {
    /// The connection.
    pub conn: &'a mut C,
    /// The transport.
    pub sock: &'a mut T,
}

impl<'a, C, T, S> Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    /// Pairs `conn` with `sock`.
    pub fn new(conn: &'a mut C, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }

    /// Drives the handshake to completion, blocking on the socket.
    pub fn complete_prior_io(&mut self) -> Result<()> {
        if self.conn.is_handshaking() {
            self.conn.complete_io(self.sock)?;
        }
        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }
        Ok(())
    }
}

impl<'a, C, T, S> Read for Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.complete_prior_io()?;
        // Fetch records until plaintext is available or the peer closes.
        while self.conn.wants_read() {
            let at_eof = self.conn.complete_io(self.sock)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.conn.process_new_packets()
                    && at_eof
                    && io_state.plaintext_bytes_to_read() == 0
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection without sending TLS close_notify",
                    ));
                }
                break;
            }
        }
        self.conn.reader().read(buf)
    }
}

impl<'a, C, T, S> Write for Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;
        let len = self.conn.writer().write(buf)?;
        // Try to write the record out; ignore WouldBlock, the caller will
        // flush or write again.
        let _ = self.conn.complete_io(self.sock);
        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        self.complete_prior_io()?;
        let len = self.conn.writer().write_vectored(bufs)?;
        let _ = self.conn.complete_io(self.sock);
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;
        self.conn.writer().flush()?;
        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }
        Ok(())
    }
}

/// A TLS stream owning its connection and socket.
#[derive(Debug)]
pub struct StreamOwned<C: Sized, T: Read + Write + Sized> {
    /// The connection.
    pub conn: C,
    /// The transport.
    pub sock: T,
}

impl<C, T, S> StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    /// Pairs `conn` with `sock`.
    pub fn new(conn: C, sock: T) -> Self {
        Self { conn, sock }
    }

    /// The transport.
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// The transport, mutably.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }

    /// Splits back into the connection and the transport.
    pub fn into_parts(self) -> (C, T) {
        (self.conn, self.sock)
    }

    fn as_stream(&mut self) -> Stream<'_, C, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T, S> Read for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, T, S> Write for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.as_stream().flush()
    }
}
