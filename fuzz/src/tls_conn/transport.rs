//! In-memory transports of the `tls_conn` target and the stream adapters
//! (`Stream`, `StreamOwned`) driven over them.

use std::io::{IoSlice, Read, Write};

use browntls_core::{ConnectionCommon, SideData, Stream, StreamOwned};

use crate::input::Input;

// ------------------------------------------------------------- transports

/// An in-memory transport for one side: reads what the peer wrote, writes
/// toward the peer, in chunks of at most the given sizes.
pub(super) struct Pipe<'a> {
    pub(super) inbound: &'a mut Vec<u8>,
    pub(super) outbound: &'a mut Vec<u8>,
    pub(super) read_chunk: usize,
    pub(super) write_chunk: usize,
    /// When nothing is left: `WouldBlock` rather than end of file.
    pub(super) would_block: bool,
}

impl Read for Pipe<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inbound.is_empty() && !buf.is_empty() {
            return if self.would_block {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else {
                Ok(0)
            };
        }
        let n = buf.len().min(self.read_chunk).min(self.inbound.len());
        buf[..n].copy_from_slice(&self.inbound[..n]);
        self.inbound.drain(..n);
        Ok(n)
    }
}

impl Write for Pipe<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.write_chunk);
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink that takes at most `limit` bytes per call (zero included).
pub(super) struct Limited<'a>(pub(super) &'a mut Vec<u8>, pub(super) usize);

impl Write for Limited<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.1);
        self.0.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A chunk size from a byte: 1 to 4096, small values likely.
pub(super) fn chunk(byte: u8) -> usize {
    match byte {
        0 => 4096,
        1..=127 => usize::from(byte),
        _ => usize::from(byte - 127) * 32,
    }
}

/// How a [`Pipe`] behaves.
#[derive(Clone, Copy)]
pub(super) struct PipeArgs {
    pub(super) read: usize,
    pub(super) write: usize,
    pub(super) would_block: bool,
}

impl PipeArgs {
    pub(super) fn read(input: &mut Input<'_>) -> Self {
        Self {
            read: chunk(input.byte()),
            write: chunk(input.byte()),
            would_block: input.bool(),
        }
    }
}

/// One action on a stream adapter; returns the connection.
pub(super) fn stream_action<C, S>(
    mut conn: C,
    mut pipe: Pipe<'_>,
    owned: bool,
    action: u8,
    data: &[u8],
    sent: &mut Vec<u8>,
    recv: &mut Vec<u8>,
) -> C
where
    C: std::ops::DerefMut + std::ops::Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn act<T: Read + Write>(
        stream: &mut T,
        action: u8,
        data: &[u8],
        sent: &mut Vec<u8>,
        recv: &mut Vec<u8>,
    ) {
        match action % 4 {
            0 => {
                if let Ok(n) = stream.write(data) {
                    sent.extend_from_slice(&data[..n]);
                }
            }
            1 => {
                let mut buf = vec![0u8; data.len().max(1)];
                if let Ok(n) = stream.read(&mut buf) {
                    recv.extend_from_slice(&buf[..n]);
                }
            }
            2 => {
                let mid = usize::from(action >> 2).min(data.len());
                let (a, b) = data.split_at(mid);
                if let Ok(n) = stream.write_vectored(&[IoSlice::new(a), IoSlice::new(b)]) {
                    sent.extend_from_slice(&data[..n]);
                }
            }
            _ => {
                let _ = stream.flush();
            }
        }
    }

    if owned {
        let mut stream = StreamOwned::new(conn, pipe);
        let read_chunk = stream.get_ref().read_chunk;
        stream.get_mut().read_chunk = read_chunk.max(1);
        act(&mut stream, action, data, sent, recv);
        let (conn, _pipe) = stream.into_parts();
        conn
    } else {
        let mut stream = Stream::new(&mut conn, &mut pipe);
        if action & 0x80 != 0 {
            let _ = stream.complete_prior_io();
        } else {
            act(&mut stream, action, data, sent, recv);
        }
        conn
    }
}
