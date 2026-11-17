//! A queue of byte chunks with an optional total-size limit.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Buffered bytes awaiting the application or the transport.
#[derive(Default, Debug)]
pub(crate) struct ChunkVecBuffer {
    chunks: VecDeque<Chunk>,
    limit: Option<usize>,
    /// Bytes of chunks appended with [`Self::append_control`] not yet taken
    /// out of the queue.
    control_len: usize,
}

/// One queued chunk, and whether it holds control records (anything but
/// application data) rather than data the application wrote.
#[derive(Debug)]
struct Chunk {
    bytes: Vec<u8>,
    control: bool,
}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            limit,
            control_len: 0,
        }
    }

    /// Sets the limit; existing contents are unaffected.
    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// The limit, if any.
    pub(crate) fn limit(&self) -> Option<usize> {
        self.limit
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.limit.is_some_and(|limit| self.len() > limit)
    }

    /// Total bytes buffered.
    pub(crate) fn len(&self) -> usize {
        self.chunks.iter().map(|c| c.bytes.len()).sum()
    }

    /// Bytes buffered by [`Self::append_control`] and not yet taken out.
    pub(crate) fn control_len(&self) -> usize {
        self.control_len
    }

    /// Appends as much of `bytes` as the limit allows; returns how many were taken.
    pub(crate) fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        if take > 0 {
            self.push(bytes[..take].to_vec(), false);
        }
        take
    }

    /// Appends `bytes` unconditionally.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        self.push(bytes, false)
    }

    /// Appends `bytes` unconditionally and counts them as control bytes
    /// until they are taken out of the queue.
    pub(crate) fn append_control(&mut self, bytes: Vec<u8>) -> usize {
        self.push(bytes, true)
    }

    fn push(&mut self, bytes: Vec<u8>, control: bool) -> usize {
        let len = bytes.len();
        if !bytes.is_empty() {
            if control {
                self.control_len += len;
            }
            self.chunks.push_back(Chunk { bytes, control });
        }
        len
    }

    /// Puts `bytes` back at the front of the queue (undoing a `pop`).
    pub(crate) fn prepend(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.chunks.push_front(Chunk {
                bytes,
                control: false,
            });
        }
    }

    /// Removes and returns the first chunk.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        let chunk = self.chunks.pop_front()?;
        if chunk.control {
            self.control_len -= chunk.bytes.len();
        }
        Some(chunk.bytes)
    }

    /// Copies up to `buf.len()` bytes out of the queue.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        while offset < buf.len() {
            let Some(front) = self.chunks.front() else {
                break;
            };
            let take = front.bytes.len().min(buf.len() - offset);
            buf[offset..offset + take].copy_from_slice(&front.bytes[..take]);
            offset += take;
            self.consume_front(take);
        }
        offset
    }

    /// The first chunk without removing it.
    pub(crate) fn chunk(&self) -> Option<&[u8]> {
        self.chunks.front().map(|c| c.bytes.as_slice())
    }

    /// Drops `used` bytes from the front.
    pub(crate) fn consume(&mut self, mut used: usize) {
        while used > 0 {
            let Some(front) = self.chunks.front() else {
                return;
            };
            let take = used.min(front.bytes.len());
            used -= take;
            self.consume_front(take);
        }
    }

    /// Drops `take` bytes, at most the whole chunk, from the first chunk.
    fn consume_front(&mut self, take: usize) {
        let Some(front) = self.chunks.front_mut() else {
            return;
        };
        if front.control {
            self.control_len -= take;
        }
        if take >= front.bytes.len() {
            self.chunks.pop_front();
        } else {
            front.bytes.drain(..take);
        }
    }

    /// How many of `len` bytes may be appended under the limit.
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        match self.limit {
            Some(limit) => len.min(limit.saturating_sub(self.len())),
            None => len,
        }
    }

    /// Writes as much as possible to `wr` in one call.
    #[cfg(feature = "std")]
    pub(crate) fn write_to(&mut self, wr: &mut dyn std::io::Write) -> std::io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }
        let bufs: Vec<std::io::IoSlice<'_>> = self
            .chunks
            .iter()
            .take(64)
            .map(|c| std::io::IoSlice::new(&c.bytes))
            .collect();
        let used = wr.write_vectored(&bufs)?;
        self.consume(used);
        Ok(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_read_consume() {
        let mut b = ChunkVecBuffer::new(Some(5));
        assert_eq!(b.append_limited_copy(&[1, 2, 3]), 3);
        assert_eq!(b.append_limited_copy(&[4, 5, 6, 7]), 2);
        assert_eq!(b.append_limited_copy(&[8]), 0);
        assert_eq!(b.len(), 5);
        assert!(!b.is_full());
        let mut out = [0u8; 4];
        assert_eq!(b.read(&mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(b.len(), 1);
        b.append(alloc::vec![9, 9]);
        assert_eq!(b.chunk(), Some(&[5u8][..]));
        b.consume(2);
        assert_eq!(b.chunk(), Some(&[9u8][..]));
        b.consume(10);
        assert!(b.is_empty());
        assert!(b.pop().is_none());
        b.set_limit(None);
        assert_eq!(b.append_limited_copy(&[0; 100]), 100);
    }

    #[test]
    fn control_bytes_are_counted_until_taken_out() {
        let mut b = ChunkVecBuffer::new(Some(4));
        b.append(alloc::vec![1, 2, 3]);
        assert_eq!(b.append_control(alloc::vec![4, 5, 6, 7, 8]), 5);
        b.append(alloc::vec![9]);
        b.append_control(Vec::new());
        assert_eq!((b.len(), b.control_len()), (9, 5));
        // Data ahead of the control chunk leaves its count alone.
        b.consume(2);
        assert_eq!(b.control_len(), 5);
        // A partial take of the control chunk counts what it took.
        let mut out = [0u8; 3];
        assert_eq!(b.read(&mut out), 3);
        assert_eq!(out, [3, 4, 5]);
        assert_eq!(b.control_len(), 3);
        b.consume(3);
        assert_eq!((b.len(), b.control_len()), (1, 0));
        b.append_control(alloc::vec![10, 11]);
        assert_eq!(b.pop(), Some(alloc::vec![9]));
        assert_eq!(b.control_len(), 2);
        assert_eq!(b.pop(), Some(alloc::vec![10, 11]));
        assert_eq!(b.control_len(), 0);
        b.prepend(alloc::vec![12]);
        assert_eq!(b.control_len(), 0);
        assert_eq!(b.limit(), Some(4));
    }

    #[cfg(feature = "std")]
    #[test]
    fn write_to_consumes_written() {
        let mut b = ChunkVecBuffer::new(None);
        b.append(alloc::vec![1, 2]);
        b.append(alloc::vec![3]);
        let mut sink = Vec::new();
        assert_eq!(b.write_to(&mut sink).unwrap(), 3);
        assert_eq!(sink, [1, 2, 3]);
        assert!(b.is_empty());
        assert_eq!(b.write_to(&mut sink).unwrap(), 0);
    }
}
