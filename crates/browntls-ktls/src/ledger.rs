//! What the kernel was given to send, set against what TCP has taken.
//!
//! On a non-blocking socket Linux reports a write as done once the record
//! is encrypted, even when TCP had no room for all of it, and sends the
//! rest later, from a work item, when room appears. Nothing reports that
//! work, but two counters the kernel does keep tell how far it has come:
//! the transmit record sequence number (`TLS_TX`, read back) counts the
//! records made, and TCP counts the bytes it has taken (acknowledged plus
//! held). The stream knows the plaintext it handed over; every record adds
//! a fixed number of bytes to its plaintext; so what the records come to on
//! the wire, less what TCP has taken since the handover, is what the kernel
//! still holds.

use std::io;
use std::os::fd::BorrowedFd;

use crate::crypto_info::{CIPHER_CHACHA20_POLY1305, CryptoInfo};
use crate::sys;

/// How often TCP's counters are read to catch them at rest: an
/// acknowledgement arriving in between spoils a reading.
const STEADY_READS: usize = 16;

/// Records the kernel has made and not yet given to TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Backlog {
    /// Their bytes on the wire. May be reported higher than it is when
    /// acknowledgements kept arriving while it was read, never lower.
    pub(crate) unsent: u64,
    /// Whether TCP holds bytes the peer has not acknowledged: an
    /// acknowledgement will come and make the kernel send more.
    pub(crate) in_flight: bool,
}

#[derive(Debug)]
pub(crate) struct Ledger {
    /// The length of the cipher's `tls12_crypto_info_*`, to read the
    /// kernel's record sequence number with.
    info_len: usize,
    /// What a record adds to its plaintext on the wire.
    overhead: u64,
    /// TCP's count of bytes taken when the transmit keys were installed.
    baseline: u64,
    /// Plaintext given to the kernel since.
    plaintext: u64,
    /// Records made under earlier transmit keys.
    earlier_records: u64,
    /// The sequence number the current keys started with.
    first_seq: u64,
}

impl Ledger {
    /// Opens the ledger on a socket whose transmit keys `info`, starting
    /// at sequence number `seq`, were just installed, before anything is
    /// sent with them.
    pub(crate) fn open(fd: BorrowedFd<'_>, info: &CryptoInfo, seq: u64) -> io::Result<Self> {
        // Nothing is being written, so TCP's count stands still; only the
        // split between acknowledged and held bytes moves. A reading that
        // is not exact would leave the ledger off for good.
        let output = tcp_output(fd)?;
        if !output.steady {
            return Err(io::Error::other("TCP's counters did not come to rest"));
        }
        let baseline = output.taken;
        let ledger = Self {
            info_len: info.as_bytes().len(),
            overhead: record_overhead(info),
            baseline,
            plaintext: 0,
            earlier_records: 0,
            first_seq: seq,
        };
        // The kernel must report the number the keys were installed with.
        if ledger.records_made(fd)? != 0 {
            return Err(mismatch());
        }
        Ok(ledger)
    }

    /// Counts plaintext the kernel accepted, as application data or as a
    /// control record.
    pub(crate) fn sent(&mut self, plaintext: usize) {
        self.plaintext = self
            .plaintext
            .saturating_add(u64::try_from(plaintext).unwrap_or(u64::MAX));
    }

    /// How many records the kernel has made under the current transmit
    /// keys.
    pub(crate) fn records_made(&self, fd: BorrowedFd<'_>) -> io::Result<u64> {
        sys::tx_record_seq(fd, self.info_len)?
            .checked_sub(self.first_seq)
            .ok_or_else(mismatch)
    }

    /// New transmit keys were installed, with sequence number zero, after
    /// the old ones had made `made` records.
    pub(crate) fn rekeyed(&mut self, made: u64) {
        self.earlier_records = self.earlier_records.saturating_add(made);
        self.first_seq = 0;
    }

    /// What the kernel holds of the records it has made.
    pub(crate) fn backlog(&self, fd: BorrowedFd<'_>) -> io::Result<Backlog> {
        // Records first: the kernel goes on sending in between, which can
        // only lower what is left.
        let records = self.records_made(fd)?;
        let output = tcp_output(fd)?;
        let expected = records
            .checked_add(self.earlier_records)
            .and_then(|records| records.checked_mul(self.overhead))
            .and_then(|overhead| overhead.checked_add(self.plaintext));
        let taken = output.taken.checked_sub(self.baseline);
        match (expected, taken) {
            (Some(expected), Some(taken)) if taken <= expected => Ok(Backlog {
                unsent: expected - taken,
                in_flight: output.in_flight,
            }),
            _ => Err(mismatch()),
        }
    }
}

/// TCP's counters, read again while acknowledgements spoil the reading; in
/// the end the last reading, whose count is then a lower bound.
fn tcp_output(fd: BorrowedFd<'_>) -> io::Result<sys::TcpOutput> {
    let mut output = sys::tcp_output(fd)?;
    for _ in 1..STEADY_READS {
        if output.steady {
            break;
        }
        output = sys::tcp_output(fd)?;
    }
    Ok(output)
}

/// The bytes a record adds to its plaintext on the wire.
///
/// TLS 1.3: the five-byte header, the content type byte and the 16-byte
/// tag (the kernel adds no padding). TLS 1.2: the header and the tag, and
/// for AES-GCM the eight-byte explicit nonce (RFC 5288); ChaCha20-Poly1305
/// has none (RFC 7905).
fn record_overhead(info: &CryptoInfo) -> u64 {
    let bytes = info.as_bytes();
    let tls13 = bytes.get(..2) == Some(&0x0304u16.to_ne_bytes()[..]);
    if tls13 {
        5 + 1 + 16
    } else if info.cipher_type() == CIPHER_CHACHA20_POLY1305 {
        5 + 16
    } else {
        5 + 8 + 16
    }
}

fn mismatch() -> io::Error {
    io::Error::other("the kernel's send counters do not match what the stream sent")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsFd;

    use browntls::crypto::cipher::{AeadKey, Iv};
    use browntls::{ConnectionTrafficSecrets, ProtocolVersion};

    use super::*;

    #[test]
    fn overhead_follows_version_and_cipher() {
        let iv = || Iv::new([0; 12]);
        let gcm = ConnectionTrafficSecrets::Aes128Gcm {
            key: AeadKey::new(&[0; 16]),
            iv: iv(),
        };
        let gcm256 = ConnectionTrafficSecrets::Aes256Gcm {
            key: AeadKey::new(&[0; 32]),
            iv: iv(),
        };
        let ccm = ConnectionTrafficSecrets::Aes128Ccm {
            key: AeadKey::new(&[0; 16]),
            iv: iv(),
        };
        let chacha = ConnectionTrafficSecrets::Chacha20Poly1305 {
            key: AeadKey::new(&[0; 32]),
            iv: iv(),
        };
        let overhead =
            |version, secrets| record_overhead(&CryptoInfo::new(version, secrets, 0).unwrap());
        for secrets in [&gcm, &gcm256, &ccm, &chacha] {
            assert_eq!(overhead(ProtocolVersion::TLSv1_3, secrets), 22);
        }
        assert_eq!(overhead(ProtocolVersion::TLSv1_2, &gcm), 29);
        assert_eq!(overhead(ProtocolVersion::TLSv1_2, &gcm256), 29);
        assert_eq!(overhead(ProtocolVersion::TLSv1_2, &chacha), 21);
    }

    /// TCP's count of bytes taken, on plain TCP: it grows by exactly what
    /// is written, whether the peer has read (and acknowledged) it or not.
    #[test]
    fn tcp_counts_every_byte_it_takes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();

        let steady = |socket: &TcpStream| {
            let output = tcp_output(socket.as_fd()).unwrap();
            assert!(output.steady);
            output
        };
        let start = steady(&sender);
        assert!(!start.in_flight);

        sender.write_all(&[7u8; 3000]).unwrap();
        // Unread by the peer: taken all the same.
        assert_eq!(steady(&sender).taken - start.taken, 3000);

        let mut got = [0u8; 3000];
        receiver.read_exact(&mut got).unwrap();
        sender.write_all(&[8u8; 1234]).unwrap();
        receiver.read_exact(&mut got[..1234]).unwrap();
        // Acknowledged in the end; the sum never changed on the way.
        let mut output = steady(&sender);
        for _ in 0..500 {
            assert_eq!(output.taken - start.taken, 4234);
            if !output.in_flight {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            output = steady(&sender);
        }
        assert!(!output.in_flight, "the peer did not acknowledge");

        // What the peer sends is not counted here.
        receiver.write_all(b"back").unwrap();
        sender.read_exact(&mut got[..4]).unwrap();
        assert_eq!(steady(&sender).taken - start.taken, 4234);
    }
}
