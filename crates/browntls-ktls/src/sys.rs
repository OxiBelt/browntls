//! The system calls of Linux kernel TLS: the crate's only `unsafe` code.
//!
//! Exception to the workspace's `unsafe_code = "deny"` (CONTRIBUTING.md,
//! "Security requirements"): the socket options and the `sendmsg`/`recvmsg`
//! control messages of kernel TLS have no safe wrapper in the standard
//! library, nor has asking the kernel whether a socket has room to send
//! (`poll`), how many bytes TCP holds unacknowledged (`ioctl`), which
//! release it is (`uname`), or sending a file's pages without reading them
//! into userspace (`sendfile`, with `fstat` for the file's length and the
//! thread's signal mask to hold `SIGPIPE` back). Every function here keeps
//! these invariants:
//!
//! * every descriptor is a [`BorrowedFd`], open for the whole call;
//! * every pointer passed to the kernel or to libc points into a live Rust
//!   value (slice, `iovec`, `msghdr`, control buffer, `utsname`, `stat`,
//!   signal set, `timespec`, or one integer such as `sendfile`'s offset)
//!   that outlives the call, with its length given next to it where the
//!   call takes one, and only values borrowed mutably here are written;
//!   a null pointer is passed only where the call takes one to mean that
//!   it shall return nothing there (`sigtimedwait`, `pthread_sigmask`);
//! * control messages are built and read only through the libc `CMSG_*`
//!   functions, within a buffer aligned for `cmsghdr` and sized with
//!   `CMSG_SPACE`, and a received control message is read only when its
//!   `cmsg_len` covers the byte read;
//! * no Rust value is created from kernel output except plain integers and
//!   bytes copied out of buffers the kernel wrote, within the length it
//!   reported;
//! * a buffer the kernel wrote key material into (`TLS_TX` read back) is
//!   wiped before the function returns;
//! * the descriptors' flags are never changed;
//! * no signal's disposition is changed, and the calling thread's signal
//!   mask is changed only to hold `SIGPIPE` back for as long as a
//!   [`HeldSigpipe`] lives (the length of a `sendfile`, or of the close of
//!   a socket that sent files), after which the mask is what it was
//!   before. Only a `SIGPIPE` that became pending in that time is taken.

#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

use libc::{c_int, c_void};

/// `TLS_TX` (`include/uapi/linux/tls.h`).
const TLS_TX: c_int = 1;
/// `TLS_RX`.
const TLS_RX: c_int = 2;
/// `TLS_TX_ZEROCOPY_RO` (Linux 5.19).
const TLS_TX_ZEROCOPY_RO: c_int = 3;
/// `TLS_RX_EXPECT_NO_PAD` (Linux 6.0).
const TLS_RX_EXPECT_NO_PAD: c_int = 4;
/// `TLS_TX_MAX_PAYLOAD_LEN` (Linux 6.19).
const TLS_TX_MAX_PAYLOAD_LEN: c_int = 5;
/// `TLS_SET_RECORD_TYPE`: the control message giving a sent record's type.
const TLS_SET_RECORD_TYPE: c_int = 1;
/// `TLS_GET_RECORD_TYPE`: the control message giving a received record's type.
const TLS_GET_RECORD_TYPE: c_int = 2;

/// A control message buffer, aligned for `cmsghdr`, large enough for one
/// one-byte control message on every Linux target (`CMSG_SPACE(1)` is at
/// most 24 bytes).
#[repr(C, align(8))]
struct ControlBuffer([u8; 32]);

/// `CMSG_SPACE(1)`: the control buffer length for one record type byte.
fn cmsg_space() -> usize {
    // SAFETY: `CMSG_SPACE` is pure arithmetic on its argument.
    let space = unsafe { libc::CMSG_SPACE(1) };
    space as usize
}

/// `CMSG_LEN(1)`: the `cmsg_len` of a control message with one data byte.
fn cmsg_len() -> usize {
    // SAFETY: `CMSG_LEN` is pure arithmetic on its argument.
    let len = unsafe { libc::CMSG_LEN(1) };
    len as usize
}

fn setsockopt(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: &[u8]) -> io::Result<()> {
    let len = libc::socklen_t::try_from(value.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    loop {
        // SAFETY: `value` is a live slice of `len` bytes, which the kernel
        // only reads during the call; `fd` is open for the call.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                value.as_ptr().cast::<c_void>(),
                len,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        // Kernel TLS takes the socket lock interruptibly.
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Reads a socket option into `value`; returns the length the kernel wrote.
fn getsockopt(
    fd: BorrowedFd<'_>,
    level: c_int,
    name: c_int,
    value: &mut [u8],
) -> io::Result<usize> {
    let mut len = libc::socklen_t::try_from(value.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `value` is a live, writable slice of `len` bytes and `len` a
    // live integer, which the kernel writes during the call only (at most
    // `len` bytes into `value`); `fd` is open for the call.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            value.as_mut_ptr().cast::<c_void>(),
            &mut len,
        )
    };
    if rc == 0 {
        Ok((len as usize).min(value.len()))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Attaches the `tls` upper layer protocol to a connected TCP socket.
///
/// Succeeds when the socket already has it (an earlier, refused handover).
pub(crate) fn set_ulp_tls(fd: BorrowedFd<'_>) -> io::Result<()> {
    match setsockopt(fd, libc::SOL_TCP, libc::TCP_ULP, b"tls") {
        Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
            let mut name = [0u8; 16];
            let len = getsockopt(fd, libc::SOL_TCP, libc::TCP_ULP, &mut name)?;
            let name = name[..len].split(|&b| b == 0).next().unwrap_or_default();
            if name == b"tls" { Ok(()) } else { Err(err) }
        }
        other => other,
    }
}

/// Whether the kernel knows `TLS_TX_MAX_PAYLOAD_LEN` (Linux 6.19), asked
/// after the upper layer protocol is attached and before any key is set.
pub(crate) fn has_tx_max_payload_len(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut value = [0u8; 2];
    match getsockopt(fd, libc::SOL_TLS, TLS_TX_MAX_PAYLOAD_LEN, &mut value) {
        Ok(_) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::ENOPROTOOPT) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Installs a `tls12_crypto_info_*` value for transmission or reception.
pub(crate) fn set_crypto_info(fd: BorrowedFd<'_>, receive: bool, info: &[u8]) -> io::Result<()> {
    let name = if receive { TLS_RX } else { TLS_TX };
    setsockopt(fd, libc::SOL_TLS, name, info)
}

/// Limits the plaintext of each transmitted record (`TLS_TX_MAX_PAYLOAD_LEN`).
pub(crate) fn set_tx_max_payload_len(fd: BorrowedFd<'_>, len: u16) -> io::Result<()> {
    setsockopt(
        fd,
        libc::SOL_TLS,
        TLS_TX_MAX_PAYLOAD_LEN,
        &len.to_ne_bytes(),
    )
}

/// Sets a kernel TLS option whose value is one `int`, zero or one.
fn set_flag(fd: BorrowedFd<'_>, name: c_int, on: bool) -> io::Result<()> {
    setsockopt(fd, libc::SOL_TLS, name, &c_int::from(on).to_ne_bytes())
}

/// Reads a kernel TLS option whose value is one `int`, zero or one.
fn flag(fd: BorrowedFd<'_>, name: c_int) -> io::Result<bool> {
    let mut value = [0u8; size_of::<c_int>()];
    let len = getsockopt(fd, libc::SOL_TLS, name, &mut value)?;
    if len != value.len() {
        return Err(io::Error::other("kernel TLS returned another value"));
    }
    Ok(c_int::from_ne_bytes(value) != 0)
}

/// `TLS_TX_ZEROCOPY_RO`: whether a network device that encrypts the
/// records itself is given the pages of a `sendfile` without a copy.
pub(crate) fn set_tx_zerocopy_ro(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
    set_flag(fd, TLS_TX_ZEROCOPY_RO, on)
}

/// Reads `TLS_TX_ZEROCOPY_RO`.
pub(crate) fn tx_zerocopy_ro(fd: BorrowedFd<'_>) -> io::Result<bool> {
    flag(fd, TLS_TX_ZEROCOPY_RO)
}

/// `TLS_RX_EXPECT_NO_PAD`: whether the kernel takes the peer's TLS 1.3
/// records to be unpadded and decrypts them into the reader's buffer.
/// The receive keys must be installed.
pub(crate) fn set_rx_expect_no_pad(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
    set_flag(fd, TLS_RX_EXPECT_NO_PAD, on)
}

/// Reads `TLS_RX_EXPECT_NO_PAD`.
pub(crate) fn rx_expect_no_pad(fd: BorrowedFd<'_>) -> io::Result<bool> {
    flag(fd, TLS_RX_EXPECT_NO_PAD)
}

/// The running kernel's release as `uname` gives it (`7.2.0-12-generic`,
/// for example).
pub(crate) fn kernel_release() -> io::Result<Vec<u8>> {
    // SAFETY: `utsname` is a struct of character arrays, for which all
    // zero bytes are a valid value.
    let mut name: libc::utsname = unsafe { mem::zeroed() };
    // SAFETY: `name` is a live `utsname`, which the kernel writes within
    // during the call only.
    let rc = unsafe { libc::uname(&mut name) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(name
        .release
        .iter()
        .map(|c| c.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
        .collect())
}

/// One `sendmsg` of `payload` with a `TLS_SET_RECORD_TYPE` control message.
fn sendmsg_record(fd: BorrowedFd<'_>, typ: u8, payload: &[u8]) -> io::Result<usize> {
    let mut control = ControlBuffer([0; 32]);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast::<c_void>(),
        iov_len: payload.len(),
    };
    // SAFETY: every field of `msghdr` is an integer or a raw pointer, for
    // which all-zero bytes are a valid value (null pointers, zero lengths).
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = cmsg_space() as _;

    // SAFETY: `msg` describes `control`, which is aligned for `cmsghdr` and
    // at least `CMSG_SPACE(1)` bytes long, so the first header fits.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("no room for the record type"));
    }
    // SAFETY: `cmsg` points to the start of `control`, aligned and large
    // enough for a `cmsghdr` (checked non-null above), whose zeroed bytes
    // are a valid `cmsghdr` (integers only); nothing else references
    // `control` while this borrow lives.
    let header = unsafe { &mut *cmsg };
    header.cmsg_len = cmsg_len() as _;
    header.cmsg_level = libc::SOL_TLS;
    header.cmsg_type = TLS_SET_RECORD_TYPE;
    // SAFETY: `CMSG_DATA` of a header inside `control` points after the
    // header; `CMSG_SPACE(1)` reserved at least one byte there.
    let data = unsafe { libc::CMSG_DATA(cmsg) };
    // SAFETY: `data` points to the reserved byte inside `control`.
    unsafe { data.write(typ) };

    // SAFETY: `msg` points to `iov` (which points to `payload`) and to
    // `control`, all alive until the call returns; the kernel only reads
    // them; `fd` is open for the call.
    let sent = unsafe { libc::sendmsg(fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

/// Sends `payload` as one record of type `typ`, completely.
///
/// For one record within the transmit payload limit the kernel takes all
/// of it or, with no room (a non-blocking socket), none of it
/// (`WouldBlock`); the caller then keeps the record and tries again. A
/// partial send is reported as an error.
pub(crate) fn send_record(fd: BorrowedFd<'_>, typ: u8, payload: &[u8]) -> io::Result<()> {
    loop {
        match sendmsg_record(fd, typ, payload) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Ok(sent) if sent != payload.len() => {
                return Err(io::Error::other("the kernel took part of a control record"));
            }
            other => return other.map(|_| ()),
        }
    }
}

/// What the kernel reports about sending on a socket right now.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sendable {
    /// Room to send (`POLLOUT`).
    pub(crate) room: bool,
    /// `POLLERR`: an error is pending on the socket, or its error queue
    /// holds something (timestamps, zero-copy notices), which says
    /// nothing about the connection.
    pub(crate) error: bool,
    /// `POLLHUP`: both directions of the connection are over.
    pub(crate) hung_up: bool,
}

/// Whether the socket has room to send right now, as the kernel reports it
/// (`poll` with no timeout, so it never waits).
#[cfg(feature = "tokio")]
pub(crate) fn sendable(fd: BorrowedFd<'_>) -> io::Result<Sendable> {
    let mut entry = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        // SAFETY: `entry` is one live `pollfd` and the count given is one;
        // the kernel writes only its `revents`. `fd` is open for the call.
        let rc = unsafe { libc::poll(&mut entry, 1, 0) };
        if rc >= 0 {
            return Ok(Sendable {
                room: entry.revents & libc::POLLOUT != 0,
                error: entry.revents & libc::POLLERR != 0,
                hung_up: entry.revents & libc::POLLHUP != 0,
            });
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// The record sequence number the kernel will give the next record it
/// makes for transmission: read back with `TLS_TX`, which wants the whole
/// `tls12_crypto_info_*` structure of the cipher (`info_len` bytes) and
/// ends it with the number.
///
/// The kernel fills in the key as well; the buffer is wiped before this
/// returns, whatever the outcome.
pub(crate) fn tx_record_seq(fd: BorrowedFd<'_>, info_len: usize) -> io::Result<u64> {
    let mut info = [0u8; crate::crypto_info::MAX_LEN];
    let result = match info.get_mut(..info_len) {
        Some(value) if info_len >= 12 => {
            getsockopt(fd, libc::SOL_TLS, TLS_TX, value).and_then(|len| {
                let seq = value.last_chunk::<8>().filter(|_| len == info_len);
                seq.map(|seq| u64::from_be_bytes(*seq))
                    .ok_or_else(|| io::Error::other("kernel TLS returned another structure"))
            })
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    };
    info.fill(0);
    // Keeps the wipe from being removed as a dead store.
    core::hint::black_box(&mut info);
    result
}

/// Where `tcpi_bytes_acked` (a native-endian `u64`) lies in `struct
/// tcp_info` (`include/uapi/linux/tcp.h`, Linux 4.1): after eight bytes of
/// small fields, twenty-four `u32`s and two `u64`s, on every architecture.
const TCP_INFO_BYTES_ACKED: usize = 120;

/// `tcpi_bytes_acked`: the bytes of this socket's output the peer has
/// acknowledged since the connection began.
fn tcp_bytes_acked(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut info = [0u8; TCP_INFO_BYTES_ACKED + 8];
    let len = getsockopt(fd, libc::SOL_TCP, libc::TCP_INFO, &mut info)?;
    match info.last_chunk::<8>() {
        Some(acked) if len == info.len() => Ok(u64::from_ne_bytes(*acked)),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_INFO does not report the acknowledged bytes",
        )),
    }
}

/// `SIOCOUTQ`: the bytes TCP holds for this socket that the peer has not
/// acknowledged, sent or not.
fn tcp_bytes_unacked(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut queued: c_int = 0;
    // SAFETY: `SIOCOUTQ` (the value of `TIOCOUTQ`) writes one `int` through
    // the pointer, which points to a live, writable `c_int`, during the
    // call only; `fd` is open for the call.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCOUTQ, &mut queued as *mut c_int) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(queued).map_err(|_| io::Error::other("TCP reported a negative queue length"))
}

/// How far TCP has come with what the socket was given to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpOutput {
    /// Bytes TCP has taken since the connection began (a SYN counts as
    /// one), acknowledged or not. Never more than it has really taken;
    /// exactly that when `steady`.
    pub(crate) taken: u64,
    /// Whether TCP holds bytes the peer has not acknowledged.
    pub(crate) in_flight: bool,
    /// No acknowledgement arrived while the two counters were read, so
    /// `taken` is exact.
    pub(crate) steady: bool,
}

/// Reads how many bytes TCP has taken from the socket's sender: the
/// acknowledged ones plus the ones it still holds.
///
/// The two counters come from two calls. The acknowledged count only
/// grows, so it is read on both sides of the other: when both readings
/// agree, no byte moved from one counter to the other in between and the
/// sum is exact; otherwise the sum with the first reading is a lower bound.
pub(crate) fn tcp_output(fd: BorrowedFd<'_>) -> io::Result<TcpOutput> {
    let acked = tcp_bytes_acked(fd)?;
    let unacked = tcp_bytes_unacked(fd)?;
    let steady = tcp_bytes_acked(fd)? == acked;
    Ok(TcpOutput {
        taken: acked.saturating_add(unacked),
        in_flight: unacked != 0,
        steady,
    })
}

/// One plain `send` of application data: the kernel closes its last record
/// at the end (no `MSG_MORE`).
pub(crate) fn send(fd: BorrowedFd<'_>, data: &[u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `data` is a live slice of `data.len()` bytes, which the
        // kernel only reads during the call; `fd` is open for the call.
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                data.as_ptr().cast::<c_void>(),
                data.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent >= 0 {
            return Ok(sent as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// The length of `file` if it is a regular file; `None` for anything else
/// (a directory, a device, a pipe, a socket).
pub(crate) fn regular_file_len(file: BorrowedFd<'_>) -> io::Result<Option<u64>> {
    // SAFETY: `stat` is a struct of integers, for which all zero bytes are
    // a valid value.
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: `stat` is a live `stat`, which the kernel writes within
    // during the call only; `file` is open for the call.
    let rc = unsafe { libc::fstat(file.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(None);
    }
    Ok(Some(u64::try_from(stat.st_size).unwrap_or(0)))
}

/// One `sendfile` of at most `count` bytes of `file`, from `offset`, to
/// the socket: the kernel makes records of the file's pages without the
/// bytes passing through userspace. Returns the bytes sent, zero at the
/// end of the file. The file's own position is neither used nor moved.
///
/// The kernel closes the last record when it has sent all of `count`. When
/// it finds the end of the file first, having sent something, it sends
/// what it holds without `MSG_DONTWAIT` (`tls_sw_splice_eof`): `count`
/// must not reach past the end of the file on a non-blocking socket.
///
/// Unlike `send`, `sendfile` cannot ask for no `SIGPIPE` on a connection
/// that is closed for sending, and kernel TLS raises the signal even for a
/// call that it reports as having sent something. The signal is held back
/// for the calling thread while the call runs ([`HeldSigpipe`]).
pub(crate) fn sendfile(
    fd: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    offset: u64,
    count: usize,
) -> io::Result<usize> {
    let offset =
        libc::off_t::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let _held = HeldSigpipe::hold()?;
    loop {
        // The kernel writes back where it stopped: each attempt starts
        // from the caller's offset.
        let mut position = offset;
        // SAFETY: `position` is a live `off_t`, which the kernel reads and
        // writes during the call only; no other memory of this process is
        // involved (the bytes go from the file's pages to the socket);
        // both descriptors are open for the call.
        let sent =
            unsafe { libc::sendfile(fd.as_raw_fd(), file.as_raw_fd(), &mut position, count) };
        if sent >= 0 {
            return Ok(sent as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// `SIGPIPE` held back for the calling thread, until this is dropped (in
/// the same thread). Dropping it takes a `SIGPIPE` that became pending in
/// the meantime, whatever raised it, and gives the thread its mask back.
/// A `SIGPIPE` that was pending before stays pending; one raised in the
/// meantime is then left with it.
///
/// The kernel sends a socket's `SIGPIPE` to the thread that made the call,
/// and a signal held back for a thread is taken from that thread's own
/// before the process's.
pub(crate) struct HeldSigpipe {
    /// The set holding `SIGPIPE` alone.
    sigpipe: libc::sigset_t,
    /// The thread's mask before.
    before: libc::sigset_t,
    /// The caller had blocked the signal itself: the mask stays as it is.
    was_blocked: bool,
    /// A `SIGPIPE` was pending already: it is not ours to take.
    was_pending: bool,
}

impl HeldSigpipe {
    pub(crate) fn hold() -> io::Result<Self> {
        let (mut sigpipe, mut before) = (empty_sigset(), empty_sigset());
        // SAFETY: `sigpipe` is a live signal set, written during the call
        // only; `SIGPIPE` is a valid signal number.
        unsafe { libc::sigaddset(&mut sigpipe, libc::SIGPIPE) };
        // SAFETY: both sets are live for the call, which reads the first
        // and writes the second; only the calling thread's mask changes.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &sigpipe, &mut before) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(Self {
            sigpipe,
            before,
            was_blocked: has_sigpipe(&before),
            // Asked once the signal is held back, so that none arrives
            // between the answer and the hold.
            was_pending: sigpipe_pending(),
        })
    }
}

impl Drop for HeldSigpipe {
    fn drop(&mut self) {
        if !self.was_pending && sigpipe_pending() {
            // SAFETY: all zero bytes are a valid `timespec`: no waiting.
            let no_wait: libc::timespec = unsafe { mem::zeroed() };
            loop {
                // SAFETY: the set and the time are live for the call, which
                // reads them; a null `siginfo_t` pointer asks for none.
                let rc = unsafe { libc::sigtimedwait(&self.sigpipe, ptr::null_mut(), &no_wait) };
                let interrupted =
                    rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted;
                if !interrupted {
                    break;
                }
            }
        }
        if !self.was_blocked {
            // SAFETY: `before` is a live signal set that the call reads (a
            // null pointer asks for no old mask); only the calling
            // thread's mask changes, back to what it was.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.before, ptr::null_mut()) };
        }
    }
}

/// Whether a `SIGPIPE` is pending for the calling thread or the process.
fn sigpipe_pending() -> bool {
    let mut pending = empty_sigset();
    // SAFETY: `pending` is a live signal set, written during the call only.
    let rc = unsafe { libc::sigpending(&mut pending) };
    rc == 0 && has_sigpipe(&pending)
}

/// A signal set holding no signal.
fn empty_sigset() -> libc::sigset_t {
    // SAFETY: a signal set is plain data, for which all zero bytes are a
    // valid value.
    let mut set: libc::sigset_t = unsafe { mem::zeroed() };
    // SAFETY: `set` is a live signal set, written during the call only.
    unsafe { libc::sigemptyset(&mut set) };
    set
}

/// Whether `set` holds `SIGPIPE`.
fn has_sigpipe(set: &libc::sigset_t) -> bool {
    // SAFETY: `set` is a live signal set that the call reads; `SIGPIPE` is
    // a valid signal number.
    let member = unsafe { libc::sigismember(set, libc::SIGPIPE) };
    member == 1
}

/// What one `recvmsg` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Received {
    /// Bytes written to the buffer.
    pub(crate) len: usize,
    /// The record type reported with `TLS_GET_RECORD_TYPE`, if any.
    pub(crate) record_type: Option<u8>,
    /// The bytes end a record (`MSG_EOR`).
    pub(crate) end_of_record: bool,
}

/// One `recvmsg` into `buf`, with room for the record type control message.
pub(crate) fn recv(fd: BorrowedFd<'_>, buf: &mut [u8], nonblocking: bool) -> io::Result<Received> {
    let mut control = ControlBuffer([0; 32]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<c_void>(),
        iov_len: buf.len(),
    };
    // SAFETY: every field of `msghdr` is an integer or a raw pointer, for
    // which all-zero bytes are a valid value.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = cmsg_space() as _;
    let flags = if nonblocking { libc::MSG_DONTWAIT } else { 0 };

    // SAFETY: `msg` points to `iov`, which points to `buf` (writable,
    // `buf.len()` bytes), and to `control` (writable, `msg_controllen`
    // bytes); all outlive the call; `fd` is open for the call.
    let len = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, flags) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut record_type = None;
    // SAFETY: `msg` still describes `control`, which the kernel filled up
    // to the `msg_controllen` it returned.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: a non-null header from `CMSG_FIRSTHDR`/`CMSG_NXTHDR` lies
        // within `control` and is aligned for `cmsghdr`.
        let header = unsafe { cmsg.read() };
        if header.cmsg_level == libc::SOL_TLS
            && header.cmsg_type == TLS_GET_RECORD_TYPE
            && header.cmsg_len as usize >= cmsg_len()
        {
            // SAFETY: `cmsg_len` covers at least one data byte, inside
            // `control`.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: `data` points to that byte.
            record_type = Some(unsafe { data.read() });
        }
        // SAFETY: `cmsg` is a header within the buffer `msg` describes.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(Received {
        len: len as usize,
        record_type,
        end_of_record: msg.msg_flags & libc::MSG_EOR != 0,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsFd;

    use super::*;

    /// A file holding `contents`, whose name is removed at once.
    fn temp_file(contents: &[u8]) -> File {
        static FILES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "browntls-ktls-sys-{}-{}",
            std::process::id(),
            FILES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.write_all(contents).unwrap();
        file
    }

    /// `sendfile` on plain TCP: the bytes asked for, from the offset asked
    /// for, nothing at or past the end of the file, the file's position
    /// left alone, and `WouldBlock` from a full non-blocking socket.
    #[test]
    fn sendfile_sends_the_bytes_asked_for() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        let contents: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut file = temp_file(&contents);
        let (fd, input) = (sender.as_fd(), file.as_fd());

        assert_eq!(sendfile(fd, input, 10, 5000).unwrap(), 5000);
        let mut got = vec![0; 5000];
        receiver.read_exact(&mut got).unwrap();
        assert_eq!(got, contents[10..5010]);

        // Past the end: what is left, then nothing.
        assert_eq!(sendfile(fd, input, 99_000, 5000).unwrap(), 1000);
        receiver.read_exact(&mut got[..1000]).unwrap();
        assert_eq!(got[..1000], contents[99_000..]);
        assert_eq!(sendfile(fd, input, 100_000, 5000).unwrap(), 0);
        assert_eq!(sendfile(fd, input, 1 << 40, 5000).unwrap(), 0);
        assert_eq!(sendfile(fd, input, 0, 0).unwrap(), 0);
        let err = sendfile(fd, input, u64::MAX, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // The file was written to its end and stays there.
        let mut rest = Vec::new();
        file.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());

        sender.set_nonblocking(true).unwrap();
        let mut sent = 0;
        let err = loop {
            match sendfile(sender.as_fd(), file.as_fd(), 0, contents.len()) {
                Ok(n) => sent += n,
                Err(err) => break err,
            }
            assert!(sent < 1 << 30, "the socket never filled");
        };
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    /// Only a regular file has a length.
    #[test]
    fn only_a_regular_file_has_a_length() {
        let file = temp_file(&[1; 12_345]);
        assert_eq!(regular_file_len(file.as_fd()).unwrap(), Some(12_345));
        assert_eq!(regular_file_len(temp_file(&[]).as_fd()).unwrap(), Some(0));
        let directory = File::open(std::env::temp_dir()).unwrap();
        assert_eq!(regular_file_len(directory.as_fd()).unwrap(), None);
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(regular_file_len(socket.as_fd()).unwrap(), None);
        let device = File::open("/dev/null").unwrap();
        assert_eq!(regular_file_len(device.as_fd()).unwrap(), None);
    }

    /// The thread's signal mask.
    fn signal_mask() -> libc::sigset_t {
        let mut mask = empty_sigset();
        // SAFETY: a null set changes nothing; `mask` is a live signal set
        // the call writes.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), &mut mask) };
        assert_eq!(rc, 0);
        mask
    }

    /// `sendfile` on a connection that is closed for sending fails with
    /// `EPIPE` and no `SIGPIPE` reaches the process; none stays pending,
    /// and the thread's mask is as before. A caller that had blocked the
    /// signal keeps it blocked, and one that was pending for it stays
    /// pending.
    #[test]
    fn sendfile_raises_no_sigpipe() {
        let delivered = test_signals::sigpipes_delivered();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_receiver, _) = listener.accept().unwrap();
        let file = temp_file(&[7; 5000]);
        sender.shutdown(std::net::Shutdown::Write).unwrap();

        assert!(!has_sigpipe(&signal_mask()));
        for _ in 0..3 {
            let err = sendfile(sender.as_fd(), file.as_fd(), 0, 5000).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
            assert!(!sigpipe_pending());
            assert!(!has_sigpipe(&signal_mask()));
        }

        // Blocked by the caller: its signal stays its own.
        let held = HeldSigpipe::hold().unwrap();
        assert!(has_sigpipe(&signal_mask()));
        let err = sendfile(sender.as_fd(), file.as_fd(), 0, 5000).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
        assert!(has_sigpipe(&signal_mask()));
        assert!(!sigpipe_pending());
        // One raised by something else and left pending is not taken by
        // the call, but by the hold it became pending under.
        // SAFETY: raises a signal this thread has blocked.
        unsafe { libc::raise(libc::SIGPIPE) };
        assert!(sigpipe_pending());
        let err = sendfile(sender.as_fd(), file.as_fd(), 0, 5000).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
        assert!(sigpipe_pending());
        drop(held);
        assert!(!sigpipe_pending());
        assert!(!has_sigpipe(&signal_mask()));
        assert_eq!(test_signals::sigpipes_delivered(), delivered);
    }
}

/// Counting the `SIGPIPE`s that reach the process, for the tests.
#[cfg(test)]
pub(crate) mod test_signals {
    use std::sync::Once;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DELIVERED: AtomicUsize = AtomicUsize::new(0);
    static COUNTING: Once = Once::new();

    extern "C" fn count(_signal: libc::c_int) {
        DELIVERED.fetch_add(1, Ordering::SeqCst);
    }

    /// How many `SIGPIPE`s were delivered to the process since the first
    /// call. That call puts a counting handler in the place of the test
    /// harness's ignoring the signal, for the rest of the test binary.
    pub(crate) fn sigpipes_delivered() -> usize {
        COUNTING.call_once(|| {
            let handler = count as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // SAFETY: the handler only adds to an atomic counter, which a
            // signal handler may do; it stays valid for the process's life.
            unsafe { libc::signal(libc::SIGPIPE, handler) };
        });
        DELIVERED.load(Ordering::SeqCst)
    }

    /// Whether a `SIGPIPE` is pending for the calling thread or the process.
    pub(crate) fn sigpipe_pending() -> bool {
        super::sigpipe_pending()
    }
}
