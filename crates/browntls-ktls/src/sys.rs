//! The system calls of Linux kernel TLS: the crate's only `unsafe` code.
//!
//! Exception to the workspace's `unsafe_code = "deny"` (CONTRIBUTING.md,
//! "Security requirements"): the socket options and the `sendmsg`/`recvmsg`
//! control messages of kernel TLS have no safe wrapper in the standard
//! library, nor has asking the kernel whether a socket has room to send
//! (`poll`). Every function here keeps these invariants:
//!
//! * the descriptor is a [`BorrowedFd`], open for the whole call;
//! * every pointer passed to the kernel points into a live Rust value
//!   (slice, `iovec`, `msghdr`, control buffer) that outlives the call, with
//!   the length given next to it, and the kernel writes only into buffers
//!   borrowed mutably here;
//! * control messages are built and read only through the libc `CMSG_*`
//!   functions, within a buffer aligned for `cmsghdr` and sized with
//!   `CMSG_SPACE`, and a received control message is read only when its
//!   `cmsg_len` covers the byte read;
//! * no Rust value is created from kernel output except plain integers and
//!   bytes copied out of buffers the kernel wrote, within the length it
//!   reported;
//! * the descriptor's flags are never changed.

#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};

use libc::{c_int, c_void};

/// `TLS_TX` (`include/uapi/linux/tls.h`).
const TLS_TX: c_int = 1;
/// `TLS_RX`.
const TLS_RX: c_int = 2;
/// `TLS_TX_MAX_PAYLOAD_LEN` (Linux 6.18).
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

/// Whether the kernel knows `TLS_TX_MAX_PAYLOAD_LEN` (Linux 6.18), asked
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

/// One plain `send` of application data: the kernel closes its last record
/// at the end (no `MSG_MORE`).
/// Whether the socket has room to send right now, as the kernel reports it
/// (`poll` with no timeout, so it never waits). An error or a hang-up
/// pending on the socket counts as room: the next call reports it.
#[cfg(feature = "tokio")]
pub(crate) fn writable(fd: BorrowedFd<'_>) -> io::Result<bool> {
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
            let ready = libc::POLLOUT | libc::POLLERR | libc::POLLHUP;
            return Ok(entry.revents & ready != 0);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

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
