# browntls-ktls

Linux kernel TLS offload for [browntls](../../README.md) connections.

The handshake runs in userspace; `KtlsStream::new` then hands the
connection's traffic keys to the kernel (`TCP_ULP` `tls`, `TLS_TX`,
`TLS_RX`), which encrypts and decrypts application data itself. Records
that are not application data (TLS 1.3 KeyUpdate and NewSessionTicket,
post-handshake authentication, alerts) come back to the stream and are
handled by `browntls_core::kernel::KernelConnection`.

| | |
|---|---|
| Protocols | TLS 1.2, TLS 1.3 |
| Ciphers | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, TLS 1.3 AES-128-CCM |
| Kernel | Linux with the `tls` module; 6.14 for TLS 1.3 key updates; 6.19 for records below 16384 bytes (a peer `record_size_limit` or a local `max_fragment_size`); 7.2 for `set_rx_expect_no_pad` |

The configuration must set `enable_secret_extraction`. When the kernel or
the connection cannot be offloaded, the connection and the socket come back
unharmed in `HandoffError::Refused`. That includes a peer that has already
closed TCP: the kernel attaches the `tls` upper layer protocol to an
established connection only (`ENOTCONN`). One case is found too late for
that: a kernel that lacks the suite's cipher (built without it, or
restricted to approved algorithms) refuses the keys only after they were
taken out of the connection, which is then lost (`HandoffError::Failed`).
The load-aware routing below asks the kernel about each cipher on a
loopback socket before it hands a connection over.

On a non-blocking socket Linux reports a write as done once the record is
encrypted, even when TCP had no room for all of it, and sends the rest when
room appears. Closing the socket or its write side before then truncates the
stream for the peer. The streams therefore keep count: `unsent()` sets the
records the kernel has made (its transmit record sequence number) against
the bytes TCP has taken, and tells how much the kernel still holds.
`AsyncKtlsStream`'s `shutdown` shuts the write side only when that is zero
(or, where `unsent()` cannot count, once the socket has room again), so
call it, and let it finish, before dropping a stream that has written;
with a `KtlsStream` on a non-blocking socket, wait for `unsent()` to be zero
before closing. Blocking sockets without a send timeout are not affected.

A read answers what the peer's records call for (KeyUpdates,
post-handshake authentication, alerts). Answers that a full non-blocking
socket has no room for wait in the stream; once they take more than
64 KiB, reads take in nothing more until the socket has taken enough of
them, so a peer that keeps asking and reads no answers cannot make them
pile up. A `KtlsStream` read then returns `WouldBlock` although the socket
stays readable: wait for it to be writable before reading again. An
`AsyncKtlsStream` read waits for that itself.

## Zero copy

`sendfile` on either stream sends part of a regular file as application
data with `sendfile(2)`: the kernel makes the records from the file's pages,
and the bytes never pass through userspace. Like a write it first sends what
the stream holds, counts the records against the confidentiality limit (by
the kernel's own record count) and keeps `unsent()` right; `sendfile` on the
socket itself (`get_ref`) does none of that. One call sends at most 64
records' worth, so call it until the file is sent:

```rust
let file = std::fs::File::open("index.html")?;
let len = file.metadata()?.len();
let mut offset = 0;
while offset < len {
    let rest = usize::try_from(len - offset).unwrap_or(usize::MAX);
    match tls.sendfile(&file, offset, rest)? {
        0 => break, // the file was cut short meanwhile
        n => offset += n as u64,
    }
}
```

A call that was cut short (no room on a non-blocking socket, a signal on a
blocking one) may leave its last bytes in a record the kernel has not
closed. They go out with what is sent next, `unsent()` counts them until
then, and they are lost if the stream is dropped first.

The streams never ask the kernel for more than the file holds: finding the
end of a file before the count it was given, the kernel waits for TCP to
take the last record even on a non-blocking socket. A file that holds less
than the size it reports (cut short while it is sent, for one) can still
cause that wait.

`sendfile(2)` cannot be told not to raise `SIGPIPE` on a connection that is
closed for sending, and kernel TLS raises it even for a call that reports
bytes as sent, and again when the socket is closed with records of a file
still in the kernel. The call holds the signal back for its thread and takes
one that became pending meanwhile, and dropping a stream that sent files
does the same around the close of its socket, so neither raises `SIGPIPE`
whatever the process does with the signal. That holds for a socket which the
stream owns and nothing else holds: the kernel sends those records when the
last holder lets go, so a borrowed, shared or duplicated socket closed
elsewhere is not covered, nor is a descriptor that a child process inherited
(a command spawned while the stream lives closes a close-on-exec socket at
`exec`, and any other when it pleases, after the parent may have dropped
the stream, and receives the signal). A `SIGPIPE`
that something else sends to the process during the hold may be taken along.
On a connection that has failed the kernel may go on reporting bytes as
sent; `unsent()` and the reads tell.

`AsyncKtlsStream::sendfile` waits for room on the socket; where the kernel
must read the file from its storage first, the call blocks the thread for
that long.

`set_tx_zerocopy_sendfile` on either stream sets the kernel's
`TLS_TX_ZEROCOPY_RO` option (Linux 5.19; off after the handover): a network
device that encrypts the records itself is then given the pages of a
`sendfile` without the kernel copying them first. The file must not change
until the peer has acknowledged its bytes, or a retransmission carries a
record that no longer authenticates and the peer ends the connection. Where
the kernel encrypts in software the option changes nothing: the ciphertext
goes to pages of the kernel's own either way.

`set_rx_expect_no_pad` on either stream sets `TLS_RX_EXPECT_NO_PAD` (off
after the handover): the kernel then decrypts a TLS 1.3 record straight
into the buffer of a read that has room for it, instead of into a buffer of
its own that it copies out. It has to decrypt a second time a record that
turns out to be padded or not application data, so the peer decides how
often that work is done twice: set it for peers trusted not to exploit
that. While it is set, a read zeroes its buffer for up to a record's length
behind the bytes it returns, where the first attempt may have left a
control record's plaintext.

The stream sets the option on Linux 7.2 or later only (`Unsupported`
otherwise). The kernel has had it since 6.0, but before 7.2 it copies the
second decryption to the wrong place in the reader's buffer, and a peer
that pads corrupts what the application reads. The kernel is told apart by
the release `uname` reports, so an older kernel that was given the
correction is refused as well, and so is a release candidate of 7.2 (the
correction came with the last of them). The release is all there is to go
by: a kernel built from a 7.2 pre-release source under a release that does
not say so (no `rc` in it) is taken for 7.2, and is for whoever sets the
option to rule out.

## Tokio

The `tokio` feature adds `AsyncKtlsStream`, the same offload on a
`tokio::net::TcpStream` with `AsyncRead` and `AsyncWrite`.
An async read processes at most eight successful kernel receives per poll
when control records yield no application data. It then reschedules itself
without losing socket readiness, so continuously arriving control records
cannot hold one Tokio worker in that read indefinitely. The blocking stream
keeps reading until data, closure or an I/O result is available.
`AsyncKtlsStream::from_client` and `from_server` take a
[browntls-tokio](../browntls-tokio/README.md) stream: they ready it with
`into_kernel_handoff` (handshake and 0-RTT phase completed, queued records
written, input read up to a record boundary), install the keys, and return
the application data received before that from the first reads. 0-RTT data
a server had accepted and not read comes first in it; `early_data_len` says
how much, since that data can be replayed.

```rust
use browntls_ktls::{AsyncKtlsStream, StreamHandoffError};

let tls = connector.connect(server_name, tcp).await?;
match AsyncKtlsStream::from_client(tls).await {
    // The kernel protects the records from here on.
    Ok(ktls) => serve(ktls).await,
    // Nothing was given to the kernel: go on in userspace, reading
    // `received` before anything from `stream`.
    Err(StreamHandoffError::Refused { stream, received, .. }) => {
        serve_in_userspace(stream, received).await
    }
    // The connection is lost.
    Err(StreamHandoffError::Failed(error)) => Err(error),
}
```

`AsyncKtlsStream::new` takes a connection that is already at rest (as
`KernelHandoff::into_parts` returns it) and its socket. The feature enables
Tokio's `net` only; the runtime is the application's.

## Load-aware routing

With the `native` feature, kernel TLS can be the first place for a
connection's records under the native provider's load-aware routing
(`browntls_core::crypto::native::accel::load`), ahead of the provider's
backends in their usual order:

```rust
use browntls_core::crypto::native::accel::load;
use browntls_ktls::routing::{self, RoutedStream};

// Once per process. Without kernel TLS everything stays in userspace.
load::enable(load::Config::DEFAULT)?;
let _ = routing::activate();

let mut tls = RoutedStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
match &tls {
    RoutedStream::Kernel(ktls) => { /* a `KtlsStream` */ }
    RoutedStream::Userspace(stream) => { /* why: `stream.kernel_refusal()` */ }
}
```

`routing::activate` asks the running kernel whether it attaches the `tls`
upper layer protocol and, if so, puts kernel TLS at the head of the order.
`RoutedStream::new` then hands each connection to the kernel, unless the
kernel cannot take it (it stays in userspace, with the refusal recorded;
whether the kernel has the connection's cipher is asked once, with keys of
zeros on a loopback socket)
or, with `accel::load` enabled, the routing keeps it in userspace: while
writes to the kernel cost more than they usually do and userspace measures
cheaper, a growing share of the new connections stays there until the
kernel has recovered. While kernel TLS is not active every connection
stays in userspace. `AsyncRoutedStream::from_client` and `from_server`
(feature `tokio`) do the same for `browntls-tokio` streams.

A server that accepts 0-RTT data should read `early_data()` before it
calls `RoutedStream::new`: what is left unread comes in-band and unmarked
with the kernel, as with `KtlsStream::new`, and stays in `early_data()` in
userspace. The Tokio streams tell how much of what they return first is
0-RTT data (`early_data_len`).

A connection keeps its place for life, so only new connections move. Both
kinds of stream report what one write in sixteen of at least 4096 bytes
cost, in processor time of the calling thread, which leaves out waiting
for the peer; `accel::load::kernel::status_all` shows the streams. An
application that needs what only the kernel does (`sendfile`) should hand
its connections over with `KtlsStream::new` instead. See
[Architecture](../../docs/Architecture.md#kernel-tls-at-the-head-of-the-order)
for the mechanism and its limits; whether a shift away from the kernel
pays on a given machine is not measured.

`src/sys.rs` holds the crate's only `unsafe` code, the socket options,
`sendmsg`/`recvmsg` control messages and `sendfile` of kernel TLS, the
thread's signal mask around the latter, `poll`, `ioctl(SIOCOUTQ)`,
`getsockopt(TCP_INFO)`, `uname`, `fstat`, plain `send`, and the thread's
processor time clock; see the invariants at its top.

## Testing

`cargo test -p browntls-ktls --all-features` runs the handover tests over
loopback TCP, for `KtlsStream` (`tests/offload.rs`, `tests/zero_copy.rs`,
`tests/sendfile.rs`) and for `AsyncKtlsStream` (`tests/tokio_offload.rs`,
`tests/tokio_zero_copy.rs`, `tests/tokio_fairness.rs`, feature `tokio`),
and the placement of connections by the routing (`tests/routing.rs`,
`tests/tokio_routing.rs`); unit tests in `src/backpressure_tests.rs` and
`src/sigpipe_tests.rs` use the kernel too. Their parts that need the kernel
are skipped when the `tls` upper layer protocol is not loaded (it is not
listed in `/proc/sys/net/ipv4/tcp_available_ulp`), unless
`BROWNTLS_KTLS_REQUIRED=1` is set (CI sets it after `sudo modprobe tls`).

The tests of `set_rx_expect_no_pad` with a peer that pads need Linux 7.2;
on an older kernel they check the refusal only and skip the rest, unless
`BROWNTLS_KTLS_NO_PAD_REQUIRED=1` is set.
