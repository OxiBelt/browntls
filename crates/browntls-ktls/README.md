# browntls-ktls

Linux kernel TLS offload for [browntls](../../README.md) connections.

The handshake runs in userspace; `KtlsStream::new` then hands the
connection's traffic keys to the kernel (`TCP_ULP` `tls`, `TLS_TX`,
`TLS_RX`), which encrypts and decrypts application data itself. Records
that are not application data (TLS 1.3 KeyUpdate and NewSessionTicket,
post-handshake authentication, alerts) come back to the stream and are
handled by `browntls::kernel::KernelConnection`.

| | |
|---|---|
| Protocols | TLS 1.2, TLS 1.3 |
| Ciphers | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, TLS 1.3 AES-128-CCM |
| Kernel | Linux with the `tls` module; 6.14 for TLS 1.3 key updates; 6.18 for a peer `record_size_limit` below 16384 |

The configuration must set `enable_secret_extraction`. When the kernel or
the connection cannot be offloaded, the connection and the socket come back
unharmed in `HandoffError::Refused`. That includes a peer that has already
closed TCP: the kernel attaches the `tls` upper layer protocol to an
established connection only (`ENOTCONN`).

On a non-blocking socket Linux reports a write as done once the record is
encrypted, even when TCP had no room for all of it, and sends the rest when
room appears. Closing the socket or its write side before then truncates the
stream for the peer. The streams therefore keep count: `unsent()` sets the
records the kernel has made (its transmit record sequence number) against
the bytes TCP has taken, and tells how much the kernel still holds.
`AsyncKtlsStream`'s `shutdown` shuts the write side only when that is zero,
so call it, and let it finish, before dropping a stream that has written;
with a `KtlsStream` on a non-blocking socket, wait for `unsent()` to be zero
before closing. Blocking sockets without a send timeout are not affected.

## Zero copy

`sendfile` on either stream sends part of a file as application data with
`sendfile(2)`: the kernel makes the records from the file's pages, and the
bytes never pass through userspace. Like a write it first sends what the
stream holds, counts the records against the confidentiality limit (by the
kernel's own record count, since the kernel may close a record after any
part of the file) and keeps `unsent()` exact; `sendfile` on the socket
itself (`get_ref`) does none of that. One call sends at most 64 records'
worth, so call it until the file is sent:

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

`AsyncKtlsStream::sendfile` waits for room on the socket; where the kernel
must read the file from its storage first, the call blocks the thread for
that long. `sendfile(2)` cannot ask the kernel not to raise `SIGPIPE` on a
reset connection: Rust programs ignore that signal unless they changed its
handling.

`set_tx_zerocopy_sendfile` on either stream sets the kernel's
`TLS_TX_ZEROCOPY_RO` option (Linux 5.19; off after the handover): a network
device that encrypts the records itself is then given the pages of a
`sendfile` without the kernel copying them first. The file must not change
until the peer has acknowledged its bytes, or a retransmission carries a
record that no longer authenticates and the peer ends the connection. Where
the kernel encrypts in software the option changes nothing: the ciphertext
goes to pages of the kernel's own either way.

`TLS_RX_EXPECT_NO_PAD`, which lets the kernel decrypt TLS 1.3 records
straight into the reader's buffer, is not offered: before Linux 7.2 the
kernel copies a record to the wrong place in the reader's buffer when it
has to decrypt it a second time (a padded record, or one that is not
application data), so a peer that pads would corrupt what the application
reads.

## Tokio

The `tokio` feature adds `AsyncKtlsStream`, the same offload on a
`tokio::net::TcpStream` with `AsyncRead` and `AsyncWrite`.
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

`src/sys.rs` holds the crate's only `unsafe` code, the socket options,
`sendmsg`/`recvmsg` control messages and `sendfile` of kernel TLS; see the
invariants at its top.

## Testing

`cargo test -p browntls-ktls --all-features` runs the handover tests over
loopback TCP, for `KtlsStream` (`tests/offload.rs`, `tests/zero_copy.rs`,
`tests/sendfile.rs`) and for `AsyncKtlsStream` (`tests/tokio_offload.rs`,
`tests/tokio_zero_copy.rs`, feature `tokio`). They are
skipped when the `tls` module is missing, unless `BROWNTLS_KTLS_REQUIRED=1`
is set (CI sets it after `sudo modprobe tls`).
