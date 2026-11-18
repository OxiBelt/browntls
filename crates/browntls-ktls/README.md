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
| Kernel | Linux with the `tls` module; 6.14 for TLS 1.3 key updates; 6.18 for a peer `record_size_limit` below 16384; 7.2 for `set_rx_expect_no_pad` |

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
correction is refused as well.

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

`src/sys.rs` holds the crate's only `unsafe` code, the socket options and
`sendmsg`/`recvmsg` control messages of kernel TLS; see the invariants at its
top.

## Testing

`cargo test -p browntls-ktls --all-features` runs the handover tests over
loopback TCP, for `KtlsStream` (`tests/offload.rs`, `tests/zero_copy.rs`)
and for `AsyncKtlsStream` (`tests/tokio_offload.rs`,
`tests/tokio_zero_copy.rs`, feature `tokio`). They are
skipped when the `tls` module is missing, unless `BROWNTLS_KTLS_REQUIRED=1`
is set (CI sets it after `sudo modprobe tls`).
