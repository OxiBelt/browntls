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
unharmed in `HandoffError::Refused`.

`src/sys.rs` holds the crate's only `unsafe` code, the socket options and
`sendmsg`/`recvmsg` control messages of kernel TLS; see the invariants at its
top.

## Testing

`cargo test -p browntls-ktls` runs the handover tests over loopback TCP. They
are skipped when the `tls` module is missing, unless
`BROWNTLS_KTLS_REQUIRED=1` is set (CI sets it after `sudo modprobe tls`).
