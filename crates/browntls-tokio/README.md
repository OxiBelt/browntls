# browntls-tokio

Asynchronous TLS streams for [Tokio](https://tokio.rs), built on
[browntls](https://github.com/OxiBelt/browntls).

`TlsConnector` and `TlsAcceptor` run a TLS 1.3 or TLS 1.2 handshake over any
transport that implements Tokio's `AsyncRead` and `AsyncWrite` (a `TcpStream`,
a `UnixStream`, an in-memory `DuplexStream`) and return a stream that
implements `AsyncRead`, `AsyncBufRead` and `AsyncWrite` over the plaintext.

> **Status.** browntls and this crate are in initial development, have not
> been independently reviewed or audited, and have no published releases.
> Do not rely on them to protect real traffic yet.

## Client

```rust,no_run
use std::sync::Arc;

use browntls_tokio::browntls::pki_types::ServerName;
use browntls_tokio::browntls::{ClientConfig, RootCertStore};
use browntls_tokio::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn get(roots: RootCertStore) -> std::io::Result<Vec<u8>> {
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect("example.com:443").await?;
    let name = ServerName::try_from("example.com").expect("valid DNS name");
    let mut tls = connector.connect(name, tcp).await?;

    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    tls.flush().await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(response)
}
```

## Server

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use browntls_tokio::browntls::ServerConfig;
use browntls_tokio::TlsAcceptor;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

async fn serve(config: ServerConfig) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("[::]:8443").await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // Bound the handshake: a silent client would hold it forever.
            let accept = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp));
            let Ok(Ok(mut tls)) = accept.await else { return };
            let _ = tls.write_all(b"hello\n").await;
            let _ = tls.shutdown().await; // sends close_notify
        });
    }
}
```

## Choosing the configuration per ClientHello

`LazyConfigAcceptor` reads the ClientHello before the server picks a
`ServerConfig`; `StartHandshake::into_stream` continues with it. A transport
that does not start with a ClientHello is answered with an alert, and
`take_io` hands it back, to answer a plain-text HTTP request, say.

```rust,no_run
use std::sync::Arc;

use browntls_tokio::browntls::server::Acceptor;
use browntls_tokio::browntls::ServerConfig;
use browntls_tokio::LazyConfigAcceptor;
use tokio::net::TcpStream;

async fn accept(
    tcp: TcpStream,
    by_name: impl Fn(Option<&str>) -> Arc<ServerConfig>,
) -> std::io::Result<()> {
    let start = LazyConfigAcceptor::new(Acceptor::default(), tcp).await?;
    let config = by_name(start.client_hello().server_name());
    let _tls = start.into_stream(config).await?;
    Ok(())
}
```

## 0-RTT early data

With `ClientConfig::enable_early_data` set and `TlsConnector::early_data(true)`,
`connect` returns before the handshake when a resumed TLS 1.3 session allows
early data. Writes then go out as early data with the ClientHello, up to the
server's allowance; the first read, flush or shutdown (or a write beyond the
allowance) completes the handshake. Early data the server declined is sent again
as ordinary data only when the same application protocol is certain (no ALPN
offered, or exactly one offered and selected, as RFC 9846 §4.2.10 requires);
otherwise that operation fails with `client::EarlyDataNotResent` and the
application decides what to send. A server that set `max_early_data_size` (with stateful
session storage) reads accepted early data through
`stream.get_mut().1.early_data()` after `accept`.

Early data can be replayed by an attacker: send only requests that are safe to
repeat.

## Behaviour

- **Flushing.** Records the transport does not take at once stay queued: call
  `flush` when a batch of writes is done.
- **Closing.** `shutdown` sends `close_notify`, then shuts the transport's
  write side; later writes fail with `BrokenPipe` (RFC 9846 §6.1). The peer's
  `close_notify` reads as end of file; a transport that ends without one fails
  the read with `UnexpectedEof` (a truncation).
- **Splitting.** `tokio::io::split` gives read and write halves for two tasks.
- **Errors.** TLS failures are `io::Error`s of kind `InvalidData` wrapping a
  `browntls::Error` (`err.get_ref()` then `downcast_ref`).
- **Answers.** A read that receives a message calling for an answer (a TLS
  1.3 `KeyUpdate` asking for ours, a post-handshake `CertificateRequest`)
  writes the answer at once if the transport has room, so a task that only
  reads does not leave the peer waiting for it. While more answers than the
  connection's send buffer limit (at most 64 KiB) are still unwritten, a
  read takes no more input and waits for the transport to take them (a
  write on another task that sends them wakes it), so a peer that keeps
  asking and reads nothing cannot make them pile up.
- **Cooperative scheduling.** With the `coop` feature the streams and
  handshake futures take part in Tokio's
  [cooperative scheduling](https://docs.rs/tokio/1/tokio/task/coop/index.html),
  as Tokio's sockets and channels do: an operation that completes takes one
  unit of the task's budget, and so does every read from the transport after
  the first in one poll. Once the budget is spent, an operation returns
  `Pending` and the task runs again after the others had their turn. A task
  that is always ready (a peer that sends faster than it is read, a transport
  that never waits) therefore cannot keep a worker thread to itself, whether
  or not the transport counts against the budget. Over a transport that
  counts too (Tokio's sockets), an operation that reaches it takes the
  transport's unit as well, so the task yields that much sooner. Wrap a
  future in `tokio::task::coop::unconstrained` to opt out for that future.
  As with Tokio's own resources, do not drive a stream from another executor
  blocked inside a Tokio task: a spent budget waits for Tokio's scheduler,
  which does not run meanwhile.

## Features

`native` (default), `rustcrypto`, `tls12` (default), `logging` (default),
`prefer-post-quantum` (default), `zlib`, `brotli` and `zstd` are passed through
to `browntls`.

`coop` (default) makes the streams take part in Tokio's cooperative
scheduling (see above). It enables Tokio's `rt` feature, which is where Tokio
keeps the task budget; `rt` adds no dependency, and an application that runs
a Tokio runtime has it enabled already. Without `coop` the crate uses Tokio's
I/O traits only and takes nothing from the budget itself (a transport that
counts still does).

## Minimum supported Rust and Tokio versions

Rust: the workspace's pinned toolchain, Rust 1.100.0.

Tokio: 1.53, the newest long-term support line (supported by Tokio until
September 2027), or any later 1.x release.

## Acknowledgements

The polling design (a synchronous connection driven through `Read`/`Write`
adapters over the task context) follows
[tokio-rustls](https://github.com/rustls/tokio-rustls) (MIT OR Apache-2.0),
which is also the interoperability oracle in this crate's tests.

## License

[Apache-2.0](LICENSE).
