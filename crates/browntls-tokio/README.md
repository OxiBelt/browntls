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

Applications normally reach this crate through
[`browntls`](../browntls/README.md), whose `tokio` feature re-exports it as
the module `browntls::tokio`:

```toml
[dependencies]
browntls = { git = "https://github.com/OxiBelt/browntls", features = ["tokio"] }
```

The items are the same ones (`browntls::tokio::TlsConnector` is
`browntls_tokio::TlsConnector`), and the features described
[below](#features) have the same names there. The examples in this file name
the items through this crate, `browntls_tokio`, and the protocol crate
through its re-export `browntls_tokio::browntls`.

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

## DTLS over UDP

The optional `dtls` feature provides `dtls::UdpClient` over a Tokio
`UdpSocket` the application binds and connects. Through the facade, enable
`browntls`'s `dtls` feature (which also enables `tokio`). This is a datagram
API, separate from the stream connector and acceptor above.

```rust,no_run
# #[cfg(feature = "dtls")]
# async fn example(config: std::sync::Arc<browntls_tokio::browntls::ClientConfig>) -> std::io::Result<()> {
use browntls_tokio::dtls::{Recv, UdpClient};
use browntls_tokio::browntls::pki_types::ServerName;
use std::time::Duration;
use tokio::net::UdpSocket;

let socket = UdpSocket::bind("127.0.0.1:0").await?;
socket.connect("127.0.0.1:4433").await?;
let name = ServerName::try_from("localhost").expect("valid DNS name");
let mut client = UdpClient::new(config, name, socket)?;
client.set_timeout(Some(Duration::from_secs(10)));
client.complete_handshake().await?;
assert!(!client.connection().is_handshaking());
client.send(b"hello").await?;
let mut buf = [0; 2048];
match client.recv(&mut buf).await? {
    Recv::Data(len) => { /* buf[..len], including a possible empty datagram */ }
    Recv::Closed => { /* authenticated close_notify */ }
}
client.close().await?;
# Ok(())
# }
```

The client takes ownership of the socket and starts no background task.
Enable the runtime's I/O and time drivers. Handshake, send, receive and close
drive core's datagrams and timers using elapsed `tokio::time::Instant` from
one fixed origin. `set_timeout` bounds each complete operation, including an
implicit handshake and protocol writes; incoming traffic does not restart
the deadline. Zero expires immediately. Without that limit core's handshake
retransmission limit still applies. Idle clients do no work; call an I/O
operation to process messages or overdue timers.

`new` and `from_connection` return before I/O; `connect` is a convenience
constructor that completes the handshake. Use the former constructors to
retain the client when cancelling a handshake. A `from_connection` connection
must be fresh, with no timers already driven under another clock origin.
`connection()` exposes negotiated parameters directly without a wrapper
cache. Live OCSP queries return `Unsupported` without bypassing verification.

Each send seals one whole application datagram. Oversized data returns
`InvalidInput`; inspect `connection().max_application_data()` after the
handshake for the current limit. Receive keeps whole records from one UDP
payload until consumed. A short application buffer returns `InvalidInput`
and retains the record; empty records return `Recv::Data(0)`, while only an
authenticated close returns `Recv::Closed`. Ordinary UDP payloads are read
into a 65,535-byte buffer; IPv6 jumbograms are unsupported. The receive side
never accumulates another UDP payload while plaintext from the current one
remains. Each poll does a bounded burst of work and then yields.

Cancellation and operation timeouts retain the client's protocol state,
plaintext ranges and pending ciphertext. Sealed ciphertext stays byte for
byte unchanged until the socket accepts the entire datagram, including after
an I/O error. A cancelled or failed send may already have accepted or sent
the application's data; the next operation first drains pending output.
Retrying the plaintext can therefore duplicate an application message. DTLS
does not reliably deliver application data. Close sends `close_notify`
without waiting for acknowledgement, can be resumed after cancellation,
and forbids later sends. Established clients can still receive. If a client
closes during the handshake, later handshake and receive calls return
`ConnectionAborted`. Dropping the client releases the socket and buffered
state.

`dtls::UdpServer` serves multiple peers on one unconnected Tokio UDP
socket. Call `next_event` to receive `Connected`, `Received`, `Closed`,
and `Failed` events. `send_to` and `close` address a peer by its socket
address. The server requires a cookie sealer. It bounds pending handshakes,
established peers, and queued datagrams. Poll an operation to drive both
socket I/O and retransmission timers.

For individually owned peers, `dtls::UdpListener::new` returns a listener
and a `SessionDriver`. Run the driver in a task owned by the application.
Each accepted `UdpSession` receives whole datagrams and can send and close
independently. `SessionLimits` bounds retained sessions and all queues.
Sends wait for command capacity. A full receive queue drops newly arriving
application datagrams while retaining close and error state.

The client, event server, and session listener default to DTLS 1.3.
Use `new_with_versions` with `browntls::dtls::Versions` to enable DTLS 1.2
explicitly. The certificates and suites in the shared TLS configuration
still determine the handshake.

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
application decides what to send.

A server that set `max_early_data_size` (with stateful session storage) reads
accepted early data through `server::TlsStream::early_data`, an `AsyncRead`
of its own: ordinary reads never return early data. By default `accept`
resolves after the handshake, when all of it is buffered. With
`TlsAcceptor::early_data(true)` (or `StartHandshake::early_data(true)` after a
`LazyConfigAcceptor`), `accept` resolves as soon as the server's flight is
written when the connection accepted early data, and the reader returns the
data as it arrives, without waiting for the client's Finished:

```rust,no_run
use browntls_tokio::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn serve(acceptor: TlsAcceptor, tcp: TcpStream) -> std::io::Result<()> {
    let mut tls = acceptor.early_data(true).accept(tcp).await?;
    if let Some(mut early) = tls.early_data() {
        // Not yet known to come from a client taking part now: see below.
        let mut request = [0; 16];
        early.read_exact(&mut request).await?;
    }
    // Sent at once with `ServerConfig::send_half_rtt_data`; otherwise the
    // write waits for the handshake.
    tls.write_all(b"response").await?;
    tls.flush().await?; // completes the handshake
    Ok(())
}
```

On such a stream an ordinary read, a flush or a shutdown completes the
handshake first; so does a write, unless `ServerConfig::send_half_rtt_data`
lets it go out ahead of the client's Finished (0.5-RTT data). The reader's end
of file comes with the end of the handshake, which the client only reaches
after the server's flight: read a request by its own framing to answer sooner.
A handshake that fails then fails every later operation. The reader borrows
the stream: read the early data before `into_split`.

Early data can be replayed by an attacker: send only requests that are safe to
repeat. On the server, a replay cannot complete a handshake, so early data read
after the handshake comes from a client that took part in it. Read before, it
may be a recorded ClientHello and early data sent again. For a resumed
session, browntls takes the session out of the server's session storage, which
makes a ticket good for one attempt as long as every server honouring it shares
that storage; early data under an external PSK that allows it has no such
protection, and the library keeps no other anti-replay store. Act before the
handshake completes only on requests that are safe to repeat (RFC 9846 §8, RFC
8470 for HTTP), and bound the operations that complete the handshake with
timeouts of their own: the one around `accept` no longer covers them.

## Kernel TLS

`into_kernel_handoff` readies a client or server stream for kernel TLS
offload (the configuration needs `enable_secret_extraction`): it finishes a
0-RTT phase (a client's, or the handshake of a server stream returned
before its end), writes and flushes every queued record, reads exactly up to the
next record boundary, and sets the plaintext already received aside. The
`KernelHandoff` it resolves to gives the transport, the connection (for
`dangerous_into_kernel_connection`, see `browntls_core::kernel`) and that
plaintext, which is read before anything the kernel delivers.

```rust,no_run
use browntls_tokio::client::TlsStream;
use tokio::net::TcpStream;

async fn offload(tls: TlsStream<TcpStream>) -> std::io::Result<()> {
    let handoff = match tls.into_kernel_handoff().await {
        Ok(handoff) => handoff,
        // Nothing is lost: `err.stream` (usable when the connection merely
        // cannot be offloaded) and `err.received` come back.
        Err(err) => return Err(err.into_io_error()),
    };
    let (tcp, conn, received) = handoff.into_parts();
    let (secrets, kernel_conn) = conn
        .dangerous_into_kernel_connection()
        .map_err(std::io::Error::other)?;
    // Install `secrets` on `tcp`, read `received` first, and give the
    // records the kernel passes back to `kernel_conn`.
    drop((tcp, secrets, kernel_conn, received));
    Ok(())
}
```

The transport must not read ahead of what it is asked for (no buffered
reader below the stream): the bytes after the record boundary are the
kernel's. 0-RTT data a server accepted and has not read comes first in the
plaintext set aside; it can be replayed, and `early_data_len` tells where it
ends.

Taking a stream apart with `into_inner` instead drops what only the stream
holds (an unfinished 0-RTT phase, a read error kept for the next read), and
the connection then refuses the handover while anything is in flight.

## Certificate status (OCSP)

A browntls verifier that needs a certificate status response the peer did
not staple pauses its connection with a query for the application to
transport. With the `ocsp` feature, `browntls_tokio::revocation` answers
such queries for the streams of this crate:

- The application supplies the HTTP request as a callback
  (`FetchRevocation`, which closures implement). This crate has no HTTP
  client and adds no dependency. The responder URLs come from the peer's
  certificate, so the callback decides which responder may be asked for
  which issuer, checks the address it dials, follows no redirects and
  bounds the answer.
- A `RevocationFetcher` wraps the callback with a deadline, one fetch per
  request at a time (connections that ask for the same request share it
  and drive it from their own polls; it is dropped when none waits any
  more), a bounded cache, and bounds on the response size and on the
  fetches running at once.
- `revocation_fetcher` attaches it, in an `Arc`, to `TlsConnector`,
  `TlsAcceptor`, `LazyConfigAcceptor` and `StartHandshake`, buffered and
  unbuffered. Handshakes (those finished inside a stream returned early for
  0-RTT data included), reads that meet a certificate after the handshake,
  and `into_kernel_handoff` then answer the queries they meet. On an
  unbuffered stream a write or shutdown that finds the connection waiting
  fetches the answer too.
- Every answer goes to the connection, whose verifier authenticates it.
  Nothing in this crate parses a response or decides whether a certificate
  is good. A cached response that a connection refuses is forgotten.

A connection with no fetcher attached, or built without the feature, has
its queries answered as unavailable at once; the verifier's policy then
accepts or refuses the certificate. While a connection waits for an answer
it reads nothing from its transport, so a peer that goes away is noticed
only afterwards: the deadline bounds that wait. Deadlines use
`tokio::time`, so the runtime needs its time driver.

`revocation::staple::StapleRefresh` is the loop a server spawns to keep
its own stapled responses fresh. It asks browntls's `ServerStapleResolver`
which response is due, fetches it through the same application callback
(with a deadline, a size bound and a backoff after failures), and hands it
to the resolver's `install`, which staples it only after verifying it for
the server's certificate. The next refresh comes after half the lifetime
the installed response has left, within a configurable interval.

## Unbuffered streams

`browntls_tokio::unbuffered` has the same connector, acceptor and lazy
acceptor over browntls's unbuffered connection API. Its streams decrypt each
record where the transport put it, in one receive buffer of 18 437 bytes:
`AsyncBufRead` lends that plaintext without a copy, one record per
`fill_buf`, and `AsyncRead` copies it once (the streams above allocate per
record and copy the plaintext once for `AsyncBufRead`, twice for
`AsyncRead`). A write encrypts up to 65 536 bytes straight into the bytes
the transport is given.

```rust,no_run
use std::sync::Arc;

use browntls_tokio::browntls::ServerConfig;
use browntls_tokio::unbuffered::TlsAcceptor;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn echo(tcp: TcpStream, config: Arc<ServerConfig>) -> std::io::Result<()> {
    let mut tls = TlsAcceptor::from(config).accept(tcp).await?;
    loop {
        // The plaintext of one record, borrowed from the receive buffer.
        let record = tls.fill_buf().await?.to_vec();
        if record.is_empty() {
            break; // the peer's close_notify
        }
        tls.consume(record.len());
        tls.write_all(&record).await?;
        tls.flush().await?;
    }
    tls.shutdown().await
}
```

`get_ref` gives an `UnbufferedClientConnection` or
`UnbufferedServerConnection` (the negotiated parameters and exporters, no
reader, writer or I/O methods), and `into_parts` the connection with the
stream's buffers. The unbuffered connector does not send 0-RTT early data; a
server's accepted early data is collected during the handshake
(`TlsStream::early_data`), and the unbuffered acceptors have no
`early_data` option to return a stream before the handshake completes.
While more than 16 KiB of answers to the peer are unwritten, reads take no
more input.

Three things under Behaviour below are not there for these streams yet:
they have no `into_split` (`tokio::io::split` splits them), the `coop`
feature does not cover them, so they take nothing from the task budget
themselves (a transport that counts, such as Tokio's sockets, still does),
and their handshake futures give only the transport (`get_ref`, `get_mut`),
not the connection.

## Behaviour

- **Flushing.** Records the transport does not take at once stay queued: call
  `flush` when a batch of writes is done.
- **Closing.** `shutdown` sends `close_notify`, then shuts the transport's
  write side; later writes fail with `BrokenPipe` (RFC 9846 §6.1). The peer's
  `close_notify` reads as end of file; a transport that ends without one fails
  the read with `UnexpectedEof` (a truncation).
- **Splitting.** `into_split` on a stream gives a `ReadHalf` and a
  `WriteHalf` for two tasks, and `reunite` gives the stream back. TLS ties
  both directions to one connection state, so the halves take turns with the
  stream, one poll at a time. They never wait for each other's poll: a half
  that finds the other half's poll in progress returns `Pending` and is
  woken when that poll ends (turns are not queued, so it may find the stream
  taken again). If a poll of one half panics, every later operation of
  either half fails. `tokio::io::split` works too; it takes a blocking
  lock for every poll (a worker thread waits while the other half's poll
  runs, record protection included) and needs Tokio's `io-util` feature.
- **Errors.** TLS failures are `io::Error`s of kind `InvalidData` wrapping a
  `browntls_core::Error` (`err.get_ref()` then `downcast_ref`).
- **Handshake state.** The handshake futures (`Connect`, `Accept` and their
  fallible forms) give the connection through `connection()` and
  `connection_mut()` while the handshake runs, as `get_ref()` gives the
  transport: a caller that polls the future itself can see, say, the server
  name and ALPN protocol as soon as the ClientHello was processed (not
  authenticated until the handshake completes).
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
to `browntls-core`.

`coop` (default) makes the streams take part in Tokio's cooperative
scheduling (see above). It enables Tokio's `rt` feature, which is where Tokio
keeps the task budget; `rt` adds no dependency, and an application that runs
a Tokio runtime has it enabled already. Without `coop` the crate uses Tokio's
I/O traits only and takes nothing from the budget itself (a transport that
counts still does).

`ocsp` enables `browntls_tokio::revocation` (see above). It enables Tokio's
`time` feature for the deadlines, which adds no dependency.

`dtls` enables the datagram client described above and Tokio's `net` and
`time` features. It adds no dependency and leaves the default feature set
unchanged.

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
