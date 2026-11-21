# browntls

The crate applications depend on: the TLS 1.2 and TLS 1.3 library of the
[browntls](https://github.com/OxiBelt/browntls) project, with its
asynchronous Tokio streams and its Linux kernel TLS offload behind features.

> **Status.** browntls is in initial development, has not been independently
> reviewed or audited, and has no published release.

The crate has no code of its own. Its root is
`browntls-core` (the protocol, DTLS 1.3 in `browntls::dtls` as a low-level
datagram API and blocking `UdpClient` and `UdpServer` over
`std::net::UdpSocket`, the crypto provider mount point and the built-in
providers), and two features add the project's other library crates as
modules:

| Feature | Module | Crate |
|---|---|---|
| (always) | the crate root | `browntls-core` |
| `tokio` | `browntls::tokio` | [`browntls-tokio`](../browntls-tokio/README.md): `TlsConnector`, `TlsAcceptor` and their streams |
| `ktls` | `browntls::ktls` | [`browntls-ktls`](../browntls-ktls/README.md): `KtlsStream`, and `AsyncKtlsStream` together with `tokio` |

```toml
[dependencies]
browntls = { git = "https://github.com/OxiBelt/browntls", features = ["tokio", "ktls"] }
# The runtime stays the application's own dependency.
tokio = { version = "1.53", features = ["rt-multi-thread", "macros", "net", "io-util"] }
```

The items are the ones those crates define, not copies:
`browntls::ClientConfig` and `browntls_core::ClientConfig` are one type, so a
library written against `browntls-core` or `browntls-tokio` works with an
application that depends on `browntls`.

## Tokio

The module `browntls::tokio` has the name of the Tokio crate. Name its items
by path, as below, or import it under another name
(`use browntls::tokio as tls;`). After `use browntls::tokio;` or
`use browntls::*;` the name `tokio` means this module in that scope, and
`tokio::net::TcpStream` or `#[tokio::main]` no longer compile there.

```rust,no_run
use std::sync::Arc;

use browntls::pki_types::ServerName;
use browntls::tokio::TlsConnector;
use browntls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

# async fn run(roots: RootCertStore) -> std::io::Result<()> {
let config = ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
let connector = TlsConnector::from(Arc::new(config));

let tcp = TcpStream::connect("example.com:443").await?;
let name = ServerName::try_from("example.com").expect("valid DNS name");
let mut tls = connector.connect(name, tcp).await?;

tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await?;
tls.flush().await?;
let mut response = Vec::new();
tls.read_to_end(&mut response).await?;
# Ok(())
# }
```


## Choosing a post-quantum hybrid group

Both built-in providers support the three RFC 10024 groups. To require
`SecP384r1MLKEM1024`, set the provider's group list before building each
endpoint's configuration. This example uses the native provider.

```rust
use std::sync::Arc;
use browntls::{ClientConfig, ServerConfig, crypto::native, version::TLS13};

let mut provider = native::default_provider();
provider.kx_groups = vec![native::kx_group::SECP384R1MLKEM1024];
let provider = Arc::new(provider);

let client = ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&TLS13]).unwrap();
let server = ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&TLS13]).unwrap();
// Complete the builders with the usual verifier and certificate settings.
```

The same group policy applies through the core, Tokio and DTLS APIs, the
QUIC v1 handshake, and the handshake that precedes a kTLS handoff. Use
`negotiated_key_exchange_group()` on the connection to inspect the result.
The matching RustCrypto provider and group are in `crypto::rustcrypto`.


## Kernel TLS (Linux)

The handshake runs in userspace; the kernel then encrypts and decrypts
application data. The configuration must set `enable_secret_extraction`.

```rust,no_run
use std::io::{Read, Write};
use std::sync::Arc;

use browntls::ktls::KtlsStream;
use browntls::{ClientConfig, ClientConnection};

# fn run(config: Arc<ClientConfig>) -> Result<(), Box<dyn std::error::Error>> {
let tcp = std::net::TcpStream::connect("example.com:443")?;
let conn = ClientConnection::new(config, "example.com".try_into()?)?;
// Completes the handshake, then hands the connection to the kernel.
let mut tls = KtlsStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
let mut response = Vec::new();
tls.read_to_end(&mut response)?;
# Ok(())
# }
```

## Features

Every feature turns on the feature of the same name in the crates behind
this one that have it. The default set is `browntls-core`'s plus `coop`.

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | Buffered I/O helpers, `KeyLogFile`, in-memory session caches, the process-wide default provider |
| `alloc` | with `std` | Present for symmetry with `browntls-core`, which always needs `alloc` |
| `native` | yes | The built-in provider backed by `browntls-crypto` |
| `rustcrypto` | no | A provider backed by the RustCrypto crates. Together with `native` there is no implicit process default: install or pass a provider |
| `tls12` | yes | TLS 1.2 |
| `logging` | yes | Debug logging through the `log` crate |
| `prefer-post-quantum` | yes | X25519MLKEM768 first in the default key exchange groups |
| `zlib`, `brotli`, `zstd` | no | Built-in certificate compression (RFC 8879); `brotli` enables `std` |
| `tokio` | no | `browntls::tokio`; enables `std` |
| `coop` | yes | With `tokio`: take part in Tokio's cooperative scheduling. Without `tokio` it does nothing |
| `ocsp` | no | `browntls::tokio::revocation`; enables `tokio` |
| `ktls` | no | `browntls::ktls`; enables `std`. Linux only: elsewhere the module holds the kernel-independent types alone |

`browntls-core`'s `fuzzing` feature (unstable entry points for the fuzz
targets) is deliberately not offered here. Cargo builds one `browntls-core`
for a whole dependency graph, so its items appear at this crate's root as
well if another package enables that feature.

Without `std` the crate is `#![no_std]` with `alloc`, as `browntls-core` is.

## License

[Apache-2.0](LICENSE).
