# Docker end-to-end tests

These tests run browntls against other TLS implementations over a real
network: every peer runs in its own container on a run-specific Docker network,
and the browntls side is the release build of
[`browntls-e2e`](../../crates/browntls-e2e/src/main.rs), a small command-line
client and server, statically linked for the target architecture. It depends
on the [`browntls`](../../crates/browntls/README.md) facade crate alone, with
the `tokio` feature and without `ktls`, so the matrix runs the library
through the paths an application uses.
[`e2e.py`](e2e.py) defines the matrix, the scenarios and the checks, and
[`.github/workflows/e2e.yml`](../../.github/workflows/e2e.yml) runs them in CI.

They complement, and do not replace, the in-process handshake suites and the
loopback OpenSSL interop tests in `crates/browntls-core/tests/`. A passing run
is evidence for the configurations listed here only.

## Matrix

Each CI job pairs one architecture with one peer suite.

| Architecture | Runner | browntls build |
|---|---|---|
| `amd64` | GitHub-hosted `ubuntu-26.04` | `x86_64-unknown-linux-musl`, `-C target-cpu=x86-64-v3` (the minimum x86-64 level) |
| `arm64` | GitHub-hosted `ubuntu-26.04-arm` | `aarch64-unknown-linux-musl` |
| `riscv64` | RISE `ubuntu-24.04-riscv` (native RV64GC hardware) | `riscv64gc-unknown-linux-musl` |
| `riscv64-zvk` | `ubuntu-26.04`, browntls under QEMU user-mode emulation (RVV 1.0, VLEN 256, vector crypto) | `riscv64gc-unknown-linux-musl` asserting `v` and the Zvk extensions |

| Suite | Peer |
|---|---|
| `openssl` | OpenSSL 3.5 or later from Alpine 3.24 ([`peer/alpine.Dockerfile`](peer/alpine.Dockerfile)), with X25519MLKEM768 |
| `openssl-3.0` | OpenSSL 3.0 from Ubuntu 24.04 LTS ([`peer/ubuntu.Dockerfile`](peer/ubuntu.Dockerfile)), without post-quantum groups |
| `openssl-ubuntu-26.04` | OpenSSL 3.5 from Ubuntu 26.04 LTS ([`peer/ubuntu-26.04.Dockerfile`](peer/ubuntu-26.04.Dockerfile)), with X25519MLKEM768; not on `riscv64`, whose runner lacks the RVA23 profile Ubuntu 26.04's riscv64 image requires |
| `gnutls` | GnuTLS 3.8 from Alpine 3.24 |
| `browntls` | browntls client and server in separate containers |
| `go` | Go 1.27 `crypto/tls` ([`peer/go.Dockerfile`](peer/go.Dockerfile), the program in [`peer/go/`](peer/go/main.go)): Encrypted Client Hello scenarios only |

Peer containers run natively on the runner; only the browntls containers use
the target platform, so in the emulated job the peers are not slowed down.
CI keeps each peer image in the Actions cache per runner label for an ISO week
and until `peer/` changes: runs on `main` save it, every other run restores
it, and a job builds the image (`build-peer`) only when the cache has none. The
distribution archives the peer images install from have been slow enough from
the x86-64 runners to time a build out.
Before the scenarios run, the harness records which acceleration backend
`browntls-e2e info` reports for each algorithm family and fails if an
architecture's expected accelerated families (AES-NI, PCLMULQDQ, AVX2 and
BMI2/ADX on x86-64-v3; AES, PMULL and SHA2 on the Arm runners; Zvkned, Zvkg,
Zvknh and RVV in the emulated RISC-V job) fell back to portable code.

## Scenarios

`python3 tests/e2e/e2e.py list` prints the scenarios of each suite. Each one
runs with browntls as client against the peer's server and, where the scenario
allows it, with browntls as server against the peer's client:

- both sides on their defaults (X25519MLKEM768 with a post-quantum peer,
  X25519 otherwise);
- TLS 1.3 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 over X25519,
  P-256, P-384 and X25519MLKEM768, with ECDSA P-256, RSA 2048 and Ed25519
  certificates;
- a HelloRetryRequest (the server accepts only P-256, which the browntls
  client does not send a key share for by default);
- client authentication in TLS 1.3 and TLS 1.2;
- session resumption in TLS 1.3 and TLS 1.2 (browntls client, second
  connection must be resumed);
- TLS 1.2 ECDHE-ECDSA and ECDHE-RSA with AES-GCM, ChaCha20-Poly1305 and AES-CBC
  with Encrypt-then-MAC;
- a TLS 1.2 CBC peer without Encrypt-then-MAC: browntls must refuse it by
  default (and fail for that reason), and must complete the handshake when
  `allow_mac_then_encrypt` is set;
- the optional extensions in TLS 1.3 (also with resumption and with client
  authentication) and TLS 1.2: a `record_size_limit` of 512 (RFC 8449) on
  the browntls side, which a peer implementing it (GnuTLS) must respect;
  GREASE values (RFC 8701) on the browntls side, in the ClientHello of a
  client and in the TLS 1.3 NewSessionTicket and CertificateRequest messages
  of a server (`tls13-optional-extensions-client-auth` has the peer client
  answer a GREASE CertificateRequest with its certificate); and, as a
  browntls client, `ticket_request` (RFC 9149) and a ClientHello padded to
  1024 bytes (RFC 7685);
- the asynchronous streams of `browntls-tokio`, reached as `browntls::tokio`
  (`browntls-e2e --async`, a single-threaded Tokio runtime, confirmed by
  `"io":"async"` in the output):
  TLS 1.3 with client authentication and TLS 1.2 in both roles, and TLS 1.3
  resumption as a client;
- Encrypted Client Hello (RFC 9849, suites `browntls` and `go`), with keys
  made per run by `browntls-e2e ech-keygen` (X25519, public name
  `ech-public.test`) in both server topologies. Shared mode (`ech-shared*`):
  one server decrypts and terminates; the peer is client or server. Split
  mode (`ech-split*`): a browntls client-facing server
  (`browntls-e2e client-facing`, network alias `tls-server`) decrypts the
  ClientHello and relays the connection to a browntls back-end server
  (`server --ech-backend`, alias `ech-backend`), so these run with the
  peer as client only (Go has no split-mode server). Each topology runs
  accepted, after a HelloRetryRequest (the terminating server accepts only
  P-256), and with a stale configuration the client retries with the
  server's retry configurations; plus GREASE, and in split mode random
  configuration identifiers with trial decryption and the public name check
  (browntls client only). The harness checks the ECH status and handshake
  kind on every side, the server name the terminating server saw (the inner
  one), the client-facing server's decisions (`Forward` for an accepted
  offer, `Local` for a rejection it completes itself as the public name),
  the single rejection before a retry, and the application data.

For every connection the harness checks the protocol version, cipher suite,
key exchange group and handshake kind the browntls side reports, the
certificates it received, and one line of application data in each direction.
Certificates and keys are generated per run, inside a Docker volume, by
[`peer/gen-pki.sh`](peer/gen-pki.sh) (including the certificate for the ECH
public name) and, for the ECH scenarios, `browntls-e2e ech-keygen`.

## Running locally

Requirements: Docker (rootful or rootless), Python 3.10 or newer, and the
toolchain from `rust-toolchain.toml` with the musl target of the architecture
(for example `rustup target add x86_64-unknown-linux-musl`). The binary is
linked by `rust-lld`, so no C cross toolchain is needed. Running another
architecture's image needs QEMU user-mode emulation registered with
`binfmt_misc`.

```sh
python3 tests/e2e/e2e.py build --arch amd64
python3 tests/e2e/e2e.py run --arch amd64 --suite openssl
python3 tests/e2e/e2e.py run --arch amd64 --suite gnutls --scenario tls13-client-auth
python3 -B -m unittest discover -s tests/e2e -p 'test_*.py'
```

`run` builds the suite's peer image first (`--skip-peer-build` uses an existing
one, for example one built by `build-peer --suite S`, which can also `--save`
it) and writes per-scenario logs, `results.json` and `summary.md` to
`--artifact-dir` when given. The harness creates one network, one volume and
short-lived containers per run, all labelled
`org.oxibelt.browntls-e2e.run=<run id>`, and removes exactly those resources
when the run ends, including on failure. It uses no bind mounts, so it also
works with a remote Docker daemon.

## Limitations

- The native RISC-V runners have no RVV 1.0, so they exercise the scalar and
  portable backends; vector and vector-crypto backends are exercised only under
  QEMU, whose `riscv_hwprobe` does not report the vector crypto extensions (the
  `riscv64-zvk` image therefore asserts them at build time).
- Peer package versions follow the pinned base images' distribution
  repositories at build time, which in CI can be up to a week before the run
  (see the cache above); the job summary records the versions used.
- The scenarios cover the default and selected explicit configurations, not
  every suite and group combination; the in-process suites cover those.
- Encrypted Client Hello in split mode has browntls on both server sides:
  no other implementation in the matrix has a client-facing or back-end
  server, so the independent check is the Go client, which verifies the
  back-end server's acceptance confirmations through the browntls relay.
  Go's server is shared mode only, and it neither sends GREASE ECH nor
  randomizes configuration identifiers, so those scenarios have a browntls
  client.

<a id="dtls-13-interoperability"></a>

## DTLS interoperability

Run from the repository root with Docker and the musl Rust target for the
chosen architecture installed. Use a separate image tag for the DTLS peer.

```sh
python3 tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:dtls-amd64
python3 -B tests/e2e/dtls.py --arch amd64 --image browntls-e2e:dtls-amd64
python3 -B -m unittest discover -s tests/e2e -p 'test_dtls.py'
```

The default `--suite all` runs DTLS 1.3 against wolfSSL and DTLS 1.2 against
OpenSSL. Select `--suite wolfssl` or `--suite openssl` to run one peer only:

```sh
python3 -B tests/e2e/dtls.py --arch amd64 --image browntls-e2e:dtls-amd64 --suite openssl
python3 -B tests/e2e/dtls.py --arch amd64 --image browntls-e2e:dtls-amd64 --suite wolfssl
python3 -B tests/e2e/dtls.py --arch amd64 --image browntls-e2e:dtls-amd64 --suite wolfssl-cid
```

The opt-in `wolfssl-cid` suite runs both roles with DTLS 1.2 RFC 9146 and
DTLS 1.3 initial connection IDs. Both peers opt in to nonempty receiving
IDs; wolfSSL requires nonempty negotiated receive and transmit IDs before
the authenticated payload and close exchange. The runner also requires full
mutual certificate authentication and the expected version on both sides.
The suite does not exercise CID rotation, migration, or packet loss. It is
not included in `--suite all`. The browntls `--dtls-cid` switch selects an
eight-byte receiving ID and allows sending the peer's ID.

The runner builds the selected peer images and reuses the full mutual
authentication runner and ephemeral PKI generator. Each suite gets its own
run-specific Docker network and PKI volume, cleaned up by the existing
harness. Peers use ECDSA P-256 credentials and run as both client and server,
verify certificates, exchange exact request and reversed reply bytes (without
a newline), and check `close_notify` in each direction. The harness requires
successful exits on both sides, the selected DTLS version, a full handshake,
peer certificates, both payloads and closure. These default exchanges remain
one-shot. Pass `--skip-peer-build` to reuse previously built peer images.

Run the isolated DTLS 1.2 resumption cases explicitly after building an image
with the DTLS 1.2 resumption implementation:

```sh
python3 -B tests/e2e/dtls.py --arch amd64 --image browntls-e2e:dtls-amd64 --suite openssl --resumption
python3 -B -m unittest discover -s tests/e2e -p 'test_dtls*.py'
```

This selects exactly four cases: RFC 6347 session IDs and RFC 5077 tickets,
each with browntls as client and as server. Each case requires an initial
full mTLS handshake, then both peers must report `Resumed` on a fresh
connection. Each handshake must exchange the exact payloads and complete
bidirectional closure. The harness checks two ordered connection records
from each peer, including the mechanism, version, cipher and retained peer
certificates; OpenSSL additionally checks EMS on each handshake. A second
full handshake fails the case. The existing six default exchanges and the
TLS matrix are unchanged.

The browntls peer uses `--tls 1.2 --dtls12-resumption session-id|ticket` with
`--connections 2` as client or `--accept 2` as server. It reuses one client
configuration/cache or server configuration/resumption context. The server
calls `ServerConfig::enable_dtls12_resumption()` after setting credentials
and the client verifier. Ticket mode installs a separate
`ServerConfig::dtls12_ticketer` with independent keys and disables session-ID
storage; ID mode keeps tickets disabled and uses a bounded memory cache.
The client selects `Tls12Resumption::SessionIdOnly` or
`SessionIdOrTickets`; ticket isolation is enforced by disabling ID storage
on the selected server. These APIs must be integrated before compiling.

The OpenSSL peer's optional final argument is `session-id` or `ticket`.
It keeps one `SSL_CTX` across two fresh `SSL` objects and, as client,
retains an `SSL_SESSION` and supplies it to the second handshake with
[`SSL_set_session`][openssl-set-session]. ID mode disables tickets; ticket
mode disables the ID cache. The server sets a fixed per-process mTLS
[session-ID context][openssl-session-context]. Both implementations retain
the UDP endpoint across orderly shutdowns, so the connected OpenSSL socket
continues to serve the same isolated peer without a rebind race. This is a
two-exchange oracle, not a multi-client server.

The browntls peer's existing repeatable `--tls` option selects the DTLS
endpoint policy: `--tls 1.2` uses `dtls::Versions::V1_2`, `--tls 1.3` uses
`V1_3`, and `--tls 1.2 --tls 1.3` uses `V1_2And1_3`. Omitting it preserves
the DTLS 1.3 default. The OpenSSL suite runs four exchanges: each browntls
role with DTLS 1.2 only, then each role explicitly permitting both DTLS 1.2
and 1.3. The mixed cases enable a suite for each version and must negotiate
DTLS 1.2 with OpenSSL.

[`peer/openssl-dtls.c`](peer/openssl-dtls.c) is a small independent OpenSSL
C peer because the OpenSSL CLI does not support `s_server -rev` with DTLS.
[`peer/openssl-dtls.Dockerfile`](peer/openssl-dtls.Dockerfile) uses the same
pinned Alpine 3.24 base as the existing OpenSSL suite. It installs the
distribution's OpenSSL 3.5 packages and builds with warnings treated as
errors; it downloads no separate sources. Build and runtime reject a
different OpenSSL minor version. Distribution package patch versions still
depend on the repositories at build time.

The OpenSSL peer uses a connected UDP datagram BIO, bounds socket I/O and
total runtime, verifies the server's DNS name as a client, and requires a
verified client certificate as a server. It restricts negotiation to DTLS 1.2
and `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` with P-256. After the handshake
it requires [extended master secret][openssl-ems]
and, by default, rejects a reused session before exchanging application data.
Session caching and tickets are disabled in that default mode. Success
requires both authenticated close alerts and a completed bidirectional shutdown.

The mock runner checks need no Docker or Cargo; they validate command
construction and success/failure gates, not a DTLS implementation. Actual
interoperability requires the Docker commands above. This bounded
oracle runs only on the isolated test network; it does not implement a
multi-client server, stateless cookie defense, or packet loss/reordering
testing. This suite is a separate runner; the existing TLS matrix and CI
workflow do not invoke it automatically.

[openssl-ems]: https://docs.openssl.org/3.5/man3/SSL_get_extms_support/
[openssl-set-session]: https://docs.openssl.org/3.5/man3/SSL_set_session/
[openssl-session-context]: https://docs.openssl.org/3.5/man3/SSL_CTX_set_session_id_context/

## Certificate with external PSK (RFC 9973)

Build the browntls peer image and the pinned wolfSSL 5.9.4 independent peer,
then run the four full handshakes:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:psk-amd64
python3 -B tests/e2e/extern_psk.py --image browntls-e2e:psk-amd64 --build-peer
python3 -B -m unittest discover -s tests/e2e -p 'test_extern_psk.py'
```

The runner covers browntls as client and server over TLS 1.3/TCP and
DTLS 1.3/UDP. It requires browntls to report the negotiated
`cert_with_extern_psk` result and peer certificate verification at the client,
checks both application payloads, and requires wolfSSL to complete with an
external PSK and verify the server certificate. TCP runs through
`browntls::tokio`. wolfSSL v5.9.4 is checksum-pinned and built with PSK,
TLS/DTLS 1.3, and certificate-with-external-PSK support.

The runner creates a uniquely named Docker network and volume and removes
those resources and its exact named containers on exit. A fresh random PSK is
sent through the container's standard input into a temporary volume file; its
bytes are not command-line arguments or log output. The generated CA and
certificates and the PSK are discarded with that volume. The peer image is
kept for reuse; select an unused `--peer-image` tag if you need to avoid
replacing an existing local image. These opt-in cases are not added to the
architecture matrix or its CI job.

## RFC 9525 service identity references

Build the browntls image and pinned OpenSSL 3.5 peer, then qualify DNS, IP,
URI, and SRV-ID SAN matches plus a CA-trusted DNS mismatch:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:identity-amd64
python3 -B tests/e2e/service_identity.py --image browntls-e2e:identity-amd64 --build-peer
python3 -B -m unittest discover -s tests/e2e -p 'test_service_identity.py'
```

The browntls client uses buffered Tokio over TCP. Each positive case checks the
reported service identity match and request/reply data. The negative case
trusts the generated certificate and requires an unrelated DNS reference to
fail authentication. Run-owned containers, network, and volume are cleaned
up; the shared OpenSSL image is retained.
