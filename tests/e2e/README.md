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
