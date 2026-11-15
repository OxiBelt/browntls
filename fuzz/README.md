# Fuzz targets

A [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) project for the
untrusted-input surfaces of browntls: message codecs, the record deframer,
certificate decompression, the PKI parsers and path validation, and the client
and server handshake state machines.

The project is not a member of the workspace. It has its own `Cargo.toml` and
`Cargo.lock`, depends on `browntls` with the `fuzzing` feature (unstable entry
points into otherwise private codecs, `browntls::fuzzing`; not a supported API)
and on `rcgen` for certificates generated at start-up. No private key, corpus
or crash artifact is committed.

## Targets

| Target | Input | Reaches |
|---|---|---|
| `handshake_message` | version and framing byte, then a handshake message or the body of a selected message type | Every handshake message decoder for TLS 1.2 and TLS 1.3; a decoded message must re-encode to something that decodes, with a stable encoding |
| `deframer` | mode byte, then a byte stream or one record payload | Record headers, handshake reassembly across records, alert and change_cipher_spec decoding |
| `cert_decompress` | limit selector, then a `CompressedCertificate` body | The zlib, Brotli and Zstandard decompressors under the RFC 8879 length rules, then the Certificate decoder; a result longer than the declared or permitted length is a failure |
| `pki_cert` | flags, then length-prefixed end entity, two intermediates, trust anchor, CRL and name | X.509 parsing, trust anchor extraction, name matching, path building with budgets, revocation checking, raw public keys |
| `pki_pem` | PEM text | Section iteration, Base64, every `PemObject` type |
| `pki_crl` | flags, serial number, issuer key, then a CRL | Borrowed and owned CRL parsing, which must agree; entry iteration, serial lookup, signature dispatch |
| `client` | mode, cut, then bytes for the client | `ClientConnection` through `read_tls` and `process_new_packets` |
| `server` | mode, cut, then bytes for the server | `ServerConnection` likewise |

`browntls-pki` has no cryptography of its own, so `pki_cert` and `pki_crl`
supply stand-in signature algorithms that accept everything, reject
everything, or decide from a signature byte. Path building therefore runs to
its full depth on forged chains, which real providers would stop at the first
signature.

### Connection targets

Mutation cannot produce a valid key share, signature or protected record, so
raw bytes alone stop at the first handshake message. The `client` and `server`
harnesses add two devices (`src/connection.rs`):

- A genuine peer in the same process delivers the first zero to three flights
  of a real handshake, optionally with records dropped from the end of the
  last one. The fuzzed bytes follow from that state, including after a
  completed handshake (tickets, KeyUpdate, alerts, application data).
- A provider variant replaces TLS 1.3 record protection with the identity
  transform, so that records written by the fuzzer are accepted as plaintext
  once handshake keys exist. That exposes EncryptedExtensions,
  CertificateRequest, Certificate, CompressedCertificate and post-handshake
  messages. Key exchange, the key schedule, Finished and signatures stay real.

The mode byte selects the provider variant, client authentication, TLS 1.2
only, raw or record-framed input, and the number of genuine flights.
Configurations are fixed for the process. Handshake randomness comes from the
operating system, so the genuine flights differ between executions and inputs
that depend on them do not replay byte for byte; a finding is reported with the
input and the behaviour, and the fuzzed part does reproduce.

TLS 1.2 keeps real record protection: after its ChangeCipherSpec only
undecryptable records can be injected.

## Running

Fuzzing needs a nightly toolchain and `cargo-fuzz`; nothing else in the
repository does.

```sh
cd fuzz
cargo run --example seed_corpus          # writes corpus/<target>/seed-NNN
cargo +nightly fuzz run handshake_message -- -max_total_time=60
```

For `cert_decompress`, add `-malloc_limit_mb=4`: libFuzzer then reports any
single allocation above 4 MiB, which the decompressors must never make
whatever a stream declares.

`cargo fuzz list` prints the targets. Crashes land in `artifacts/<target>/`;
`cargo +nightly fuzz run <target> artifacts/<target>/<file>` replays one. Treat
a crash as a potential vulnerability: follow [SECURITY.md](../SECURITY.md), do
not attach inputs to public issues, and keep evidence in the private
repository named in [Maintenance](../docs/Maintenance.md#private-security-evidence).

## Checks on the stable toolchain

The harness bodies live in the library (`src/`), the targets in
`fuzz_targets/` are one line each. CI builds everything and runs every harness
over its generated seeds, their truncations and a few mutations with the pinned
stable toolchain, so the harnesses keep compiling and keep reaching a
completed handshake. This is a smoke test, not fuzzing:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path fuzz/Cargo.toml --locked
```

CI does not run the fuzzers themselves; there is no continuous fuzzing
service. Record each manual campaign (revision, toolchain, targets, duration,
result) with the change it supports.
