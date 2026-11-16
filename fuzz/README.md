# Fuzz targets

A [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) project for the
untrusted-input surfaces of browntls (message codecs, the record deframer,
certificate decompression, the PKI parsers and path validation, the client and
server handshake state machines) and for the whole public API of the three
library crates, through API targets grouped by topic.

The project is not a member of the workspace. It has its own `Cargo.toml` and
`Cargo.lock`, depends on `browntls` with the `fuzzing` feature (unstable entry
points into otherwise private codecs, `browntls::fuzzing`; not a supported API)
and on `rcgen` for certificates generated at start-up. It enables both the
`native` and the `rustcrypto` providers, so the library has no implicit default
provider; harnesses call `browntls_fuzz::init()` to install the native one.
The crypto targets also depend on the RustCrypto crates that `browntls-crypto`
uses as test oracles. No private key, corpus or crash artifact is committed.

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

### Public API targets

Each API target is a module `src/<target>.rs` (with private submodules in
`src/<target>/`) exposing `run` and `seeds`. `run` decodes its input with
`src/input.rs` as a short program: an operation selector, then fuzzed
arguments, repeated up to a fixed number of operations. Results are checked,
not only produced: against an independent implementation where one exists
(the RustCrypto crates, `std::net`, a model written in the harness), between
the portable and every accelerated backend the CPU has (`accel` policies and
explicit backends), and by round trips, tamper rejection and re-encoding
stability.

| Target | Topic | Reaches |
|---|---|---|
| `crypto_hash` | crypto-symmetric | SHA-1, SHA-2, SHA-3, SHAKE and the 4-way SHAKE, Keccak-f, HMAC, HKDF, the TLS 1.2 PRF; one-shot, chunked and cloned states against the oracles under every acceleration policy |
| `crypto_cipher` | crypto-symmetric | AES (every backend), AES-GCM, AES-CCM (every parameter set), ChaCha20, Poly1305, ChaCha20-Poly1305, AES-CBC and the TLS 1.2 CBC record transform; oracle outputs, tamper rejection, wiped buffers on failure |
| `crypto_ecc` | crypto-asymmetric | X25519, X448, Ed25519, Ed448, P-256, P-384 and P-521 ECDH and ECDSA; key and signature decoding, agreement and verdicts against the oracles and between backends |
| `crypto_rsa` | crypto-asymmetric | RSA public and private keys (DER, components), PKCS#1 v1.5 and PSS signing and verification on every backend, against a num-bigint reference |
| `crypto_kem` | crypto-asymmetric | ML-KEM-512/768/1024 key generation, encapsulation, decapsulation (implicit rejection) and key parsing against the `ml-kem` oracle; FFDHE peer validation and agreement against num-bigint |
| `crypto_hpke` | crypto-asymmetric | HPKE identifiers, keys and sessions (seal, open, export, sequence numbers) byte for byte against the `hpke` oracle; the TLS-side HPKE provider |
| `crypto_util` | crypto-util | The DER reader and writer against a reference TLV parser, constant-time helpers, zeroization, random sources, CPU feature detection and acceleration policies |
| `pki_api` | pki | Server names and IP addresses against `std::net`, times, algorithm identifiers, RSASSA-PSS parameters, DER containers, PEM, certificates and path validation against a model, signatures and CRLs with real providers |
| `tls_config` | tls-config | Client and server configuration builders, providers and cipher suites, signers, verifiers and root stores, ticketers, certificate compression, key logs, session caches and certificate resolvers |
| `tls_conn` | tls-connection | An in-process client and server driven by API calls: transfers with damaged bytes, reader and writer, early data, close_notify, key updates, exporters, `complete_io`, `Stream`, `Acceptor`, accessors, secret extraction |
| `tls_unbuffered` | tls-connection | The unbuffered API of both sides with fuzzed buffer sizes, damaged delivery, early data, key updates and exporters |
| `tls_ech` | tls-extensions | ECH configuration lists, server keys, SVCB records and handshakes (accepted, rejected with retry configurations, GREASE) |
| `tls_psk` | tls-extensions | External PSKs, the RFC 9258 importer and RFC 8773, with handshakes using matching and differing PSKs |
| `tls_auth` | tls-extensions | Delegated credentials (decoding, issuing, validity windows, handshakes) and exported authenticators between connected peers |
| `tls_codec` | tls-codec | The doc-hidden codec re-exports, record payload types, distinguished names and stored session values |

The protocol targets generate certificates and keys once per process and
handshake randomness comes from the operating system, as in the connection
targets below.

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

## Public API coverage

Together the targets must reach every `pub fn` of `browntls`,
`browntls-crypto` and `browntls-pki`. `scripts/fuzz/api_coverage.py` checks
it: it builds the library tests above with LLVM source-based coverage, runs
them, and fails for any public function (outside test modules) whose body
never ran. A function defined in a macro must run in every expansion.

```sh
rustup component add llvm-tools
python3 scripts/fuzz/api_coverage.py run      # or: list, check <llvm-cov export>
```

A function that cannot be reached from outside the crate goes into
`api-coverage-exemptions.txt` with its reason; an exemption that no longer
matches a missing function fails the check, so the list only shrinks. The
check runs on x86-64; a public function compiled only for another architecture
would be reported as not compiled and need an exemption (there is none today).
Coverage counts everything the tests run, seed generation included, and the
seeds contain certificates with fresh random keys, so a function reached only
through a mutated seed could pass in one run and fail in the next; no such
case is known.

## Continuous fuzzing

The [Fuzz workflow](../.github/workflows/fuzz.yml) runs the targets as a GitHub
Actions matrix built by `scripts/fuzz/plan.py` from `targets.toml`, which
gives each target a topic and the source files it covers. Every job runs on
one x86-64 runner (`ubuntu-26.04`):

- Pull requests fuzz, for two minutes each, the targets whose sources or
  harness changed; a change to the shared fuzz infrastructure selects every
  target.
- A daily run fuzzes every target for twenty minutes and keeps each target's
  minimized corpus in the Actions cache, which later runs start from.
- A manual run chooses the targets, the time per target and the
  granularity: one job per target, or one per topic running its targets one
  after another.

Every job builds with AddressSanitizer and debug assertions, which include
overflow checks. The `api-coverage` job runs the coverage check above.

CI therefore fuzzes the x86-64 backends and the portable code only. The
aarch64 and riscv64 backends are compared with the portable code by the
native and QEMU test jobs of the [Rust workflow](../.github/workflows/rust.yml)
instead; to fuzz them, run `scripts/fuzz/run-targets.sh` on such a machine
(`FUZZ_SANITIZER=none` on riscv64, where Rust has no AddressSanitizer
runtime).

`scripts/fuzz/run-targets.sh SECONDS TARGET...` is what each job runs and
works the same locally (set `FUZZ_TOOLCHAIN` to the workflow's nightly). Since
CI logs of this repository are public, a failing target prints only its name,
the kind of finding, libFuzzer's seed, its final statistics and the SHA-256 of
the input. The input and the log are not uploaded and are lost with the
runner, and the seed alone does not replay the run (the starting corpus and
the generated certificates differ), so a CI finding is a signal: fuzz that
target locally until it reproduces, and handle the result as a potential
vulnerability, as described under [Running](#running). A topic-granularity run
keeps its own corpus, separate from the per-target corpora of the daily run.

Record each manual campaign (revision, toolchain, targets, duration, result)
with the change it supports.
