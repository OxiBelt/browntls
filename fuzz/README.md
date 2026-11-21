# Fuzz targets

A [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) project for the
untrusted-input surfaces of browntls (message codecs, the record deframer,
certificate decompression, the PKI parsers and path validation, the client and
server handshake state machines) and for the whole public API of four
library crates (`browntls-crypto`, `browntls-pki`, `browntls-core` and
`browntls-tokio`), through API targets grouped by topic. `browntls-ktls` is
not fuzzed, and the facade `browntls` has no function of its own.

The project is not a member of the workspace. It has its own `Cargo.toml` and
`Cargo.lock`, depends on `browntls-core` with the `fuzzing` feature (unstable
entry points into otherwise private codecs, `browntls_core::fuzzing`; not a
supported API) and on `rcgen` for certificates generated at start-up. It names
the library crates directly, not through the facade `browntls`, which does not
offer `fuzzing`. It enables both the
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
the portable and every accelerated backend the CPU has (`accel` policies,
explicit backends, and `accel::load` routing with a fuzzed share of the calls
fixed on a fuzzed alternate backend), and by round trips, tamper rejection
and re-encoding stability.

| Target | Topic | Reaches |
|---|---|---|
| `crypto_hash` | crypto-symmetric | SHA-1, SHA-2, SHA-3, SHAKE and the 4-way SHAKE, Keccak-f, HMAC, HKDF, the TLS 1.2 PRF; one-shot, chunked and cloned states against the oracles under every acceleration policy |
| `crypto_cipher` | crypto-symmetric | AES (every backend), AES-GCM (also with load-aware routing between its AES backends), AES-CCM (every parameter set), ChaCha20, Poly1305, ChaCha20-Poly1305 (also with load-aware routing between its ChaCha20 backends), AES-CBC and the TLS 1.2 CBC record transform; oracle outputs, tamper rejection, wiped buffers on failure |
| `crypto_ecc` | crypto-asymmetric | X25519 (also with load-aware routing between its backends), X448, Ed25519, Ed448, P-256, P-384 and P-521 ECDH and ECDSA (public keys, agreement, signing and verification also with load-aware routing between their backends) and their field, scalar and point arithmetic (against num-bigint and the RustCrypto scalars, points and SEC 1 decoders, on both backends); key and signature decoding, agreement and verdicts against the oracles and between backends |
| `crypto_rsa` | crypto-asymmetric | RSA public and private keys (DER, components), PKCS#1 v1.5 and PSS signing and verification on every backend (signing also with load-aware routing between them, for the 2048- and 3072-bit keys of the harness), against a num-bigint reference |
| `crypto_kem` | crypto-asymmetric | ML-KEM-512/768/1024 key generation, encapsulation, decapsulation (implicit rejection) and key parsing against the `ml-kem` oracle, on every backend and with load-aware routing between them; FFDHE peer validation and agreement against num-bigint |
| `crypto_hpke` | crypto-asymmetric | HPKE identifiers, keys and sessions (seal, open, export, sequence numbers) byte for byte against the `hpke` oracle; the TLS-side HPKE provider |
| `crypto_util` | crypto-util | The DER reader and writer against a reference TLV parser, constant-time helpers, zeroization, random sources, CPU feature detection, acceleration policies, the load-aware routing controls (`accel::load`: configurations, stream status, fixed shares) and kernel TLS in the routing order (`accel::load::kernel`: activation, placement of connections, reported writes, fixed shares) |
| `pki_api` | pki | Server names and IP addresses against `std::net`, times, algorithm identifiers, RSASSA-PSS parameters, DER containers, PEM, certificates and path validation against a model, signatures and CRLs with real providers, certificate extensions, alternative names and X.501 names against an independent DER reading and a model of the `Name` parsing rules, `SignedData` against the algorithm model, path validation and `RawPublicKeyEntity` |
| `pki_revocation` | pki | Signed OCSP and SCT evidence, Clubcard snapshots and ordered deltas, revocation pause and resume over buffered TLS and QUIC, in-memory Tokio connections over both TLS drivers with live lookup, response caching, and staple refresh, RFC 9162 transparency lists, items, SCT v2 and tree head verification, and Merkle proofs, and the RFC 9162 `transparency_info` extension and CT 2.0 client policy over buffered and unbuffered TLS 1.2 and 1.3 handshakes |
| `tls_config` | tls-config | Client and server configuration builders, providers and cipher suites, signers, verifiers and root stores, ticketers, certificate compression, key logs, session caches and certificate resolvers, `trusted_ca_keys` identifiers from fuzzed certificates and its resolver over TLS 1.2 and 1.3 handshakes |
| `tls_conn` | tls-connection | An in-process client and server driven by API calls: transfers with damaged bytes, reader and writer, early data, close_notify, key updates, exporters, `complete_io`, `Stream`, `Acceptor`, accessors, secret extraction |
| `tls_tokio` | tls-connection | `browntls-tokio`: connector entry points, acceptor, lazy acceptor (including refusals and `take_io`), fallible futures, client and server streams and their accessors, split halves and their reunion, 0-RTT on resumed connections (read by the server after the handshake, or before its end from a stream returned early, with 0.5-RTT answers), the kernel handoff of a stream (a ready stream has no blocker and its connection's handover succeeds; the plaintext set aside continues what was read, with a server's unread 0-RTT data counted in front; a server's stream returned early has its handshake completed first; refused, abandoned and turned-back streams carry on), over an in-memory transport with fuzzed chunk sizes, `Pending` patterns, damaged, inserted and ended bytes |
| `tls_tokio_unbuffered` | tls-connection | `browntls_tokio::unbuffered`: connector entry points, acceptor, lazy acceptor (`into_stream`, `into_parts` and `from_parts`, refusals, `take_io`), fallible futures, client and server streams against each other and against the buffered streams of the crate root, plain and vectored writes, `poll_read` and `poll_fill_buf`, key updates, post-handshake authentication, 0-RTT data a server accepts, `into_parts` with the connection driven by hand afterwards, over an in-memory transport with fuzzed chunk sizes, `Pending` patterns, capacity, damaged, inserted and ended bytes and failing reads and writes; optionally with identity record protection, so that forged records (KeyUpdate requests, alerts, data) are accepted. On an undisturbed connection nothing may fail or stall and everything written must arrive; a failure must stay one; what a stream buffers must stay bounded |
| `tls_unbuffered` | tls-connection | The unbuffered API of both sides with fuzzed buffer sizes, damaged delivery, early data, key updates and exporters |
| `tls_kernel` | tls-connection | Kernel TLS offload (`browntls_core::kernel`): handover blockers against the handover's result (buffered and unbuffered API, both sides, both providers, suites with and without a kernel form), `bytes_to_record_boundary` against the record headers, then a `KernelConnection` driven through a stand-in for Linux kernel TLS that protects records with the extracted secrets: data, KeyUpdate, close_notify and post-handshake authentication from the peer, `records_sent` around the confidentiality limit, fuzzed `handle_record` input; output order (RxKeys, owed KeyUpdate then TxKeys), nothing but alerts after a failure, no key in `Debug` |
| `tls_ech` | tls-extensions | ECH configuration lists, server keys, SVCB records and handshakes (accepted, rejected with retry configurations, GREASE) in shared and split mode (client-facing server fed in fuzz-chosen pieces, back-end server, trial decryption with random identifiers) |
| `tls_psk` | tls-extensions | External PSKs, the RFC 9258 importer and RFC 9973, with handshakes using matching and differing PSKs |
| `tls_binding` | tls-extensions | RFC 8844 external identity and session binding: decoding and building the hash and session identifier against a model of their lengths, assertion hashes on both providers against an independent SHA-256, and handshakes (TLS 1.2 and 1.3) with fuzzed bindings, whose outcome and reported peer values must match a model of what each side sends and accepts |
| `tls_quic` | tls-extensions | QUIC-TLS (RFC 9001): Initial keys, packet and header protection, key updates, Retry tags and CRYPTO_ERROR codes against their properties; in-process QUIC handshakes on both providers with fuzzed suites, groups, ALPN, transport parameters, resumption, 0-RTT, split and damaged CRYPTO data, and post-handshake bytes |
| `tls_dtls` | tls-extensions | DTLS 1.3 (RFC 9147): in-process handshakes on both providers with fuzz-chosen versions, suites (CCM_8 refused), key types, groups and datagram sizes, the cookie exchange on or off, the stateless `Acceptor` (also with a cookie from another address), a deferred revocation check and resumption, over a network that drops, duplicates, reorders, damages and forges datagrams with a fuzz-driven clock; then data both ways, key updates, close_notify, exporters, MTU changes, and datagrams shaped like DTLS records (plaintext and unified headers, ACKs, handshake fragments) and replays fed to established connections, and to fresh clients, servers and the `Acceptor`. An undamaged handshake must complete with matching exporters and DTLS 1.3, data must arrive exactly once, datagrams must fit the MTU, and nothing forged or replayed may fail an established connection |
| `tls_dtls_udp` | tls-extensions | The blocking DTLS 1.3 API, `dtls::UdpClient` and `dtls::UdpServer`, over loopback sockets: a server run with short read timeouts in the harness's thread, clients connected with `connect` (the server then on a scoped thread) or with `from_connection` and handshake rounds (also with small MTUs), then data both ways (short buffers, oversized data), close_notify from either side, key updates through `connection_mut`, `remove`, the handshake limit and timeout, read timeouts down to zero, `into_parts` and `from_connection`, a verifier asking for live OCSP, and datagrams shaped like DTLS records sent to the server from other sockets and from clients' sockets, and to clients from the server's socket. The server must report events only for connected clients and never `Failed`, data must arrive intact and once, `handshakes()` must keep to the limit, blocking calls must keep to their read timeout (also under a flood of junk), and junk must never fail a connection |
| `tls_dtls_tokio` | tls-extensions | The real `browntls_tokio::dtls::{UdpClient, UdpServer, UdpListener, SessionLimits, SessionDriver, UdpSession}` public APIs over ephemeral loopback sockets on a bounded current-thread runtime: constructors, authenticated cookie handshakes, separate and empty datagrams, short-buffer retention, oversized rejection, operation deadlines, cancellation and resumption, traffic key updates, close from either side, removal, limits, session isolation, driver lifecycle and accessors; deterministic seed replay checks meaningful paths |
| `tls_auth` | tls-extensions | Delegated credentials (decoding, issuing, validity windows, `validate` against an independent validation, handshakes with a server's credential, and client authentication with a client's credential in or after the handshake, against a buffered or unbuffered server that asks for one or not, with fuzz-chosen schemes, sides and clocks, and resumption) and exported authenticators between connected peers, and client certificate URLs (RFC 6066 §5): PkiPath decoding and encoding, URL entries and lists against a model, TLS 1.2 handshakes whose server pauses for the chain (buffered, unbuffered and the six Tokio acceptors with a fetcher) with fuzz-chosen policies, URLs and answers; a query surfaces exactly when the policy allows every URL, a paused server reads nothing and refuses a wrong id |
| `tls_codec` | tls-codec | The doc-hidden codec re-exports, record payload types, distinguished names and stored session values |

The `tls_dtls` CID API programs select DTLS 1.2 or 1.3, either provider,
three server construction paths and nonempty or empty CID directions. They
exchange authenticated application records over the bounded simulated network;
DTLS 1.3 also requests and issues IDs and checks immediate rotation. DTLS 1.2
checks the negotiated AEAD capability and exercises CID record protection via
the connection. The blocking server constructor is exercised when a loopback
socket can be bound. These programs use a fixed address and do not model path
migration or return routability checks.

The protocol targets generate certificates and keys once per process and
handshake randomness comes from the operating system, as in the connection
targets below.

`browntls-pki` has no cryptography of its own, so `pki_cert` and `pki_crl`
supply stand-in signature algorithms that accept everything, reject
everything, or decide from a signature byte. Path building therefore runs to
its full depth on forged chains, which real providers would stop at the first
signature.

### Tokio DTLS programs

`tls_dtls_tokio` enables the existing `browntls-tokio/dtls` feature and reuses
`src/tls_dtls/setup.rs` with real providers, generated localhost certificates,
root verification and cookie sealing. Each input creates an event server and
one client, or a session listener/driver with at most two authenticated clients,
on `127.0.0.1:0`. They run in the calling thread with real I/O and monotonic
timers; there are no endpoint tasks or external destinations.
The runtime and all sockets are dropped when the input ends or unwinds.

The three-byte header selects the client constructor modulo four (`new`,
`from_connection`, `connect`, or `new` with handshake cancellation and a
positive API timeout before resumption), provider bits 0 and 1 and certificate
key type in bits 2 and 3 of the second byte, and MTU modulo three (256, 512,
1200, used by `from_connection`). Bit 4 of the second byte first exercises
rejected unconnected client sockets, connected server sockets and a server
configuration without cookies. A maximum of 24 actions follow:

| Selector modulo 16 | Arguments and action |
|---|---|
| 0, 1, 2 | One-byte-length payload: client send, server send, server send followed by a short client receive buffer and a full retry |
| 3 | One byte modulo three: idle client/server API deadlines in milliseconds, including zero, then `None`, cancellation and restoration |
| 4 | Poll and drop pending client receive and server event futures, then exchange data to verify resumption |
| 5 | Server traffic key refresh, then data both ways |
| 6 | Addresses, negotiated version, peers, handshake count, connection accessors and matching exporters |
| 7 | Two bytes: handshake/peer limits modulo four, and handshake lifetime in milliseconds; established traffic must continue |
| 8, 9, 10 | Oversized sends rejected on both sides, unknown-peer operations rejected locally, or repeated handshake completion |
| 11, 12, 13, 14 | Client close, server close, removal, or poll client close once and resume it; these end the program |
| 15 | One-byte-length payload: queue two distinct datagrams each way before receiving them separately |

Client payloads are capped at the negotiated application-data limit, except
for the explicit oversized action. Receives compare each entire record with
its expected bytes; empty records must return `Recv::Data(0)`, and a short
buffer must preserve the record. Unexpected events, duplicate application
records, missing data and failed authentic associations fail the harness.
Each wait has a two-second outer bound and an input a ten-second bound;
these cooperative Tokio timers cannot preempt a synchronous poll that hangs.
The positive API timeout checks elapsed time and the outer bound detects
stalls. No paused-time auto-advance races real socket readiness.

Four fixed seeds cover every selector and all 25 public functions in
`crates/browntls-tokio/src/dtls/{client,server}.rs` by intended call paths.
`tls_dtls_tokio::tests::seeds_reach_public_api_sequences` asserts the
constructor, authenticated handshake, data, cancellation, deadline and close
milestones without depending on mutations. The shared seed smoke test also
runs their truncations and mutations. Actual public-function coverage is
established by the LLVM coverage command below, after execution.

Migration seeds in `tls_dtls` run a CID update, lookup, and protected RRC
challenge and response on the simulated network. `tls_dtls_udp` runs blocking
loopback rebinding with both path-selection policies and empty or nonempty
client receiving CIDs. Header bit 7 selects this bounded program.
`tls_dtls_tokio` header bit 6 selects a separate listener/session rebinding
program with the same directions; it checks the address-change notification
and stable original peer address. These programs require replay and LLVM
coverage measurement to establish which public function bodies were reached.

Bit 5 of the second header byte selects the session program below. Inputs
with that bit clear retain the existing event-server program and its four
seeds. In session mode, even constructor selectors use `UdpListener::new`;
odd selectors use `new_with_versions` with explicit DTLS 1.3. Clients use
`from_connection` for selector 1 and `new` otherwise. The MTU choice also
selects receive queues of 2--4 datagrams and command queues of 1--2 commands.
Both handle and accept limits are two. `SessionLimits::default` and Debug
implementations are exercised without allocating the default queues. Bit 4
tests zero/oversized counts, overflowing and excessive byte budgets,
connected sockets and configurations without cookies before a valid listener.

The session action byte uses its low nibble as the operation and its high
nibble modulo the current peer count as the peer selector. Up to 24 actions
run; at most two handshakes occur, even with repeated admission actions.

| Low nibble | Arguments and session action |
|---|---|
| 0, 1, 2 | One-byte-length payload: client send, session send, or two distinct datagrams each way before separate receives |
| 3 | Cancel pending session receive and listener accept, then prove receive resumes |
| 4 | Cancel a queued send and a queued or capacity-blocked close, then exchange data both ways |
| 5 | Reject a 65,536-byte session send, then prove the session remains usable |
| 6 | Authenticate and accept a second client, if admissions remain open and only one handshake has occurred |
| 7 | Drop the listener, then prove existing sessions still exchange data |
| 8, 9 | Remote or local graceful close; check drained input, repeated EOF/close, send rejection and unrelated peer usability; end the program |
| 10 | Drop the running driver; check `BrokenPipe` from live session operations and listener accept; end the program |
| 11 | Drop the selected handle; end the program and check driver shutdown after all remaining handles drop |
| 12, 13, 14, 15 | Address/Debug accessors, empty datagrams both ways, cancel a queued close then send, or exchange distinct traffic on every live peer |

The driver future is polled alongside application operations without spawning
a task. Cancellation setup polls only the application, ensuring queued
commands cannot execute before cancellation. Shared association contracts
compare entire datagrams, clamp client payloads to its MTU-dependent limit,
and check terminal behavior. Nonterminal program completion pumps I/O through
short idle deadlines to check for unexpected data or a delayed close.
Five additional seeds register through the existing target and corpus
generator; `tls_dtls_tokio::tests::session_seeds_reach_public_api_contracts`
asserts their listener, session, cancellation and driver milestones. The
shared seed smoke test also mutates and truncates these seeds. LLVM coverage
must still establish actual function reachability after execution.

Cancellation is deterministic for pending handshake, receive, event and
session-command futures. The event-server close action polls once and
resumes, but a writable socket may finish the first poll. This target does
not force socket backpressure, cancel a sealed send, saturate session receive
or accept queues, test admission eviction or inject forged traffic. These
are coverage limits, not reasons to exempt public functions.

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
repository named in
[Maintenance](../docs/Maintenance.md#private-security-evidence).

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

Together the targets must reach every `pub fn` of `browntls-core`,
`browntls-crypto`, `browntls-pki` and `browntls-tokio`.
`scripts/fuzz/api_coverage.py` checks it: it builds the library tests above with
LLVM source-based coverage, runs them, and fails for any public function
(outside test modules) whose body never ran. A function defined in a macro must
run in every expansion. The facade `browntls` is not in the list: it defines no
`pub fn`, and the functions it re-exports are counted in the crates that define
them.

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

The revocation seeds exercise signed evidence generated once per process,
using a fixed verification time and process-local keys. The Tokio cases run
with the `ocsp` feature, a paused timer, and an in-memory responder.

## Continuous fuzzing

The [Fuzz workflow](../.github/workflows/fuzz.yml) runs the targets as a GitHub
Actions matrix built by `scripts/fuzz/plan.py` from `targets.toml`, which
gives each target a topic and the source files it covers. Every job runs on
one x86-64 runner (`ubuntu-26.04`):

- Pull requests fuzz, for two minutes each, the targets whose sources or
  harness changed; a change to the shared fuzz infrastructure selects every
  target.
- A weekly run fuzzes every target for twenty minutes and keeps each target's
  minimized corpus in the Actions cache, which later runs start from. A job
  saves its corpus only when every target it ran was clean.
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
the input. Before fuzzing, the script prints the CPU model, its
crypto-relevant flags and the backend `browntls-crypto` selects for each
algorithm family (`cargo run --example cpu_features`), since runners of the
same label differ in CPU and a finding may depend on the backend that ran.

The seed alone does not replay a run (the starting corpus and the generated
certificates differ), so the workflow keeps a failing job's findings
directory (crash inputs, libFuzzer logs and the quarantined corpus) for the
maintainers, encrypted: `scripts/fuzz/findings-envelope.sh seal` packs it and
encrypts it as CMS AuthEnvelopedData (ECDH P-384, AES-256-GCM) to the
recipient certificate in the Actions variable `FUZZ_FINDINGS_RECIPIENT`
(PEM; an organization variable at present, which GitHub does not pass to
workflows of pull requests from forks), and only the sealed file is
uploaded, as the artifact `fuzz-findings-sealed-<job>-<attempt>`, kept for
14 days. Anyone signed in
can download it; only the private key opens it. The job log shows the
certificate's SHA-256 fingerprint. Without the variable, or in a run that
does not receive it, nothing is uploaded and the findings are lost with the
runner. A maintainer opens a download with

```sh
scripts/fuzz/findings-envelope.sh open KEY CERT findings.cms NEW-DIRECTORY
```

which refuses a modified file before unpacking anything and leaves
`NEW-DIRECTORY` and everything in it accessible to the caller only, whatever
the caller's umask or the modes the archive records (a default ACL on a parent
directory weakens this; see the script's header). Anyone can encrypt
to the public certificate, so treat what it unpacks as untrusted input, keep
it out of public places, and handle a finding as a potential vulnerability,
as described under [Running](#running). The private key is never committed to
this repository; `findings-envelope.sh keygen KEY CERT` makes a new pair
(replace the variable to rotate it). Without the sealed findings, fuzz that
target locally until it reproduces.

The input that fails can be an entry of the corpus the job started from (a
cached corpus or a seed) rather than a new mutation. Pull requests, from forks
too, can restore the Actions cache, so a saved corpus holding that input would
publish what the printed hash identifies. The script therefore moves a failing
target's corpus into `FUZZ_FINDINGS` (`<target>/corpus.XXXXXX/`; locally under
`fuzz/findings/`, where it also helps to reproduce the finding), and the
workflow saves no corpus from a job that failed, was cancelled or timed out.
Once the finding is fixed, the next clean run saves a corpus again.

A topic-granularity run keeps its own corpus, separate from the per-target
corpora of the weekly run.

Record each manual campaign (revision, toolchain, targets, duration, result)
with the change it supports.
