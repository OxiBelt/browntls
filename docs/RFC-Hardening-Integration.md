# RFC hardening integration

Phase 6 integrates the hardening work from Phases 0–5. The
[Phase 0 inventory](RFC-Hardening-Baseline.md) records the original
`c6ac441` baseline. The integration starts from
`1fe3286594f0b87b9fe0a350f8625cf2ef04e6b1`, which includes the five
implementation phases. The listed targets qualify the stated requirements
under their test configurations. The requirements and limits apply to the
existing APIs.

## RFC requirements and core coverage

| Phase and requirement | Core regression targets and observations |
| --- | --- |
| 0. Pin the implemented scope and evidence | The baseline maps normative requirements, deliberate deviations, and test configurations. Use the historical source links to distinguish the original gaps from the results below. |
| 1. RFC 9846 §§4.3.10 and 8, and Appendix F.5 | `external_psk`, `tls13`, and `unbuffered` distinguish ticket and external-PSK early data, including accepted and declined flights. External PSKs need a live cutoff and a committed replay mark for early acceptance. The connection reports provisional ALPN and the application controls retransmission. QUIC session-based early data retains its separate transport parameters. |
| 2. RFC 8449 §§4–4.1 and RFC 9345 §§4–4.2 | `extensions` checks asymmetric record lengths, the first protected TLS 1.3 server flight, and ticket and PSK limits tied to their early-data keys. `dtls` checks protection and fragmentation with directional limits across MTU and epoch changes. `delegated_credentials`, `quic`, and `dtls` check attachment, actual delegated-key use, both authentication roles, and the original absolute deadline across resumed sessions where applicable. |
| 3. RFC 4055 §§2.1 and 3, RFC 5280 §4.1, RFC 5756 §2, RFC 8879 §§3–5, and RFC 8878 §3.1.1.1.2 | PKI signature and CRL tests check semantic equality of supported identifiers while retaining the signed bytes. `native_rsa_pss_keys` checks the restricted-key scheme and parameters. `cert_compression` and `cert_compression_memory` cover actual decompression and separate window, scratch, and output limits. The core library test `libzstd_one_shot_and_streaming_fixtures_decode_with_checksum_verification` checks the independent libzstd vectors. |
| 4. RFC 9162 §§2.1, 4.7–4.12, and 8.1.6, RFC 9147 §§4–8, and RFC 9853 §§3–5 | PKI `transparency_independent` uses a separate producer for signed artifacts and proof roots. Core `transparency` checks the effective ClientHello offers. `dtls` checks caller-clock retries, delayed ACKs, asynchronous key epochs, and encrypted CID-bound migration, including preservation of the association and delivery through a validated path. |
| 5. RFC 9850 §§1.1–3 | Core `api`, `quic`, `dtls`, and `key_log_public` plus the core library tests cover compiled-out emission, default and explicit sinks, handshake-specific labels, and Linux file-sink boundaries. The ECH-specific labels belong to a separate workstream. Test evidence records only metadata. |

Use the corresponding `_native` core targets for the native provider
where they exist. Standalone PKI fixture checks and native restricted-PSS
signing have different coverage. The PKI tests exercise certificate and
CRL verification independently of the TLS private-key loader.

### Errata checked for integration

The [RFC Editor index][errata] was checked on 2026-11-23 UTC. RFCs 8449,
9345, 9850, and 9853 had no entries. The verified RFC 9846 item 9040
covers Appendix E.2. The two reported §4.2.3 entries concern
signature algorithms, and are tracked as reported. The verified
RFC 8879 item 8753 applies to the Certificate body without its
handshake header. See the baseline for the verified PSS and Zstandard
items within the tested sections. RFC 9147 item 8100 remains verified
for the ACK content type. Its flight and epoch items remain reported.
The CT Merkle proof item 8670 remains held for document update.

[errata]: https://www.rfc-editor.org/errata.json

## Public API coverage

| Entry points | Regression and caller contract |
| --- | --- |
| Buffered and unbuffered core TLS and QUIC-TLS | `tls13`, `unbuffered`, `extensions`, and `quic` observe early-data acceptance, provisional ALPN and resumption. The QUIC caller drives CRYPTO bytes and owns transport parameter enforcement and retransmission. |
| Tokio buffered and unbuffered clients and acceptors | `early_data`, `unbuffered_early`, and `unbuffered_peers` compare public outcomes to bytes received by the peer. The unbuffered client checks explicit resend with matching, changed and absent ALPN and requires ordered application writes after acknowledgement. `server_early_data`, `lazy`, `unbuffered_lazy`, `delegated_credentials`, and `transparency` exercise handshake continuations and the selected configuration. |
| Caller-clock DTLS and blocking and Tokio UDP | `dtls` combines delayed ACK delivery and an epoch transition with path validation. `dtls_udp`, `dtls_client`, `dtls_server`, `dtls_sessions`, and `dtls_session_recovery` cover loopback drivers, admission, migration, and recovery. The public facade `dtls` test observes the migrated session through its re-exports. |
| Linux blocking and async kTLS | `offload`, `tokio_offload`, and `tokio_routing` check the handoff boundary, including direct refusal and userspace fallback for an unenforceable local receive limit. The TX test hands off to the real kernel and checks all bytes at a userspace peer enforcing a reduced cap. `key_log_handoff` checks exact per-label counts at handoff and after data transfer. |
| `browntls` facade | The `tokio` target exercises both lazy acceptors and Zstandard receive policy. `key_log_public` checks enabled and disabled feature forwarding during public application I/O. The `ktls` target exercises facade blocking offload when Linux supports it. |

For callers settling rejected early data, see the
[Tokio example](../crates/browntls-tokio/README.md#0-rtt-early-data).
The outcome tracks TLS bytes written, resent and still unresent. The
application decides whether a declined request can be retried.

## Qualification results

The final workspace, feature-specific reruns, Clippy, rustdoc and
formatting used `f9f0c8eeb57d151512e4763c7a3b817ba8d7b2ee`. Its tree
`3f77e029160532e7583914b9823d1e29a94212a7` is also the tree of signed
adapter commit `d8ce83c900c8e968d1eda9519e71deef18d01b88`. The initial
focused counts below came from the Phase 6 working tree before the review
corrections. The changed tests were rerun in the final workspace and
feature controls. The native container images, the OCSP example, and the
ASan harnesses used the integration base. The production sources,
manifests, lockfiles, harnesses and Docker inputs are identical between
the base and the signed adapter tree.

### Rust, Python and fuzzing

| Run | Result |
| --- | --- |
| Focused PKI and core | 32 PKI and 922 core tests passed. The separate libzstd fixture unit test also passed. The core run includes both providers and the isolated decoder memory test. |
| Tokio and alloc-only | 122 tests per provider across 15 Tokio targets. Both alloc-only core builds passed. Following the review changes, both standalone Tokio key-log tests passed under each provider. |
| Facade and real Linux kTLS | 17 facade and 31 kTLS tests passed in the focused runs. The isolated key-log-off and dependency-feature-unified controls each passed six tests. The separately compiled-out core control passed one test. |
| Forced software crypto | 449 tests passed and 16 were ignored. |
| All-feature workspace including doctests | 3,285 passed, zero failed and 16 ignored. The ignore set covers table regeneration, slow vectors and parameter checks, throughput, and stack measurement. |
| Build and repository checks | Strict workspace Clippy and rustdoc, core Clippy without TLS 1.2, Rust and fuzz formatting, Markdown links, line width, file sizes, facade features, whitespace and checksum-verified actionlint 1.7.12 passed. |
| Python | 104 repository, 71 Docker harness, and 36 Kubernetes harness tests passed. |
| Fuzz coverage | 37 locked seed tests passed. Public API coverage reached 1,574 of 1,578 functions with four existing exemptions and zero missing. Fuzz Clippy passed. |
| AddressSanitizer | All 25 targets selected from the affected source paths completed their 120-second runs without findings. The pinned nightly and cargo-fuzz versions are listed below. |

The initial all-feature run failed on the new Tokio README doctest. The
corrected example uses the synchronous acknowledgement on the unsplit
stream. Review also identified that direct crate feature flags do not
reflect dependency feature unification. The corrected tests retain
strict enabled and disabled controls and exercise the unified case.
The first core feature-off filter selected zero tests. The rerun selected
the `api` target and executed the intended case. The initial workspace
formatting check found a wrapping difference during the review repairs.
The final formatting check passed.

### Independent Docker peers

The selected amd64 exchanges ran on Docker 29.10.0. Image IDs below
identify the peer image configurations used for the local runs.

| Phase | Peer and image ID | Observed result |
| --- | --- | --- |
| 2 | GnuTLS 3.8.14, `d6ae9ef58f2e` | Four exchanges. TLS 1.2 and 1.3 with browntls in both roles, asymmetric limits and data exchange. |
| 2 | BoringSSL `4764de153d52fa6a60740c68b2d4cc82f44da915`, image `0b192b27968b` | One TLS 1.3 exchange. The browntls client authenticated the independently signed server delegated credential and exchanged data. |
| 3 | OpenSSL 4.0.3 with Zstandard, `f1a665773bb1` | Two TLS 1.3 mutual-authentication exchanges with browntls in both roles. The independent peer observed Zstandard CompressedCertificate in both directions. |
| 4 | OpenSSL 3.5.9, `a6654c330772`, and wolfSSL 5.9.4, `939722d23c72` | Four OpenSSL DTLS 1.2 and two wolfSSL DTLS 1.3 authenticated exchanges. Both browntls roles passed. |
| 4 | Pion DTLS 4.0.2, `5b519c7726cf` | Four authenticated migration exchanges. Pion server validated the browntls client rebind in DTLS 1.2 and 1.3. A browntls DTLS 1.3 server validated Pion client rebinds in both validation modes. |
| 5 | OpenSSL 3.0.13, `189101081877` | Four authenticated TLS 1.2 and 1.3 exchanges across both roles. One and five labels matched, respectively, per exchange. The runner compared synthetic key logs in memory. |

The first BoringSSL fixture timed out while generating the test PKI.
Its stopped container and two ownership-labeled volumes were removed.
The rerun with the same peer image passed.

### minikube Service evidence

The run used minikube 1.39.0, Kubernetes 1.37.0, containerd 2.3.4 and
Calico on amd64. Both TLS endpoints used browntls. The OCSP responder
used OpenSSL.

| Phase | Service cases and observations |
| --- | --- |
| 1 | Four external-PSK early-data cases. Buffered and unbuffered Tokio each accepted and declined early data as configured and completed the ordinary data exchange. |
| 2 | Four cases. TLS 1.3 buffered and unbuffered Tokio used mutual delegated credentials over TCP and DTLS 1.2 and 1.3 negotiated asymmetric limits over UDP. |
| 3 | Three cases. Buffered TLS, unbuffered TLS and DTLS each decoded Zstandard certificates and passed mutual authentication and data exchange. |
| 4 | Four authenticated UDP rebind cases with DTLS 1.2 and 1.3, each under basic and enhanced return routability checks. |
| 5 | Four authenticated TLS 1.3 cases. The enabled build created a nonempty `0600` file in the private directory. The enabled permissive case and both disabled cases left the file absent. The observer checked metadata. |
| Adjacent revocation | Three Calico policy cases. Live OCSP succeeded, egress denial produced strict rejection, and two different authenticated staples verified while responder access was blocked. |

The initial run passed early data and revocation. The record-limit
harness timed out on pod status, the Zstandard harness timed out on
image import, the DTLS harness received a Kubernetes API EOF, and the
key-log harness timed out waiting for a Kubernetes condition. The four
serial reruns on the same profile passed all their cases.
The OCSP namespace-deletion wait also timed out after its three assertions
passed. A later query returned only the system and default namespaces.
The test namespaces, run-owned profile and temporary source image tags
were removed. The profile and its Docker container were absent on
readback.

### Review and limits

A separate Codex reviewer running GPT-6.2 Astra at high effort inspected
the actual core and adapter diffs and affected callers, then reviewed
the corrections at `da2d086f8c1afe1ca4d7d5dfd17aacb420978842` and
`f9f0c8eeb57d151512e4763c7a3b817ba8d7b2ee`. It verified both local
signatures and the parent chain and found the doctest, feature
unification, and libzstd mapping issues resolved on follow-up. The
primary agent ran the validation. The adapter attribution amendment
retained the reviewed tree.

A separate Codex reviewer, requested as GPT-6.2 Sol, compared the handoff
diff with the run summaries, counts, source tree and peer provenance.
The report incorporates its findings on run revisions and cleanup.

Independent 0-RTT peer coverage and public CT 2.0 log coverage remain
open. The CT OCSP fixture starts after extraction of the CT list. The
BoringSSL fixture covers server credentials in TLS 1.3. Client
credentials, DTLS and QUIC-TLS have in-process coverage.
QUIC packet delivery is owned by the transport. DTLS early data and
ECH-specific key-log labels are outside this hardening workstream.
Linux kTLS cannot install a reduced local receive cap, so its routing
tests verify userspace fallback. The Zstandard profile retains its
bounded decoder and the documented dictionary and skippable-frame
restrictions.

The runtime matrix is native amd64 Linux. The two alloc-only provider
checks compile without `std`. Miri was outside the selected gates
because the patch changes tests and guidance. Hosted workflow results
and release qualification remain outside this evidence.

## Reproduction

Run the commands from the repository root with the toolchain pinned in
`rust-toolchain.toml`. The local run used x86-64 Linux 7.0.0-44-generic,
Rust 1.100.0, and host OpenSSL 3.5.5. Set the two requirements on Linux
so the kTLS and independent host OpenSSL checks fail if unavailable.

```sh
export BROWNTLS_KTLS_REQUIRED=1 BROWNTLS_OPENSSL_INTEROP=require
cargo test --locked -p browntls-pki --test signed_data --test crl \
  --test verify_chain --test transparency_independent
cargo test --locked -p browntls-core --all-features --lib \
  libzstd_one_shot_and_streaming_fixtures_decode_with_checksum_verification
cargo test --locked -p browntls-core --all-features --no-fail-fast \
  --test tls12 --test tls12_native --test tls13 --test tls13_native \
  --test unbuffered --test unbuffered_native \
  --test external_psk --test external_psk_native \
  --test extensions --test extensions_native \
  --test delegated_credentials --test delegated_credentials_native \
  --test native_rsa_pss_keys --test cert_compression \
  --test cert_compression_native --test cert_compression_memory \
  --test transparency --test transparency_native --test dtls --test dtls_native \
  --test dtls_udp --test dtls_udp_native --test quic --test quic_native \
  --test key_log_public

for provider in native rustcrypto; do
  cargo test --locked -p browntls-tokio --no-default-features \
    --features "$provider,tls12,dtls,ocsp,zstd,key-log" --no-fail-fast \
    --test early_data --test unbuffered_early --test unbuffered_peers \
    --test lazy --test unbuffered_lazy --test server_early_data \
    --test kernel_handoff_early --test delegated_credentials \
    --test transparency --test revocation --test dtls_client --test dtls_server \
    --test dtls_session_recovery --test dtls_sessions --test key_log_public
  cargo check --locked -p browntls-core --no-default-features \
    --features "alloc,$provider,tls12,zstd"
done

BROWNTLS_KEY_LOG_REQUIRE_DISABLED=1 \
  cargo test --locked -p browntls -p browntls-ktls -p browntls-tokio \
  --features browntls/ktls,browntls/tokio,browntls-ktls/tokio \
  --test key_log_handoff --test key_log_public
cargo test --locked -p browntls-core --no-default-features \
  --features std,rustcrypto,tls12 --test api key_log_callbacks_are_compiled_out
cargo test --locked -p browntls -p browntls-ktls -p browntls-tokio \
  --features browntls/ktls,browntls/tokio,browntls-ktls/tokio,browntls-tokio/key-log \
  --test key_log_handoff --test key_log_public
cargo test --locked -p browntls --all-features \
  --test tokio --test dtls --test ktls --test key_log_public
cargo test --locked -p browntls-ktls --all-features \
  --test offload --test tokio_offload --test routing --test tokio_routing \
  --test key_log_handoff
RUSTFLAGS='--cfg browntls_force_soft' cargo test -p browntls-crypto --locked
cargo test --locked --workspace --all-features --no-fail-fast
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy -p browntls-core --all-targets --no-default-features \
  --features std,native,rustcrypto,logging --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo fmt --all --check
rustfmt --edition 2024 --check \
  crates/browntls-core/tests/cases/*.rs crates/browntls-core/tests/cases/*/*.rs
```

Run the repository scripts in the
[contributor guide](../CONTRIBUTING.md#local-checks), the Python harness
suites and the locked fuzz tests.

```sh
for suite in scripts e2e kubernetes; do
  python3 -B -m unittest discover -s "tests/$suite" -p 'test_*.py'
done
python3 -B scripts/fuzz/plan.py check
cargo fmt --manifest-path fuzz/Cargo.toml --check
cargo test --manifest-path fuzz/Cargo.toml --locked
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
python3 -B scripts/fuzz/api_coverage.py run --work-dir "$COVERAGE_DIR"
```

For the bounded ASan run, derive the target list from the Phase 0 baseline
and the Phase 6 runtime source paths. Use nightly-2026-11-14 and cargo-fuzz
0.13.2. Run in a temporary source checkout with a private findings
directory. The local runs shared one seed generation and partitioned the
target loop into independent jobs.

```bash
mapfile -t targets < <(
  python3 -B scripts/fuzz/plan.py matrix --changed-files <(
    git diff --name-only c6ac441 HEAD -- \
      'crates/browntls-core/src/**' 'crates/browntls-pki/src/**' \
      'crates/browntls-tokio/src/**' 'crates/browntls-ktls/src/**'
  ) | python3 -c 'import json,sys; print(*(j["targets"] for j in json.load(sys.stdin)["include"]), sep="\n")'
)
FUZZ_TOOLCHAIN=nightly-2026-11-14 FUZZ_SANITIZER=address \
  FUZZ_FINDINGS="$PRIVATE_DIR" scripts/fuzz/run-targets.sh 120 "${targets[@]}"
```

### Docker and minikube

Use the Docker driver and native amd64 images. `PLAIN`, `ZSTD`, and
`KEY_LOG` are temporary local image tags. The examples below use the
existing local peer images after building any missing images with the
[Docker harness](../tests/e2e/README.md). The BoringSSL fixture builds
its peer when passed `--build-peer`.

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag "$PLAIN"
python3 -B tests/e2e/e2e.py build --arch amd64 --zstd --tag "$ZSTD"
python3 -B tests/e2e/e2e.py build --arch amd64 --key-log --tag "$KEY_LOG"
python3 -B tests/e2e/e2e.py build-peer --suite gnutls
python3 -B tests/e2e/e2e.py run --arch amd64 --image "$PLAIN" --suite gnutls \
  --scenario tls12-rsl-asymmetric --scenario tls13-rsl-asymmetric --skip-peer-build
python3 -B tests/e2e/boringssl_dc.py --image "$PLAIN" --build-peer
python3 -B tests/e2e/boringssl_dc.py --image "$PLAIN"  # retry with the built peer
python3 -B tests/e2e/zstd_interop.py --image "$ZSTD" --skip-peer-build
for suite in openssl wolfssl pion; do
  python3 -B tests/e2e/dtls.py --arch amd64 --image "$PLAIN" \
    --suite "$suite" --skip-peer-build
done
python3 -B tests/e2e/e2e.py build-peer --suite openssl-3.0
python3 -B tests/e2e/key_log.py --image "$KEY_LOG"
```

Use a run-owned `PROFILE` with Calico, the Kubernetes-release-matched
`KUBECTL` binary, and a locked, static `REVOCATION_BIN` build of the
`revocation_kubernetes` example with `browntls-tokio/ocsp`.

```sh
minikube -p "$PROFILE" start --driver=docker --container-runtime=containerd \
  --kubernetes-version=v1.37.0 --cni=calico --keep-context \
  --cpus=2 --memory=4096 --wait-timeout=180s
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --locked --release -p browntls-tokio --features ocsp \
  --target x86_64-unknown-linux-musl --example revocation_kubernetes
python3 -B tests/kubernetes/early_data.py --profile "$PROFILE" --image "$PLAIN"
python3 -B tests/kubernetes/record_limits.py --profile "$PROFILE" --image "$PLAIN"
python3 -B tests/kubernetes/zstd_compression.py --profile "$PROFILE" --image "$ZSTD"
python3 -B tests/kubernetes/dtls.py --profile "$PROFILE" --image "$PLAIN"
python3 -B tests/kubernetes/key_log.py --profile "$PROFILE" --plain-image "$PLAIN" \
  --key-log-image "$KEY_LOG" --kubectl "$KUBECTL"
python3 -B tests/kubernetes/revocation.py --profile "$PROFILE" --binary "$REVOCATION_BIN"
```
