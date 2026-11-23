# New RFC capabilities baseline

This audit inventories the existing APIs and tests that Phases 1–9 can
build on. It records support at an immutable revision. Each test result
applies to the stated provider, API, configuration, and environment.

## Source and environment

- Source [`bce3863`][tree], Git tree
  `c70b6c35938cc15d00f53bd6dbf2ecc62e48c76c`, matched hosted `main`
  at audit start on 2026-11-23 UTC. The original planning snapshot
  was `c6ac441`. The [companion hardening handoff][hardening] is present
  in the audited tree. Use its older results with their original provenance.
- Rust 1.100.0 (`0ef1bc386`), `x86_64-unknown-linux-gnu`, Linux
  7.0.0-44-generic, host OpenSSL 3.5.5.
- SHA-256 of `Cargo.lock` is
  `adfbc9b4023414349ed1305638886b912fd1a33e90cf3b51d36a8ea4b30d5d65`.
  SHA-256 of `fuzz/Cargo.lock` is
  `437e29c74ad862f8587ce329405819f5b6281029eec22e1f54730a15194f142f`.

## Source and test inventory

Cargo defaults select the `native` provider feature for core and the
facade. The `rustcrypto` provider feature is opt-in. The provider
checks below disable default features to isolate each implementation.

| Surface | Source at the baseline | Existing evidence and limits |
| --- | --- | --- |
| Crypto primitives and PKI | [HPKE suite and contexts][hpke], [X.509 algorithm identifiers][alg], [signed-data dispatch][signed], [path verification][path], [CRLs][crl], and [RSA primitives][rsa] | [HPKE tests][hpke-test] exercise base mode with RFC vectors and independent `hpke` crate comparisons where available. The ML-DSA OIDs and [SignatureScheme values][schemes] are defined. There is no built-in ML-DSA signing, signature verification, or private-key association. |
| Provider mount point, resolvers and verifiers | [`CryptoProvider` and `KeyProvider`][provider], [`SigningKey`, `Signer` and `CertifiedKey`][signer], [native signer][native-sign], [RustCrypto signer][rustcrypto-sign], and [WebPKI scheme mapping][verify] | The native provider signs with RSA. The RustCrypto provider verifies RSA but its built-in signer rejects RSA keys. Custom key and peer verification hooks remain distinct from built-in support. `rsa_key_algorithm_restricts_schemes` checks native RSA key constraints. |
| Stream TLS client and server | [Version selection][versions], [typed builder][builder], [client handshake][client13], [server handshake][server13] and [client-auth selection][client-auth] drive the shared protocol. The [core exports][core] include client/server configs, connections and the buffered `Acceptor`. [`Stream` and `StreamOwned`][stream] drive buffered connections over blocking I/O. | [API tests][api-test], [TLS 1.3 tests][tls13-test], and [host OpenSSL tests][openssl-test] cover configuration, authentication and peer behavior. TLS 1.2 remains in the default version list when built with `tls12`. TLS 1.3-only is already selectable on both builders. |
| Unbuffered stream TLS | [Caller-driven TLS state and buffer API][unbuffered], `UnbufferedClientConnection`, `UnbufferedServerConnection` and `UnbufferedAcceptor` from the [core exports][core]. | [Unbuffered tests][unbuffered-test] exercise handshake, auth, fragmented input and key-log callbacks. Alloc-only core builds cover this API shape. The blocking I/O wrappers require `std`. |
| HPKE, ECH, and DNS input | [HPKE provider traits][hpke-traits], [native HPKE suites][native-hpke], [ECH options][ech], [client offer][ech-client], [shared server][ech-server], [split server][ech-split], and [SVCB helpers][svcb]. `EchConfig::new` accepts caller-supplied suites. | [Native ECH tests][ech-test] cover acceptance, authenticated rejection/retry, HelloRetryRequest, GREASE and split forwarding. The [alloc-only PEM test][ech-alloc-test] supplies its own codec. A split backend can run with RustCrypto. RustCrypto supplies no built-in HPKE for endpoints that seal or open ECH. SVCB helpers extract and validate `ech` from parameters, RDATA or presentation format. They offer no resolver or general service selection. |
| Key logging | [`KeyLog` and `NoKeyLog`][keylog], [file sink][filelog] and the shared protocol callback helper. Both builders default to `NoKeyLog`. The built-in file sink requires Linux, `std`, the non-default `key-log` feature and explicit setup. | [Protocol tests][keylog-test] cover ordinary TLS labels, resumed TLS 1.2 and effective ClientHello random selection. With `key-log` excluded, built-in protocol calls to custom callbacks are compiled out. `ECH_SECRET` and `ECH_CONFIG` are absent. |
| QUIC-TLS | [`quic` connections and key APIs][quic] expose handshake bytes, transport parameters and packet-key changes. The caller supplies the QUIC transport. | [QUIC tests][quic-test] cover rustls interoperability, key changes and TLS 1.3 key logging. The transport uses TLS 1.3 and has no stream record or kTLS handoff. QUIC rules restrict post-handshake messages. |
| DTLS datagrams and blocking UDP | [DTLS engine, acceptor, settings and versions][dtls], [blocking UDP wrappers][dtls-udp], and [return routability checks][dtls-rrc]. The datagram API drives an explicit clock. The `std` wrappers own socket I/O. | [Datagram tests][dtls-test], [UDP tests][dtls-udp-test] and [key-label tests][dtls-log-test] cover existing DTLS operations. DTLS 1.3 is the default. DTLS 1.2 is separately selectable with `tls12`. Optional DTLS 1.3 early data, ECH and post-handshake client authentication are absent. Per-epoch record replay windows and CID/migration tests have their own scope. |
| Tokio stream and UDP | [Tokio exports][tokio] expose buffered and unbuffered connectors, acceptors and lazy acceptors, including an ALPN-specific buffered connector and handoff paths. [Tokio UDP][tokio-dtls] exposes its client, multi-peer event server, and session-oriented listener and session driver. | [Unbuffered tests][tokio-test], [lazy accept tests][lazy-test], [session tests][dtls-session-test], [ECH PEM tests][tokio-ech-test] and [key-log tests][tokio-log-test] drive the adapters. Configs and verifiers come from core. A core test alone gives shared-path evidence for adapters without their own assertion. |
| Linux kTLS | [Core kernel handoff][kernel] and [kTLS exports][ktls] feed the blocking `KtlsStream` and Tokio `AsyncKtlsStream`. Authentication and ECH run in userspace up to handoff. | [Blocking][ktls-test] and [Tokio][ktls-tokio-test] tests use Linux sockets. [Key-log handoff][ktls-log-test] and [ECH PEM][ktls-ech-test] cover applicable userspace transitions. The offload tests exercise TLS stream paths. |
| Facade | [Re-exports][facade] and [features][facade-features] expose core, optional Tokio (including UDP under `dtls`) and optional Linux kTLS. | [Facade tests][facade-test], [Tokio tests][facade-tokio-test] and [kTLS tests][facade-ktls-test] exercise application entry points. The facade aliases core types, so underlying provider evidence is attributable to the shared implementation when the facade target selects no test. |

## Local qualification

Commands run from the repository root. Workspace and targeted runtime
checks requested real Linux kTLS and host OpenSSL with
`BROWNTLS_KTLS_REQUIRED=1` and `BROWNTLS_OPENSSL_INTEROP=require`.

| Check | Observed result |
| --- | --- |
| Locked workspace, all features, including doctests | 3,285 passed, 16 ignored, zero failed. |
| Locked facade defaults | 14 passed, two ignored. |
| Isolated native and RustCrypto core | 280 and 278 passed, respectively. |
| Isolated Tokio with UDP and without key logging | 58 passed per provider across six targets. |
| Facade with one provider, Tokio and kTLS | Native 35 passed. RustCrypto-only built successfully with zero passed and three ignored. Core, Tokio and kTLS tests supply separate RustCrypto runtime evidence. |
| Direct real Linux kTLS, with Tokio and key logging | 29 passed per provider across blocking offload, Tokio offload and key-log handoff. |
| Native TLS 1.3-only facade target | 10 passed. The resolved feature tree for this selection omitted `tls12` and `key-log`. |
| RustCrypto TLS 1.3-only core with key logging compiled out | One callback suppression test passed. |
| Alloc-only core, default features disabled | Checked both providers independently on Linux. |
| Embedded builds, default features disabled | Crypto and PKI built with warnings denied on all three targets below. |
| Forced-software crypto | 449 passed, 16 ignored, zero failed. |
| Formatting and strict workspace Clippy | Workspace and included-case formatting passed. All-target, all-feature Clippy passed with warnings denied. |
| Python harness tests | 71 Docker and 36 Kubernetes tests passed. |

The provider-specific commands below were run with `P=native` and
`S=_native`, then `P=rustcrypto` with an empty suffix.

```sh
cargo test --workspace --all-features --locked
cargo test -p browntls --locked
cargo test -p browntls-core --no-default-features \
  --features "std,$P,tls12,zstd,prefer-post-quantum" --locked --no-fail-fast \
  --test "tls13$S" --test "unbuffered$S" --test "quic$S" --test "dtls$S" \
  --test "dtls_udp$S" --test "api$S"
cargo test -p browntls-tokio --no-default-features \
  --features "$P,tls12,dtls,prefer-post-quantum" --locked --no-fail-fast \
  --test unbuffered --test unbuffered_lazy --test dtls_client \
  --test dtls_server --test dtls_sessions --test key_log_public
cargo test -p browntls --no-default-features \
  --features "std,$P,tls12,dtls,ktls,zstd,prefer-post-quantum" \
  --locked --no-fail-fast
cargo test -p browntls-ktls --no-default-features \
  --features "$P,tls12,tokio,key-log" --locked --no-fail-fast \
  --test offload --test tokio_offload --test key_log_handoff
cargo check -p browntls-core --no-default-features \
  --features "alloc,$P,tls12,zstd" --locked
cargo test -p browntls --no-default-features --features std,native,tokio,ktls \
  --locked --test facade
cargo tree -p browntls --no-default-features --features std,native,tokio,ktls \
  -e features --locked
cargo test -p browntls-core --no-default-features --features std,rustcrypto \
  --locked --test key_log_public
RUSTFLAGS=-Dwarnings cargo build -p browntls-crypto -p browntls-pki \
  --no-default-features --target "$TARGET" --locked
```

The embedded targets are `x86_64-unknown-none`,
`aarch64-unknown-none`, and `riscv64gc-unknown-none-elf`. These are
build checks for the primitive and PKI crates. Core alloc-only checks
use Linux and do not establish a bare-metal handshake.

## Docker and minikube

Docker 29.10.0 ran rootless on amd64. Both browntls images were built
from the baseline as `x86_64-unknown-linux-musl` with `x86-64-v3`.

| Docker peer | Cases and results |
| --- | --- |
| OpenSSL 3.0.13 | Six passed. TLS 1.2, TLS 1.3 and Tokio TLS 1.3 client-authentication scenarios exercised browntls in both roles. |
| Go 1.27.4 | Six passed. Shared-mode ECH acceptance, HelloRetryRequest and stale-config retry in both browntls roles. |
| OpenSSL 3.5.9 | Four passed. DTLS 1.2 fixed and mixed-version policy in both browntls roles. |
| wolfSSL 5.9.4-stable, source `3c5eead44904df64e6a5a1f4ebdce377d35a849a` | Two passed. DTLS 1.3 authenticated exchanges in both browntls roles. |
| OpenSSL 3.0.13 | Four synthetic key-log comparisons passed. One TLS 1.2 label and five TLS 1.3 labels matched in each role. |

The first stream invocation stopped before any exchange because the
default `openssl` suite's Alpine image was missing with
`--skip-peer-build`. The `openssl-3.0` suite used the existing Ubuntu
OpenSSL image and passed the same selected cases. The Go image was
built for the run. The OpenSSL and wolfSSL images were reused.

Minikube 1.39.0 used Kubernetes 1.37.0, containerd 2.3.4 and Calico.
Both TLS endpoints in the Service tests used browntls.

| Service suite | Cases and results |
| --- | --- |
| TCP ECH | Two passed. Current configuration acceptance through Tokio and blocking stale-configuration rejection, authenticated retry and acceptance. |
| UDP DTLS rebind | Four passed. Mutual authentication and basic/enhanced return routability in DTLS 1.2 and 1.3. |
| TCP key log | Four passed. The enabled build in a private directory produced a nonempty `0600` file. The enabled permissive-directory case and both disabled-build cases left the file absent. The observer checked metadata. |

Minikube fell back to the configured Docker Hub base image after the
GCR download failed. The initial TCP ECH run stopped at image
ownership readback before any handshake. Its isolated rerun passed
both cases. The run namespaces, disposable profile and node, and
run-created source and Go peer image tags were absent on readback.

The commands below use run-specific image names and a disposable
profile. The three Kubernetes suites ran serially.

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag "$IMAGE"
python3 -B tests/e2e/e2e.py build --arch amd64 --key-log --tag "$LOG_IMAGE"
python3 -B tests/e2e/e2e.py run --arch amd64 --image "$IMAGE" \
  --suite openssl-3.0 --skip-peer-build --scenario tls12-client-auth \
  --scenario tls13-client-auth --scenario async-tls13-client-auth
python3 -B tests/e2e/e2e.py run --arch amd64 --image "$IMAGE" --suite go \
  --scenario ech-shared --scenario ech-shared-hello-retry-request \
  --scenario ech-shared-retry-configs
python3 -B tests/e2e/dtls.py --arch amd64 --image "$IMAGE" \
  --suite all --skip-peer-build
python3 -B tests/e2e/key_log.py --image "$LOG_IMAGE"
python3 -B tests/kubernetes/ech_service.py --image "$IMAGE" --profile "$PROFILE"
python3 -B tests/kubernetes/dtls.py --image "$IMAGE" --profile "$PROFILE"
python3 -B tests/kubernetes/key_log.py --key-log-image "$LOG_IMAGE" \
  --plain-image "$IMAGE" --profile "$PROFILE" --kubectl "$KUBECTL"
```

The [Docker recipes][docker-recipes] and [Kubernetes
instructions][kube-recipes] describe prerequisites. These live runs
qualify the specific amd64 scenarios above. Existing companion
hardening evidence remains attributable to its original revision.
QEMU, other CPU architectures and fresh fuzz campaigns are outside
the scope of these runtime results.

[tree]: https://github.com/OxiBelt/browntls/tree/bce3863cc21164b5c6989a5ef6724763e7951941
[hardening]: RFC-Hardening-Integration.md
[hpke]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-crypto/src/hpke/mod.rs
[alg]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-pki/src/alg_id.rs
[signed]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-pki/src/signed_data.rs
[path]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-pki/src/verify.rs
[crl]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-pki/src/crl.rs
[rsa]: https://github.com/OxiBelt/browntls/tree/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-crypto/src/rsa
[hpke-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-crypto/tests/hpke.rs
[provider]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/mod.rs
[signer]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/signer.rs
[native-sign]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/native/sign.rs
[rustcrypto-sign]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/rustcrypto/sign.rs
[verify]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/webpki/verify.rs
[versions]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/versions.rs
[builder]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/builder.rs
[client13]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/client/tls13.rs
[server13]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/server/tls13.rs
[core]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/lib.rs
[stream]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/stream.rs
[api-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/api.rs
[tls13-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/tls13.rs
[openssl-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/openssl_interop.rs
[unbuffered]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/unbuffered.rs
[unbuffered-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/unbuffered.rs
[hpke-traits]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/hpke.rs
[native-hpke]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/crypto/native/hpke.rs
[ech]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/ech/mod.rs
[ech-client]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/ech/client.rs
[ech-server]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/ech/server.rs
[ech-split]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/ech/split.rs
[svcb]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/ech/svcb.rs
[ech-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/ech_native.rs
[ech-alloc-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/ech_pem_alloc.rs
[keylog]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/key_log.rs
[filelog]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/key_log_file.rs
[keylog-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/key_log_protocol.rs
[quic]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/quic.rs
[quic-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/quic.rs
[dtls]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/dtls.rs
[dtls-udp]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/dtls/udp.rs
[dtls-rrc]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/dtls/rrc.rs
[dtls-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/dtls.rs
[dtls-udp-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/dtls_udp.rs
[dtls-log-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/tests/cases/dtls_key_log.rs
[tokio]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/src/lib.rs
[tokio-dtls]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/src/dtls/mod.rs
[tokio-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/tests/unbuffered.rs
[lazy-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/tests/unbuffered_lazy.rs
[dtls-session-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/tests/dtls_sessions.rs
[tokio-ech-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/tests/ech_pem.rs
[tokio-log-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-tokio/tests/key_log_public.rs
[kernel]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/kernel.rs
[ktls]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-ktls/src/lib.rs
[ktls-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-ktls/tests/offload.rs
[ktls-tokio-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-ktls/tests/tokio_offload.rs
[ktls-log-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-ktls/tests/key_log_handoff.rs
[ktls-ech-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-ktls/tests/ech_pem.rs
[facade]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls/src/lib.rs
[facade-features]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls/Cargo.toml
[facade-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls/tests/facade.rs
[facade-tokio-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls/tests/tokio.rs
[facade-ktls-test]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls/tests/ktls.rs
[docker-recipes]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/tests/e2e/README.md
[kube-recipes]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/tests/kubernetes/README.md
[schemes]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/enums.rs
[client-auth]: https://github.com/OxiBelt/browntls/blob/bce3863cc21164b5c6989a5ef6724763e7951941/crates/browntls-core/src/server/tls13/client_auth.rs
