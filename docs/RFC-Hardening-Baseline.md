# RFC hardening baseline

This is the Phase 0 inventory for the existing browntls implementations.
It records what the baseline does, the evidence for each claim, and the
smallest follow-up worth considering. The test results apply to the
specified revision, features, peers, and platform.

## Baseline and method

- Source commit [`c6ac441`][baseline], tree
  `318c0da9691843cd92458adfc2a50d9b330c6520`.
- Rust 1.100.0 (`0ef1bc386`), `x86_64-unknown-linux-gnu`, Linux
  7.0.0-44-generic, host OpenSSL 3.5.5. The Docker peer build targets
  `x86_64-unknown-linux-musl` and `x86-64-v3`.
- Lockfile SHA-256 values are
  `51fc1dedf2ed6a631ccc1073f7ccb1e13324431bc4e3207d578313c0b66c5baa`
  for `Cargo.lock` and
  `005d08463044d9ebe6ec6889d899800b6b7d64318e565b375ee83dd49c04b8e4`
  for `fuzz/Cargo.lock`. The workspace locks Tokio 1.54.1 and the rustls
  interoperability oracle 0.23.46.
- Standards and the RFC Editor [errata index][errata] were checked on
  2026-11-22 UTC. A verified erratum informs the requirement. Reported
  and held items retain their status.

| Configuration | API entry points represented |
| --- | --- |
| Workspace `--all-features` | TLS 1.2/1.3, DTLS 1.2/1.3, QUIC-TLS, PKI, both providers, all built-in certificate codecs, Tokio and kTLS, and the public facade. |
| Facade defaults | `std,native,tls12,logging,prefer-post-quantum,coop`. The optional Tokio and kTLS modules require their features. Core DTLS is available through the core re-export. |
| Facade per provider | `std,tls12,dtls,ktls,zstd` plus exactly one of `native` or `rustcrypto`. Facade `dtls` enables Tokio UDP and, with `ktls`, the async handoff. |
| Core per provider | `alloc,tls12,zstd` plus one provider with defaults disabled on the Linux target. Covers compilation of the core alloc APIs independently of std adapters. |
| CI embedded targets | Default-disabled primitives and PKI on `x86_64-unknown-none`, `aarch64-unknown-none`, and `riscv64gc-unknown-none-elf`. These builds cover the CI packages, not a bare-metal core handshake. |

A shared test target shows the contract at its tested entry point. The
maps identify adapters that use the same path and name missing adapter
assertions. A fixture or same-library peer gives bounded evidence. An
independent peer or vector adds evidence only for what it exercises.

The status in each row describes source behavior, tested behavior,
a coverage gap, a documented policy, or an API exclusion. Regression
names are suggestions for later phases and exact existing names are
marked as coverage. Links to source and test files point to the pinned
baseline, so the inventory remains attributable as the code changes.

### Qualification commands and results

The locked x86-64 Linux run used Rust 1.100.0. The workspace tests required
real kTLS and host OpenSSL by setting `BROWNTLS_KTLS_REQUIRED=1` and
`BROWNTLS_OPENSSL_INTEROP=require`. Test commands below run from the
repository root. Container input names stand for a fresh local tag.

| Check | Result |
| --- | --- |
| `cargo test --workspace --all-features --locked` | 3,157 passed, 16 ignored, 0 failed. The ignored tests cover slow vectors, benchmarks, stack measurement and source-table regeneration. |
| `cargo test -p browntls --locked` | 12 passed, 2 ignored. |
| `cargo test -p browntls --no-default-features --features std,native,tls12,dtls,ktls,zstd --locked` | 30 passed. Includes the matching Linux offload paths. |
| Same facade command with `rustcrypto` in place of `native` | Completed the build. Existing test gates selected zero passing and three ignored cases. RustCrypto runtime evidence is in the core and Tokio runs below. |
| `cargo test -p browntls-tokio --no-default-features --features PROVIDER,tls12,dtls --test dtls_client --test dtls_server --test dtls_sessions --locked` | 28 passed per provider. |
| Focused core runs below | Native 364 passed and 1 failed. RustCrypto 361 passed and 1 failed. |
| `cargo check -p browntls-core --no-default-features --features alloc,PROVIDER,tls12,zstd --locked` | Passed for both providers on the Linux target. |
| `RUSTFLAGS='-D warnings' cargo build -p browntls-crypto -p browntls-pki --no-default-features --target TARGET --locked` | Passed for all three listed embedded targets. |
| `cargo tree -p browntls -e features --locked` and the workspace all-features equivalent | Resolved both feature graphs. |
| Workspace formatting and included-case formatting per CONTRIBUTING, and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed. |
| Repository, E2E, and Kubernetes Python suites per CONTRIBUTING (`python3 -B -m unittest discover` against each test directory) | 104, 62, and 25 passed respectively. Pinned actionlint 1.7.12 passed after archive checksum verification. |

For the isolated core runs, use `PROVIDER=native` and `SUFFIX=_native`,
then `PROVIDER=rustcrypto` and an empty `SUFFIX`.

```sh
cargo test -p browntls-core --no-default-features \
  --features "std,$PROVIDER,tls12,zstd" --locked --no-fail-fast \
  --test "tls13$SUFFIX" --test "unbuffered$SUFFIX" --test "extensions$SUFFIX" \
  --test "external_psk$SUFFIX" --test "cert_compression$SUFFIX" \
  --test "delegated_credentials$SUFFIX" --test "transparency$SUFFIX" \
  --test "dtls$SUFFIX" --test "quic$SUFFIX"
```

Both isolated runs failed at the setup assertion in
`a_split_second_client_hello_is_kept_once_its_cookie_arrives`. With
`prefer-post-quantum` added to the same features, the single test passed
for each provider. The all-features run also passed it. The failure
occurs before the fixture reaches the fragmented reassembly assertion.
Keep that coverage limit for the smaller ClientHello configuration.

### Independent peers and UDP Service

Docker 29.10.0 rootless ran the amd64 suites. The OpenSSL TLS and DTLS
peer images reported OpenSSL 3.5.9. The wolfSSL image was built from
5.9.4-stable at `3c5eead44904df64e6a5a1f4ebdce377d35a849a`.
Minikube 1.39.0 ran Kubernetes 1.37.0 with containerd in a disposable
profile.

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag "$IMAGE"
python3 -B tests/e2e/e2e.py run --arch amd64 --image "$IMAGE" --suite openssl \
  --scenario tls12-optional-extensions --scenario tls13-optional-extensions \
  --scenario tls13-optional-extensions-client-auth \
  --scenario tls13-optional-extensions-resumption
python3 -B tests/e2e/dtls.py --arch amd64 --image "$IMAGE" --suite all
python3 -B tests/e2e/dtls.py --arch amd64 --image "$IMAGE" --suite wolfssl-cid
python3 -B tests/kubernetes/dtls.py --image "$IMAGE"
```

| Run | Result and evidence boundary |
| --- | --- |
| OpenSSL stream TLS | 7 of 7 passed. TLS 1.2 and 1.3 with optional extensions in both roles, TLS 1.3 client authentication in both roles, and one TLS 1.3 resumption scenario. |
| DTLS peers | 6 of 6 passed. OpenSSL DTLS 1.2 covered fixed and mixed selection in both roles. wolfSSL covered DTLS 1.3 in both roles. |
| wolfSSL CID | 4 of 4 passed. Initial CIDs, mutual authentication, payload and shutdown in both roles for both versions. |
| Minikube UDP Service | 4 of 4 passed. DTLS 1.2 and 1.3, basic and enhanced rebind. Both endpoints use browntls. |

The disposable profile and node container were gone after the run.
Namespace teardown succeeded, and both run-specific image tags were
absent after cleanup. Keep independent interop claims to the exercised
amd64 scenarios. The bare-metal checks are build-only evidence.

[baseline]: https://github.com/OxiBelt/browntls/tree/c6ac441cecba25b9d524e6dec8c55613f8815fb0
[errata]: https://www.rfc-editor.org/errata.json
