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

## TLS early data and record limits

Review owner for these rows is
**Codex TLS and I/O review (requested GPT-6.2 Astra)**.
The RFC Editor index lists verified RFC 9846 erratum 9040 for Appendix E.2,
outside the early-data obligations below. RFC 8449, 9258, and 9973 had no
entries. RFC 9257 erratum 7643 applies to its stack-interface guidance.
RFC 9001 erratum 9272 concerns header protection outside the 0-RTT map.

| Claim and requirement | Entry points and transition | Existing coverage | Gap, constraints, and smallest follow-up |
| --- | --- | --- | --- |
| **1A. Ticket 0-RTT.** RFC 9846 [§4.3.10][tls-early] constrains acceptance to the selected PSK, version, cipher suite and ALPN. [§§8–8.1][tls-replay] require at-most-once acceptance per server instance and describe single-use tickets. | [TLS 1.3 server][tls-server] consumes state through the session store. [Early-data decision][early-decision] checks first identity, freshness, suite, version, ALPN, application decline, and stateful ticket mode. | `early_data_is_accepted_and_readable`, `early_data_is_not_offered_with_stateless_tickets`, `early_data_is_rejected_after_hello_retry_request`, and Tokio’s `a_replayed_first_flight_is_not_accepted_early`. | Preserve the existing single-use path. Its guarantee depends on the custom store’s take semantics and sharing across instances. Later case `stateful_ticket_take_is_single_use_across_workers` should assert the store contract. Application-level deduplication remains necessary. |
| **1A. External PSKs.** RFC 9846 [§§4.3.10–11][tls-early] and [§8][tls-replay] also apply to accepted early data under an external PSK. RFC 9257 [§6][psk-guidance] gives provisioning guidance. RFC 9258 [§4][psk-import] binds imported identities to context. RFC 9973 [§4][psk-cert] requires fatal `illegal_parameter` when a ClientHello offers the certificate-with-external-PSK extension together with early data. | [External PSK config][psk-source], the TLS 1.3 binder and selection path, and `decide_if_external_early_data_allowed`. The opt-in per-key limit is separate from the stateful ticket path. Importer, ECH and HRR affect selection and transcript handling. | `early_data_with_an_external_psk_when_allowed`, `early_data_with_an_external_psk_is_off_by_default`, `imported_psk_tickets_keep_the_import_context`, and [RFC 9973 tests][psk-cert-tests]. | The [documented opt-in][early-doc] has no replay decision. Scope a bounded atomic replay policy with fail-closed early-data handling when the policy is unavailable. Preserve normal handshakes and the RFC 9973 exclusion. `external_psk_early_data_requires_replay_policy` and `external_psk_policy_failure_declines_early_data` should assert those outcomes. |
| **1B. Rejected 0-RTT resend.** RFC 9846 [§4.3.10][tls-early] discourages automatic resend and requires the same ALPN for it. [Appendix F.5][tls-app] requires application instruction to resend. | [Buffered Tokio `poll_finish`][tokio-early] completes and flushes the handshake, then may resend for a matching single offered ALPN or when both sides omit ALPN. Its write accounting and result also feed kernel handoff. Core exposes early rejection to callers. | `declined_early_data_is_resent_as_ordinary_data`, `declined_early_data_is_not_resent_when_the_protocol_may_differ`, `declined_early_data_is_resent_before_the_handover`, and split-wakeup tests. | Today `TlsConnector::early_data(true)` enables the buffered behavior. Later, separate resend authorization from enabling early data and define how callers obtain the unresent count. Cover equal, different and absent ALPN, writes across polls, split, flush, cancellation and offload. `declined_early_data_requires_resend_opt_in` should assert that the first ordinary write occurs only with consent. |
| **2A. TLS record limits.** RFC 8449 [§§4–4.1][rsl-rfc] requires the protected plaintext bound and fatal `record_overflow` in TLS. TLS 1.3 counts the content type and padding. Values below 64 require `illegal_parameter`. The server must tolerate higher client advertisements, while the client may refuse a value above the negotiated maximum. | [Client limit processing][rsl-client], [server selection][rsl-server], and [record layer][rsl-record] set independent inbound and outbound bounds. Outbound fragmentation also honors the local `max_fragment_size`. TLS 1.2 answers in ServerHello and TLS 1.3 in EncryptedExtensions. | `record_size_limits_bound_both_directions`, `record_size_limit_and_max_fragment_size_smaller_wins`, `tls12_record_size_limit_is_clamped_and_answered_in_server_hello`, `record_size_limit_below_64_is_refused`, and plaintext accounting unit cases. | A bounded clamp above the protocol maximum is consistent with the server rule and the client’s optional abort. Existing tests establish conforming peer fragmentation. The server checks the lower bound on the path that answers the extension. `record_size_limit_checks_peer_value_on_declined_negotiation` should pin validation when the server declines negotiation. |
| **2A. Timing and handoff.** RFC 8449 §4 ties limits to the handshake that produced the protection keys. | The [client transition][rsl-ee] installs the receive cap while processing EncryptedExtensions, after the record carrying that message has been read. Under early read keys, the [record layer][rsl-record] bypasses its negotiated-size check. kTLS exports the effective transmit cap and [refuses unsuitable kernels][ktls-timing] when it cannot preserve that cap. | `tls13_inbound_record_size_limit_counts_type_and_padding`, `a_smaller_peer_record_size_limit_is_reported`, and `a_smaller_record_size_limit_reaches_the_kernel`. | When negotiated, the client’s limit also covers the server record carrying EncryptedExtensions. Ticket 0-RTT uses parameters from the ticket-issuing connection. External PSKs depend on provisioned parameters. `resumed_early_record_uses_protection_epoch_limit` and `record_size_limit_bounds_first_protected_server_flight` should pin the key transitions. The socket test covers offloaded TX to userspace RX. The local advertised limit after RX offload remains unverified. |

### API reach and boundaries

- `ClientConnection`, `ServerConnection`, the unbuffered connections
  and both acceptors use the common stream handshake and record policies.
  The unbuffered APIs can drive core 0-RTT. Tokio's unbuffered connector
  has no client early-write phase. Its server collects accepted data
  during the handshake and exposes it afterward through `early_data()`
  and `take_early_data()`. Buffered Tokio adds sending and resend,
  server early reads, and split-stream accounting. Both blocking and
  async kTLS finish or decline userspace handoff at a record boundary
  under the same core connection configuration.
- QUIC-TLS exposes CRYPTO bytes and keys through its own API. External
  PSKs may authenticate the handshake and are excluded from QUIC 0-RTT.
  Session-based QUIC 0-RTT uses remembered transport parameters under
  RFC 9000 [§7.4.1][quic-params] and RFC 9001 [§4.6][quic-early].
  QUIC-TLS applies the ticket acceptance policy and offers directional
  keys. The transport checks remembered parameter compatibility, can
  decline 0-RTT, and owns packets and delivery. Stream TLS record bounds
  and Tokio resend have no QUIC analogue.
- The DTLS 1.2 and 1.3 record paths do not currently implement
  `record_size_limit`. DTLS 0-RTT is outside the implemented API.
  See [DTLS scope][dtls-scope]. Facade users select the same configurations
  and feature-gated adapters.

### Representative TLS evidence

The stock `tls13` and `tls13_native` early-data cases passed, six in each
target under the `early_data_is_` filter. Endpoint logs were filtered to
event names. Test assertions supply the result of the protected exchange.

| Case | Retained sequence and result |
| --- | --- |
| Stateful ticket accepted | Full handshake and ticket → resumed ClientHello with early traffic keys → early data accepted and readable → 1-RTT traffic in both directions. |
| Server declines on ticket resumption | Ticket → client early traffic keys → server enters trial decryption and skips the rejected early record → resumed handshake completes → ordinary data works. |
| Record size in both directions | `extensions` and `extensions_native` both passed `record_size_limits_bound_both_directions`. The test reads serialized record headers after negotiation. For 64-byte and 100-byte advertised limits, TLS 1.3 protected application bodies maxed at 80 and 116 bytes by direction. TLS 1.2 AES-GCM bodies maxed at 88 and 124 bytes. These are ciphertext lengths, excluding the record headers. |

[tls-early]: https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.10
[tls-replay]: https://www.rfc-editor.org/rfc/rfc9846.html#section-8
[tls-app]: https://www.rfc-editor.org/rfc/rfc9846.html#appendix-F.5
[psk-guidance]: https://www.rfc-editor.org/rfc/rfc9257.html#section-6
[psk-import]: https://www.rfc-editor.org/rfc/rfc9258.html#section-4
[psk-cert]: https://www.rfc-editor.org/rfc/rfc9973.html#section-4
[rsl-rfc]: https://www.rfc-editor.org/rfc/rfc8449.html#section-4
[quic-params]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1
[quic-early]: https://www.rfc-editor.org/rfc/rfc9001.html#section-4.6
[tls-server]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/server/tls13.rs#L83
[early-decision]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/server/tls13/early_data.rs#L46
[psk-source]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/psk.rs
[psk-cert-tests]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/tests/cases/external_psk/rfc9973.rs
[tokio-early]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-tokio/src/client/early.rs#L97
[early-doc]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/docs/Architecture.md#tls-13-external-psks
[rsl-client]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/client/hs.rs#L164
[rsl-server]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/server/hs/select.rs#L15
[rsl-record]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/record_layer.rs#L102
[rsl-ee]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/client/tls13.rs#L474
[ktls-timing]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/docs/Architecture.md#linux-kernel-tls-browntls-ktls
[dtls-scope]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/docs/Roadmap.md
