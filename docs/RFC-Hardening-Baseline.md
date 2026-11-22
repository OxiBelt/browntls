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

## Credential and certificate processing

Review owner for these rows is
**Codex PKI and crypto review (requested GPT-6 Luna)**.
Checked errata include RFC 4055 verified 1468 (§3) and 1676 (§§3.1,
4.1), RFC 8879 verified 8753 (§4), and RFC 8878 verified 6442
(§3.1.1.5) and 7297 (§3.1.1.3.1.1). The RFC 5280 §4.1.1.3 item
3986 and RFC 9162 §2.1.3.2 item 8670 are held. The index includes
other clauses of these RFCs outside this map. RFC 5756 erratum 2021
is held. RFC 9345 had no entries.

| Claim and requirement | Entry points and transition | Existing coverage | Gap, constraints, and smallest follow-up |
| --- | --- | --- | --- |
| **2B. Delegated credentials.** RFC 9345 [§§4–4.2][dc-rfc] requires authorization by the parent certificate and peer validation of the signature, role context, algorithms and validity. Use is permitted when the peer offers it. | [`CertifiedKey` attachment][dc-attach] checks parent authorization and key and scheme suitability. [Credential validation][dc-validate] checks the signature and validity during the peer handshake. Client and server enforce the expiry on descendant resumption state. | Native and RustCrypto handshake targets include `handshake_with_delegated_credential`, `tampered_credential_is_illegal_parameter`, `credential_key_must_match`, and client-auth and resumption cases. Tokio has its own integration test. | Attachment leaves issuer signature verification to the peer. Treat optional early validation as local configuration hardening. Evaluate what the existing key and verifier APIs can validate without checking a staged credential against the wrong clock or trusting it on the peer's behalf. `attachment_checks_delegated_credential_issuer_and_role` should assert typed error reporting once the fallible API is decided. |
| **3A. PSS parameter identity and restrictions.** RFC 4055 [§2.1][pss-encoding] and [§§3.1–3.3][pss-rfc] distinguish algorithm encodings, PSS SPKI restrictions and signature parameters. RFC 5756 [§2][pss-update] requires PSS signature parameters and distinguishes CA and end-entity SPKI recommendations. RFC 5280 [§§4.1.1.2 and 4.1.2.3][pkix-rfc] requires the certificate's inner and outer signature algorithm identifiers to agree. RFC 9846 [§4.3.3][tls-sigs] adds TLS signature-scheme rules. | [Algorithm matching][pss-id] and the [PSS parser][pss-parser] already canonicalize supported incoming identifiers. [Certificate parsing][pss-cert] compares the two certificate fields bytewise. [Signed-data verification][pss-signed] and native signer checks apply key and signature restrictions at use. | `equivalent_pss_encodings_match_the_canonical_algorithms`, `equivalent_identifiers_in_certificate_chains_validate`, `signature_algorithm_mismatch_is_rejected_at_parse_time`, cover parsing and path validation. Native signing tests separately cover supported private-key restrictions. | Preserve strict DER, TLS digest-length salt, hash and MGF checks, and the existing SHA-1 policy. Review whether any remaining comparison requires semantic equivalence, separately for certificates, CRLs and custom verification descriptors. `restricted_pss_parameter_equivalence_preserves_policy` should distinguish valid supported encodings from different or disallowed parameters. |
| **3B. Zstandard bounds.** RFC 8879 [§§3–5][cc-rfc] permits an offered algorithm and requires exact decompressed length and failure on decompression errors. Verified erratum 8753 specifies the Certificate body without the handshake header. RFC 8878 [§3.1.1.1.2][zstd-rfc] recommends support for windows up to 8 MiB and permits local decoder limits. | [Zstandard codec][zstd-source] checks its 128 KiB window limit before decoding. The [handshake encoder][cc-wire] compresses the serialized Certificate body. The [compression layer][cc-source] bounds decoded output independently with a configurable limit and a 64 KiB hard cap. It feeds normal certificate verification. | `frames_declaring_a_large_window_are_refused_unread`, `built_ins_compress_both_certificates`, `a_server_certificate_of_another_length_is_bad_certificate`, `compression_across_providers`, and the memory suite. | The smaller window is a documented interoperability tradeoff. Seek independently produced libzstd one-shot and streaming frames with provenance, then evaluate an allocation budget independently of output size. Keep zlib and Brotli coverage separate. `libzstd_frames_within_budget_decode_exactly` should cover legitimate encoder output and independently check output bounds. |
| **4A. CT 2.0 evidence.** RFC 9162 [§2.1][ct-merkle] specifies Merkle proof algorithms, [§§4.8–4.12][ct-artifacts] specifies signed artifacts and proofs, and [§§6.3–6.5][ct-transport] specifies TLS presentation. Log count, freshness and trust configuration require an explicit relying-party policy. | [PKI transparency][ct-pki] checks artifacts and proofs. [WebPKI CT policy][ct-core] evaluates evidence from certificates, OCSP and TLS. The core TLS offer and server list are shared by supported stream adapters. | `scts_from_the_three_sources`, `inclusion_with_a_delivered_tree_head`, `sct_of_a_wrong_key_or_certificate_does_not_count`, and both providers' TLS cases. The stock fixtures and separate RFC-derived Merkle reference are repository-generated. | Independent signed artifacts and public log interoperability remain open. Prefer a published or independently generated fixture with revision, producer, expected result and reuse terms. `independent_ct_v2_signatures_and_proofs_validate` should check SCT and STH signatures, inclusion and consistency, and the configured proof and policy limits. |

### API reach and boundaries

- Delegated credentials use common certificate configuration and
  verification hooks for buffered, unbuffered and Tokio TLS. Client
  use includes handshake and post-handshake authentication on supported
  stream paths. Key issuance coverage uses the native provider. Peer
  verification uses the configured provider and verifier. A custom
  verifier must supply its delegated-key verification hook.
- PSS parsing and PKI validation can run with `alloc`. Verify shared
  path, CRL, and TLS 1.2/1.3 verification separately from the native
  PSS-key signing cases. The presence of a provider entry point does
  not imply that it can load each key type.
- Zstandard is an optional core and facade codec. A Tokio TLS stream
  uses the selected core configuration. QUIC-TLS and DTLS share parts of the
  TLS 1.3 handshake. Their applicability is feature-specific and
  subject to each transport's rules. Shared code is source evidence
  and dedicated adapter assertions remain a qualification gap.
  Linux kTLS inherits the established identity at handoff.
- CT low-level parsing and proof logic are independent of sockets.
  Tests for TLS 1.2 and 1.3 cover the offer, policy and connection
  observation. This is distinct from demonstrating CT in QUIC or
  DTLS end to end. The [documented QUIC paths][ct-quic] distinguish
  TLS handshake support from independent QUIC interoperability.

### Representative certificate evidence

`built_ins_compress_both_certificates` passed in both
`cert_compression` targets. The current fixture asserts that each
enabled codec processes both peer Certificate messages during TLS 1.3
client authentication. The other checked tests validate failure on
length mismatch and offer handling. No certificate bytes are included
in this summary. Local libzstd CLI 1.5.7 was available. An independent
fixture and peer exchange remain future evidence.

### Phase 3 implementation

The table above records the baseline. The Phase 3 changes validate
equivalent PSS signature identifiers in both certificates and CRLs and
preserve the signed DER. They compare matching RSA public-key bytes and
the exact key restrictions for credential pairing and path loop detection.
The existing verification profile remains in force, including the
issuer's minimum salt, TLS digest-length salt, and SHA-1 rejection.

The Zstandard decoder separates the accepted window advertisement, the
decoder workspace, and the exact expanded Certificate body. It verifies
present checksums and accepts up to 64 data frames. Dictionary-dependent
and skippable frames remain unsupported. The TLS handshake body ceiling
applies both with and without compression. The focused codec fixtures
include libzstd one-shot and streaming output. Provider and transport
tests distinguish receipt of a compressed message from offering the
algorithm alone.

[dc-rfc]: https://www.rfc-editor.org/rfc/rfc9345.html#section-4
[pss-encoding]: https://www.rfc-editor.org/rfc/rfc4055.html#section-2.1
[pss-rfc]: https://www.rfc-editor.org/rfc/rfc4055.html#section-3.2
[pss-update]: https://www.rfc-editor.org/rfc/rfc5756.html#section-2
[pkix-rfc]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1
[tls-sigs]: https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.3
[cc-rfc]: https://www.rfc-editor.org/rfc/rfc8879.html#section-3
[zstd-rfc]: https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1.1.2
[ct-merkle]: https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1
[ct-artifacts]: https://www.rfc-editor.org/rfc/rfc9162.html#section-4.8
[ct-transport]: https://www.rfc-editor.org/rfc/rfc9162.html#section-6.3
[dc-attach]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/crypto/signer.rs#L218
[dc-validate]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/delegated_credential.rs
[pss-id]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-pki/src/alg_id.rs#L41
[pss-parser]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-pki/src/rsassa_pss.rs
[pss-cert]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-pki/src/cert.rs#L125
[pss-signed]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-pki/src/signed_data.rs#L203
[zstd-source]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/compress/zstd.rs#L54
[cc-wire]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/server/tls13/flight.rs#L423
[cc-source]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/compress.rs
[ct-pki]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-pki/src/transparency.rs
[ct-core]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/webpki/transparency.rs
[ct-quic]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/docs/Architecture.md#ct-20-in-tls

## DTLS recovery and key logging

Review owner for these rows is
**Codex DTLS and key-log review (requested GPT-6.2 Sol)**.
Apply RFC 9147 verified erratum 8100 to §4.1 ACK demultiplexing.
Its reported flight and epoch errata remain open, including 8107
(§7), 8108 (§7.2), 8047 (§8), and 8050 (§8). RFCs 9146, 9850 and
9853 had no entries in the checked index.

| Claim and requirement | Entry points and transition | Existing coverage | Gap, constraints, and smallest follow-up |
| --- | --- | --- | --- |
| **4B. DTLS 1.3 recovery.** RFC 9147 [§§5 and 7–9][dtls-flight-rfc] covers loss, ACKs, retransmission, and epoch updates. New write keys wait for acknowledgement. The RFC requires the prior receive keys through the first successful new-key decryption. | Caller-timed [datagram connections][dtls-core] use the [flight driver][dtls-flight], [epoch state][dtls-state], replay window, and bounded reassembly. The stateless acceptor verifies address-bound cookies. The receive state retains up to four epochs and evicts on installation. | Both providers share `every_single_datagram_loss_is_recovered`, `heavy_loss_duplication_reordering_and_corruption`, `key_update_survives_loss`, and close with a missing ACK. Unit tests cover reassembly and ACK bounds. | The named simulations passed under both providers. The isolated smaller ClientHello configuration hit the [fixture setup failure](#qualification-commands-and-results) before testing reassembly. Add evidence for timeout and ACK ordering across high-level drivers where it is missing. `dtls_key_update_waits_for_ack_across_driver_deadline` should protect the transition. Bound per-peer work, receive windows and reassembly during retries. |
| **4B. Migration.** RFC 9853 [§§3–5][rrc-rfc] couples negotiation to CID and requires authenticated and encrypted control messages. Basic validation checks the candidate. Enhanced validation keeps the old path on a valid response and checks the candidate on an old-path drop or timeout. Candidate sends obey the amplification limit. | [RRC engine][rrc-engine] and [shared UDP migration policy][rrc-udp] gate path selection. The blocking and Tokio event adapters retain the association and apply the shared policy of discarding the candidate’s application input before that path is validated. Tokio sessions inherit this policy from the event server and add bounded queues and stable session identity. | Low-level `rrc_negotiates_only_with_mutual_opt_in_and_cid`, blocking loopback rebind, Tokio event and session rebind, and the minikube UDP Service harness. | Independent peers cover handshake and initial CID negotiation. Migration and loss evidence use browntls record handling. `rrc_candidate_never_delivers_application_data_before_validation` should verify the project’s delivery policy in both modes while preserving the existing validated path and queue limits. |
| **5. Secret log format and exposure.** RFC 9850 [§§1.1–3][keylog-rfc] prohibits this mechanism in production and defines line fields and TLS labels. For accepted ECH, ordinary TLS 1.3 labels use the inner ClientHello random. RFC 9850 §2.3 uses the outer random for the ECH-specific labels, which are outside this workstream. File access affects confidentiality and integrity. | [`KeyLog` and `NoKeyLog`][keylog-core] are available in core without std and default to no output. The [file sink][keylog-file] is std-gated and reads `SSLKEYLOGFILE` when constructed. It requests Unix mode `0600` on creation and uses best-effort append. TLS 1.2 and the shared [TLS 1.3 key schedule][keylog-ks] supply callbacks. Ordinary diagnostic logging is configured separately. | `unset_variable_logs_nothing`, `writes_nss_format`, `unopenable_path_is_tolerated`, `key_log_receives_every_tls13_secret`, and `key_log_receives_the_tls12_master_secret`. The stock file fixture checks the resulting Unix mode. | Creation-mode evidence does not cover all existing-file, symlink, file-type, ownership, or concurrent-writer cases. Evaluate a portable fail-closed sink policy as a project decision and preserve usable diagnostics. `key_log_file_policy_rejects_unapproved_destination` should assert a secret-free result. Evaluate buffer lifetime separately from format correctness. |

### API reach and boundaries

- Core DTLS lets callers drive datagrams, timeouts and RRC events.
  Blocking UDP, Tokio event APIs, and Tokio sessions add socket driving
  and admission, with a different ownership boundary at each layer.
  DTLS 1.2 shares CID and RRC policy and has separate record and
  handshake machinery. The facade re-exports core DTLS and gates Tokio
  UDP behind its `dtls` feature.
- Core buffered, unbuffered TLS and DTLS, blocking I/O, Tokio TLS and
  UDP, and facade callers select their sink through the shared client
  and server configuration. QUIC-TLS also invokes the shared key
  schedule and leaves packet protection use to its transport caller.
  Dedicated DTLS, QUIC, kTLS, and accepted-ECH label coverage remains
  open. kTLS handoff inherits userspace configuration and
  does not create another `SSLKEYLOGFILE` sink.
- On the filesystem boundary, assess Unix and non-Unix behavior
  independently. A single sink's mutex establishes only per-instance
  serialization. Diagnostics and retained evidence should carry label,
  field length, and outcome only.

### Representative datagram and key-log evidence

- Both `every_single_datagram_loss_is_recovered` targets passed.
  The existing simulated network varies the lost flight datagram across
  directions, and both endpoints still complete the handshake and
  exchange application traffic. These are simulator assertions.
- The existing Tokio loopback `event_server_migrates_dtls13_in_both_modes`
  passed under `strace -f -s 0` with UDP send and receive syscalls selected.
  The retained summary contains 35 successful `sendto` and 29 successful
  `recvfrom` calls, each carrying 31–1,200 bytes. The test asserts
  migration and data delivery. The capture verifies datagram I/O sizes.
- The `api` and `api_native` callback tests each passed for TLS 1.2 and
  1.3. TLS 1.3 asserts handshake and initial application secrets in both
  directions and the exporter label, with matching client and server
  entries and 32-byte random fields. TLS 1.2 asserts one `CLIENT_RANDOM`
  record with a 48-byte master-secret field. The summary retains no
  field values.

## Phase 2 follow-up

The baseline above records the earlier source revision. Phase 2 applies
these checks over the Phase 1 parent.

| Requirement | Implementation and regression evidence |
| --- | --- |
| RFC 8449 §4, negotiated stream limits | `extensions` and `extensions_native` cover asymmetric caps, lower-bound errors when the server declines, the first protected EncryptedExtensions record, and extension omission. The record-layer cases check the full TLS 1.3 authenticated plaintext length, including type and padding. |
| RFC 8449 §4, records use their key epoch's cap | Both TLS 1.3 targets exercise acceptance across ticket rollover with a smaller or larger new-handshake cap. Unit tests distinguish old server session encodings from encodings that carry the cap. External PSKs provision their early-data cap on both endpoints and still require the replay policy. |
| RFC 8449 §4, DTLS limits independent of PMTU | The native and RustCrypto DTLS targets cover opt-in asymmetric limits with cookies, retransmission, CID and MTU changes. The DTLS 1.3 case also refreshes traffic keys. Limits apply to protected records, and QUIC continues to use transport parameters. |
| Kernel TLS compatibility | Direct blocking and Tokio handoffs refuse a reduced negotiated receive cap. Routing continues the existing userspace connection. The real Linux transmit test separately checks kernel TX with a peer's smaller cap. |
| RFC 9345 §§4–4.2, credential attachment | Both core provider targets and the Tokio credential tests cover role and leaf binding, issuer signature, expiry, and the existing authentication paths. Opaque-key verification and wire bounds have focused unit tests. Peer authentication and original resumption deadlines are checked independently of attachment. Separate DTLS 1.3 and QUIC-TLS tests verify that the peer used the delegated key. |

The Docker fixtures check asymmetric stream negotiation against GnuTLS in
both TLS versions and both browntls roles. The pinned BoringSSL fixture
checks a browntls TLS 1.3 client authenticating a server delegated
credential. The minikube fixtures check asymmetric negotiated DTLS limits
on UDP Services in both versions and mutual delegated credentials over
Tokio TCP, including unbuffered connections.

See [Architecture](Architecture.md#optional-clienthello-extensions),
[DTLS 1.2](DTLS12.md), and [delegated credentials][phase2-dc-api] for
configuration and API migration.

[phase2-dc-api]: Architecture.md#delegated-credentials-rfc-9345

## Phase 4 follow-up

Phase 4 starts from the Phase 3 tip `a664b6c`. The RFC Editor index lists
DTLS erratum 8100 as verified. The existing ACK content type already
matches its correction. Flight and epoch errata remain reported. CT
erratum 8670 is held for document update and concerns the Merkle proof
description. The index lists no RFC 9853 errata for this baseline.

| Requirement | Regression and interoperability coverage |
| --- | --- |
| RFC 9162 §§2.1 and 4.7–4.12 | [Independent PKI vectors][phase4-ct-vectors] verify both log algorithms, embedded and delivered items, signed heads, and inclusion and consistency against public fixture roots. They exercise timestamp and work bounds. OCSP artifacts enter after extraction of the CT list. |
| RFC 9162 §8.1.6 | The context-aware verifier checks both offers from the effective ClientHello in both TLS versions, after cookies or HelloRetryRequest where applicable. Core, Tokio, QUIC-TLS, DTLS, and kTLS tests exercise the shared authentication path. Standalone verification and exported authenticators use explicit contexts. |
| RFC 9147 §§4, 5, 7 and 8 | Caller-clock and socket-adapter tests cover deadlines, delayed original ACKs, prior epochs, rollover, replay, cookies and bounded reassembly. A bounded sent-record history keeps eligible original ACKs usable after retry is scheduled. |
| RFC 9853 §§3–5 | Both versions and selection modes exercise protected probes, the candidate byte budget, old-path traffic, address binding, expiry, and retained session identity. A single listening socket treats its local path as preferred while validating a remote address independently. |

Public log coverage remains open for CT 2.0. DTLS peer coverage is
documented by suite and direction in the [Docker DTLS matrix][phase4-dtls-e2e].
The minikube UDP Service harness uses browntls at both endpoints for
deployment and adapter coverage.

[phase4-ct-vectors]: ../crates/browntls-pki/tests/data/ct_v2_independent/README.md
[phase4-dtls-e2e]: ../tests/e2e/README.md#dtls-13-interoperability

## Phase 6 handoff

Start each follow-up from the claim and its named regression. Re-evaluate
rows touched by source or RFC changes and record exact commands,
providers, platforms, fixture provenance, results, and missing coverage.
For a substantive change, obtain a named non-author review of the actual
diff and affected callers under [CONTRIBUTING][contrib]. Extend the
affected fuzz targets and format, build, test, and interop gates as
applicable. This baseline supports that review and carries no full-RFC
compliance or release qualification claim.

The three review owners above were separate read-only Codex agents.
Their runtime reports exposed the GPT-6 family. The requested variants
identify the assignments and the runtime exposed no finer model
identifiers. They compared the map to the pinned source, public RFC
text, errata, and the available unit, peer and adapter evidence.
The review applies to this baseline documentation.

[dtls-flight-rfc]: https://www.rfc-editor.org/rfc/rfc9147.html#section-5
[rrc-rfc]: https://www.rfc-editor.org/rfc/rfc9853.html#section-3
[keylog-rfc]: https://www.rfc-editor.org/rfc/rfc9850.html#section-1.1
[dtls-core]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/dtls/connection.rs#L88
[dtls-flight]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/dtls/flight.rs
[dtls-state]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/dtls/state.rs
[rrc-engine]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/dtls/rrc_engine.rs
[rrc-udp]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/dtls/udp/migration.rs
[keylog-core]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/key_log.rs
[keylog-file]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/key_log_file.rs#L68
[keylog-ks]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/crates/browntls-core/src/tls13/key_schedule.rs#L187
[contrib]: https://github.com/OxiBelt/browntls/blob/c6ac441cecba25b9d524e6dec8c55613f8815fb0/CONTRIBUTING.md#independent-review
