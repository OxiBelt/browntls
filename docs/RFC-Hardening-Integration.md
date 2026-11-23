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
