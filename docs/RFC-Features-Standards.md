# New RFC capabilities standards and interoperability

The [source and test baseline](RFC-Features-Baseline.md) fixes the
repository revision for these observations. Standards, registries, draft
status and the [RFC Editor errata index][errata] were checked on
2026-11-23 UTC. Recheck them before assigning wire behavior in a feature
PR. Verified errata inform requirements. Reported, held and rejected
items retain their recorded status.

## Phase matrix

Owner roles are proposed assignments. The maintainer names an owner and
a non-author reviewer before each follow-on phase. A listed oracle is
qualified only for the behavior it actually exercises.

| Phase and proposed owner | Standard and identifiers | Baseline, default and compatibility | Provider and build reach | Oracle and remaining evidence |
| --- | --- | --- | --- | --- |
| **0. Audit** · integration maintainer | Applicable RFCs and registrations are pinned below. This phase assigns no wire identifiers. | Source inventory, test baseline and follow-on sequencing. | Both built-in providers, custom interfaces, facade and transports. Alloc and embedded checks have separate scope. | Scoped local, Docker and minikube evidence in the [baseline](RFC-Features-Baseline.md). |
| **1. ML-DSA primitives and X.509** · crypto and PKI maintainer | [FIPS 204][fips204] §§5–7 and [RFC 9881][9881] §§2–6. The NIST OIDs for 44/65/87 are `2.16.840.1.101.3.4.3.17`, `.18` and `.19`. | OID constants exist. Built-in signing, verification and key loading are absent. The proposed certificate policy is explicit. Preserve existing path and trust-anchor behavior. | Align PKI verification interfaces with each supported provider. Preserve an alloc-free PKI verification build and existing alloc configurations. | Independent NIST ACVP vectors and DER cases. OpenSSL 3.5 documents the primitive and key formats. Go 1.27 documents ML-DSA primitives and X.509. Verify exact fixture forms and operations. |
| **2. ML-DSA TLS 1.3** · TLS authentication maintainer | [draft-ietf-tls-mldsa-06][mldsa-draft] §§3–5. [IANA][tls-iana] lists `mldsa44/65/87` as `0x0904`, `0x0905`, `0x0906`, Recommended `N`. | Code points exist. Built-in negotiation and signing are absent. Any draft-era offer is experimental and opt-in. The PKI and transcript uses have separate rules. | Depends on Phase 1 plus signing and verification mappings in both providers. Trace shared stream, QUIC and DTLS paths, their constraints and alloc support before enabling. | Go 1.27.4 ran baseline ECH and is a candidate based on documented TLS support. Its existing harness lacks ML-DSA credentials and exact scheme assertions. EVP primitive support alone supplies zero TLS negotiation evidence. |
| **3. Legacy RSA client authentication** · TLS authentication maintainer | [RFC 9963][9963] §§3–5. Signature schemes `0x0420`, `0x0520`, `0x0620` are the SHA-256/384/512 legacy variants. | Absent. Proposed opt-in TLS 1.3 client `CertificateVerify` only. Retain RSASSA-PSS for capable keys and required server support. Existing PKCS#1 certificate code points keep their roles. | Native signing is available for ordinary schemes. RustCrypto has RSA verification but lacks built-in RSA signing. Inventory custom signers and preserve alloc-only core. | Existing OpenSSL mutual authentication is a control. Exact legacy scheme and key restrictions need a separate verified peer or a documented gap. |
| **4. ECH key log** · ECH and diagnostics maintainer | [RFC 9850][9850] §§1.1, 2.3, 3 and 5. `ECH_SECRET` and `ECH_CONFIG` are registered log labels. [RFC 9849][9849] and [RFC 9180][9180] define the underlying configuration and KEM. | Generic logging and ECH exist. Both ECH labels are absent. Preserve `NoKeyLog` and the non-default diagnostic feature. Logging adds diagnostic output while the ECH handshake retains its existing wire format. | Built-in ECH HPKE is native. Trace custom suites and split-role boundaries. Preserve alloc for callbacks and Linux `std` for the file sink. | Go ECH, OpenSSL ordinary labels and the minikube file-state checks cover adjacent behavior. Verify a pinned Wireshark build with synthetic ECH captures before requiring its decoding. |
| **5. TLS version policy** · configuration and facade maintainer | [RFC 9852][9852] §4 and [RFC 9851][9851] §4. TLS 1.3 uses the existing `supported_versions` extension and `0x0304` version value. | Exact version selection exists. Defaults prefer TLS 1.3 and include TLS 1.2 where compiled. Document explicit TLS 1.3 selection and assess a convenience preset. | Applies to both client and server builders, both providers and alloc. Adapters consume shared configuration. QUIC already requires TLS 1.3. These policies leave DTLS version selection to its own rules. | Local opt-in and refusal tests on both sides. The OpenSSL matrix establishes connectivity for the configured TLS 1.2 and TLS 1.3 cases. |
| **6. HPKE modes** · crypto maintainer | [RFC 9180][9180] §5 and Appendix A. Modes `0x00` base, `0x01` PSK, `0x02` Auth, `0x03` AuthPSK. Check the [IANA HPKE registries][hpke-iana] and [successor draft][hpke-draft]. | Base only. A separately justified primitive could add explicit modes. ECH stays on base. | Native primitive and provider adapter. Preserve alloc for public HPKE contexts. RustCrypto provider coverage and the independent dev-only `hpke` crate are separate. | Existing base vectors and differential checks. RFC vectors for extra modes and a version-pinned oracle that exercises them are required for the approved scope. |
| **7. DTLS 1.3 options** · DTLS transport maintainer | [RFC 9147][9147] §§5.3, 5.6, 5.8.4, 5.9, 6.1 and 7 with [RFC 9853][9853]. ECH uses [RFC 9849][9849]. Each feature has its own mapping below. | Early data, ECH and post-handshake client auth are absent. Plan explicit opt-ins per feature, retaining DTLS 1.3 defaults and separately enabled DTLS 1.2. | Core datagram/acceptor APIs, blocking UDP, Tokio events and sessions, facade. Preserve alloc for core and keep socket effects in the `std` adapters. ECH needs an HPKE suite. | Existing wolfSSL, Pion and OpenSSL harnesses cover other DTLS behavior. No exact external scenario was established for these options. Use deterministic loss/reorder tests and confirm any peer used. |
| **8. HTTPS/SVCB integration** · client configuration maintainer | [RFC 9460][9460] §§2.2, 2.4, 3, 7–9 and [RFC 9848][9848] §§3–5. [IANA SvcParamKeys][svcb-iana] include `mandatory` 0, `alpn` 1, `no-default-alpn` 2, `port` 3, and `ech` 5. DNS RR types SVCB/HTTPS are 64/65. | ECH parameter extraction exists. Generic selection and resolver policy are absent. Any new integration is caller-controlled and consumes validated resolution results. | Parser uses alloc and is provider-independent. Using extracted ECH config requires a compatible HPKE suite. Facade and Tokio have shared core access. | Existing wire/presentation parser cases and Go ECH exchanges. The latter start after service discovery. Add RFC-derived RRset selection fixtures and verify a DNS oracle separately. |
| **9. Integration qualification** · integration maintainer | Use the exact standards and wire IDs from each completed phase. | Validation and public handoff. Record tested configurations and explicit deferrals. | Cover each affected provider, API, transport, facade feature and platform. | Fixed peers and known-answer vectors, real kTLS where affected, scoped Docker/minikube/QEMU evidence and bounded fuzz tests selected from changed surfaces. |

## Cryptography, authentication, and secret handling

- **Phase 1.** RFC 9881 requires absent `AlgorithmIdentifier` parameters
  for the pure variants. Verify canonical encoding, key and signature
  lengths and all supported private-key forms, including consistency
  when seed and expanded key are both supplied. Cover path and CRL
  failures, allocation bounds, key erasure, entropy and side channels.
  Verified errata [8699][e8699] and [8700][e8700] correct Appendix A's
  ML-DSA-87 public-key size to 2,592 bytes and the ASN.1 arc name.
  Apply NIST's separately published potential-update list when reviewing
  the primitive. [NIST vectors][nist-vectors] · [OpenSSL 3.5][openssl-ml-dsa]
  · [Go 1.27][go]
- **Phase 2.** The Datatracker lists revision 06 in the RFC Editor queue.
  The draft defines pure ML-DSA with empty FIPS 204 context and an
  end-entity SPKI matching the scheme. The TLS 1.3 transcript context
  and the FIPS 204 context are distinct inputs. Separate certificate
  chain signature negotiation from `CertificateVerify`, select by
  authenticated role and key, and refuse unoffered schemes or role,
  key and scheme mismatches. Bound certificate buffers and review HRR,
  resumption, PHA, delegated credentials and compression before claiming
  those paths. [Draft status][mldsa-status] · [Go 1.27][go]
- **Phase 3.** Only a server CertificateRequest can offer the legacy
  IDs for use in client `CertificateVerify`. A server may accept only
  a scheme it offered. Ordinary certificate-signature negotiation
  retains its existing IDs. Reject server use and client advertisements
  of the legacy IDs, wrong digests and invalid DER, including absent
  mandatory NULL in DigestInfo. Test direct keys and reviewed caller
  signers within the same role and advertisement constraints.
- **Phase 4.** A real client offer is eligible whether accepted or
  rejected. Server eligibility starts at successful ECH decryption.
  Both labels use the outer random. `ECH_SECRET` records the HPKE KEM
  shared secret and `ECH_CONFIG` records the selected ECHConfig in
  hexadecimal. RFC 9850 §1.1 prohibits SSLKEYLOGFILE in production.
  The current HPKE traits expose encapsulation and context operations.
  Review how the log path can reach the KEM value under explicit
  authorization. Cover GREASE, failed trial decryptions, HRR, split
  forwarding and rejected offers. Restrict evidence to synthetic
  traffic, label counts and file metadata. [Wireshark candidate][wireshark]

The RFC Editor index contained zero entries for RFCs 9963, 9850, 9848,
9849, 9851, 9852, 9853, 9146, 9934 and 10024. For adjacent TLS
requirements in RFC 9846, verified erratum 9040 is in Appendix E.2,
while 9042, 9043, 9157 and 9161 are Reported. RFC 9001 has verified
erratum 9272 on header protection, held 9231 and rejected 7785.

## Policy, HPKE, datagrams, and DNS

- **Phase 5.** RFC 9852 requires TLS 1.3 as the default for new
  protocols using TLS. It permits a non-default TLS 1.2 option when
  deployment warrants it. RFC 9851
  permits urgent security fixes under TLS WG consensus, new exporter
  labels, and new ALPN IDs. Both are scoped to TLS. Exercise explicit
  TLS 1.3-only client and server configurations against a TLS 1.2-only
  peer and verify configuration keeps the intended version policy.
- **Phase 6.** For the implemented suites, IANA KEM IDs are
  `0x0010/11/12` and `0x0020/21`. KDF IDs are `0x0001/2/3`. AEAD
  IDs are `0x0001/2/3` plus export-only `0xffff`. Verified errata
  6941, 7121, 7790, 7932, 7934 and 7937 address single-shot guidance,
  X25519 vectors, Auth-mode guarantees, sequencing text, PSK/ID and
  `info` clarification, and KEM derivation. Items 7251 and 7933 are
  Held. Review authenticated-mode limits, including the absence of
  Insider-Auth guarantees, paired PSK inputs, suite binding, nonce and
  context limits, and exporter separation. The successor revision 06
  proposes to obsolete RFC 9180 and specifies Base and PSK only. It
  reserves Auth and AuthPSK IDs for the RFC 9180 variants. Resolve the
  target specification and real application use before implementing
  any mode. Resolved on 2026-11-28: the target is RFC 9180 with the
  verified errata, for all three modes, and `draft-ietf-hpke-hpke-06`
  agrees on PSK. The users are applications of the HPKE primitive and
  of the core provider API; no browntls protocol uses the new modes,
  and ECH stays on base mode. See
  [Architecture](Architecture.md#primitive-backends).
- **Phase 7.** RFC 9147 §5.6 omits EndOfEarlyData, including in the
  transcript. Section 6.1 assigns early data to epoch 1. The TLS
  `early_data` extension uses ID 42. Add cross-connection replay
  authorization before allowing application delivery. Section 5.8.4
  defines separate reliable post-handshake authentication exchanges.
  Use the existing `post_handshake_auth` extension ID 49 and check
  request contexts, flight ownership, limits and out-of-order delivery.
  RFC 9849 §§5.1–5.2 and 6.1 cover DTLS ECH serialization, outer AAD and
  base-mode HPKE. Also check DTLS transcript and label rules. ECH uses
  `encrypted_client_hello` `0xfe0d`, `ech_outer_extensions`
  `0xfd00`, and `ech_required` alert 121. Review each feature around
  CID, authenticated migration and resource budgets. RFC 9147 verified
  erratum 8100 clarifies the ACK code point. Technical reports 8047,
  8048, 8050, 8051, 8066, 8067, 8107, 8108 and 8141 remain Reported.
- **Phase 8.** Audit whole-RRset handling separately from extracting
  an `ech` value. Check AliasMode and ServiceMode, priority, mandatory
  keys, ALPN, port, duplicate/truncated input and fallback. RFC 9848
  §5.1 requires ECH-capable, SVCB-optional clients to use SVCB-reliant
  connection establishment when SVCB resolution succeeds and all
  alternative endpoints advertise `ech`. Application policy owns DNS
  validation. Preserve the origin reference identifier
  for certificate verification regardless of a DNS-selected alternative
  target. RFC 9460 errata 7871, 8168 and 8787 are Rejected.

[errata]: https://www.rfc-editor.org/errata.json
[fips204]: https://csrc.nist.gov/pubs/fips/204/final
[9881]: https://www.rfc-editor.org/rfc/rfc9881.html
[mldsa-draft]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-06
[mldsa-status]: https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/
[tls-iana]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
[9963]: https://www.rfc-editor.org/rfc/rfc9963.html
[9850]: https://www.rfc-editor.org/rfc/rfc9850.html
[9849]: https://www.rfc-editor.org/rfc/rfc9849.html
[9852]: https://www.rfc-editor.org/rfc/rfc9852.html
[9851]: https://www.rfc-editor.org/rfc/rfc9851.html
[9180]: https://www.rfc-editor.org/rfc/rfc9180.html
[hpke-iana]: https://www.iana.org/assignments/hpke/hpke.xhtml
[hpke-draft]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-06
[9147]: https://www.rfc-editor.org/rfc/rfc9147.html
[9853]: https://www.rfc-editor.org/rfc/rfc9853.html
[9460]: https://www.rfc-editor.org/rfc/rfc9460.html
[9848]: https://www.rfc-editor.org/rfc/rfc9848.html
[svcb-iana]: https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
[e8699]: https://www.rfc-editor.org/errata/eid8699
[e8700]: https://www.rfc-editor.org/errata/eid8700
[nist-vectors]: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
[openssl-ml-dsa]: https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/
[go]: https://go.dev/doc/go1.27
[wireshark]: https://www.wireshark.org/docs/wsar_html/structssl__master__key__map__t.html
