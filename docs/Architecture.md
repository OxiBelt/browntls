# Architecture

This document describes the design of browntls: a TLS 1.2 / TLS 1.3 library
written from scratch in Rust, targeting the feature level of rustls 0.23, with
its own cryptographic primitives behind a pluggable provider interface.
Implementation status is tracked in [Status](#status); the
[contributor guide](../CONTRIBUTING.md) and [security policy](../SECURITY.md)
govern how changes land.

## Crates

```text
browntls-crypto   primitives; no_std, no alloc; arch backends; no dependencies
       ^
       | (feature "native", default)
browntls ----------> browntls-pki   PKI types, PEM, X.509 path validation;
  crypto::*  (mount point)           no_std + alloc; no cryptography
  crypto::native     (default provider, browntls-crypto)
  crypto::rustcrypto (optional provider, RustCrypto crates)
       ^
       |
browntls-tokio      Tokio AsyncRead/AsyncWrite streams over browntls
```

| Crate | Role | `unsafe` |
|---|---|---|
| `browntls-crypto` | Hashes, MACs, KDFs, AEADs, key exchange, signatures, KEM, HPKE, CPU detection, OS entropy | Denied crate-wide; allowed only in architecture backend modules, CPU detection, zeroisation and the system-call trampoline |
| `browntls-pki` | Certificate/key/name/time types, PEM, X.509 path building, name and revocation checks | Forbidden |
| `browntls` | Record layer, handshake state machines, configuration, provider traits and providers | Forbidden |
| `browntls-tokio` | Asynchronous client and server streams for Tokio over the buffered connection API | Forbidden |

`browntls-pki` performs no cryptography: signatures are checked through the
`SignatureVerificationAlgorithm` trait supplied by the active provider. This
keeps certificate policy independent of any particular primitive library.
An algorithm is selected by its key and signature `AlgorithmIdentifier`s,
compared byte for byte except for `id-RSASSA-PSS`, whose equivalent
parameter encodings (RFC 4055) are first mapped to one canonical constant
(`AlgorithmIdentifier::matches_public_key` and `matches_signature`, used by
path validation and by handshake signature verification alike).

## Crypto provider mount point

`browntls::crypto` defines the provider interface, modelled on rustls 0.23 so
that existing provider designs map onto it:

- `CryptoProvider`: cipher suites, key-exchange groups, signature
  verification algorithms, secure random source and private-key loader. A
  process default can be installed; configurations can also be built with an
  explicit provider.
- Traits for each capability: hashing, HMAC, HKDF (TLS 1.3), PRF (TLS 1.2),
  record protection (`Tls13AeadAlgorithm`, `Tls12AeadAlgorithm`,
  `MessageEncrypter`, `MessageDecrypter`), key exchange (`SupportedKxGroup`,
  `ActiveKeyExchange`, including hybrid post-quantum groups), signing
  (`SigningKey`, `Signer`), randomness and key loading, plus hooks that export
  traffic secrets for kernel TLS offload.

Providers shipped in the `browntls` crate:

| Provider | Feature | Backing |
|---|---|---|
| `crypto::native` | `native` (default) | `browntls-crypto` |
| `crypto::rustcrypto` | `rustcrypto` | RustCrypto crates |

A provider is plain data (static trait objects), so applications can build a
mixed provider, for example native AEADs with RustCrypto signatures, or supply
their own implementation of any trait; `crates/browntls/tests/native_mixed.rs`
shows the pattern. When exactly one provider feature is enabled it becomes the
implicit default; with both enabled, the application installs one explicitly.

### Algorithm tiers (native provider)

Everything RFC 9846 §9.1 makes mandatory or recommended is preferred. The
remaining TLS 1.3 algorithms that RFC 9846 defines form a non-preferred tier:
they come after every other entry of each preference list, so they are only
negotiated when a peer shares nothing earlier.

| Kind | Preferred (default order) | Non-preferred tier (default) | Opt-in only (`ALL_*` lists) |
|---|---|---|---|
| TLS 1.3 suites | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 | AES-128-CCM, then AES-128-CCM-8 (64-bit tag; no kernel TLS export) | |
| TLS 1.2 suites | ECDHE with AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 (ECDSA and RSA) | ECDHE AES-CBC: AES-256-CBC-SHA384, AES-128-CBC-SHA256, then AES-256-CBC-SHA, AES-128-CBC-SHA (ECDSA and RSA; RFC 5289, RFC 8422); Encrypt-then-MAC only by default; no kernel TLS export | |
| Groups | X25519MLKEM768, X25519, P-256, P-384 | X448, then FFDHE2048, FFDHE3072, FFDHE4096 (TLS 1.3 only, RFC 10015 §3) | FFDHE6144, FFDHE8192 (server cost 10 to 20 ms per handshake); the other ML-KEM groups and P-521 |
| Signature schemes | ECDSA, Ed25519, RSA-PSS (rsae), RSA PKCS #1 v1.5 | Ed448, then `rsa_pss_pss_sha512/384/256` (RSASSA-PSS public keys) | |

A browntls server applies the same ranking whatever the client's order:
within each tier it follows the client's order (or its own with
`ignore_client_order`), but it picks a non-preferred suite or group only when
no preferred one is mutually supported, and it answers a key share for a
non-preferred group with a HelloRetryRequest when a preferred group is
available (`CipherSuite::is_non_preferred`, `NamedGroup::is_non_preferred`).
With AES-128-CCM-8, a server that rejects 0-RTT fails the handshake once 2^7
records have failed authentication under the client handshake key (RFC 9147
Appendix B.3), including the client's own early-data records.

The RustCrypto provider does not implement the non-preferred tier.

### TLS 1.2 record protection

TLS 1.2 suites are either `GenericAEADCipher` or `GenericBlockCipher`
(RFC 5246 §6.2.3); `Tls12RecordProtection` names which, and the key block
(RFC 5246 §6.3) is split accordingly (`KeyBlockShape`). Stream ciphers (RC4,
RFC 7465) and the RSA and finite-field Diffie-Hellman key exchanges that
RFC 10015 prohibits in TLS 1.2 are not implemented.

For the CBC suites the client sends `encrypt_then_mac` (RFC 7366) whenever a
CBC suite is on offer, and the server acknowledges it only when it selects a
CBC suite. By default neither side uses a CBC suite without it (RFC 9325 §4.2):
a server with `allow_mac_then_encrypt` unset does not select a CBC suite for
a client that did not offer the extension, and a client with it unset refuses
a CBC suite the server selected without acknowledging it. The MAC-then-encrypt
transform is implemented, for the opt-in, in time independent of the padding
(`browntls_crypto::tls_cbc`): a fixed number of hash compressions per record
length and a constant-time padding check, the Lucky Thirteen countermeasure.
SHA-1 exists only as the HMAC of the `*_CBC_SHA` suites; no signature uses it
(RFC 9155). The explicit per-record IV comes from the operating system.

A TLS 1.2 client also requires the server to acknowledge
`renegotiation_info` (RFC 5746) unless `require_secure_renegotiation` is
cleared (RFC 9325 §3.5), and neither side ever renegotiates. A connection
that ends with a fatal alert forgets its TLS 1.2 session on both sides
(RFC 5246 §7.2.2), and a TLS 1.2 server honours the client's curves for its
ECDSA certificate as well as for key exchange (RFC 8422 §5.3).

### TLS 1.3 protocol rules (RFC 9846)

TLS 1.3 follows RFC 9846, which obsoletes RFC 8446; RFC 6066 supplies
`server_name` and `status_request`. The rules that RFC 9846 tightened, and
where they live:

- Extensions are checked against RFC 9846 Table 1 (`tls13::extensions`;
  extensions outside the table follow the TLS 1.3 column of the IANA
  registry, and TLS 1.2-only ones are allowed in a ClientHello alone;
  `record_size_limit` and `ticket_request` may appear in ClientHello and
  EncryptedExtensions only). A
  recognised extension in a message that may not carry it is
  `illegal_parameter`; one that answers nothing we sent is
  `unsupported_extension`. This covers ServerHello, HelloRetryRequest,
  EncryptedExtensions, CertificateRequest, CertificateEntry and
  NewSessionTicket.
- Versions: a ClientHello with `supported_versions` and a TLS 1.3
  ServerHello or HelloRetryRequest must carry `legacy_version` 0x0303
  (`protocol_version` otherwise); a `supported_versions` value the client did
  not offer, or below TLS 1.3, is `illegal_parameter`.
- HelloRetryRequest: the server remembers the cipher suite and group it
  selected; the second ClientHello must carry exactly one key share, for that
  group, and still offer that suite (`illegal_parameter`). After a
  HelloRetryRequest the client drops a PSK whose hash differs from the
  selected suite's.
- KeyUpdate (`CommonState::key_update_to_send`, `ConnectionCore::
  maybe_send_key_update`): the answer to `update_requested` is sent once,
  after the received flight is processed and before any further application
  data, however many requests arrived; a side that asked does not ask again
  until a KeyUpdate from the peer arrives (a refresh then rotates only its own
  key); no more than 2^48-1 key updates are sent, after which a peer's request
  is ignored and the public `refresh_traffic_keys` fails. A write that reaches
  the confidentiality limit rotates the key before the write returns; when
  the key cannot be rotated yet (a server's half-RTT data before the client's
  Finished), the record layer takes no more data until it can, and plaintext
  buffered before the handshake stays buffered across the rotation. 0-RTT
  data, which cannot be rekeyed, stops short of the limit. No KeyUpdate (and
  no ticket) is sent after our own `close_notify` (§6.1). The limit is not
  enforced on received records. A peer that keeps requesting updates without
  sending non-empty application data in between is cut off after eight
  requests, a local resource bound.
- Record layer: a protected `change_cipher_spec` record, or one whose value
  is not 0x01, is `unexpected_message`.
- Rejected 0-RTT: a server that declines early data skips the client's
  undecryptable records while their plaintext totals at most
  `max_early_data_size` (§4.2.10); each record is charged its length less
  the suite's tag and content type byte, an upper bound on its plaintext,
  and at least one byte, so the budget also bounds the number of records
  tried (`RecordLayer::doing_trial_decryption`). One byte more fails with
  `bad_record_mac`. After a HelloRetryRequest no key is tried: records are
  charged their length, at least one byte, and the next one past the budget
  is read as the second ClientHello.
- Alerts: `general_error` (117) exists; `user_canceled` is ignored at either
  level in TLS 1.3 (the peer must follow it with `close_notify`), within the
  same bound as TLS 1.2 warning alerts; every other alert except
  `close_notify` ends the connection whatever its level.
- Tickets: a server sends NewSessionTicket only when the ClientHello offered
  `psk_dhe_ke`, announces a lifetime of at most seven days (one day for
  session-cache tickets, the ticketer's otherwise), sends no ticket when that
  lifetime would be zero, and does not resume a PSK older than it. A client
  discards a ticket with a zero lifetime.
- Signatures: in TLS 1.3 an ECDSA scheme binds its curve (a P-384 key
  cannot verify `ecdsa_secp256r1_sha256`); a client's CertificateVerify must
  use a scheme from the server's CertificateRequest list. A signature inside
  the certificate chain that fails, or uses an algorithm not accepted (MD5,
  SHA-1), is `bad_certificate`; `decrypt_error` is kept for handshake
  signatures.
- Server certificates: an empty Certificate message is `decode_error` when it
  arrives; a non-empty `certificate_request_context` is `illegal_parameter`;
  OCSP responses may come with any entry (only the end entity's is used).
- Key shares come in `supported_groups` order, and a server that would have
  preferred a group other than the one the client's shares allowed lists its
  groups in EncryptedExtensions (RFC 9846 §4.3.7). Key shares are generated
  per connection and never reused.

Not implemented: RFC 6066 `max_fragment_length` (not "Recommended" in
RFC 9846 Table 1; `record_size_limit` and the local `max_fragment_size`
setting cover the use case).

### Client session resumption

A saved client session (TLS 1.2 session ID or ticket, TLS 1.3 ticket) is
bound to the identities of the `Arc`s that established it: the
configuration's server certificate verifier and its client certificate
resolver (`ClientConfig::client_auth_cert_resolver`). A configuration offers a
stored session only when both are the same objects, compared by address and
held weakly, so the store keeps neither alive and a later allocation cannot
reuse the address while the session exists. A session authenticated with a
delegated credential is offered only while `enable_delegated_credentials` is
set.

A `ClientSessionStore` shared between configurations, or a cloned
configuration given another verifier with
`DangerousClientConfig::set_certificate_verifier`, therefore makes a full
handshake under its own verifier rather than resuming a session another
verifier accepted, and does not reuse a TLS 1.2 session whose client identity
another resolver chose. Configurations that share the verifier and resolver
(for example clones) keep resuming each other's sessions. Equivalent but
distinct verifier objects do not match, and a verifier whose own policy
changes at run time keeps its sessions; give such configurations separate
stores.

Configurations sharing a store still share its slots: an incompatible TLS 1.3
ticket is consumed and dropped (no older ticket or TLS 1.2 session is tried
instead), and the next full handshake replaces the single TLS 1.2 session
kept per server name. This costs resumptions, never verification.

### Post-handshake client authentication (RFC 9846 §4.7.2)

A client offers `post_handshake_auth` when `ClientConfig::
enable_post_handshake_auth` is set (off by default) and its certificate
resolver has certificates. Its traffic state then keeps a copy of the
transcript through its Finished and answers every CertificateRequest at
once, in order, from the resolver: Certificate echoing the request's
context, CertificateVerify over `Transcript-Hash(handshake .. client
Finished, CertificateRequest, Certificate)` when it has a usable key (an
empty Certificate otherwise), and a Finished keyed by the current
`client_application_traffic_secret_N`. Each exchange starts from the
handshake transcript, not from earlier exchanges (§4.5). A
CertificateRequest without our offer is `unexpected_message`, one with an
empty `certificate_request_context` is `illegal_parameter` (§4.4.2); its
extensions are checked as in the handshake. Each answer costs a signature,
so a client answers at most eight requests while the server sends no
application data and then aborts with `unexpected_message`, the same local
resource bound as for KeyUpdate requests.

A server learns the offer from the ClientHello (`ServerConnection::
post_handshake_auth_offered`). `ServerConnection::request_client_auth`
needs a completed TLS 1.3 handshake, the offer, a verifier that offers
client authentication and no request still unanswered (one at a time,
which bounds the state kept per connection). The request's
`certificate_request_context` is an 8-byte request counter followed by 24
random bytes: unique on the connection and unpredictable (§4.4.2). The
answer may come after any amount of application data or KeyUpdates, but
once its Certificate has arrived the CertificateVerify and Finished must
follow with nothing in between (`unexpected_message` otherwise). The
answer goes through the same checks as the handshake's client
authentication (context echo, `ClientCertVerifier`, scheme from our list,
signature), then a constant-time Finished check (`decrypt_error`). Only
after the Finished does `peer_certificates` change and
`post_handshake_auth_status` become `Authenticated`; an empty Certificate
is `Declined` (and `certificate_required` when the verifier makes client
authentication mandatory). A resumed handshake may be followed by
post-handshake authentication, as §4.4.2 allows.

With `ServerConfig::request_client_auth_after_handshake` set, a server
leaves client authentication out of a TLS 1.3 handshake whose client
offered `post_handshake_auth`; other clients, and TLS 1.2, are asked in the
handshake as before. The handshake then completes without a client
certificate even when the verifier makes it mandatory, so the application
must request and check it. RFC 8740 forbids post-handshake authentication
over HTTP/2; the library does not tie either setting to ALPN, the
application chooses.

### Stateless HelloRetryRequest cookies (RFC 9846 §4.3.2)

`ServerConfig::hello_retry_cookies` (default `None`) holds a
`ProducesTickets` sealer, which should be a dedicated instance with its own
key (for example a separate `TicketRotator` over an AEAD ticket producer).
Creating a connection with the `ServerConfig::ticketer` instance itself as
the sealer fails; a separate sealer sharing the ticketer's key cannot be
detected, but the plaintexts stay disjoint (a ticket starts with a 0 or 1
byte, a cookie with its label), which a unit test pins.
When it is set, a HelloRetryRequest carries a cookie that seals
(`server::cookie`):

```text
"browntls hrr ck1" (domain label, 16 bytes) | issued_at u64 (seconds)
| cipher_suite u16 | named_group u16 | Hash(ClientHello1) <1 byte length>
| legacy_session_id <1 byte length> | server_name <1 byte length>
```

The connection that sent the HelloRetryRequest keeps its state and requires
the second ClientHello to echo the cookie byte for byte
(`missing_extension` if absent, `illegal_parameter` if different). A fresh
`ServerConnection` or `Acceptor` whose first ClientHello carries a cookie
opens it instead: it must authenticate under the sealer's current or
previous key, carry the label, parse exactly and be at most 60 seconds old
(in either direction, for servers sharing a key); the suite and group must
still be configured, the hash length must match the suite's, and the
ClientHello must repeat the session ID and server name. Any failure is
`illegal_parameter` (RFC 9846 names no alert for a bad cookie; RFC 9147
§5.1 uses `illegal_parameter` for DTLS). The connection then rebuilds the
transcript as `message_hash(Hash(ClientHello1))` followed by the
HelloRetryRequest re-encoded from the cookie (§4.5), takes the cookie's
suite and group as the retry's choice, and continues with the usual
second-ClientHello rules. Like the stateful path, it compares the second
ClientHello with the first only through what the cookie carries (suite,
group, session ID, server name) and through `Hash(ClientHello1)` in the
transcript, which the PSK binders and Finished cover. If the clock fails
while a cookie is issued or opened, the handshake aborts with
`internal_error`. Such a connection ignores change_cipher_spec
records before that ClientHello (within the usual bound), as §4.3.2
requires; ahead of any other first ClientHello they stay
`unexpected_message`. Without a sealer no cookie is sent and one in a first
ClientHello is ignored, as before.

No cookie is sent when the first ClientHello offered 0-RTT: the client's
early data records would reach a fresh connection ahead of its second
ClientHello, so that retry stays stateful. Nor when it carried an ECH extension (GREASE
included): the HPKE context and the HelloRetryRequest's ECH extension
cannot be rebuilt from a cookie, so a fresh connection refuses a cookie
whose ClientHello offers ECH (`illegal_parameter`). A cookie can be replayed during
its lifetime by anyone who saw it; that gives no more than replaying the
second ClientHello would, since the handshake still needs the client's key
share and Finished. Cookies are not bound to the client's address: that
is fine over TCP, where the handshake itself proves the address, but a
datagram transport would need that binding to stop amplification.

### Exporters

`export_keying_material` is the RFC 9846 §7.5 exporter (RFC 5705 in TLS
1.2, where it requires the extended master secret). `ConnectionCommon::
export_early_keying_material` is the separate early exporter that §7.5
recommends, from `early_exporter_master_secret` (logged as
`EARLY_EXPORTER_SECRET`; checked against RFC 8448 §4). A client has it from
the moment it offers 0-RTT and loses it if the server rejects 0-RTT; a
server has it once it accepts 0-RTT. Like 0-RTT data it is not forward
secret and replays with the ClientHello.

`tls_exporter_channel_binding` is the RFC 9266 `tls-exporter` channel
binding: 32 bytes under the label `EXPORTER-Channel-Binding` with an empty
context. RFC 9266 §2 defines it for TLS 1.3 and for earlier versions only
with the extended master secret, which the TLS 1.2 exporter requires
anyway; since browntls never renegotiates, the RFC 9266 §4.2 renegotiation
exclusion does not arise.

### TLS 1.3 external PSKs

External pre-shared keys (RFC 9846 §4.3.11) live in `browntls::psk`. An
`ExternalPsk` carries its identity, key, hash (SHA-256 or SHA-384) and
optional restrictions: one cipher suite, one server name, one ALPN protocol.
A caller may also attach an opaque local key generation with
`with_key_generation`; each endpoint applies its own value independently, and
it is not sent in the handshake.
A client lists its keys in `ClientConfig::external_psks`; a server finds them
through a `ResolvesExternalPsk` in `ServerConfig::external_psks`
(`with_external_psks_only` builds a server without a certificate).

- Key exchange: only `psk_dhe_ke`. The `psk_ke` mode, which gives up forward
  secrecy (RFC 9257), is neither offered nor accepted; a server ignores the
  PSKs of a client that offers only `psk_ke`.
- Client: a resumption ticket comes first, then the external PSKs in
  configuration order, each with an obfuscated ticket age of zero and a
  binder over the hash of the first offered suite it is usable with, under
  the `ext binder` label (`imp binder` for imported keys, `res binder` for
  tickets). After a HelloRetryRequest only the PSKs usable with the selected
  suite are offered again. The key schedule then continues with the
  negotiated suite (which may differ from the binder's in everything but
  the hash).
- Server: the first offered external PSK usable with a suite the server
  could select narrows the suite choice to the suites it is usable with (the
  server "MUST ensure that it selects a compatible PSK (if any) and cipher
  suite"). Of the first 16 identities (a local bound on lookups and ticket
  decryption; later ones are ignored), the first that names a usable external
  PSK or ticket is selected and only its binder is checked, in constant time;
  a wrong binder is `decrypt_error`. An identity whose binder length is not
  that of the key's hash is passed over. A handshake that selects an external
  PSK sends no certificate; with no PSK selected, a server without a
  certificate fails with `handshake_failure`. A client that offers TLS 1.3
  only and a PSK may omit `signature_algorithms` (RFC 9846 §4.3.3); it is
  then served by PSK only. Only servers configured with external PSKs defer
  the missing-certificate failure to after PSK selection.
- 0-RTT: off by default for external PSKs (RFC 9257). `with_early_data`
  enables it per key; the key needs a provisioned suite and must be the first
  offered, and the server checks suite and ALPN protocol against the
  provisioned ones (RFC 9846 §4.3.10). There is no anti-replay protection
  for external PSKs: such early data can be replayed.
- Importer (RFC 9258): a key configured with `imported(context)` is used
  only through the importer. The client offers one `ImportedIdentity` per
  hash of its TLS 1.3 suites (target protocol TLS 1.3, target KDF
  `HKDF_SHA256` or `HKDF_SHA384`), with `ipskx = HKDF-Expand-Label(
  HKDF-Extract(0, epsk), "derived psk", Hash(ImportedIdentity), L)` under the
  EPSK's hash; the server parses the identity, resolves its external identity
  and requires the same context. The EPSK's hash must be that of one of the
  provider's TLS 1.3 suites. No published test vectors exist; the derivation
  is checked against an independent HMAC computation and across providers.
- Certificate authentication with an external PSK (RFC 8773,
  `tls_cert_with_extern_psk`, 0x0021): opt-in on both sides
  (`cert_with_extern_psk`). A client sends the extension only when it offers
  an external PSK, and then no 0-RTT under one; a server echoes it in its
  ServerHello only when it selected an external PSK and has a certificate,
  and then authenticates with Certificate and CertificateVerify (and may
  request client authentication) on top of the PSK and (EC)DHE. A client
  rejects the extension without an external PSK (`illegal_parameter`) and,
  with `require_cert_with_extern_psk`, a server that does not negotiate it.
  A client that sends the extension offers no resumption ticket alongside,
  so the server cannot skip the requested certificate by resuming instead (a
  conservative choice, not an RFC 8773 requirement).
- `CommonState::external_psk_identity` reports the key used, once the peer's
  Finished has verified (until then the peer has not proven it holds the
  key); such a handshake is `HandshakeKind::Full`. A peer that offers or
  accepts external PSKs may still complete a handshake without one;
  `require_external_psk` (client and server) refuses that with
  `handshake_failure`, otherwise the application must check
  `external_psk_identity` after the handshake. With it, a client offers only
  tickets from external-PSK sessions and a server passes over other tickets;
  TLS 1.2 is refused.
- Tickets: a ticket issued on a connection that used an external PSK records
  the PSK's identity, importer context and a per-ticket verifier derived from
  the raw key, optional key generation and that ticket's resumption secret
  (in the server's encrypted ticket and in the client's
  `Tls13ClientSessionValue`). Resuming it reports the same
  `external_psk_identity` (as `HandshakeKind::Resumed`) and counts for
  `require_external_psk`. The client offers such a ticket only while the PSK
  is configured, usable for the connection and still verifies; the server
  resolves the identity again and applies the same check. Changing either the
  key bytes or the optional generation therefore invalidates existing tickets;
  removing the key does too. Identity-only ticket records from older browntls
  revisions fail closed rather than resuming without a key binding.

RFC 9257 guidance and what browntls enforces:

- Keys shorter than 128 bits are refused (`ExternalPsk::MIN_KEY_LEN`); the
  entropy of a key cannot be measured, and a low-entropy secret such as a
  password must not be used as a PSK (it needs a PAKE).
- A PSK must be known to exactly two parties, and a node that acts as client
  and as server must use distinct PSKs for the two roles: sharing a key more
  widely lets any holder impersonate any other (including reflection of a
  connection back to its sender). browntls cannot see this; it is a
  provisioning rule for the application.
- Identities are sent in clear and can link connections of one client;
  choose identities that reveal nothing and, where linkability matters, are
  not stable. The resolver receives unauthenticated identities and should
  not leak through timing or errors which identities exist. The handshake
  itself tells them apart: a known identity with a wrong binder fails with
  `decrypt_error`, while an unknown one is passed over (a certificate
  handshake, or `handshake_failure` without one). This is inherent in
  checking binders only for identities the server knows.
- A server that holds an external PSK and a certificate authenticates with
  the PSK when one is offered; the PSK proves only possession of the key,
  not any certificate identity.

### Optional ClientHello extensions

- `record_size_limit` (RFC 8449), both sides, TLS 1.3 and 1.2, on by
  default (`ClientConfig::record_size_limit`,
  `ServerConfig::record_size_limit`, default 16385): the client announces
  the configured value, lowered to the protocol maximum (2^14 + 1 when TLS
  1.3 is offered, 2^14 otherwise); a server answers only a client that sent
  it, in EncryptedExtensions (TLS 1.3) or the ServerHello (TLS 1.2), with
  its value lowered to the negotiated version's maximum. Once negotiated,
  records we send carry at most the peer's limit of plaintext (minus one in
  TLS 1.3, whose limit counts the content type) or `max_fragment_size` less
  the header, whichever is smaller (`MessageFragmenter`); protected records
  the peer sends that exceed our limit (TLS 1.3: the whole
  `TLSInnerPlaintext`, padding included, derived from the ciphertext length
  less the suite's expansion) end the connection with `record_overflow`
  (`RecordLayer::set_inbound_record_size_limit`). A peer value below 64 is
  `illegal_parameter`; a value above the protocol maximum is lowered, not
  refused; a configured value below 64 fails connection creation
  (`Error::BadRecordSizeLimit`). 0-RTT data, sent before the client could
  see the server's limit, is exempt, and a TLS 1.3 client applies its own
  limit from the record after EncryptedExtensions (the server's handshake
  records already respect it).
- `ticket_request` (RFC 9149), TLS 1.3 only: the client sends
  `ClientConfig::tls13_ticket_request` (default none) when it offers TLS
  1.3; the server sends at most `resumption_count` tickets for a resumed
  session and `new_session_count` otherwise, never more than
  `send_tls13_tickets`, and announces that number as `expected_count` in
  EncryptedExtensions. The extension in a ServerHello or HelloRetryRequest
  is `illegal_parameter` (TLS 1.3) or `unsupported_extension` (TLS 1.2).
- GREASE (RFC 8701, `msgs::grease`), client only, opt-in
  (`ClientConfig::enable_grease`, default off until the GnuTLS end-to-end
  scenarios have run with it): random per-connection GREASE values first in
  the cipher suites, `supported_groups`, `key_share` (a one-byte share),
  `supported_versions`, `signature_algorithms` and `psk_key_exchange_modes`,
  plus an empty GREASE extension first and a one-byte one after every other
  extension but `padding` and `pre_shared_key`. A second ClientHello repeats
  the values, but drops the GREASE key share when the HelloRetryRequest
  named a group. The values never enter the lists the server's choices are
  checked against, so a server selecting one fails as for any value not
  offered (`illegal_parameter`, or `unsupported_extension` for an
  extension). ALPN is not GREASEd. A browntls server ignores GREASE values
  like any unknown value and sends none itself (RFC 8701 §4 is optional).
- `padding` (RFC 7685), client: by default
  (`ClientHelloPadding::AvoidProblematicLengths`) a ClientHello handshake
  message of 256 to 511 bytes is padded to 512 (RFC 7685 §4);
  `AtLeast(n)` pads to at least `n` bytes first; `Disabled` never pads. The
  extension comes right before `pre_shared_key`, which stays last, and is
  sized with the binders in place. A server ignores its content.

### Connection APIs

Both APIs drive the same handshake state machines through
`ConnectionCore` (`conn.rs`), which deframes and processes one unit at a
time (`ConnectionCore::process_one`) over a `DeframerBuffer`:

- Buffered (`std`): `ClientConnection`/`ServerConnection` own a receive
  buffer (`DeframerVecBuffer`, at most one maximum-size record),
  queue received plaintext and outgoing records, and offer `read_tls`,
  `write_tls`, `reader()` and `writer()`. The send buffer limit
  (`set_buffer_limit`, 64 KiB by default) caps the application data a
  write takes; control records (handshake messages, alerts, KeyUpdates)
  are queued whatever the limit, but the outgoing queue counts them apart
  (`ChunkVecBuffer::control_len`). Once the handshake is done, while more
  control bytes wait unwritten than the limit allows (capped at 64 KiB),
  `wants_read` is false and `read_tls` fails: a peer that keeps asking for
  answers (KeyUpdate `update_requested`, post-handshake CertificateRequest)
  while it reads nothing cannot grow the queue without bound. The check
  falls between reads: the records one `read_tls` took in (at most one
  maximum-size record's worth) are processed in full, so the queue may pass
  the bound by what they call for (one KeyUpdate, or one post-handshake
  authentication answer per CertificateRequest among them). Reading resumes once `write_tls` has taken the backlog;
  `complete_io` writes before it reads, so it never meets the bound.
- Unbuffered (`unbuffered.rs`, no `std` needed):
  `UnbufferedClientConnection`/`UnbufferedServerConnection`.
  `process_tls_records(&mut incoming)` parses records from the front of the
  caller's buffer (`DeframerSliceBuffer`), decrypts them in place and
  returns a `ConnectionState` plus the number of bytes to discard.
  Application data (and a server's accepted 0-RTT data) is returned as a
  slice of the caller's buffer, one record per call: the state machine still
  judges every record, but `CommonState::take_received_plaintext` and the
  server's early-data store only flag it instead of copying it.
  `WriteTraffic::encrypt` encrypts into a caller buffer after checking the
  whole size first (`InsufficientSize` carries the exact requirement, and
  nothing is consumed); a KeyUpdate that is due (an answer to the peer, or
  the RFC 9846 §5.5 refresh) is written into the same buffer in order. At
  the limit, data that cannot be rekeyed (TLS 1.2, 0-RTT) fails with
  `EncryptExhausted`, and a server's half-RTT data fails with the temporary
  `KeyUpdateAwaitsHandshake` until the client's Finished arrives, instead of
  being held back. Should a provider's record turn out longer than its
  `encrypted_payload_len` promised, a KeyUpdate that no longer fits stays
  queued for `EncodeTlsData`, and data records already sequenced are never
  withdrawn.
  Handshake messages, alerts and KeyUpdates produced by the state machine
  are queued as encoded records until `EncodeTlsData::encode` copies them
  out; that queue and the handshake joiner are bounded by the protocol, not
  by application data. After a fatal error the alert is offered through
  `EncodeTlsData` first, then the error is returned on every call. A client
  writes 0-RTT data through `TransmitTlsData::may_encrypt_early_data` right
  after its ClientHello.

### Asynchronous streams (`browntls-tokio`)

`browntls-tokio` adapts the buffered API to Tokio's `AsyncRead`,
`AsyncBufRead` and `AsyncWrite`; it depends only on Tokio's I/O traits (no
Tokio feature, no runtime). Each poll pairs the connection with the
transport for its duration (`common::Stream`) and drives `read_tls` and
`write_tls` through adapters that turn the task context's `Pending` into
`WouldBlock`, the design of tokio-rustls:

- `TlsConnector`/`TlsAcceptor` return futures (`Connect`, `Accept`, and
  `into_fallible` variants that hand the transport back on error) that run
  the handshake. A handshake that can neither read nor write while still
  in progress (the peer's `close_notify` mid-handshake) ends with
  `UnexpectedEof` instead of polling forever, the asynchronous counterpart
  of the `complete_io` fix.
- `LazyConfigAcceptor` drives `server::Acceptor` over the transport until
  it yields the ClientHello (`StartHandshake`, which picks the
  `ServerConfig`). A refusal, from the acceptor or from
  `Accepted::into_connection`, writes and flushes the `AcceptedAlert` before
  the future fails; `take_io` returns the transport afterwards.
- With `TlsConnector::early_data(true)` and a resumable session that
  allows 0-RTT, `Connect` resolves before the handshake
  (`IoSession::skip_handshake`). Writes go to `ClientConnection::early_data`
  and are kept; the first read, flush or shutdown, or a write the allowance
  cannot take, completes the handshake and flushes our last flight
  (EndOfEarlyData, Finished). Declined early data is resent as 1-RTT data
  only when the same ALPN protocol is certain (none offered, or one offered
  and selected; RFC 9846 §4.2.10); otherwise that operation fails once with
  `EarlyDataNotResent`. A handshake failure in this phase is kept and fails
  every later operation. Whichever operation ends the phase wakes a read
  waiting in it, whose transport registration it may have replaced.
  Servers read accepted early data from the connection after `Accept`; the
  streams never mix it into ordinary reads.
- Reads return plaintext through `Reader::into_first_chunk`, which lends the
  first buffered chunk for the connection's lifetime so `poll_fill_buf` can
  return it. A read whose records queue an answer (an alert, a KeyUpdate
  answer, a post-handshake authentication response) writes and flushes it
  as far as the transport takes it at once, since the peer may wait for it
  (a server awaiting client authentication before it responds); records
  that writes queued are left to them. Such a write may replace a parked
  writer's write-readiness registration in the transport (tokio-rustls's
  crate documentation gives wakeup problems of this kind as its reason for
  not writing during reads), so it registers a waker for both the reading
  and the writing task: writability wakes the writer even if the reader is
  never polled again, and nothing is woken at a mere `Pending`, which would
  spin a task that polls both directions. A write that moved bytes also
  wakes the writer at once. An answer the transport took only in part
  stays the reads' to finish. A read that fails writes and flushes the
  alert and wakes the writer, which then sees the failure. When the
  connection stops reading because the control records it owes are past
  the bound (see the buffered API above), a read writes everything queued,
  the writer's records ahead of the answers included, with the same joint
  waker, and waits for writability instead of taking more input or
  polling itself again. A write, flush or shutdown that takes the
  registration over wakes that read once it moves bytes or fails.
- A write encrypts what the send buffer takes and writes queued records
  until the transport blocks; a write that took nothing returns `Pending`
  only while records wait for the transport, so a retry cannot spin.
- `shutdown` queues `close_notify` once and then shuts the transport's write
  side. Writes after it fail with `BrokenPipe` without reaching the
  connection (RFC 9846 §6.1). The peer's `close_notify` is end of file;
  end of file without it is `UnexpectedEof`.
- TLS errors surface as `io::Error` of kind `InvalidData` wrapping
  `browntls::Error`; the alert describing a local failure is written if
  the transport takes it at once.

### Delegated credentials (RFC 9345)

`browntls::delegated_credential` holds the `DelegatedCredential` codec,
signing (`DelegatedCredential::issue`) and validation; the native provider
adds `crypto::native::delegated_credential::generate`, which creates an
ECDSA (P-256/384/521), Ed25519 or Ed448 credential key and has the
certificate's key sign the credential. A credential is attached to a
`CertifiedKey` with `with_delegated_credential`, which checks that the
certificate carries the `DelegationUsage` extension
(1.3.6.1.4.1.44363.44, parsed by `browntls-pki`) and the
`digitalSignature` key usage, and that the key matches the credential's
public key. Credential keys may not be `rsaEncryption` keys (§4): the
`rsa_pss_rsae_*` schemes are never issued, attached, offered or accepted
(`rsa_pss_pss_*` is allowed). `CertifiedKey` keeps its credentials in a
private field (`delegated_credentials()` reads them), so it can no longer
be built with a struct literal; `CertifiedKey::new` remains.

- Server: when the ClientHello carries `delegated_credential` and a
  credential is unexpired, has at most seven days left, uses a
  `dc_cert_verify_algorithm` the client listed and is signed with a scheme
  in its `signature_algorithms`, the credential goes on the end-entity
  CertificateEntry and its key signs CertificateVerify. Otherwise the
  certificate key signs, as before. Never with raw public keys or TLS 1.2.
- Client: off unless `ClientConfig::enable_delegated_credentials`. The
  chain is verified as usual; then the credential is validated (offered
  schemes, not expired, at most seven days left and not beyond the
  certificate's `notAfter`, CertificateVerify scheme equal to
  `dc_cert_verify_algorithm`, `DelegationUsage` and `digitalSignature`,
  signature by the certificate key) and CertificateVerify is verified with
  its key through
  `ServerCertVerifier::verify_tls13_signature_with_delegated_key` (the
  default implementation refuses). `ClientConnection::delegated_credential`
  returns the credential used by a full handshake; it remains `None` on a
  resumed connection.
- Resumption: the client and server save the absolute expiry of the delegated
  credential that authenticated the original full handshake. A ticket is not
  offered or accepted, including for 0-RTT, when the current time is at or
  after that deadline. The client checks again after the resumed server
  Finished so a handshake that crossed the deadline cannot complete. Every
  descendant ticket carries the original deadline unchanged; the server also
  caps its advertised ticket lifetime to the remaining credential lifetime
  and sends no ticket when none remains. This is independent of an RFC 8773
  external-PSK binding; both properties are retained when both authenticated
  the session.
- Persistence: the private client session value carries the deadline without
  changing `ClientSessionStore`. The server session encoding has a mandatory
  tagged deadline field. Because the old encoding cannot distinguish sessions
  authenticated with a delegated credential, an upgrade deliberately rejects
  every pre-change server session value (TLS 1.3 and TLS 1.2); old and new
  members of a mixed-version fleet therefore cold-miss each other's cached
  sessions and tickets rather than resuming ambiguous authentication state.
- Alerts (§4.1.3): an invalid credential is `illegal_parameter`; one the
  client did not ask for is `unexpected_message`; one on an entry other than
  the end entity's is `illegal_parameter`; a CertificateVerify that fails
  under the credential's key gets the same alert as one that fails under a
  certificate key (`decrypt_error` for a bad signature).
- Not implemented: client credentials (the extension is parsed in
  CertificateRequest but never sent, and a client never presents one; a
  server answers a client Certificate entry carrying one with
  `unsupported_extension`, like other unsolicited entry extensions).
  No other implementation the project tests against supports delegated
  credentials, so the tests are browntls to browntls only.

### Exported authenticators (RFC 9261)

`browntls::exported_authenticator` adds `request_authenticator`,
`authenticator` and `validate_authenticator` to `ClientConnection` and
`ServerConnection`. The messages are carried by the application protocol,
not the record layer. A client request is a `ClientCertificateRequest`
(type 17), a server request a TLS 1.3 `CertificateRequest`; the answer is
TLS 1.3 `Certificate`, `CertificateVerify` and `Finished` messages, or a lone
`Finished` over an empty certificate list to decline (also when no key can
sign with a requested scheme). A server may authenticate spontaneously with
a random 32-byte context.

- Keys: the exporter with the labels `EXPORTER-client authenticator
  handshake context` / `... finished key` (`server` for server
  authenticators), a zero-length context (§5.1; in TLS 1.2 its two length
  octets enter the RFC 5705 seed, in TLS 1.3 it equals no context) and the
  length of the connection's hash. TLS 1.3 and TLS 1.2 with the extended
  master secret (the TLS 1.2 exporter refuses sessions without it); for
  TLS 1.2 the HMAC comes from a TLS 1.3 suite of the provider with the
  same hash.
- Validation: the request must be one this side made and not yet answered
  (recognised by a digest of its bytes); framing is bounded by the
  handshake message limit; request type and context are checked;
  `Finished` is compared in constant time before any certificate or
  signature is verified; the CertificateVerify scheme must be one the
  request offered (for a spontaneous authenticator, one the client's
  verifier supports); then the chain and signature go through the
  configured `ServerCertVerifier` (with the connection's server name, the
  SNI; no secondary host names) or `ClientCertVerifier`. Entry extensions
  are refused.
- Local policy: contexts are 1 to 255 bytes and used once per connection
  (a reused context is `PeerMisbehaved::ReusedAuthenticatorContext`). Each
  side keeps three lists of at most 256 entries, capped separately:
  requests it made, authenticators it made, and spontaneous authenticators
  it validated. A full list makes further requests, authenticators or
  spontaneous validations fail; answers to its own requests are recorded
  on the request, so a peer cannot use up the room they need. A request's `signature_algorithms` is required;
  `certificate_authorities` may be set, `server_name`, `oid_filters` and
  `status_request` are not supported.
- Errors are returned to the caller; no alert is sent and the connection
  continues, since the messages are outside the TLS record layer.
- No other implementation the project tests against exposes exported
  authenticators, so the tests are browntls to browntls only.

### Encrypted Client Hello (RFC 9849)

`browntls::ech` implements ECH on top of the HPKE traits in `crypto::hpke`
(`Hpke`, `HpkeSealer`, `HpkeOpener`); the native provider implements them in
`crypto::native::hpke` for every `browntls_crypto::hpke` suite. The
RustCrypto provider has no HPKE, so the client and the servers that decrypt
need the native provider or another implementation of the traits; the
back-end server of split mode decrypts nothing and works with either
provider. Both server topologies of RFC 9849 §3.1 are implemented: shared
mode, where one server decrypts and terminates the connection, and split
mode, where a client-facing server decrypts and relays the connection to a
back-end server that terminates it.

- Client (`ClientConfig::ech_mode`): `EchConfig::new` picks the first
  configuration in an `ECHConfigList` with RFC 9849's version, no unknown
  mandatory extension, a public name that is an LDH host name not ending in a
  numeric or `0x` label, and a cipher suite the given HPKE suites cover. The
  handshake state machine builds the inner ClientHello (TLS 1.3 only, an
  `inner` ECH extension, no 0-RTT, and no TLS 1.2 session: TLS 1.2 sessions
  are not even looked up, so the `legacy_session_id` both hellos share is
  always fresh random and never one a TLS 1.2 server issued for the hidden
  name), then
  `ech::client` seals it into the outer one: a fresh random, the public name
  as SNI, no ALPN, a GREASE `pre_shared_key` mirroring the inner PSK, the
  longest run of extensions identical in both replaced by
  `ech_outer_extensions`, and the §6.1.3 padding. With RFC 8701 GREASE on,
  both hellos carry the same GREASE values; RFC 7685 `padding` goes only into
  the outer hello (the inner one is padded by §6.1.3), sized for the outer
  hello and covered by its AAD. An inner PSK, a ticket or an external PSK, is
  mirrored by a GREASE one in the outer hello. Both transcripts are kept
  until the ServerHello (or the HelloRetryRequest's ECH extension) shows
  whether the server confirmed acceptance; on rejection the handshake
  continues with the outer hello, authenticates the public name, answers a
  CertificateRequest with an empty Certificate, and after Finished sends
  `ech_required` and fails with `Error::RejectedEch`, which carries the
  retry configurations. A HelloRetryRequest that confirmed acceptance
  followed by a ServerHello that does not is `illegal_parameter`. GREASE
  (`EchMode::Grease`) sends a random `config_id`, a real `enc` and a payload
  sized like a padded inner hello, and ignores the server's ECH answers.
- Server in shared mode (`ServerConfig::ech`, `EchServerConfig`): keys are
  matched by `config_id` (several keys may share one) and trial-decrypted;
  with `EchServerConfig::with_trial_decryption` every key is tried whatever
  the identifier (§7.1, the second method, for clients that randomize it;
  §10.4 allows it only when configured, since each ClientHello that does
  not decrypt then costs one decapsulation per key and suite). With
  `EchServerConfig::with_public_name_check`, an extension that decrypts
  under a configuration whose public name differs from the outer
  `server_name` (ignoring ASCII case) is `illegal_parameter`; only the
  configuration that decrypted is compared, so keys shared between
  configurations with different public names cause no spurious failure. The
  inner
  hello is rebuilt in linear time (one cursor into the outer extensions;
  missing, repeated, out-of-order or ECH references, and non-zero padding,
  are `illegal_parameter`), must carry an `inner` ECH extension and offer
  nothing below TLS 1.3, and replaces the outer ClientHello for the rest of
  the handshake (also through `Acceptor`, using the configuration passed to
  `Accepted::into_connection`). The ServerHello random and, after a
  HelloRetryRequest, its ECH extension carry the acceptance confirmations.
  The second ClientHello must repeat the `config_id` and cipher suite with an
  empty `enc` and decrypt with the same HPKE context (`missing_extension`,
  `illegal_parameter`, `decrypt_error`). An extension that does not decrypt
  (GREASE included) leaves the outer hello in use; EncryptedExtensions then
  carries the server's `ECHConfigList` as retry configurations, and a
  HelloRetryRequest carries 8 random bytes in place of a confirmation. An
  `ech_outer_extensions` extension, or an ECH extension of type `inner` or of
  an unknown type, in a ClientHello as received is `illegal_parameter`.
- Client-facing server of split mode (`ech::split::ClientFacing`, §7.1):
  a sans-I/O object per connection, fed the client's and the back-end
  server's bytes. It reassembles the first ClientHello (plaintext handshake
  records, at most 64 KiB, nothing else in the records) and decrypts it with
  the shared-mode code, then decides: `Forward` when ECH is accepted (the
  inner ClientHello, re-framed in records of the client's record version, is
  queued for the back-end server chosen by its `server_name`), `Local`
  otherwise (no extension, GREASE, stale keys, or input that is not a
  ClientHello or does not parse as one). A ClientHello whose framing is
  wrong (an empty handshake record, more than 64 KiB, or more handshake data
  after it in its record) is a fatal error instead, because a local server
  would decrypt and answer it before noticing; refusing empty records also
  bounds what is buffered before the decision. After `Local`, the bytes
  received so far go to an ordinary shared-mode `ServerConnection` with the
  same keys
  (`into_server_connection` or `into_received`), which decrypts again,
  reaches the same result, authenticates as the public name and sends the
  retry configurations. After `Forward`, client records are forwarded whole
  until the back-end server's first handshake message: a
  HelloRetryRequest (recognised by its random) makes the client-facing
  server decrypt the second ClientHelloOuter with the first one's HPKE
  context (§7.1.1, the same checks and alerts as shared mode) and forward
  its inner ClientHello; a ServerHello, an alert or anything else switches
  both directions to unmodified relaying (`is_relaying`). An `inner` or
  unknown ECH type, `ech_outer_extensions`, or a malformed inner
  ClientHello is a fatal error with a plaintext alert for the client
  (`take_for_client`). The client-facing server never holds traffic keys.
  It buffers one partial record per direction, one ClientHello, a copy of
  the client's bytes until the decision (for a local hand-off), and what it
  queues for each side until the caller takes it. It issues no
  HelloRetryRequest cookie (§7.1.1), so it keeps its state for the whole
  handshake.
- Back-end server of split mode (`ServerConfig::ech_backend`, §7.2): a
  ClientHello with an `inner` ECH extension (as the client-facing server
  forwards it) is confirmed in the ServerHello random and, after a
  HelloRetryRequest, in its ECH extension, with the same code as shared
  mode; the HelloRetryRequest stays stateful, as in shared mode. An `outer`
  or unknown type is `illegal_parameter` (§7), as is an inner ClientHello
  offering TLS 1.2 or below (stricter than §7.2, which only forbids
  confirming when TLS 1.2 is negotiated; a conforming client-facing server
  never forwards such a hello, §7.1); after a
  HelloRetryRequest the second ClientHello must carry `inner` again
  (`missing_extension` otherwise), and one that adds it is
  `illegal_parameter`. A ClientHello without ECH is served as usual.
  `ech_backend` and `ech` exclude each other (`ServerConnection::new` and
  `Accepted::into_connection` fail).
- Client with a random identifier (`EchConfig::with_random_config_id`,
  §10.4): one random `config_id`, repeated after a HelloRetryRequest, for
  servers known to use trial decryption.
- `ech::svcb` reads the `ech` SvcParam (RFC 9848) from SVCB/HTTPS record
  data or its Base64 presentation form; the crate does no DNS lookups.

Tests: shared and split mode in-process (`crates/browntls/tests/ech_native.rs`:
acceptance with and without a HelloRetryRequest, input fed byte by byte, an
inner ClientHello spanning records, resumption, rejection completed locally
with retry configurations and the retry forwarded, GREASE and non-ECH
connections kept local, every error path of the client-facing and back-end
servers, trial decryption with random identifiers, a back-end server on the
RustCrypto provider), the `tls_ech` fuzz target (split mode in fuzz-chosen
pieces), and the Docker E2E matrix (`ech-*` scenarios: browntls in every
role, and Go crypto/tls 1.27 as client and shared-mode server, also as the
client of the browntls split-mode servers).

Not implemented: ECH with DTLS or QUIC, and a client-facing server that
inspects anything after the back-end server's ServerHello (by design: it
relays the encrypted handshake unmodified).

### QUIC-TLS (RFC 9001)

`browntls::quic` is the TLS half of QUIC, shaped like `rustls::quic`: a QUIC
implementation feeds the contents of CRYPTO frames to `read_hs`, takes the
bytes to send from `write_hs`, and receives the keys of each encryption level
as a `KeyChange`. Packets, frames, transport parameters, loss recovery and
the choice of packet number space stay with the QUIC implementation; browntls
does not implement QUIC transport (RFC 9000). Only QUIC version 1 is
supported.

- Connections: `quic::ClientConnection` and `quic::ServerConnection` share
  the TLS 1.3 state machines through `CommonState::quic`. In that mode
  handshake messages are queued with the level that protects them (Initial,
  Handshake or 1-RTT) instead of being written as records; no record layer
  keys are installed, no ChangeCipherSpec is sent (§8.4), no EndOfEarlyData
  is sent or expected (§8.3) and `legacy_session_id` is empty.
- Levels: `write_hs` emits one level's bytes per call and returns the next
  level's keys once they exist; the bytes written by that call belong to the
  previous level. `read_hs` refuses bytes that continue past a message that
  changes the peer's level (§4.1.3, `KeyEpochWithPendingFragment`).
- Packet protection: each TLS 1.3 suite names a `quic::Algorithm` in its
  `quic` field: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 on both
  providers, AES-128-CCM on the native one; TLS_AES_128_CCM_8_SHA256 has none
  (§5.3) and is never offered. The RustCrypto provider computes the ChaCha20
  header protection block itself, since the `chacha20` crate refuses block
  counter 0xffffffff, which a peer can choose. Keys come from "quic key", "quic iv" and
  "quic hp" (§5.1); Initial keys from the client's Destination Connection ID
  (§5.2). Header protection masks the packet number without branching on its
  length (§9.5). Each packet key reports the §6.6 confidentiality and
  integrity limits; counting packets is the QUIC implementation's job.
- Key update: `Secrets::next_packet_keys` derives the next phase with
  "quic ku" (§6); a TLS KeyUpdate message is `unexpected_message`.
- Other TLS extensions: `record_size_limit` is neither offered nor
  acknowledged, since QUIC has no TLS records. An external PSK can
  authenticate a QUIC handshake but never carries 0-RTT, because 0-RTT
  needs the transport parameters remembered with a ticket (RFC 9000
  §7.4.1). Encrypted Client Hello (shared mode or as a split-mode back-end
  server) is refused on QUIC connections for now:
  the outer ClientHello has no ALPN, so a QUIC server rejecting ECH could
  not complete the handshake that delivers retry configurations.
- Post-handshake client authentication (§4.4): a QUIC client never offers
  `post_handshake_auth`, and a QUIC server ignores the offer, so
  `request_client_auth_after_handshake` does not defer client
  authentication there. A post-handshake CertificateRequest is a
  PROTOCOL_VIOLATION, without an alert.
- Transport parameters: the `quic_transport_parameters` extension (0x39) is
  required in QUIC (`missing_extension`) and refused by a TLS server
  (`unsupported_extension`); the pre-RFC code point 0xffa5 is not recognised.
  A client keeps the server's parameters with its ticket for 0-RTT.
- ALPN: if either side configures protocols and none is agreed, the
  handshake fails with `no_application_protocol` (§8.1).
- 0-RTT: a server allows it only with `max_early_data_size` 0 or `u32::MAX`
  (§4.6.1), and a client refuses a ticket announcing any other early data
  size. A server exposes 0-RTT keys only when it accepted early data; a
  client drops them after a HelloRetryRequest or a refusal. Whether to
  accept 0-RTT is decided before the stored resumption data is visible, and
  needs stateful session storage, as for TLS.
- Errors: the first fatal alert is available from `alert`, and
  `crypto_error_code` maps it to CRYPTO_ERROR `0x0100 + alert` (§4.8).
  The violations RFC 9001 makes a PROTOCOL_VIOLATION (data left over at a
  level change, a ticket without the 0-RTT sentinel, a ClientHello with a
  session ID) fail without an alert, so `alert` stays `None`.
- `read_hs` takes no encryption level: apart from level changes, the QUIC
  implementation checks which level CRYPTO data may arrive at.
- Retry: `retry_integrity_tag` and `verify_retry_integrity` compute and check
  the §5.8 tag with a provider's TLS_AES_128_GCM_SHA256 suite (any other
  suite is refused).

### Cargo features (`browntls`)

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | Buffered connections and I/O helpers (`Stream`, `KeyLogFile`), default session caches, system time; the unbuffered API needs only `alloc` |
| `native` | yes | Provider backed by `browntls-crypto` |
| `rustcrypto` | no | Provider backed by RustCrypto crates (RSA verification only) |
| `tls12` | yes | TLS 1.2 support |
| `logging` | yes | `log` crate diagnostics |
| `prefer-post-quantum` | yes | X25519MLKEM768 first in the default group list |
| `zlib` | no | zlib certificate compression (RFC 8879), `miniz_oxide` |
| `brotli` | no | Brotli certificate compression (RFC 8879), `brotli`; enables `std` |
| `zstd` | no | Zstandard certificate compression (RFC 8879), `ruzstd` |
| `fuzzing` | no | Unstable entry points for the [fuzz targets](../fuzz/README.md); not a supported API |

### Certificate compression (RFC 8879)

`browntls::compress` defines the `CertCompressor` and `CertDecompressor`
traits and, behind the `zlib`, `brotli` and `zstd` features, one built-in
pair per RFC 8879 algorithm (`compress::ZLIB`, `BROTLI`, `ZSTD`). Enabled
built-ins are the default compressor and decompressor lists of new client and
server configurations, in the order Brotli, zlib, Zstandard; without those
features the lists are empty and the extension is neither offered nor
accepted. Compression applies to TLS 1.3 only, in both directions: a server
compresses its Certificate with its first compressor the ClientHello offered,
a client its own with the first one the CertificateRequest offered, and a
compressed message that would not be smaller is sent uncompressed. Servers
cache compressed messages (`CompressionCache`).

On receipt (`compress::receive_compressed_certificate`, used by both sides):

- an algorithm that was not offered is `illegal_parameter`;
- `uncompressed_length` must be non-zero and at most the configuration's
  `cert_decompression_limit`, itself capped at 64 KiB
  (`compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE`, the limit for an
  uncompressed Certificate message); the codec already rejects a length above
  that cap with `decode_error`, anything else over a limit is
  `bad_certificate`, in both cases before any decompression;
- the output buffer is allocated once at the declared length and the
  decompressor must fill it exactly: shorter, longer, truncated or trailing
  input is `bad_certificate` (RFC 8879 §4), as is a decompressed message that
  is not a well-formed Certificate.

A `cert_decompression_limit` of zero turns reception off: the client does
not send the extension, the server leaves it out of its CertificateRequest,
and a compressed message is then an algorithm that was not offered.

The built-in decoders use memory besides that buffer, bounded by the expected
length and the format, never by what the stream declares:

| Algorithm | Working memory besides the output buffer | Refused before decoding |
|---|---|---|
| zlib | Fixed decoder state (about 11 KiB); the output buffer is the window | |
| Brotli | A window of at most the expected length rounded up to a power of two (the decoder's byte allocator refuses larger requests, so a stream announcing more fails without the allocation), context maps up to 16 KiB, prefix code tables (at most 256 per category) | Large-window streams |
| Zstandard | The declared window, at most 128 KiB, plus one block (128 KiB) and entropy tables | Skippable frames, dictionaries, a declared content size other than the expected length, a window above 128 KiB |

The Zstandard window limit is below the 8 MiB that RFC 8878 §3.1.1.1.2
recommends decoders accept. One-shot encoders, which know the size of a
Certificate message, write single-segment frames whose window is the content
size, and the built-in encoder declares 128 KiB; a frame from a streaming
encoder that was not told the size (libzstd then declares at least 512 KiB)
is refused. `tests/cert_compression_memory.rs` checks, on Linux, that
refusing streams of a few hundred bytes which announce 8 to 16 MiB does not
raise the process's peak resident memory by more than 1 MiB. Zstandard
compression uses the single level `ruzstd` implements.

## Primitive backends

Each primitive has a portable, constant-time implementation that is the
reference for testing, plus accelerated backends selected at run time.

| Family | x86-64 | aarch64 | riscv64 |
|---|---|---|---|
| SHA-1 (HMAC-SHA1 for TLS 1.2 `*_CBC_SHA` suites only, never signatures) | SHA-NI | FEAT_SHA1 | Zbb scalar |
| SHA-2 | SHA-NI | FEAT_SHA256, FEAT_SHA512 | Zvknha/Zvknhb, Zknh |
| SHA-3 / SHAKE | AVX2 multi-lane | NEON, FEAT_SHA3 | RVV |
| AES-GCM | AES-NI + PCLMULQDQ, VAES + VPCLMULQDQ (YMM, and ZMM with a fused CTR+GHASH loop) | FEAT_AES + FEAT_PMULL | Zvkned + Zvkg / Zvbc, Zkne + Zbc/Zbkc |
| AES decryption (CBC) | AES-NI, VAES (YMM) | FEAT_AES | Zvkned, Zknd |
| ChaCha20-Poly1305 | AVX2, AVX-512 | NEON | RVV |
| X25519 / Ed25519 | BMI2 + ADX field arithmetic | portable 64-bit | portable 64-bit |
| X448 / Ed448 | portable 64-bit (Karatsuba field multiplication, precomputed fixed-base comb) | portable 64-bit | portable 64-bit |
| P-256 / P-384 / P-521 | BMI2 + ADX field arithmetic (per-curve kernels; the same specialised reductions in portable code elsewhere) | portable 64-bit | portable 64-bit |
| RSA | BMI2 + ADX Montgomery kernel, AVX-512 IFMA exponentiation | portable 64-bit | portable 64-bit |
| FFDHE (RFC 7919) | RSA BMI2 + ADX Montgomery kernel | portable 64-bit | portable 64-bit |
| ML-KEM | AVX2 NTT | NEON NTT | RVV NTT |

AES-CCM (TLS 1.3 `TLS_AES_128_CCM_SHA256` and `TLS_AES_128_CCM_8_SHA256`) runs
on the AES backends of this table: counter mode uses each backend's
pipelined keystream, and CBC-MAC encrypts one block at a time.

AES-CBC without padding (`browntls_crypto::cbc`, for the TLS 1.2 CBC suites
with AES-128 and AES-256) also follows the AES backend selection and
acceleration policy. Encryption is serial and encrypts one block at a time;
decryption pipelines eight blocks per iteration (AES-NI, FEAT_AES), sixteen
(VAES, also on the AVX-512 tier) or `VLEN/32` (Zvkned). The portable inverse
cipher is bitsliced like the forward one. The scalar riscv64 tier decrypts
with Zknd when present and with the portable code on Zkne-only CPUs.

`browntls_crypto::tls_cbc` implements the TLS 1.2 CBC record transform
(RFC 5246 MAC-then-encrypt and RFC 7366 encrypt-then-MAC, with HMAC-SHA1,
HMAC-SHA256 or HMAC-SHA384) over a `CbcBlockCipher` trait. For
MAC-then-encrypt, the padding check and the record MAC are constant time with
respect to the padding (the Lucky Thirteen countermeasure): the number of hash
compressions depends only on the record length.

`browntls_crypto::hpke` implements RFC 9180 Hybrid Public Key Encryption in
base mode for Encrypted Client Hello: DHKEM over X25519, X448, P-256, P-384
and P-521, HKDF-SHA256/384/512, and AES-128-GCM, AES-256-GCM,
ChaCha20-Poly1305 or export-only. It composes the crate's own primitives (and
therefore their accelerated backends), adds no `unsafe`, and stays
allocation-free: `seal`/`open` returning vectors exist only with `alloc`.
NIST public keys must be uncompressed points on the curve, X25519/X448
all-zero shared secrets are rejected, and a failed `open` leaves the sequence
number unchanged. The PSK and authenticated modes are not implemented.

The table states the design target; [Status](#status) records what has been
implemented and executed.

### Supported platforms

- **x86-64**: the supported baseline is x86-64-v3 (AVX2, BMI1/2, FMA, MOVBE).
  The crate still builds for the default `x86_64-unknown-linux-gnu` target:
  every accelerated function carries `#[target_feature]` and is entered only
  after run-time detection, so a v3 build (`-C target-cpu=x86-64-v3`) lets the
  compiler resolve the checks statically. AES-NI, PCLMULQDQ, SHA, SHA512,
  VAES, VPCLMULQDQ, ADX and AVX-512 are optional extensions detected with
  `CPUID`/`XGETBV`.
- **aarch64**: Advanced SIMD (NEON) is assumed; the Cryptographic Extension
  features (AES, PMULL, SHA2, SHA3, SHA512) are detected through `std`, or
  taken from compile-time target features without `std`.
- **riscv64**: RVV 1.0 and the vector cryptography extensions (Zvkned,
  Zvknha/Zvknhb, Zvkg, Zvbc, Zvbb, Zvkb) plus scalar Zbb/Zbc/Zbkb/Zbkc/Zknh/
  Zkne/Zknd are detected with the Linux `riscv_hwprobe` system call. RVV
  intrinsics are not available on stable Rust, so vector code uses inline
  assembly with `.option arch` directives and is written to be correct for any
  VLEN from 128 to 1024 bits. Processors that implement only RVV 0.7.1
  (XTheadVector), such as the T-Head TH1520, report no vector support and use
  the scalar paths. Builds may assert extensions that a kernel or emulator does
  not report with `--cfg browntls_assume_riscv="<ext>"`.

`--cfg browntls_force_soft` disables every SIMD and hardware backend.

### Acceleration policy and status

Accelerated backends use one or both kinds of hardware support:

| Kind | Instructions |
|---|---|
| SIMD | AVX2, AVX-512, NEON, RVV vector units |
| Dedicated | AES-NI, PCLMULQDQ, SHA, Armv8 AES/PMULL/SHA2/SHA512/SHA3, RISC-V Zk\*/Zvk\*/Zbc/Zbkc, and scalar multi-precision or bit-manipulation extensions (BMI1/BMI2/ADX, Zbb) |

For example AES-NI and SHA-NI are dedicated, ChaCha20 AVX2 and the ML-KEM
NTTs are SIMD, and VAES, RISC-V Zvkned/Zvkg/Zvknh\* and the x86-64-v3 SHA-2
schedule (AVX2 with BMI2) use both.

At run time, `browntls_crypto::accel` (re-exported as
`browntls::crypto::native::accel`) holds a process-wide `Policy` per
algorithm family (SHA-1, SHA-256, SHA-512, Keccak, four-way Keccak, AES, GHASH,
ChaCha20, Poly1305, X25519, P-256, RSA, ML-KEM, P-384, P-521) with one level
per kind:

| Level | Behaviour for that kind |
|---|---|
| `Preferred` (default) | Backends using it may be selected; the best available one wins |
| `Required` | The selected backend must use it; setting fails with `Unsupported` if no available backend qualifies |
| `None` | Backends using it are never selected |

`accel::set_policy`, `set_policy_all`, `set_kind`, `set_kind_all` and
`native::default_provider_with_acceleration` set levels; `accel::status_all`,
`accelerated` and `accelerated_by(kind)` report, per family, the policy, the
kinds the CPU offers, and the selected backend with the kinds it uses.
Keyed objects (AES-GCM, ML-KEM and RSA private keys) keep the backend chosen
when they were created or loaded. Hardware feature checks that guard `unsafe` code are
independent of the policy.

### Load-aware backend routing

The policy's choice is static: one backend per family, the *primary*.
`accel::load` (off by default, `load::enable(Config)`; needs the `std`
feature for its clock and per-thread state) can move part of a family's
work to another backend while the primary runs slower than it usually does.
The premise is that a processor's hardware for one kind of instruction is a
fixed resource, so when other work is using it, calls that depend on it take
longer, and instructions of another kind may then be the faster way to the
same result.

Work is grouped in *streams*, one per homogeneous kind of work of a family
(for example the records of an AEAD), and each stream runs this loop:

| Phase | What happens |
|---|---|
| Steady | Everything runs on the primary. Some calls are timed (about one record of at least 4096 bytes in sixteen; every key exchange, encapsulation and signature operation), giving a short-term average cost and a baseline, the cost in normal operation. The baseline follows slow drift (weight 1/1024 upwards, 1/256 downwards) but not a run of slow calls |
| Probing | The short-term cost exceeded the baseline by `threshold_percent` (default 25, at least 20) and five of the last eight timed calls were each that slow. One call in eight goes to the next permitted backend in preference order, until at least four of them and sixteen calls of the primary were timed |
| Shifting | The probed backend measured at least 5% cheaper than the congested primary. Every eight timed calls of the primary its share grows by 1/16 of the work while that holds (up to `max_shift_percent`, default 90), or shrinks by as much when the primary has recovered to within half the threshold of its baseline or the alternate is the slower one |

When no alternate is cheaper, the present cost is accepted as the baseline
(at most doubling it per episode). An episode that moved nothing, or that
ended with nothing left on the alternate while the primary was still slow,
is followed by a pause of 256 timed calls of the primary, doubled for each
such episode up to 65536; a doubling is forgotten after 4096 uneventful
timed calls. A probe or a shift that ends because the primary recovered is
followed by a quarter of that pause. `load::status_all` reports, per
stream, the phase, both backends, the shifted share and the costs;
`load::set_fixed` pins a share by hand for experiments.

Which calls are timed, probed or shifted is decided by a per-thread call
counter mixed (SplitMix64) with a per-thread random key, using separate bits
for the three choices. No state is shared between threads on that path, and
a peer cannot tell in advance where a call will run.

Properties this design keeps:

- Every backend of a family computes the same function bit for bit (the
  differential tests compare each with the portable one), so routing never
  changes an output, a negotiated parameter or a record on the wire.
- Alternates are the backends the family's `Policy` permits and the CPU can
  run, so `Acceleration::None` and `Required` bind shifted work too.
  `Config::portable` says whether the portable backend is one of them.
- Decisions use call counters, input lengths and measured durations, never
  secret values. The durations are those of code written to run in constant
  time; if a backend's time did depend on a secret, routing could make that
  dependence visible in which backend runs later, so it adds no leak of its
  own but relies on the backends as much as their direct use does.
- An alternate takes work only while its timed calls are cheaper than the
  primary's. Load that slows every backend alike moves little: it costs a
  few probes per alternate and then the growing pause. In simulations of
  such load (steady, random and periodic bursts) under 1% of the calls ran
  on an alternate, and the time lost stayed under 1% even with an
  alternate three times slower.
- A keyed object is routed only while the policy still selects the backend
  it was created for, and one created with explicit backends never is.
- An ML-KEM key and an RSA private key hold nothing that depends on the
  backend their arithmetic runs on (the ML-KEM backends share one
  representation of the key polynomials; an RSA key's Montgomery constants
  are the same for every multiplication kernel), so a routed call uses the
  key as it is: nothing is added to a key, and it does not matter when the
  key was created. An RSA signature moves only to a backend below the
  key's own; the AVX-512 IFMA backend's per-key constants are used by that
  backend alone.
- A keyed object whose key is expanded per backend (an AES-GCM key) is
  routable only if it was created while routing was enabled. It then keeps
  a copy of the AES key in a small allocation and expands it for the
  alternates when one of its records is first routed to one; until then it
  costs nothing else, and a key created earlier or with explicit backends
  never enters the routing code. Each alternate AES backend runs with the
  GHASH backend of its own instruction class (VAES with VPCLMULQDQ of the
  same width, AES-NI with PCLMULQDQ, and so on), so a moved record leaves
  the primary's instructions for both halves of the work; where the GHASH
  policy forbids that backend or the CPU lacks it, the next permitted one
  in GHASH preference order is used, and without one that AES backend is
  not an alternate. On x86-64 an expanded AES-GCM key takes 1664 bytes,
  which is the size of the key types with or without routing; each
  alternate of an expanded key adds as much on the heap (4992 bytes per key
  for the three alternates of AVX-512 VAES). The key copy and the whole of
  the alternates' storage are zeroised on drop.

Limits:

- Costs are wall-clock times. A slowdown that hits every backend alike (too
  few cores, a descheduled virtual machine) is probed and then accepted as
  the baseline. Pauses are counted in timed calls, so a stream with little
  traffic pauses for long.
- The baseline settles somewhat below the mean of a jittery cost. Very
  noisy timings, or timed calls that alternate between two cost levels,
  cause fruitless episodes and long pauses; an alternate that is nearly as
  slow as the congested primary is given up when timings are noisy.
- Someone able to slow the primary's calls but not the alternate's moves
  work to the alternate, which may be slower than an undisturbed primary
  (by at most the factor of the slowdown). Contention for the primary's
  instructions does exactly that, which is the case routing exists for;
  doing it call by call would need the schedule, which is keyed with a
  non-cryptographic mixing function.
- Records shorter than 4096 bytes are too short to time and always run on
  the primary, unless a share was fixed by hand. A record whose additional
  data exceeds 1/64 of its length is routed but not timed.
- A key exchange or signature stream is meant to hold calls of one cost.
  Calls that do not fit are left out of the measurements and still routed:
  - a rejected signature and a ciphertext of the wrong length (a peer
    chooses how many of those it sends);
  - an ECDSA signature with another hash than the curve's TLS hash, whose
    RFC 6979 nonce derivation costs differently (P-256 with SHA-512
    measured 28% above P-256 with SHA-256 on one machine);
  - an ECDSA verification that did less work than random inputs cause.
    Verification runs in variable time on public values, and whoever
    supplies both the key and the signature can make it cost a tenth
    (measured on P-256), which would drag the stream's baseline down.
    Verifications that pass this check vary by under a tenth.

  When such calls land on a probe they yield no sample, so a stream of them
  can keep a probe from completing. What remains varies within the
  threshold but is partly in other hands: an ML-KEM public key chosen for
  it raises the cost of encapsulating to it by up to 10%, and an RSA key's
  public exponent changes its signing cost by 4% (3 against 65537) to 17%
  (the largest accepted), through the two public-exponent exponentiations
  of blinding and the fault check.
- Only the polynomial arithmetic of an ML-KEM operation moves; its Keccak
  permutations follow their own policies and are not routed.
- The cost per byte depends somewhat on the record length (about 10%
  between 4096 and 16384 bytes for ChaCha20-Poly1305 on one machine), which
  is why the threshold cannot be set below 20%.
- The controller's constants were chosen by reasoning and simulation (the
  `accel::load` unit tests drive the state machine with synthetic costs,
  including the fixed-capacity model of the premise with jitter of up to
  20%, where it stays within a few percent of the best fixed split for
  alternates that help by a fifth or more); they were not tuned on
  contended hardware.
- `load::status` exposes average durations of recent calls, including
  secret-key operations; it is diagnostic data for the operator.

Routed so far: ChaCha20-Poly1305 records (ChaCha20 backends), AES-GCM
records (AES backends, each with its GHASH companion; one stream per key
size, since 256-bit keys cost more per byte), the X25519 ladder, P-256,
P-384 and P-521 (four streams per curve: public key derivation, ECDH, ECDSA
signing and accepted ECDSA verifications), ML-KEM (nine streams: key
generation, encapsulation and decapsulation of each parameter set) and RSA
signatures, that is the private-key operation with its blinding and fault
check, of 2048-, 3072- and 4096-bit keys (one stream per size; keys of
other sizes are not routed). That includes their uses by the native TLS
provider once an application calls `load::enable`; for AES-GCM that means
keys created after the call. AES-CCM, AES-CBC, the AES block types, RSA
verification, FFDHE, X448, Ed25519, Ed448 and the hash functions are not
routed.

### Operating-system interface

On Linux x86-64, aarch64 and riscv64, `browntls-crypto` issues `getrandom(2)`
and `riscv_hwprobe(2)` without libc through a single naked, C-variadic
`syscall(nr, ...)` trampoline (stable since Rust 1.99). Other targets obtain
entropy from the optional `getrandom` crate feature.

## Toolchain and dependency policy

- Rust 1.100.0 is pinned in `rust-toolchain.toml` and is the MSRV
  (`rust-version`). Toolchain upgrades are explicit changes.
- `Cargo.lock` is committed and CI builds with `--locked`.
- Runtime dependencies: none for `browntls-crypto` and `browntls-pki`; `log`
  (optional), the RustCrypto crates (only with `rustcrypto`) and the
  pure-Rust compression crates `miniz_oxide`, `brotli` and `ruzstd` (only
  with `zlib`, `brotli`, `zstd`) for `browntls`; `tokio` (I/O traits only)
  for `browntls-tokio`. Independent implementations (RustCrypto, rustls with
  ring, tokio-rustls, rcgen) are dev-dependencies used as test oracles.
- `deny.toml` defines advisory, license, ban and source policy, enforced with
  a checksum-pinned cargo-deny in CI.

## Testing strategy

| Layer | Evidence |
|---|---|
| Primitives | RFC/NIST known-answer tests, Wycheproof vectors, differential tests against RustCrypto, and every available backend compared with the portable one |
| Platforms | Native x86-64 and aarch64 on GitHub-hosted Ubuntu 26.04 runners (each with dispatch and portable-only builds; the Arm runner implements every Armv8 extension the backends use) and riscv64 on the RISE runner, plus QEMU user-mode profiles for the x86-64 SHA-NI/VAES tier and every RISC-V tier (static musl binaries, since the Ubuntu 26.04 riscv64 glibc requires RVA23) (scalar, Zk, RVV with VLEN 128/256/1024 with and without vector crypto) |
| PKI | Run-time generated certificate chains, curated public test certificates, malformed-input robustness |
| TLS | Codec round trips and rejection tests, in-memory handshakes across suites, groups, signature schemes and versions (Encrypted Client Hello: accepted, after a HelloRetryRequest, with resumption, rejected with retry configurations, GREASE, and tampered second ClientHellos, `crates/browntls/tests/ech_native.rs`), interoperability with rustls in both directions (TLS and QUIC-TLS; asynchronous streams against tokio-rustls over loopback TCP, `crates/browntls-tokio/tests/interop.rs`), RFC 9001 Appendix A packet protection vectors, and with the OpenSSL 3 command-line tool over loopback TCP in both directions, with and without client authentication, plus `s_client` answering post-handshake authentication and following a stateless HelloRetryRequest onto a fresh connection (`crates/browntls/tests/openssl_interop.rs`, required in the x86-64 CI jobs) |
| Entropy | Millions of samples per public generator (OS entropy and both providers' `secure_random`, every key-generation function, HPKE, key-exchange groups, ticket keys and nonces, and full TLS 1.3 and 1.2 handshakes for randoms, session IDs, key shares and traffic secrets), each checked for duplicates, bit and byte bias with per-byte min-entropy and Shannon floors, window collision entropy, repeated blocks and serial correlation at a 10^-9 false-alarm level, on x86-64, and at smoke size on aarch64 and riscv64 ([`crates/browntls-entropy/`](../crates/browntls-entropy/README.md)); detects visible low entropy only, not a well-hashed small seed |
| Fuzzing | cargo-fuzz targets for the message codecs, deframer, certificate decompression, PKI parsers and path validation, both connection state machines, and one API-sequence target per topic that together reach every public function ([`fuzz/`](../fuzz/README.md)); CI runs generated seeds on the stable toolchain, checks public API coverage, and fuzzes the targets as a GitHub Actions matrix on one x86-64 runner on pull requests and daily |
| End-to-end | Release builds of the `browntls-e2e` client and server in containers on a Docker network against OpenSSL 3.5 (Alpine), OpenSSL 3.0 (Ubuntu 24.04), GnuTLS 3.8 and browntls itself, for x86-64-v3, aarch64, native riscv64 and riscv64 with vector crypto under QEMU: TLS 1.3 and 1.2 suites and groups including X25519MLKEM768, HelloRetryRequest, client authentication, resumption, Encrypt-then-MAC required by default (`tests/e2e/`, [Docker end-to-end tests](../tests/e2e/README.md)) |

Test certificates and keys are generated at run time; no private keys are
committed. Successful CI is evidence for the tested configurations only and
is not a security assessment.

## Status

The first implementation milestone establishes the crates, the provider mount
point, primitive backends and the TLS state machines. Measured throughput
against OpenSSL is recorded in [Performance](Performance.md). Coverage, gaps and
deferred features are listed in the [roadmap](Roadmap.md).
