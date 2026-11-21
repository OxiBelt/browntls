# DTLS 1.2 certificate handshakes

DTLS endpoints default to DTLS 1.3. The existing `tls12` compile feature
also enables the DTLS 1.2 certificate handshake adapter. It uses the shared
TLS 1.2 certificate verification and ECDHE handshake states and the selected
provider's AES-GCM or ChaCha20-Poly1305 record algorithms. It adds no
primitive, dependency or unsafe code.

An endpoint opts in through `dtls::Versions`:

| Policy | Allowed versions |
| --- | --- |
| `V1_3` (default) | DTLS 1.3 |
| `V1_2And1_3` | DTLS 1.3, then DTLS 1.2 in negotiation preference |
| `V1_2` | DTLS 1.2 |

Use `dtls::ClientConnection::new_with_versions` or
`dtls::ServerConnection::new_with_versions`. The server constructor retains
the address cookie requirement. `dtls::Acceptor::new_with_versions` provides
stateless acceptance under the same policy. Blocking UDP endpoints expose
`dtls::UdpClient::connect_with_versions` and
`dtls::UdpServer::new_with_versions`.

The endpoint policy intersects the versions and suites in the supplied TLS
configuration. It does not change the configuration, provider, QUIC policy,
or TLS stream behavior. Both endpoints permitting DTLS 1.3 negotiate 1.3.
A timeout retransmits the same flight; it never switches versions.
`CommonState::protocol_version` reports `DTLSv1_2` when 1.2 is selected.

DTLS 1.2 uses the following protocol boundaries:

- Full certificate authentication, including requested or required client
  certificates, retains the shared verifier and signature checks. EMS is
  required on both endpoints, even when the shared TLS configuration allows
  a stream handshake without EMS.
- An address-bound, sealed HelloVerifyRequest cookie uses a distinct domain
  and a bounded lifetime. The configured `hello_retry_cookies` capability
  seals it. The stateless acceptor checks the cookie before retaining a
  connection. The HelloVerifyRequest version field does not select the
  negotiated version.
- Finished, EMS and CertificateVerify use canonical twelve-byte DTLS
  handshake headers with the original message sequence. Fragment offsets
  are zero and lengths describe the complete message. The first
  ClientHello and HelloVerifyRequest are excluded after a cookie retry.
- CCS is an epoch-zero record retained with its flight. Read activation
  waits for the shared handshake state to expect CCS, including after
  certificate verification pauses. The protected Finished uses epoch one.
- Record protection passes `(epoch << 48) | record_sequence` and the wire
  DTLS version to the existing AEAD interface. Sequence consumption,
  confidentiality limits, failed authentication limits, replay rejection,
  datagram MTU limits and bounded handshake reassembly remain explicit.
  DTLS 1.2 closes on key exhaustion; it has no KeyUpdate.
- Whole-flight acknowledgement waits for a ClientHello, ServerHelloDone or
  in-order Finished boundary. The server retains the final flight
  for retransmission; authenticated application data acknowledges it.
  Final-flight retention expires after the bounded retransmission schedule.

DTLS 1.2 resumption is disabled: no session lookup, ticket request, session
save, server cache/ticket acceptance or issuance, or stream-session
invalidation. DTLS 1.3 tickets retain their existing transport separation.
Cached-information and CertificateURL extensions are not negotiated over
DTLS in this layer; certificates and requests are sent in full. Connection
IDs, renegotiation, 0-RTT, ECH and post-handshake authentication remain outside
this DTLS layer.

The deterministic public-path cases are in
`crates/browntls-core/tests/cases/dtls12.rs`, included by both provider DTLS
test targets. They cover endpoint policy, all existing ECDHE AEAD suites,
mTLS, fragmentation, loss, reordering, duplication, stateless cookies,
replay rejection, repeated full handshakes and timeout behavior. Existing
DTLS 1.3 cases remain in both targets. These added cases have not yet been
compiled or executed in the implementation worktree; compilation, execution,
feature-matrix checks, external interoperability and independent review
remain qualification requirements.

Protocol references: [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347),
[RFC 7627](https://www.rfc-editor.org/rfc/rfc7627), and
[RFC 7905](https://www.rfc-editor.org/rfc/rfc7905).
