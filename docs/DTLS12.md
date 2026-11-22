# DTLS 1.2 handshakes and resumption

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
  `dtls::Settings::with_record_size_limit` optionally limits protected
  records in each direction, independently of MTU. With a connection ID it
  covers the inner content type and any padding.
  DTLS 1.2 closes on key exhaustion; it has no KeyUpdate.
- Whole-flight acknowledgement waits for a ClientHello, ServerHelloDone or
  in-order Finished boundary. The server sends and retains the final flight
  in a full handshake; the client does so in an abbreviated handshake.
  Authenticated application data acknowledges it. Final-flight retention
  expires after the bounded retransmission schedule, including after an
  immediate local close.

## Session resumption

Server resumption is opt-in. After selecting the client verifier and server
credential resolver, call `ServerConfig::enable_dtls12_resumption()`. It
creates a fresh random policy context and returns an error if randomness is
unavailable. Cloned configurations keep the context. Calling it again on a
configuration gives that configuration a fresh context and invalidates its
old sessions. Replacing either authentication object disables DTLS 1.2
resumption until the method is called again. Mutable policy objects must
rotate the context when their authentication decisions change.

The default client memory cache supports separate DTLS 1.2 entries. The
existing `Resumption::tls12_resumption` setting also controls DTLS 1.2:
`Disabled`, `SessionIdOnly`, or `SessionIdOrTickets`. Custom
`ClientSessionStore` implementations can opt in through
`set_dtls12_session`, `dtls12_session`, and `remove_dtls12_session`; their
default methods store nothing and return no session, so existing
implementations remain source-compatible. These operations never use or
invalidate the stream TLS 1.2 slot or the DTLS 1.3 ticket queue. Returned
`Tls12ClientSessionValue` objects carry a `protocol_version()` tag, checked
even when a custom store files an entry in the wrong slot.

Session IDs use the configured server cache under a DTLS-specific key
namespace. RFC 5077 stateless tickets use `ServerConfig::dtls12_ticketer`,
disabled by default. Give it independently generated keys from both
`ticketer` and `hello_retry_cookies`; reusing either `Arc` is rejected.
Separate producer objects sharing secret keys cannot be detected, so key
separation is also the caller's responsibility. The ordinary `ticketer`
continues to serve stream TLS and DTLS 1.3.

Both cached values and ticket plaintext retain the negotiated `DTLSv1_2`
tag, the server policy context, the selected server certificate chain hash,
and the selected certificate types and client-authentication requirements.
Resumption requires the same SNI, ALPN, suite and EMS state. The client
retains its existing verifier and credential-resolver identity checks;
the server restores only the client identity authenticated under its bound
policy. A required client certificate cannot be inherited from an
unauthenticated session. Revocation policies requiring fresh certificate
checks and RFC 8844 external authentication bindings keep full handshakes
and issue no resumable state.

Cookie validation precedes cache lookup and ticket decryption on unvalidated
paths, including through the stateless acceptor. Full handshakes send the
client's CCS/Finished first; abbreviated handshakes send the server's
ServerHello, optional NewSessionTicket, CCS and Finished first. Each CCS is
sent at epoch zero and activates epoch one for the sender; the receiving
state must expect CCS before activating its read epoch. An empty-ID ticket
offer is distinguished from a full handshake by the next server message.
A dual-version client can offer its cached pre-1.3 ID, but DTLS 1.3
ServerHello and HelloRetryRequest responses always have an empty ID.

DTLS server entries expire after at most seven days; stateless tickets are
also bounded by the configured producer lifetime. Clients enforce advertised
ticket lifetimes. A renewal replaces the ticket only after Finished verifies;
without a replacement, the original credential and expiry are retained.
Fatal errors invalidate only the connection's own DTLS 1.2 cache entry;
stateless tickets cannot be recalled individually. Existing stream and DTLS
1.3 persistence formats are unchanged, and neither accepts a DTLS 1.2 value.

Cached-information and CertificateURL extensions are not negotiated over
DTLS in this layer. Certificates and requests are sent in full. It supports
opt-in connection IDs and RFC 9853 path validation on both providers.
Renegotiation, 0-RTT, ECH and post-handshake authentication are out of scope.

The deterministic public-path cases are in
`crates/browntls-core/tests/cases/dtls12.rs`, included by both provider DTLS
test targets. They cover endpoint policy, all existing ECDHE AEAD suites,
mTLS, fragmentation, loss, reordering, duplication, stateless cookies,
replay rejection, repeated full handshakes and timeout behavior. The added
`dtls12_resumption.rs`, `dtls12_resumption_auth.rs`, and
`dtls12_resumption_cache.rs` cases cover session IDs, tickets, mTLS across
suites, policy binding, cross-transport cache separation and invalidation,
legacy custom stores, expiry, cookie ordering, mixed-version negotiation,
empty-ID ticket acceptance and decline, failed ticket renewal, deterministic
abbreviated-flight loss/reordering, and immediate client closure. Existing
DTLS 1.3 cases remain in both targets. On a DTLS 1.2-only endpoint the stateless
acceptor can challenge an initial ClientHello split across datagrams before
allocating peer state. This supports large certificate-bound session tickets.
A mixed endpoint needs the first ClientHello in one datagram for version
selection.

The
[Docker interoperability tests](../tests/e2e/README.md#dtls-interoperability)
cover mutual certificate authentication with OpenSSL in both roles, with
1.2-only and mixed-version browntls endpoints, ECDSA P-256, AES-128-GCM,
application data and authenticated closure. Additional cases exercise
OpenSSL session IDs and tickets and bilateral CID negotiation with wolfSSL.

Protocol references: [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347),
[RFC 5077](https://www.rfc-editor.org/rfc/rfc5077),
[RFC 7627](https://www.rfc-editor.org/rfc/rfc7627), and
[RFC 7905](https://www.rfc-editor.org/rfc/rfc7905).
