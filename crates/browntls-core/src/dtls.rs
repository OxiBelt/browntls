//! DTLS 1.3 (RFC 9147): TLS 1.3 over datagrams.
//!
//! The handshake state machines are those of TLS 1.3. What differs sits
//! here: records that carry their own epoch and sequence number
//! ([`wire`], [`keys`]), a replay window per epoch ([`replay`]), handshake
//! messages that are fragmented, reordered and retransmitted
//! ([`reassembly`]), and the flights, acknowledgements and timers that
//! make the handshake reliable ([`state`]).

mod keys;
mod reassembly;
mod replay;
mod state;
mod wire;

pub(crate) use state::Dtls;

/// The `HKDF-Expand-Label` prefix of DTLS 1.3 (RFC 9147 §5.9). It has no
/// trailing space, unlike that of TLS 1.3.
pub(crate) const LABEL_PREFIX: &[u8] = b"dtls13";
