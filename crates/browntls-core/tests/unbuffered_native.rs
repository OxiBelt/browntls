//! The unbuffered (caller-buffer) connection API: in-memory handshakes and
//! data against buffered browntls peers, other unbuffered peers and rustls,
//! with whole and byte-by-byte input, undersized output buffers, closure,
//! resumption, 0-RTT data, KeyUpdate, and the `UnbufferedAcceptor` (the
//! configuration chosen from the ClientHello).
//!
//! This target runs the cases in `cases/unbuffered.rs` with the native
//! provider; `unbuffered.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/unbuffered.rs");
