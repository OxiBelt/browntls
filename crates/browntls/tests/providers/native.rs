//! The provider under test: `browntls::crypto::native`.
//!
//! Included as `mod prov` by the native handshake targets; the shared cases
//! in `tests/cases/` and the helpers in `tests/common/` reach provider items
//! only through this module. The native provider mirrors the RustCrypto item
//! names; the one difference the cases rely on is bridged here rather than
//! in the provider: RustCrypto exports a rotating `Ticketer`, the native
//! provider only the AES-256-GCM `ticketer::AeadTicketProducer`, so
//! [`Ticketer`] wraps that in the crate's `TicketRotator` the same way.
#![allow(dead_code, unreachable_pub, unused_imports)]

use std::sync::Arc;

pub use browntls::crypto::native::*;

/// The provider's name, for messages.
pub const NAME: &str = "native";

/// Whether the provider's key loader signs with RSA keys.
pub const SIGNS_RSA: bool = true;

/// A rotating AES-256-GCM ticketer, built as `rustcrypto::Ticketer` is.
#[derive(Debug)]
pub struct Ticketer;

impl Ticketer {
    /// Ticket lifetime in seconds (as `rustcrypto::Ticketer`).
    const LIFETIME: u32 = 6 * 60 * 60;

    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Arc<dyn browntls::server::ProducesTickets>, browntls::Error> {
        Ok(Arc::new(browntls::ticketer::TicketRotator::new(
            Self::LIFETIME,
            || Ok(Box::new(ticketer::AeadTicketProducer::new()?)),
        )?))
    }
}
