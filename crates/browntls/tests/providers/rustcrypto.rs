//! The provider under test: `browntls::crypto::rustcrypto`.
//!
//! Included as `mod prov` by the RustCrypto handshake targets; the shared
//! cases in `tests/cases/` and the helpers in `tests/common/` reach provider
//! items only through this module.
#![allow(dead_code, unreachable_pub, unused_imports)]

pub use browntls::crypto::rustcrypto::*;

/// The provider's name, for messages.
pub const NAME: &str = "rustcrypto";

/// Whether the provider's key loader signs with RSA keys. RustCrypto's does
/// not (every `rsa` release is affected by RUSTSEC-2023-0071).
pub const SIGNS_RSA: bool = false;
