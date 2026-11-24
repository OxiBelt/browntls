//! Fuzz harnesses for browntls.
//!
//! Each public function here is the body of the fuzz target of the same name
//! in `fuzz_targets/`. Keeping the bodies in a library lets the pinned stable
//! toolchain type-check them and run them over the generated inputs of
//! [`seeds`] (`cargo test`), so the harnesses cannot rot between fuzzing
//! runs; only the instrumented binaries need a nightly toolchain.
//!
//! Every harness takes untrusted bytes and must return without panicking.
//! A panic, an abort (for example an allocation beyond the fuzzer's memory
//! limit) or a timeout is a finding.
//!
//! The first targets reach the untrusted-input parsers. The API targets
//! (one module per target, each with `run` and `seeds`) decode their input as
//! a sequence of calls into the public API of one topic, check results
//! against independent implementations or algebraic properties where those
//! exist, and together reach every public function (`fuzz/README.md`,
//! "Public API coverage").

mod codec;
mod connection;
#[cfg(test)]
mod early_data_adapters;
pub mod input;
mod pki;
pub mod seeds;
#[cfg(test)]
mod service_identity_adapters;

pub mod crypto_cipher;
pub mod crypto_ecc;
pub mod crypto_hash;
pub mod crypto_hpke;
pub mod crypto_kem;
pub mod crypto_rsa;
pub mod crypto_util;
pub mod pki_api;
pub mod pki_revocation;
pub mod tls_auth;
pub mod tls_binding;
pub mod tls_codec;
pub mod tls_config;
pub mod tls_conn;
pub mod tls_dtls;
pub mod tls_dtls_tokio;
pub mod tls_dtls_udp;
pub mod tls_ech;
pub mod tls_kernel;
pub mod tls_psk;
pub mod tls_quic;
pub mod tls_tokio;
pub mod tls_tokio_unbuffered;
pub mod tls_unbuffered;

pub use codec::{cert_decompress, deframer, handshake_message};
pub use connection::{client, server};
pub use pki::{pki_cert, pki_crl, pki_pem};

/// Installs the native provider as the process default.
///
/// The fuzz project enables both the `native` and the `rustcrypto`
/// providers, so the library has no implicit default; every harness that
/// uses a `builder()` without a provider calls this first. Idempotent.
pub fn init() {
    // Err means a provider is installed already.
    let _ = browntls_core::crypto::native::default_provider().install_default();
}

/// Splits the next length-prefixed field off `data`: a 16-bit big-endian
/// length (clamped to what remains) and that many bytes.
fn take_field<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return core::mem::take(data);
    };
    let len = usize::from(u16::from_be_bytes(*len)).min(rest.len());
    let (field, rest) = rest.split_at(len);
    *data = rest;
    field
}

/// Takes the next byte of `data`, or zero when none is left.
fn take_byte(data: &mut &[u8]) -> u8 {
    match data.split_first() {
        Some((byte, rest)) => {
            *data = rest;
            *byte
        }
        None => 0,
    }
}
