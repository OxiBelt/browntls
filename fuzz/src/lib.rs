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

mod codec;
mod connection;
mod pki;
pub mod seeds;

pub use codec::{cert_decompress, deframer, handshake_message};
pub use connection::{client, server};
pub use pki::{pki_cert, pki_crl, pki_pem};

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
