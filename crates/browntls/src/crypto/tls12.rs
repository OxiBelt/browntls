//! The TLS 1.2 pseudorandom function (RFC 5246 §5).

use alloc::boxed::Box;

use super::{ActiveKeyExchange, hmac};
use crate::error::Error;
use crate::versions::TLS12;

/// The TLS 1.2 PRF for a particular hash.
pub trait Prf: Send + Sync {
    /// Computes the 48-byte master secret from the key exchange output.
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error>;

    /// `PRF(secret, label, seed)` into `output`.
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]);

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// A [`Prf`] built from any [`hmac::Hmac`].
pub struct PrfUsingHmac<'a>(pub &'a dyn hmac::Hmac);

impl Prf for PrfUsingHmac<'_> {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        let secret = kx.complete_for_tls_version(peer_pub_key, &TLS12)?;
        prf(
            output,
            &*self.0.with_key(secret.secret_bytes()),
            label,
            seed,
        );
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf(output, &*self.0.with_key(secret), label, seed);
    }
}

/// `P_hash(secret, label || seed)` (RFC 5246 §5) with `hmac_key` keyed by the secret.
pub(crate) fn prf(out: &mut [u8], hmac_key: &dyn hmac::Key, label: &[u8], seed: &[u8]) {
    // A(0) = seed; A(i) = HMAC(secret, A(i-1)); P = HMAC(secret, A(1) || seed) || ...
    let mut a = hmac_key.sign(&[label, seed]);
    for chunk in out.chunks_mut(hmac_key.tag_len()) {
        let p = hmac_key.sign(&[a.as_ref(), label, seed]);
        chunk.copy_from_slice(&p.as_ref()[..chunk.len()]);
        a = hmac_key.sign(&[a.as_ref()]);
    }
}
