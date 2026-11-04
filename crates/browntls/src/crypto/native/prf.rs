//! The TLS 1.2 PRF (RFC 5246 §5) via `browntls_crypto::tls12_prf`.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::hash as bc_hash;
use browntls_crypto::tls12_prf::prf;

use super::hash::Named;
use crate::crypto::ActiveKeyExchange;
use crate::crypto::tls12::Prf;
use crate::error::Error;
use crate::versions::TLS12;

/// `P_SHA256`.
pub static PRF_SHA256: &dyn Prf = &PRF_SHA256_IMPL;
/// `P_SHA384`.
pub static PRF_SHA384: &dyn Prf = &PRF_SHA384_IMPL;

pub(crate) static PRF_SHA256_IMPL: PrfImpl<bc_hash::Sha256> = PrfImpl(PhantomData);
pub(crate) static PRF_SHA384_IMPL: PrfImpl<bc_hash::Sha384> = PrfImpl(PhantomData);

/// The TLS 1.2 PRF over a `browntls-crypto` hash.
pub(crate) struct PrfImpl<H>(PhantomData<H>);

impl<H: Named> Prf for PrfImpl<H> {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        let secret = kx.complete_for_tls_version(peer_pub_key, &TLS12)?;
        prf::<H>(output, secret.secret_bytes(), label, &[seed]);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf::<H>(output, secret, label, &[seed]);
    }
}

impl<H: Named> fmt::Debug for PrfImpl<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prf({:?})", H::BC_ALGORITHM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls12::PrfUsingHmac;

    #[test]
    fn sha256_vector() {
        let secret = hex::decode("9bbe436ba940f017b17652849a71db35").unwrap();
        let seed = hex::decode("a0ba9f936cda311827a6f796ffd5198c").unwrap();
        let mut out = [0u8; 100];
        PRF_SHA256.for_secret(&mut out, &secret, b"test label", &seed);
        assert_eq!(
            hex::encode(&out[..32]),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
        );
    }

    #[test]
    fn matches_generic_hmac_construction() {
        for (prf, hmac) in [
            (PRF_SHA256, super::super::hmac::HMAC_SHA256),
            (PRF_SHA384, super::super::hmac::HMAC_SHA384),
        ] {
            let mut a = [0u8; 77];
            let mut b = [0u8; 77];
            prf.for_secret(&mut a, b"secret", b"label", b"seed");
            PrfUsingHmac(hmac).for_secret(&mut b, b"secret", b"label", b"seed");
            assert_eq!(a, b);
        }
    }
}
