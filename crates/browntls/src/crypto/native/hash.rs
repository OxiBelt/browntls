//! SHA-2 via `browntls_crypto::hash`.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::hash::{self as bc_hash, HashFunction};

use crate::crypto::hash::{Context, Hash, HashAlgorithm, Output};

/// SHA-256 (FIPS 180-4).
pub static SHA256: &dyn Hash = &SHA256_IMPL;
/// SHA-384 (FIPS 180-4).
pub static SHA384: &dyn Hash = &SHA384_IMPL;
/// SHA-512 (FIPS 180-4).
pub static SHA512: &dyn Hash = &SHA512_IMPL;

pub(crate) static SHA256_IMPL: Sha2<bc_hash::Sha256> = Sha2(PhantomData);
pub(crate) static SHA384_IMPL: Sha2<bc_hash::Sha384> = Sha2(PhantomData);
pub(crate) static SHA512_IMPL: Sha2<bc_hash::Sha512> = Sha2(PhantomData);

/// Which TLS code point a `browntls-crypto` hash corresponds to.
pub(crate) trait Named: HashFunction + Send + Sync + 'static {
    /// The TLS `HashAlgorithm` code point.
    const ALGORITHM: HashAlgorithm;
    /// The `browntls-crypto` run-time identifier.
    const BC_ALGORITHM: bc_hash::HashAlgorithm;
}

impl Named for bc_hash::Sha256 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA256;
    const BC_ALGORITHM: bc_hash::HashAlgorithm = bc_hash::HashAlgorithm::Sha256;
}

impl Named for bc_hash::Sha384 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA384;
    const BC_ALGORITHM: bc_hash::HashAlgorithm = bc_hash::HashAlgorithm::Sha384;
}

impl Named for bc_hash::Sha512 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA512;
    const BC_ALGORITHM: bc_hash::HashAlgorithm = bc_hash::HashAlgorithm::Sha512;
}

/// A [`Hash`] backed by a `browntls-crypto` SHA-2 implementation.
pub(crate) struct Sha2<H>(PhantomData<H>);

impl<H: Named> Hash for Sha2<H> {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha2Context(H::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(H::digest(data).as_ref())
    }

    fn output_len(&self) -> usize {
        H::OUTPUT_LEN
    }

    fn algorithm(&self) -> HashAlgorithm {
        H::ALGORITHM
    }
}

impl<H: Named> fmt::Debug for Sha2<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", H::BC_ALGORITHM)
    }
}

struct Sha2Context<H>(H);

impl<H: Named> Context for Sha2Context<H> {
    fn fork_finish(&self) -> Output {
        Output::new(self.0.clone().finalize().as_ref())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(self.0.finalize().as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            hex::encode(SHA256.hash(b"abc").as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(SHA384.hash(b"abc").as_ref()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(SHA512.output_len(), 64);
        assert_eq!(SHA384.algorithm(), HashAlgorithm::SHA384);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let out = SHA256.hash(b"abc");
        let mut ctx = SHA256.start();
        ctx.update(b"a");
        let forked = ctx.fork();
        ctx.update(b"bc");
        assert_eq!(ctx.fork_finish().as_ref(), out.as_ref());
        assert_eq!(ctx.finish().as_ref(), out.as_ref());
        assert_eq!(forked.finish().as_ref(), SHA256.hash(b"a").as_ref());
    }
}
