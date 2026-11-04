//! SHA-2 via the `sha2` crate.

use alloc::boxed::Box;
use core::marker::PhantomData;

use sha2::Digest;

use crate::crypto::hash::{Context, Hash, HashAlgorithm, Output};

/// Which TLS code point a digest type corresponds to.
pub(crate) trait Named {
    const ALGORITHM: HashAlgorithm;
}

impl Named for sha2::Sha256 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA256;
}

impl Named for sha2::Sha384 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA384;
}

impl Named for sha2::Sha512 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA512;
}

/// A hash function implemented by a `sha2` digest type.
pub(crate) struct HashImpl<D>(PhantomData<D>);

pub(crate) static SHA256: HashImpl<sha2::Sha256> = HashImpl(PhantomData);
pub(crate) static SHA384: HashImpl<sha2::Sha384> = HashImpl(PhantomData);

impl<D> Hash for HashImpl<D>
where
    D: Digest + Clone + Named + Send + Sync + 'static,
{
    fn start(&self) -> Box<dyn Context> {
        Box::new(ContextImpl(D::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&D::digest(data))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        D::ALGORITHM
    }
}

struct ContextImpl<D>(D);

impl<D> Context for ContextImpl<D>
where
    D: Digest + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(ContextImpl(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_answer() {
        let out = SHA256.hash(b"abc");
        assert_eq!(
            hex::encode(out.as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA384.output_len(), 48);
        assert_eq!(SHA256.algorithm(), HashAlgorithm::SHA256);
        let mut ctx = SHA256.start();
        ctx.update(b"a");
        let forked = ctx.fork();
        ctx.update(b"bc");
        assert_eq!(ctx.fork_finish().as_ref(), out.as_ref());
        assert_eq!(ctx.finish().as_ref(), out.as_ref());
        assert_eq!(forked.finish().as_ref(), SHA256.hash(b"a").as_ref());
    }
}
