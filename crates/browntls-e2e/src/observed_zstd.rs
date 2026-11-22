//! Test-only wrapper that records successfully decoded Zstandard certificates.

use std::sync::atomic::{AtomicUsize, Ordering};

use browntls::CertificateCompressionAlgorithm;
use browntls::compress::{CertDecompressor, DecompressionFailed, ZSTD};

#[derive(Debug)]
pub(super) struct ObservedZstd;

pub(super) static OBSERVED_ZSTD: ObservedZstd = ObservedZstd;

static RECEIVED: AtomicUsize = AtomicUsize::new(0);

pub(super) fn reset() {
    RECEIVED.store(0, Ordering::Relaxed);
}

pub(super) fn received() -> usize {
    RECEIVED.load(Ordering::Relaxed)
}

impl CertDecompressor for ObservedZstd {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        ZSTD.decompress(input, output)?;
        RECEIVED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}
