use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_core::CertificateCompressionAlgorithm;
use browntls_core::compress::{CertDecompressor, DecompressionFailed};

/// Wraps a decompressor and counts the messages it expanded.
#[derive(Debug)]
pub(crate) struct Counting {
    inner: &'static dyn CertDecompressor,
    calls: AtomicUsize,
}

impl Counting {
    pub(crate) fn new(inner: &'static dyn CertDecompressor) -> &'static Self {
        Box::leak(Box::new(Self {
            inner,
            calls: AtomicUsize::new(0),
        }))
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CertDecompressor for Counting {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        self.inner.decompress(input, output)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(feature = "zstd")]
    fn decompress_with_zstd_limits(
        &self,
        input: &[u8],
        output: &mut [u8],
        limits: browntls_core::compress::ZstdDecompressionLimits,
    ) -> Result<(), DecompressionFailed> {
        self.inner
            .decompress_with_zstd_limits(input, output, limits)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.inner.algorithm()
    }
}
