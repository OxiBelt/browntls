//! What a connection's writes cost its thread, for the placement of new
//! connections.
//!
//! With the `native` feature, the load-aware routing of the native
//! provider (`accel::load`) has kernel TLS as the first place for a
//! connection's records (`accel::load::kernel`) and wants to know what
//! writes cost there and in userspace. A [`Meter`] belongs to one
//! connection and times the writes that the routing asks for, in processor
//! time of the calling thread: waiting for the peer or for the socket is
//! not a cost of either place. Without the feature a meter does nothing.

#[cfg(feature = "native")]
mod on {
    use browntls_core::crypto::native::accel::load::kernel::{self, Place, Records, Sample};
    use browntls_core::{CipherSuite, ConnectionTrafficSecrets, SupportedCipherSuite};

    use crate::sys;

    /// The stream that places connections with `suite`, if its record
    /// protection is one the routing knows.
    pub(crate) fn records_of(suite: SupportedCipherSuite) -> Option<Records> {
        match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Some(Records::Aes128Gcm),
            CipherSuite::TLS13_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Some(Records::Aes256Gcm),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                Some(Records::ChaCha20Poly1305)
            }
            _ => None,
        }
    }

    /// Times the writes of one connection for the routing.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Meter {
        records: Option<Records>,
        place: Place,
    }

    impl Meter {
        /// For a connection the kernel was given, with the keys it sends
        /// under.
        pub(crate) fn kernel(tx: &ConnectionTrafficSecrets) -> Self {
            let records = match tx {
                ConnectionTrafficSecrets::Aes128Gcm { .. } => Some(Records::Aes128Gcm),
                ConnectionTrafficSecrets::Aes256Gcm { .. } => Some(Records::Aes256Gcm),
                ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => {
                    Some(Records::ChaCha20Poly1305)
                }
                _ => None,
            };
            Self {
                records,
                place: Place::Kernel,
            }
        }

        /// For a connection that stays in userspace.
        pub(crate) fn userspace(records: Option<Records>) -> Self {
            Self {
                records,
                place: Place::Userspace,
            }
        }

        /// Before a write of `len` bytes of application data: `Some` when
        /// the routing wants it timed. Costs two relaxed atomic loads
        /// while routing is disabled or kernel TLS is not in its order.
        pub(crate) fn start(&self, len: usize) -> Option<Timing> {
            let sample = kernel::sample(self.records?, self.place, len)?;
            let start = sys::thread_cpu_nanos()?;
            Some(Timing { sample, start })
        }
    }

    /// A write that is being timed.
    #[derive(Debug)]
    pub(crate) struct Timing {
        sample: Sample,
        start: u64,
    }

    impl Timing {
        /// The write gave `sent` bytes to the socket. A write that failed
        /// is not reported.
        pub(crate) fn done(self, sent: usize) {
            if let Some(now) = sys::thread_cpu_nanos() {
                self.sample.done(sent, now.saturating_sub(self.start));
            }
        }
    }
}

#[cfg(not(feature = "native"))]
mod off {
    use browntls_core::ConnectionTrafficSecrets;

    /// Nothing is routed without the native provider.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Meter;

    impl Meter {
        pub(crate) fn kernel(_tx: &ConnectionTrafficSecrets) -> Self {
            Self
        }

        pub(crate) fn start(&self, _len: usize) -> Option<Timing> {
            None
        }
    }

    /// Never made.
    #[derive(Debug)]
    pub(crate) struct Timing(core::convert::Infallible);

    impl Timing {
        pub(crate) fn done(self, _sent: usize) {}
    }
}

#[cfg(not(feature = "native"))]
pub(crate) use off::Meter;
#[cfg(feature = "native")]
pub(crate) use on::{Meter, records_of};
