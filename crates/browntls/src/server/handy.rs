//! Ready-made session stores, ticketers and certificate resolvers for servers.

use alloc::vec::Vec;

use super::server_conn::{ClientHello, ProducesTickets, ResolvesServerCert, StoresServerSessions};
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;

/// A store that keeps nothing, so no session can be resumed.
#[derive(Debug)]
pub struct NoServerSessionStorage {}

impl StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }

    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn can_cache(&self) -> bool {
        false
    }
}

#[cfg(feature = "std")]
mod cache {
    use alloc::vec::Vec;
    use core::fmt::{Debug, Formatter};
    use std::sync::Mutex;

    use crate::limited_cache::LimitedCache;
    use crate::server::server_conn::StoresServerSessions;
    use crate::sync::Arc;

    /// An in-memory session store bounded to a number of sessions.
    pub struct ServerSessionMemoryCache {
        cache: Mutex<LimitedCache<Vec<u8>, Vec<u8>>>,
    }

    impl ServerSessionMemoryCache {
        /// Stores up to `size` sessions.
        pub fn new(size: usize) -> Arc<Self> {
            Arc::new(Self {
                cache: Mutex::new(LimitedCache::new(size.max(1))),
            })
        }
    }

    impl StoresServerSessions for ServerSessionMemoryCache {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            match self.cache.lock() {
                Ok(mut cache) => {
                    cache.insert(key, value);
                    true
                }
                Err(_) => false,
            }
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache.lock().ok()?.get(key).cloned()
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache.lock().ok()?.remove(key)
        }

        fn can_cache(&self) -> bool {
            true
        }
    }

    impl Debug for ServerSessionMemoryCache {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ServerSessionMemoryCache")
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn put_get_take() {
            let c = ServerSessionMemoryCache::new(2);
            assert!(c.can_cache());
            assert!(c.put(alloc::vec![1], alloc::vec![10]));
            assert!(c.put(alloc::vec![2], alloc::vec![20]));
            assert_eq!(c.get(&[1]), Some(alloc::vec![10]));
            assert!(c.put(alloc::vec![3], alloc::vec![30]));
            assert_eq!(c.get(&[1]), None);
            assert_eq!(c.take(&[3]), Some(alloc::vec![30]));
            assert_eq!(c.get(&[3]), None);
        }
    }
}

#[cfg(feature = "std")]
pub use cache::ServerSessionMemoryCache;

/// A ticketer that issues no tickets.
#[derive(Debug)]
pub(super) struct NeverProducesTickets {}

impl ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

impl ResolvesServerCert for SingleCertAndKey {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[cfg(feature = "std")]
mod sni_resolver {
    use alloc::string::ToString;
    use core::fmt::Debug;
    use std::collections::HashMap;

    use browntls_pki::{DnsName, EndEntityCert, ServerName};

    use crate::error::Error;
    use crate::server::server_conn::{ClientHello, ResolvesServerCert};
    use crate::sign::CertifiedKey;
    use crate::sync::Arc;
    use crate::webpki::pki_error;

    /// Chooses a certificate by the client's server name.
    ///
    /// Clients that send no server name are refused.
    #[derive(Debug, Default)]
    pub struct ResolvesServerCertUsingSni {
        by_name: HashMap<DnsName<'static>, Arc<CertifiedKey>>,
    }

    impl ResolvesServerCertUsingSni {
        /// An empty resolver.
        pub fn new() -> Self {
            Self::default()
        }

        /// Serves `ck` for `name`, after checking the certificate is valid for it.
        pub fn add(&mut self, name: &str, ck: CertifiedKey) -> Result<(), Error> {
            let server_name = ServerName::try_from(name)
                .map_err(|_| Error::General("Bad DNS name".to_string()))?;
            let ServerName::DnsName(dns) = &server_name else {
                return Err(Error::UnsupportedNameType);
            };

            let end_entity = ck.end_entity_cert()?;
            let cert = EndEntityCert::try_from(end_entity).map_err(pki_error)?;
            cert.verify_is_valid_for_subject_name(&server_name)
                .map_err(pki_error)?;

            self.by_name.insert(dns.to_lowercase_owned(), Arc::new(ck));
            Ok(())
        }
    }

    impl ResolvesServerCert for ResolvesServerCertUsingSni {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            let name = client_hello.server_name()?;
            let dns = DnsName::try_from(name).ok()?.to_lowercase_owned();
            self.by_name.get(&dns).cloned()
        }
    }
}

#[cfg(feature = "std")]
pub use sni_resolver::ResolvesServerCertUsingSni;
