//! Ready-made session stores and certificate resolvers for clients.

use browntls_pki::ServerName;

use super::client_conn::{ClientSessionStore, ResolvesClientCert};
use crate::enums::SignatureScheme;
use crate::msgs::enums::NamedGroup;
#[cfg(feature = "tls12")]
use crate::msgs::persist::Tls12ClientSessionValue;
use crate::msgs::persist::Tls13ClientSessionValue;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;

/// A session store that remembers nothing.
#[derive(Debug)]
pub struct NoClientSessionStorage;

impl ClientSessionStore for NoClientSessionStorage {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    #[cfg(feature = "tls12")]
    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}

    #[cfg(feature = "tls12")]
    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    #[cfg(feature = "tls12")]
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, _: ServerName<'static>, _: Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

#[cfg(feature = "std")]
mod cache {
    use alloc::collections::VecDeque;
    use core::fmt;
    use std::sync::Mutex;

    use browntls_pki::ServerName;

    use crate::client::client_conn::ClientSessionStore;
    use crate::limited_cache::LimitedCache;
    use crate::msgs::enums::NamedGroup;
    #[cfg(feature = "tls12")]
    use crate::msgs::persist::Tls12ClientSessionValue;
    use crate::msgs::persist::Tls13ClientSessionValue;

    /// How many TLS 1.3 tickets are kept per server.
    const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

    struct ServerData {
        kx_hint: Option<NamedGroup>,
        #[cfg(feature = "tls12")]
        tls12: Option<Tls12ClientSessionValue>,
        tls13: VecDeque<Tls13ClientSessionValue>,
    }

    impl Default for ServerData {
        fn default() -> Self {
            Self {
                kx_hint: None,
                #[cfg(feature = "tls12")]
                tls12: None,
                tls13: VecDeque::with_capacity(MAX_TLS13_TICKETS_PER_SERVER),
            }
        }
    }

    /// An in-memory session store bounded to a number of servers.
    pub struct ClientSessionMemoryCache {
        servers: Mutex<LimitedCache<ServerName<'static>, ServerData>>,
    }

    impl ClientSessionMemoryCache {
        /// Remembers sessions for up to `size` servers.
        pub fn new(size: usize) -> Self {
            let max_servers = size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1) / MAX_TLS13_TICKETS_PER_SERVER;
            Self {
                servers: Mutex::new(LimitedCache::new(max_servers.max(1))),
            }
        }
    }

    impl ClientSessionStore for ClientSessionMemoryCache {
        fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
            if let Ok(mut servers) = self.servers.lock() {
                servers.get_or_insert_default_and_edit(server_name, |data| data.kx_hint = Some(group));
            }
        }

        fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
            self.servers
                .lock()
                .ok()?
                .get(server_name)
                .and_then(|sd| sd.kx_hint)
        }

        #[cfg(feature = "tls12")]
        fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
            if let Ok(mut servers) = self.servers.lock() {
                servers.get_or_insert_default_and_edit(server_name, |data| data.tls12 = Some(value));
            }
        }

        #[cfg(feature = "tls12")]
        fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
            self.servers
                .lock()
                .ok()?
                .get(server_name)
                .and_then(|sd| sd.tls12.as_ref().map(|v| v.clone_for_resumption()))
        }

        #[cfg(feature = "tls12")]
        fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
            if let Ok(mut servers) = self.servers.lock()
                && let Some(data) = servers.get_mut(server_name)
            {
                data.tls12 = None;
            }
        }

        fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
            if let Ok(mut servers) = self.servers.lock() {
                servers.get_or_insert_default_and_edit(server_name, |data| {
                    if data.tls13.len() == MAX_TLS13_TICKETS_PER_SERVER {
                        data.tls13.pop_front();
                    }
                    data.tls13.push_back(value);
                });
            }
        }

        fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
            self.servers
                .lock()
                .ok()?
                .get_mut(server_name)
                .and_then(|sd| sd.tls13.pop_back())
        }
    }

    impl fmt::Debug for ClientSessionMemoryCache {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientSessionMemoryCache").finish_non_exhaustive()
        }
    }
}

#[cfg(feature = "std")]
pub use cache::ClientSessionMemoryCache;

/// A resolver that never offers a certificate.
#[derive(Debug)]
pub(super) struct FailResolveClientCert {}

impl ResolvesClientCert for FailResolveClientCert {
    fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

impl ResolvesClientCert for SingleCertAndKey {
    fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
