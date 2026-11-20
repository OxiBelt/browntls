//! A bounded in-memory [`ClientCachedInfoStore`].

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use std::sync::Mutex;

use browntls_pki::ServerName;

use super::{CachedInformationType, CachedObject, ClientCachedInfoStore};
use crate::limited_cache::LimitedCache;
use crate::sync::Arc;

#[derive(Default)]
struct ServerObjects {
    cert: VecDeque<Arc<CachedObject>>,
    cert_req: VecDeque<Arc<CachedObject>>,
}

impl ServerObjects {
    fn of(&self, typ: CachedInformationType) -> &VecDeque<Arc<CachedObject>> {
        match typ {
            CachedInformationType::Cert => &self.cert,
            CachedInformationType::CertReq => &self.cert_req,
        }
    }

    fn of_mut(&mut self, typ: CachedInformationType) -> &mut VecDeque<Arc<CachedObject>> {
        match typ {
            CachedInformationType::Cert => &mut self.cert,
            CachedInformationType::CertReq => &mut self.cert_req,
        }
    }
}

/// An in-memory [`ClientCachedInfoStore`] bounded by a number of server
/// names and a number of objects of each type per server name.
///
/// When full, the server name inserted longest ago is forgotten, and within
/// a server name the object inserted longest ago; storing an object again
/// (same fingerprint) makes it the most recent. Each object holds one
/// handshake message of at most 64 KiB, so the store holds at most
/// `max_servers * per_server * 2` messages.
pub struct ClientCachedInfoMemoryCache {
    servers: Mutex<LimitedCache<ServerName<'static>, ServerObjects>>,
    per_server: usize,
}

impl ClientCachedInfoMemoryCache {
    /// Remembers objects for up to `max_servers` server names and up to
    /// `per_server` objects of each type for each (both at least one).
    pub fn new(max_servers: usize, per_server: usize) -> Self {
        Self {
            servers: Mutex::new(LimitedCache::new(max_servers.max(1))),
            per_server: per_server.max(1),
        }
    }
}

impl ClientCachedInfoStore for ClientCachedInfoMemoryCache {
    fn lookup(
        &self,
        server_name: &ServerName<'_>,
        typ: CachedInformationType,
    ) -> Vec<Arc<CachedObject>> {
        let Ok(servers) = self.servers.lock() else {
            return Vec::new();
        };
        servers
            .get(server_name)
            .map(|objects| objects.of(typ).iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    fn insert(&self, server_name: ServerName<'static>, object: Arc<CachedObject>) {
        let Ok(mut servers) = self.servers.lock() else {
            return;
        };
        let per_server = self.per_server;
        servers.get_or_insert_default_and_edit(server_name, |objects| {
            let list = objects.of_mut(object.typ());
            list.retain(|old| old.fingerprint() != object.fingerprint());
            list.push_back(object);
            while list.len() > per_server {
                list.pop_front();
            }
        });
    }
}

impl fmt::Debug for ClientCachedInfoMemoryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCachedInfoMemoryCache")
            .field("per_server", &self.per_server)
            .finish_non_exhaustive()
    }
}
