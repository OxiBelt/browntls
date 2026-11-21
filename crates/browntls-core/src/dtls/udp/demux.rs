//! Bounded DTLS CID prefix lookup for socket adapters.
//!
//! A match is only a routing hint. The connection must authenticate and
//! replay-check the record, and RRC must validate a changed physical path.

use alloc::vec::Vec;
use core::hash::Hash;
use std::collections::{HashMap, HashSet};

use crate::dtls::{MAX_CONNECTION_IDS, wire};
use crate::enums::ContentType;

/// An index for core-issued, nonempty receiving CIDs (8 through 32 bytes).
/// At most 16 CIDs are stored per owner. Lookup makes at most 25 hash
/// lookups, regardless of the number of associations. Duplicate CIDs and
/// ambiguous prefixes fail closed, including collisions between lengths.
/// The adapter must refresh an owner's IDs after input and caller mutation,
/// and remove them when that association ends.
pub struct CidDemux<P> {
    ids: HashMap<Vec<u8>, Owners<P>>,
    owners: HashMap<P, Vec<Vec<u8>>>,
}

struct Owners<P> {
    all: HashSet<P>,
    // Cache the sole owner so lookup never scans a collision set's capacity.
    unique: Option<P>,
}

impl<P> Default for CidDemux<P> {
    fn default() -> Self {
        Self {
            ids: HashMap::new(),
            owners: HashMap::new(),
        }
    }
}

impl<P: Copy + Eq + Hash> CidDemux<P> {
    /// Replaces an owner's bounded set of core-issued receiving IDs.
    /// Invalid lengths and IDs beyond the lifetime cap are ignored.
    pub fn replace<'a>(&mut self, owner: P, ids: impl IntoIterator<Item = &'a [u8]>) {
        let ids: Vec<Vec<u8>> = ids
            .into_iter()
            .take(MAX_CONNECTION_IDS)
            .filter(|id| (8..=32).contains(&id.len()))
            .map(<[u8]>::to_vec)
            .collect();
        if self.owners.get(&owner) == Some(&ids) {
            return;
        }
        self.remove(owner);
        for id in &ids {
            let owners = self.ids.entry(id.clone()).or_insert_with(|| Owners {
                all: HashSet::new(),
                unique: None,
            });
            owners.all.insert(owner);
            owners.unique = (owners.all.len() == 1).then_some(owner);
        }
        if !ids.is_empty() {
            self.owners.insert(owner, ids);
        }
    }

    /// Drops all lookup state for an association. A formerly ambiguous
    /// CID becomes usable again if exactly one owner remains.
    pub fn remove(&mut self, owner: P) {
        for id in self.owners.remove(&owner).into_iter().flatten() {
            if let Some(owners) = self.ids.get_mut(&id) {
                owners.all.remove(&owner);
                owners.unique = if owners.all.len() == 1 {
                    owners.all.iter().next().copied()
                } else {
                    None
                };
                if owners.all.is_empty() {
                    self.ids.remove(&id);
                }
            }
        }
    }

    /// Whether the first record advertises a CID header in either version.
    pub fn has_cid(datagram: &[u8]) -> bool {
        datagram
            .first()
            .is_some_and(|first| *first == u8::from(ContentType::Tls12Cid) || first & 0xf0 == 0x30)
    }

    /// Locates a unique receiving association using only the first record.
    /// Later records are authenticated by that connection, never rerouted.
    pub fn lookup(&self, datagram: &[u8]) -> Option<P> {
        if !Self::has_cid(datagram) {
            return None;
        }
        let start = if datagram[0] == u8::from(ContentType::Tls12Cid) {
            11
        } else {
            1
        };
        let mut found = None;
        for len in 8..=32 {
            let Some(prefix) = datagram.get(start..start + len) else {
                break;
            };
            let Some(owners) = self.ids.get(prefix) else {
                continue;
            };
            if wire::parse_record(datagram, len).is_none() {
                continue;
            }
            if owners.unique.is_none() || found.is_some() {
                return None;
            }
            found = owners.unique;
        }
        found
    }
}

impl<P> core::fmt::Debug for CidDemux<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CidDemux")
            .field("associations", &self.owners.len())
            .field("identifiers", &self.ids.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lookup_and_collision_cleanup() {
        let mut map = CidDemux::default();
        let id = [7; 8];
        let mut datagram = alloc::vec![0x30];
        datagram.extend_from_slice(&id);
        datagram.extend_from_slice(&[0; 32]);
        map.replace(1, [&id[..]]);
        assert_eq!(map.lookup(&datagram), Some(1));
        map.replace(2, [&id[..]]);
        assert_eq!(map.lookup(&datagram), None);
        map.remove(2);
        assert_eq!(map.lookup(&datagram), Some(1));
        let longer = &datagram[1..17];
        map.replace(3, [longer]);
        assert_eq!(map.lookup(&datagram), None);
        map.remove(3);
        assert_eq!(map.lookup(&datagram), Some(1));
        map.remove(1);
        assert_eq!(map.lookup(&datagram), None);
    }

    #[test]
    fn lookup_requires_a_complete_nonempty_cid_header() {
        let mut map = CidDemux::default();
        let id = [8; 8];
        map.replace(1, [&id[..]]);
        for first in [0x20, 22, 25, 0xff] {
            let mut datagram = alloc::vec![first];
            datagram.extend_from_slice(&id);
            assert_eq!(map.lookup(&datagram), None);
        }
        assert_eq!(map.lookup(&[0x30; 8]), None);
    }

    #[test]
    fn replacing_an_owner_removes_old_ids_and_caps_new_ids() {
        let mut map = CidDemux::default();
        let old = [1; 8];
        map.replace(1, [&old[..]]);
        let ids: Vec<Vec<u8>> = (2..20).map(|byte| alloc::vec![byte; 8]).collect();
        map.replace(1, ids.iter().map(Vec::as_slice));
        assert_eq!(map.owners[&1].len(), MAX_CONNECTION_IDS);
        assert!(!map.ids.contains_key(&old[..]));
        assert!(!map.ids.contains_key(&ids[MAX_CONNECTION_IDS][..]));
        map.replace(1, [&[2; 7][..], &[3; 33][..]]);
        assert!(!map.owners.contains_key(&1));
        assert!(map.ids.is_empty());
    }
}
