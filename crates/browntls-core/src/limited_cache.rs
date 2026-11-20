//! A map with a fixed capacity that evicts its oldest insertion.

use alloc::collections::VecDeque;
use core::borrow::Borrow;
use core::hash::Hash;
use std::collections::HashMap;

/// A bounded map: inserting into a full cache removes the oldest key.
pub(crate) struct LimitedCache<K: Clone + Hash + Eq, V> {
    map: HashMap<K, V>,
    oldest: VecDeque<K>,
    capacity: usize,
}

impl<K, V> LimitedCache<K, V>
where
    K: Eq + Hash + Clone + core::fmt::Debug,
    V: Default,
{
    /// A cache holding at most `capacity_order_of_magnitude` entries.
    pub(crate) fn new(capacity_order_of_magnitude: usize) -> Self {
        let capacity = capacity_order_of_magnitude.max(1);
        Self {
            map: HashMap::with_capacity(capacity),
            oldest: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Fetches `k`, inserting a default value if absent, and lets `edit` modify it.
    pub(crate) fn get_or_insert_default_and_edit(&mut self, k: K, edit: impl FnOnce(&mut V)) {
        let inserted_new_item = match self.map.entry(k) {
            std::collections::hash_map::Entry::Occupied(value) => {
                edit(value.into_mut());
                false
            }
            entry @ std::collections::hash_map::Entry::Vacant(_) => {
                self.oldest.push_back(entry.key().clone());
                edit(entry.or_insert_with(V::default));
                true
            }
        };
        if inserted_new_item {
            self.evict_excess();
        }
    }

    /// Inserts `v` under `k`, evicting the oldest entry if the cache is full.
    pub(crate) fn insert(&mut self, k: K, v: V) {
        let inserted_new_item = match self.map.entry(k) {
            std::collections::hash_map::Entry::Occupied(mut old) => {
                old.insert(v);
                false
            }
            entry @ std::collections::hash_map::Entry::Vacant(_) => {
                self.oldest.push_back(entry.key().clone());
                entry.or_insert(v);
                true
            }
        };
        if inserted_new_item {
            self.evict_excess();
        }
    }

    fn evict_excess(&mut self) {
        while self.map.len() > self.capacity {
            match self.oldest.pop_front() {
                Some(key) => {
                    self.map.remove(&key);
                }
                None => break,
            }
        }
    }

    pub(crate) fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(k)
    }

    pub(crate) fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(k)
    }

    pub(crate) fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let value = self.map.remove(k)?;
        if let Some(pos) = self.oldest.iter().position(|x| x.borrow() == k) {
            self.oldest.remove(pos);
        }
        Some(value)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

impl<K: Clone + Hash + Eq + core::fmt::Debug, V> core::fmt::Debug for LimitedCache<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LimitedCache")
            .field("len", &self.map.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn evicts_oldest_when_full() {
        let mut cache: LimitedCache<String, usize> = LimitedCache::new(3);
        cache.insert("a".into(), 1);
        cache.insert("b".into(), 2);
        cache.insert("c".into(), 3);
        assert_eq!(cache.len(), 3);
        cache.insert("d".into(), 4);
        assert!(cache.len() <= 3);
        assert!(cache.get("a").is_none());
        assert_eq!(cache.get("d"), Some(&4));
        cache.insert("d".into(), 5);
        assert_eq!(cache.get("d"), Some(&5));
        assert_eq!(cache.remove("d"), Some(5));
        assert!(cache.get("d").is_none());
        assert!(cache.remove("zz").is_none());
    }

    #[test]
    fn edits_in_place() {
        let mut cache: LimitedCache<u8, Vec<u8>> = LimitedCache::new(2);
        cache.get_or_insert_default_and_edit(1, |v| v.push(1));
        cache.get_or_insert_default_and_edit(1, |v| v.push(2));
        assert_eq!(cache.get(&1), Some(&alloc::vec![1, 2]));
        cache.get_mut(&1).unwrap().push(3);
        assert_eq!(cache.get(&1).unwrap().len(), 3);
        cache.get_or_insert_default_and_edit(2, |_| {});
        cache.get_or_insert_default_and_edit(3, |_| {});
        assert!(cache.len() <= 2);
    }

    #[test]
    fn size_one_keeps_latest() {
        let mut cache: LimitedCache<u8, u8> = LimitedCache::new(1);
        cache.insert(1, 1);
        cache.insert(2, 2);
        assert_eq!(cache.get(&2), Some(&2));
        assert!(cache.get(&1).is_none());
    }
}
