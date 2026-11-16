//! AES-GCM keys as the public types hold them: the key expanded for the
//! selected backends and, for load-aware routing ([`crate::accel::load`]),
//! what it takes to run a record on another AES backend.

use super::{Gcm, GhashBackend, GhashKey, Instance};
use crate::Error;
use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::aes;

/// What a key that takes part in load-aware routing holds besides its
/// primary instance.
///
/// An expanded key serves one backend, and expanding takes about as long as
/// a few short records and as much memory as the key object itself. Routing
/// rarely moves anything, so the alternates are expanded when a record of
/// this key is first routed to one, from the key kept here; until then a
/// routable key costs this small allocation and nothing else.
#[cfg(feature = "std")]
struct Routing {
    /// The AES key (its first `16 * (LANE + 1)` bytes).
    key: [u8; 32],
    /// The key expanded for each alternate AES backend with its GHASH
    /// companion, as of the first record routed to an alternate. Empty if
    /// there was none then or the memory could not be had.
    alternates: std::sync::OnceLock<alloc::boxed::Box<[Option<Gcm>]>>,
}

#[cfg(feature = "std")]
impl Drop for Routing {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(feature = "std")]
impl Routing {
    /// Wipes the key and frees the alternates, wiped.
    fn wipe(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.key);
        if let Some(alternates) = self.alternates.take() {
            // Each expanded key wipes the material it owns when dropped, but
            // it was moved into its slot from the stack, and a slot is as
            // large as the largest kind of expanded key: the bytes a smaller
            // kind does not own hold whatever the stack held, which can be
            // key material of the expansion. Wipe the slots whole.
            crate::zeroize::wipe_boxed(alternates);
        }
    }

    /// The expanded keys for the alternates of `own` under the policies and
    /// the configuration in force now, on `stream`.
    fn expand(
        key: &[u8],
        stream: &'static crate::accel::load::Stream,
        own: aes::Backend,
    ) -> alloc::boxed::Box<[Option<Gcm>]> {
        let alternates = || {
            crate::accel::load::alternates(stream, own)
                .filter_map(|ab| Some((ab, GhashBackend::companion(ab)?)))
        };
        let mut keys = alloc::vec::Vec::new();
        if keys.try_reserve_exact(alternates().count()).is_err() {
            return alloc::boxed::Box::default();
        }
        // The capacity is exact, so neither the pushes nor the conversion
        // move key material to another allocation.
        for (aes_backend, ghash_backend) in alternates() {
            if keys.len() < keys.capacity() {
                keys.push(Gcm::new(key, aes_backend, ghash_backend).ok());
            }
        }
        keys.into_boxed_slice()
    }

    /// The expanded key for the alternate AES backend `backend`, expanding
    /// the alternates if this is the first time one is asked for.
    fn alternate<const LANE: usize>(
        &self,
        own: aes::Backend,
        backend: aes::Backend,
    ) -> Option<&Gcm> {
        self.alternates
            .get_or_init(|| Self::expand(&self.key[..16 * (LANE + 1)], &aes::LOAD[LANE], own))
            .iter()
            .flatten()
            .find(|gcm| gcm.aes.backend() == backend)
    }
}

/// An AES-GCM key as the public types hold it: the key expanded for the
/// selected backends (the primary instance) and, when its records are routed
/// ([`crate::accel::load`]), the means to expand it for the alternates.
/// Every expanded key zeroises its key material when dropped.
///
/// `LANE` is the stream of the AES family the key's records belong to: 0
/// for a 128-bit key, 1 for a 256-bit one, whose records cost more per byte.
pub(super) struct Keys<const LANE: usize> {
    aes: aes::Key,
    ghash: GhashKey,
    /// Set for a key created by `Aead::new` while routing was enabled. A
    /// key without it never calls into the routing code.
    #[cfg(feature = "std")]
    routing: Option<alloc::boxed::Box<Routing>>,
}

impl<const LANE: usize> Keys<LANE> {
    /// A key for explicit backends, which is never routed.
    pub(super) fn pinned(
        key: &[u8],
        aes_backend: aes::Backend,
        ghash_backend: GhashBackend,
    ) -> Result<Self, Error> {
        let Gcm { aes, ghash } = Gcm::new(key, aes_backend, ghash_backend)?;
        Ok(Self {
            aes,
            ghash,
            #[cfg(feature = "std")]
            routing: None,
        })
    }

    /// A key for the selected backends, routable if routing is enabled now.
    pub(super) fn selected(key: &[u8]) -> Result<Self, Error> {
        let Gcm { aes, ghash } = Gcm::new(key, aes::Backend::select(), GhashBackend::select())?;
        Ok(Self {
            aes,
            ghash,
            #[cfg(feature = "std")]
            routing: Self::routing(key),
        })
    }

    #[cfg(feature = "std")]
    fn routing(key: &[u8]) -> Option<alloc::boxed::Box<Routing>> {
        crate::accel::load::config()?;
        let mut routing = alloc::boxed::Box::new(Routing {
            key: [0; 32],
            alternates: std::sync::OnceLock::new(),
        });
        routing.key.get_mut(..key.len())?.copy_from_slice(key);
        Some(routing)
    }

    /// The AES and GHASH backends the key was created for.
    pub(super) fn backends(&self) -> (aes::Backend, GhashBackend) {
        (self.aes.backend(), self.ghash.backend())
    }

    /// The instance for the selected backends.
    fn primary(&self) -> Instance<'_> {
        Instance {
            aes: &self.aes,
            ghash: &self.ghash,
        }
    }

    /// The routing state, if a record of `len` bytes needs a routing
    /// decision: the key is routable, routing is enabled and the record is
    /// long enough to be timed or a share is fixed.
    #[cfg(feature = "std")]
    #[inline]
    fn routable(&self, len: usize) -> Option<&Routing> {
        let routing = self.routing.as_deref()?;
        (!crate::accel::load::idle(&aes::LOAD[LANE], len)).then_some(routing)
    }

    #[inline]
    pub(super) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        #[cfg(feature = "std")]
        if let Some(routing) = self.routable(in_out.len()) {
            return self.seal_routed(routing, nonce, aad, in_out);
        }
        self.primary().seal(nonce, aad, in_out)
    }

    #[inline]
    pub(super) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        #[cfg(feature = "std")]
        if let Some(routing) = self.routable(in_out.len()) {
            return self.open_routed(routing, nonce, aad, in_out, tag);
        }
        self.primary().open(nonce, aad, in_out, tag)
    }

    /// The AES backend for a record of `len` bytes with `aad_len` bytes of
    /// additional data, and the instance that runs it.
    #[cfg(feature = "std")]
    fn route<'a>(
        &'a self,
        routing: &'a Routing,
        len: usize,
        aad_len: usize,
    ) -> (crate::accel::load::Route<aes::Backend>, Instance<'a>) {
        let own = self.aes.backend();
        let expanded = routing.alternates.get().is_some();
        let route = crate::accel::load::route(&aes::LOAD[LANE], own, len, |b| {
            routing.alternate::<LANE>(own, b).is_some()
        });
        let instance = match routing.alternates.get() {
            Some(_) if route.backend() != own => routing
                .alternate::<LANE>(own, route.backend())
                .map_or_else(|| self.primary(), Gcm::instance),
            _ => self.primary(),
        };
        // The cost is counted per record byte: additional data beyond a
        // record header would make the record look slow, and so would the
        // key expansion if this record was the one to trigger it.
        let untimed = aad_len > len / 64 || (!expanded && routing.alternates.get().is_some());
        (if untimed { route.untimed() } else { route }, instance)
    }

    /// [`Self::seal`] for a record that needs a routing decision. Kept out
    /// of line so that other records run the code they ran before routing
    /// existed.
    #[cfg(feature = "std")]
    #[inline(never)]
    fn seal_routed(
        &self,
        routing: &Routing,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        super::check_lengths(aad, in_out)?;
        let (route, instance) = self.route(routing, in_out.len(), aad.len());
        // The result is passed on as it is: taking the tag out and wrapping
        // it again copies it in pieces, which the caller's load of the
        // whole tag then has to wait for.
        let sealed = instance.seal(nonce, aad, in_out);
        if sealed.is_ok() {
            route.done();
        }
        sealed
    }

    /// [`Self::open`] for a record that needs a routing decision.
    #[cfg(feature = "std")]
    #[inline(never)]
    fn open_routed(
        &self,
        routing: &Routing,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        super::check_lengths(aad, in_out)?;
        let (route, instance) = self.route(routing, in_out.len(), aad.len());
        // A rejected record is not reported to the balancer: it may cost
        // less than its length suggests, and a peer chooses how many to
        // send.
        instance.open(nonce, aad, in_out, tag)?;
        route.done();
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::{Aes128Gcm, Aes256Gcm};
    use super::*;
    use crate::aead::Aead as _;

    fn check_record(gcm: Instance<'_>, key: &[u8; 32], what: &str) {
        let reference = Gcm::new(key, aes::Backend::Soft, GhashBackend::Soft).unwrap();
        for len in [0usize, 1, 16, 33, 700] {
            let data: std::vec::Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let mut expected = data.clone();
            let tag = reference
                .instance()
                .seal(&[5; 12], b"aad", &mut expected)
                .unwrap();
            let mut buf = data.clone();
            assert_eq!(gcm.seal(&[5; 12], b"aad", &mut buf).unwrap(), tag, "{what}");
            assert_eq!(buf, expected, "{what}");
            gcm.open(&[5; 12], b"aad", &mut buf, &tag).unwrap();
            assert_eq!(buf, data, "{what}");
        }
    }

    /// Keys made while routing is disabled (it never is enabled in this test
    /// binary; `tests/accel_load_aes.rs` covers the rest) and keys for
    /// explicit backends hold nothing besides the primary instance, and
    /// nothing is expanded for an alternate while routing is disabled.
    #[test]
    fn keys_are_not_routable_without_routing() {
        assert!(Aes128Gcm::new(&[1; 16]).unwrap().inner.routing.is_none());
        assert!(Aes256Gcm::new(&[1; 32]).unwrap().inner.routing.is_none());
        let pinned = Aes256Gcm::with_backends(&[1; 32], aes::Backend::Soft, GhashBackend::Soft);
        assert!(pinned.unwrap().inner.routing.is_none());
        let own = aes::Backend::select();
        assert!(Routing::expand(&[1; 32], &aes::LOAD[1], own).is_empty());
    }

    /// A routable key expands its alternates when one is first asked for,
    /// finds each by its AES backend, and each computes the same function.
    /// (With routing disabled there are none to expand, so the slots are
    /// filled by hand here.)
    #[test]
    fn alternates_are_found_by_backend() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 9 + 2) as u8);
        let own = aes::Backend::select();
        let routes: std::vec::Vec<_> = aes::Backend::ALL
            .into_iter()
            .filter(|ab| *ab != own && ab.is_available())
            .filter_map(|ab| Some((ab, GhashBackend::companion(ab)?)))
            .collect();
        let slots: std::vec::Vec<_> = routes
            .iter()
            .map(|(ab, gb)| Gcm::new(&key, *ab, *gb).ok())
            .collect();
        let mut routing = Routing {
            key,
            alternates: std::sync::OnceLock::new(),
        };
        assert!(routing.alternates.set(slots.into_boxed_slice()).is_ok());
        assert!(routing.alternate::<1>(own, own).is_none());
        for (ab, gb) in &routes {
            let gcm = routing.alternate::<1>(own, *ab).unwrap();
            assert_eq!((gcm.aes.backend(), gcm.ghash.backend()), (*ab, *gb));
            check_record(gcm.instance(), &key, &std::format!("{ab:?}/{gb:?}"));
        }
        // Dropping wipes the key and gives the alternates' storage back
        // wiped (`zeroize::wipe_boxed`, whose test checks the bytes).
        routing.wipe();
        assert_eq!(routing.key, [0; 32]);
        assert!(routing.alternates.get().is_none());
    }

    /// The routing state lives behind a pointer: a key object is no larger
    /// than its expanded key where the expanded key's alignment leaves the
    /// room (as on x86-64), and by at most a pointer elsewhere.
    #[test]
    fn routing_costs_a_pointer_when_unused() {
        use core::mem::{align_of, size_of};
        let (gcm, align) = (size_of::<Gcm>(), align_of::<Gcm>());
        std::println!(
            "Gcm {gcm} (align {align}), Option<Gcm> {}, Aes128Gcm {}, Aes256Gcm {}, Routing {}",
            size_of::<Option<Gcm>>(),
            size_of::<Aes128Gcm>(),
            size_of::<Aes256Gcm>(),
            size_of::<Routing>(),
        );
        let parts = size_of::<aes::Key>() + size_of::<GhashKey>();
        let limit = (parts + size_of::<usize>()).next_multiple_of(align);
        assert!(size_of::<Aes128Gcm>() <= limit);
        assert!(size_of::<Aes256Gcm>() <= limit);
        assert_eq!(size_of::<Option<Gcm>>(), gcm);
        assert!(size_of::<Routing>() <= 64);
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        assert_eq!((size_of::<Aes256Gcm>(), gcm), (1664, 1664));
    }

    /// A key that is not routable seals and opens as the primary instance
    /// does, and rejects a forged record.
    #[test]
    fn unrouted_keys_use_the_primary_instance() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 9 + 2) as u8);
        let keys = Keys::<1>::selected(&key).unwrap();
        check_record(keys.primary(), &key, "primary");
        let mut buf = [3u8; 40];
        let tag = keys.seal(&[5; 12], b"aad", &mut buf).unwrap();
        let mut direct = [3u8; 40];
        let direct_tag = keys.primary().seal(&[5; 12], b"aad", &mut direct);
        assert_eq!((buf, Ok(tag)), (direct, direct_tag));
        let mut forged = buf;
        assert_eq!(
            keys.open(&[5; 12], b"aad!", &mut forged, &tag),
            Err(Error::DecryptFailed)
        );
        assert_eq!(forged, [0u8; 40]);
        keys.open(&[5; 12], b"aad", &mut buf, &tag).unwrap();
        assert_eq!(buf, [3u8; 40]);
    }
}
