//! AES-GCM keys as the public types hold them: the key expanded for the
//! selected backends and, for load-aware routing ([`crate::accel::load`]),
//! for the alternate AES backends.

use super::{Gcm, GhashBackend, GhashKey, Instance, check_lengths};
use crate::Error;
use crate::accel::load::{self, Route};
use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::aes;

/// A key expanded for the alternate AES backends, for a key that takes part
/// in load-aware routing. The entries are options so that the allocation has
/// its final size and place before any key material is written to it.
#[cfg(feature = "alloc")]
type Alternates = alloc::boxed::Box<[Option<Gcm>]>;
/// Without an allocator a key has no alternates and is never routed.
#[cfg(not(feature = "alloc"))]
type Alternates = [Option<Gcm>; 0];

/// An AES-GCM key as the public types hold it: the key expanded for the
/// selected backends (the primary instance) and, when its records are routed
/// ([`crate::accel::load`]), once more per alternate AES backend. Every
/// expanded key zeroises its key material when dropped.
///
/// `LANE` is the stream of the AES family the key's records belong to: 0
/// for a 128-bit key, 1 for a 256-bit one, whose records cost more per byte.
pub(super) struct Keys<const LANE: usize> {
    aes: aes::Key,
    ghash: GhashKey,
    /// Empty unless the key was created by `Aead::new` while routing was
    /// enabled and its AES backend had alternates. A key without alternates
    /// never calls into the routing code.
    alternates: Alternates,
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
            alternates: Alternates::default(),
        })
    }

    /// A key for the selected backends and, while routing is enabled, for
    /// the alternates of the selected AES backend.
    pub(super) fn selected(key: &[u8]) -> Result<Self, Error> {
        let mut keys = Self::pinned(key, aes::Backend::select(), GhashBackend::select())?;
        keys.alternates = Self::alternates(key, keys.aes.backend());
        Ok(keys)
    }

    /// The expanded keys that records of a key created for the AES backend
    /// `own` are routed to: one per alternate of `own` that has a GHASH
    /// companion.
    #[cfg(feature = "alloc")]
    fn alternates(key: &[u8], own: aes::Backend) -> Alternates {
        // At most one entry per AES backend other than `own`.
        let mut routes = [None; aes::Backend::ALL.len()];
        let alternates = load::alternates(&aes::LOAD[LANE], own)
            .filter_map(|ab| Some((ab, GhashBackend::companion(ab)?)));
        for (route, alternate) in routes.iter_mut().zip(alternates) {
            *route = Some(alternate);
        }
        Self::expand(key, &routes)
    }

    #[cfg(not(feature = "alloc"))]
    fn alternates(_key: &[u8], _own: aes::Backend) -> Alternates {
        []
    }

    /// Expands `key` for each of `routes`. If the memory cannot be had, or a
    /// backend cannot run after all (which its availability rules out), the
    /// key has no alternates and is not routed.
    #[cfg(feature = "alloc")]
    fn expand(key: &[u8], routes: &[Option<(aes::Backend, GhashBackend)>]) -> Alternates {
        let count = routes.iter().flatten().count();
        let mut keys = alloc::vec::Vec::new();
        if count == 0 || keys.try_reserve_exact(count).is_err() {
            return Alternates::default();
        }
        keys.resize_with(count, || None);
        // Still without key material, so it does not matter whether this
        // moves the allocation; from here on it stays where it is.
        let mut keys = keys.into_boxed_slice();
        for (slot, (aes_backend, ghash_backend)) in keys.iter_mut().zip(routes.iter().flatten()) {
            match Gcm::new(key, *aes_backend, *ghash_backend) {
                Ok(gcm) => *slot = Some(gcm),
                // Dropping `keys` wipes the keys expanded so far.
                Err(_) => return Alternates::default(),
            }
        }
        keys
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

    /// The expanded key for the alternate AES backend `backend`, if the key
    /// has one.
    fn alternate(&self, backend: aes::Backend) -> Option<&Gcm> {
        self.alternates
            .iter()
            .flatten()
            .find(|gcm| gcm.aes.backend() == backend)
    }

    /// The AES backend for a record of `len` bytes with `aad_len` bytes of
    /// additional data, for a key that has alternates.
    fn route(&self, len: usize, aad_len: usize) -> Route<aes::Backend> {
        let own = self.aes.backend();
        let route = load::route(&aes::LOAD[LANE], own, len, |b| self.alternate(b).is_some());
        // The cost is counted per record byte; additional data beyond a
        // record header would make the record look slow.
        if aad_len > len / 64 {
            route.untimed()
        } else {
            route
        }
    }

    /// The instance that runs a record routed to `backend`: the alternate's,
    /// or the primary one for the key's own backend.
    fn routed(&self, backend: aes::Backend) -> Instance<'_> {
        if backend == self.aes.backend() {
            return self.primary();
        }
        self.alternate(backend)
            .map_or_else(|| self.primary(), Gcm::instance)
    }

    #[inline]
    pub(super) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        if self.alternates.is_empty() {
            return self.primary().seal(nonce, aad, in_out);
        }
        self.seal_routed(nonce, aad, in_out)
    }

    #[inline]
    pub(super) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        if self.alternates.is_empty() {
            return self.primary().open(nonce, aad, in_out, tag);
        }
        self.open_routed(nonce, aad, in_out, tag)
    }

    /// [`Self::seal`] for a key that has alternates. Kept out of line so
    /// that a key without them runs the code it ran before routing existed.
    #[inline(never)]
    fn seal_routed(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        check_lengths(aad, in_out)?;
        let route = self.route(in_out.len(), aad.len());
        // The result is passed on as it is: taking the tag out and wrapping
        // it again copies it in pieces, which the caller's load of the
        // whole tag then has to wait for.
        let sealed = self.routed(route.backend()).seal(nonce, aad, in_out);
        if sealed.is_ok() {
            route.done();
        }
        sealed
    }

    /// [`Self::open`] for a key that has alternates.
    #[inline(never)]
    fn open_routed(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        check_lengths(aad, in_out)?;
        let route = self.route(in_out.len(), aad.len());
        // A rejected record is not reported to the balancer: it may cost
        // less than its length suggests, and a peer chooses how many to
        // send.
        self.routed(route.backend()).open(nonce, aad, in_out, tag)?;
        route.done();
        Ok(())
    }
}

#[cfg(test)]
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

    /// A key holds one expanded key per route it is given, found by its AES
    /// backend, and each computes the same function.
    #[test]
    fn alternates_are_expanded_per_backend() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 9 + 2) as u8);
        let own = aes::Backend::select();
        let mut routes = [None; aes::Backend::ALL.len()];
        for (route, ab) in routes.iter_mut().zip(aes::Backend::ALL) {
            if ab != own && ab.is_available() {
                *route = GhashBackend::companion(ab).map(|gb| (ab, gb));
            }
        }
        let mut keys = Keys::<1>::pinned(&key, own, GhashBackend::select()).unwrap();
        keys.alternates = Keys::<1>::expand(&key, &routes);
        assert_eq!(keys.alternates.len(), routes.iter().flatten().count());
        assert!(keys.alternate(own).is_none());
        assert!(core::ptr::eq(keys.routed(own).aes, &keys.aes));
        check_record(keys.primary(), &key, "primary");
        for (ab, gb) in routes.iter().flatten() {
            let gcm = keys.alternate(*ab).unwrap();
            assert_eq!((gcm.aes.backend(), gcm.ghash.backend()), (*ab, *gb));
            let routed = keys.routed(*ab);
            assert!(core::ptr::eq(routed.aes, &gcm.aes));
            assert!(core::ptr::eq(routed.ghash, &gcm.ghash));
            check_record(routed, &key, &std::format!("{ab:?}/{gb:?}"));
        }
        // A backend the key holds nothing for runs on the primary instance.
        for ab in aes::Backend::ALL {
            if keys.alternate(ab).is_none() {
                assert!(core::ptr::eq(keys.routed(ab).aes, &keys.aes), "{ab:?}");
            }
        }
        // Routing is never enabled in this test binary, so the routed path
        // runs the primary instance; it rejects a forged record like the
        // direct path.
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

        // No routes, or a backend that cannot run here: no alternates.
        assert!(Keys::<1>::expand(&key, &[None, None]).is_empty());
        for ab in aes::Backend::ALL {
            if !ab.is_available() {
                let routes = [
                    Some((aes::Backend::Soft, GhashBackend::Soft)),
                    Some((ab, GhashBackend::Soft)),
                ];
                assert!(Keys::<1>::expand(&key, &routes).is_empty(), "{ab:?}");
            }
        }
    }

    /// Keys made while routing is disabled (it never is enabled in this test
    /// binary; `tests/accel_load_aes.rs` covers the rest) and keys for
    /// explicit backends hold nothing besides the primary instance.
    #[test]
    fn keys_have_no_alternates_without_routing() {
        assert!(
            Aes128Gcm::new(&[1; 16])
                .unwrap()
                .inner
                .alternates
                .is_empty()
        );
        assert!(
            Aes256Gcm::new(&[1; 32])
                .unwrap()
                .inner
                .alternates
                .is_empty()
        );
        let pinned = Aes256Gcm::with_backends(&[1; 32], aes::Backend::Soft, GhashBackend::Soft);
        assert!(pinned.unwrap().inner.alternates.is_empty());
        assert!(Keys::<1>::alternates(&[1; 32], aes::Backend::select()).is_empty());
    }

    /// The alternates live behind a pointer: a key that has none is larger
    /// than its expanded key by at most that pointer and its length (and
    /// not at all where the expanded key's alignment leaves the room, as on
    /// x86-64), and an alternate takes as much memory as an expanded key.
    #[test]
    fn alternates_cost_a_pointer_when_unused() {
        use core::mem::{align_of, size_of};
        let (gcm, align) = (size_of::<Gcm>(), align_of::<Gcm>());
        std::println!(
            "Gcm {gcm} (align {align}), Option<Gcm> {}, Aes128Gcm {}, Aes256Gcm {}",
            size_of::<Option<Gcm>>(),
            size_of::<Aes128Gcm>(),
            size_of::<Aes256Gcm>()
        );
        let parts = size_of::<aes::Key>() + size_of::<GhashKey>();
        let limit = (parts + 2 * size_of::<usize>()).next_multiple_of(align);
        assert!(size_of::<Aes128Gcm>() <= limit);
        assert!(size_of::<Aes256Gcm>() <= limit);
        assert_eq!(size_of::<Option<Gcm>>(), gcm);
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        assert_eq!((size_of::<Aes128Gcm>(), size_of::<Aes256Gcm>()), (gcm, gcm));
    }
}
